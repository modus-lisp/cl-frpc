;;;; Minimal hashicorp/yamux client in Common Lisp.
;;;;
;;;; Frame (12 bytes, all multi-byte fields big-endian):
;;;;   ver(1)=0  type(1)  flags(2)  streamID(4)  length(4)
;;;; Types: 0=Data, 1=WindowUpdate, 2=Ping, 3=GoAway.
;;;; Flags: SYN=0x1, ACK=0x2, FIN=0x4, RST=0x8.
;;;;
;;;; What we implement:
;;;;   - one session per underlying byte stream (TCP / TLS)
;;;;   - client-only (we open streams; server can too — we accept incoming
;;;;     SYN so the slot exists, but most real FRP servers don't open back)
;;;;   - flow control (recv/send windows; default 256 KB but the peer can
;;;;     advertise a larger initial window via the SYN/ACK exchange)
;;;;   - automatic Ping reply
;;;;   - GoAway terminates the session
;;;;
;;;; What we DON'T implement:
;;;;   - graceful shutdown handshake on session close
;;;;   - the keep-alive Ping sender (FRP sends its own app-layer pings)
;;;;   - server-mode (we only OPEN streams, never accept new ones)


(defpackage :yamux
  (:use :cl)
  (:export #:make-session #:close-session
           #:open-stream  #:close-stream
           #:stream-write #:stream-read
           #:stream-id
           #:make-binary-stream
           #:*trace*))

(in-package :yamux)

;; Single-writer logging helper. yamux loads *before* frpc (frpc depends
;; on yamux), so we can't reference FRPC:SAY at read time. Resolve it
;; lazily and route through it when available so yamux's error lines
;; share frpc's log mutex; otherwise fall back to a raw FORMAT.
(defun yamux-log (fmt &rest args)
  (let ((say (find-symbol "SAY" :cl-frpc)))
    (cond
      ((and say (fboundp say)) (apply say fmt args))
      (t (apply #'format *error-output* fmt args)
         (finish-output *error-output*)))))

;;; ---------- frame-level tracing ----------
;;;
;;; When *TRACE* is true, every frame in/out is logged via yamux-log
;;; (which holds frpc's log mutex so lines don't interleave). Logged
;;; format: "[yamux] HH:MM:SS.mmm dir TYPE flags(F) sid=N len=N".
;;; Off by default; flip from anywhere with (setf yamux:*trace* t).

(defvar *trace* (and (sb-ext:posix-getenv "YAMUX_TRACE") t))

(defun type-name (typ)
  ;; Inline ints because the +t-…+ constants are defined further down
  ;; the file and we want this callable at any load order.
  (cond ((= typ 0) "DATA")
        ((= typ 1) "WUPD")
        ((= typ 2) "PING")
        ((= typ 3) "GOAWAY")
        (t (format nil "?~A" typ))))

(defun flag-tags (flags)
  ;; SYN=1 ACK=2 FIN=4 RST=8 — inline so call order doesn't matter.
  (with-output-to-string (s)
    (when (logtest flags 1) (write-string "SYN " s))
    (when (logtest flags 2) (write-string "ACK " s))
    (when (logtest flags 4) (write-string "FIN " s))
    (when (logtest flags 8) (write-string "RST " s))))

(defun trace-frame (dir typ flags sid len)
  (when *trace*
    (multiple-value-bind (sec usec) (sb-ext:get-time-of-day)
      (multiple-value-bind (s m h)
          (decode-universal-time (+ sec 2208988800) 0)
        (yamux-log "~&[yamux] ~2,'0D:~2,'0D:~2,'0D.~6,'0D ~A ~6A ~A sid=~D len=~D~%"
                   h m s usec dir (type-name typ) (flag-tags flags) sid len)))))

(defconstant +ver+    0)
(defconstant +t-data+ 0)
(defconstant +t-wupd+ 1)
(defconstant +t-ping+ 2)
(defconstant +t-go+   3)
(defconstant +f-syn+  #x1)
(defconstant +f-ack+  #x2)
(defconstant +f-fin+  #x4)
(defconstant +f-rst+  #x8)
(defconstant +initial-window+ (* 256 1024))   ; spec default

;;; ---------- byte-stream helpers ----------

(declaim (inline put-be-u16 put-be-u32 get-be-u16 get-be-u32))
(defun put-be-u16 (b off v)
  (setf (aref b off)       (logand #xff (ash v -8))
        (aref b (1+ off))  (logand #xff v)))
(defun put-be-u32 (b off v)
  (setf (aref b (+ off 0)) (logand #xff (ash v -24))
        (aref b (+ off 1)) (logand #xff (ash v -16))
        (aref b (+ off 2)) (logand #xff (ash v  -8))
        (aref b (+ off 3)) (logand #xff v)))
(defun get-be-u16 (b off)
  (logior (ash (aref b off) 8) (aref b (1+ off))))
(defun get-be-u32 (b off)
  (logior (ash (aref b (+ off 0)) 24)
          (ash (aref b (+ off 1)) 16)
          (ash (aref b (+ off 2))  8)
          (aref b (+ off 3))))

;;; ---------- session + stream ----------

(defstruct (session (:constructor %make-session))
  conn                                  ; underlying char stream
  ;; Writes are funneled through a dedicated writer thread + a FIFO
  ;; queue. Producers (application stream-write, reader-thread's
  ;; WINDOW_UPDATE / PING-ACK, control-side writers) enqueue and
  ;; return immediately; the writer pops the queue and does the
  ;; actual write_sequence + force-output, which is the only place
  ;; that can block on TCP backpressure. That isolation is what stops
  ;; a slow flush from freezing the reader-thread or stacking up all
  ;; other producers waiting for the same write lock — the failure
  ;; mode that made work-conn opens hang for 60-90 seconds.
  (state-lock      (bt:make-lock "yamux-st"))
  ;; Single FIFO send queue. We tried a hi-pri/lo-pri split (small
  ;; frames jumping ahead of big bulk-data ones) — that scrambled
  ;; per-stream byte order, because stream-write naturally emits
  ;; small partial-window chunks interleaved with full-size chunks.
  ;; Sub-stream reordering = silent file corruption. Don't do it.
  ;; pool_count on the FRP side keeps the user-visible control
  ;; latency low without any reordering tricks.
  (send-queue       nil)
  (send-queue-lock  (bt:make-lock "yamux-sendq"))
  (send-queue-cond  (bt:make-condition-variable :name "yamux-sendq"))
  writer-thread
  (next-id    1)                        ; client uses odd ids
  (streams    (make-hash-table))
  reader-thread
  keepalive-thread                      ; sends yamux pings every 30s (hashicorp default)
  closed-p
  go-away-error)

(defstruct mux-stream
  session
  id
  ;; Incoming buffered data: a list of (simple-array (unsigned-byte 8) (*))
  ;; chunks plus an offset into the head chunk.
  (inbox     nil)
  (inbox-off 0)
  (inbox-bytes 0)
  (inbox-lock (bt:make-lock "yamux-stream-in"))
  (inbox-cond (bt:make-condition-variable :name "yamux-stream-in"))
  ;; Flow control. SEND-WINDOW is what *we* may send; +initial-window+ until
  ;; the peer sends WindowUpdate. RECV-WINDOW is what we've granted them.
  ;; SEND-LOCK/SEND-COND gate writers so they block when SEND-WINDOW is
  ;; depleted instead of blasting past the peer's recv buffer — the
  ;; old non-blocking behaviour worked for tiny FRP control messages
  ;; but turned a 13 MB static-file response into a protocol violation
  ;; that took down the whole TLS session.
  (send-window +initial-window+)
  (send-lock  (bt:make-lock "yamux-stream-send"))
  (send-cond  (bt:make-condition-variable :name "yamux-stream-send"))
  (recv-window +initial-window+)
  (max-recv-window +initial-window+)
  ;; SYN/ACK gating
  syn-acked
  (syn-cond (bt:make-condition-variable :name "yamux-syn"))
  ;; lifecycle
  local-closed
  remote-closed
  rst)

;; Public alias so callers can say YAMUX:STREAM-ID without exporting the
;; struct's internal accessor name (mux-stream-id).
(declaim (inline stream-id))
(defun stream-id (st) (mux-stream-id st))

;;; ---------- frame I/O ----------

(defun read-fully (s buf len)
  "read-sequence from TLS/socket streams can return short — loop until
   we've filled LEN bytes or hit EOF. Errors on EOF mid-read."
  (let ((got 0))
    (loop while (< got len) do
          (let ((n (read-sequence buf s :start got :end len)))
            (when (= n got)
              (error 'end-of-file :stream s))
            (setf got n)))
    got))

(defun read-frame (s)
  "Block-read a single 12-byte header (+ payload if data). Returns
   (values type flags stream-id length payload-or-nil)."
  (let ((hdr (make-array 12 :element-type '(unsigned-byte 8))))
    (read-fully s hdr 12)
    (let* ((typ   (aref hdr 1))
           (flags (get-be-u16 hdr 2))
           (sid   (get-be-u32 hdr 4))
           (len   (get-be-u32 hdr 8)))
      (trace-frame "<-" typ flags sid len)
      (cond
        ((= typ +t-data+)
         (let ((buf (make-array len :element-type '(unsigned-byte 8))))
           (when (plusp len)
             (read-fully s buf len))
           (values typ flags sid len buf)))
        (t
         (values typ flags sid len nil))))))

(defun write-frame (sess type flags sid length &optional payload)
  "Build a yamux frame and enqueue it for the writer thread. Returns
   immediately — the actual write_sequence + force-output happens on
   the dedicated writer, so no caller blocks on TCP backpressure or
   on contention from other writers. Single FIFO queue: yamux is a
   stream protocol and any reordering across frames belonging to the
   same stream silently corrupts the payload, so we don't get cute
   with priorities."
  (let* ((hdr-len 12)
         (payload-len (if payload (length payload) 0))
         (frame (make-array (+ hdr-len payload-len)
                            :element-type '(unsigned-byte 8))))
    (setf (aref frame 0) +ver+
          (aref frame 1) type)
    (put-be-u16 frame 2 flags)
    (put-be-u32 frame 4 sid)
    (put-be-u32 frame 8 length)
    (when payload
      (replace frame payload :start1 hdr-len))
    (trace-frame "->" type flags sid length)
    (bt:with-lock-held ((session-send-queue-lock sess))
      (when (session-closed-p sess)
        (error "yamux session closed during write"))
      (push frame (session-send-queue sess))
      (bt:condition-notify (session-send-queue-cond sess)))))

(defun try-write-frame (sess type flags sid length)
  "Compat shim: now that write-frame is non-blocking (writer-thread
   drains an enqueued FIFO), there's no lock-contention case to avoid.
   Always succeeds unless the session is closed."
  (handler-case (progn (write-frame sess type flags sid length) t)
    (error () nil)))

(defun writer-loop (sess)
  "Single writer thread. Drains the FIFO send queue in batches, writes
   them all then force-output once per batch — that minimises syscalls
   when many small frames arrive (heartbeat, ACK, etc.) but still
   keeps bulk transfers flowing because each large frame still gets
   its own write-sequence call."
  (unwind-protect
       (loop
         (let (batch)
           (bt:with-lock-held ((session-send-queue-lock sess))
             (loop while (and (null (session-send-queue sess))
                              (not (session-closed-p sess)))
                   do (bt:condition-wait (session-send-queue-cond sess)
                                          (session-send-queue-lock sess)))
             (when (and (session-closed-p sess)
                        (null (session-send-queue sess)))
               (return))
             (setf batch (nreverse (session-send-queue sess))
                   (session-send-queue sess) nil))
           (handler-case
               (progn
                 (dolist (frame batch)
                   (write-sequence frame (session-conn sess)))
                 (force-output (session-conn sess)))
             (error (e)
               (yamux-log "~&[yamux] writer died: ~A~%" e)
               (setf (session-closed-p sess) t)
               (return)))))
    ;; Make sure any threads blocked on stream state (send-window,
    ;; syn-ack, inbox) observe the closed session.
    (setf (session-closed-p sess) t)
    (wake-all-streams sess)
    ;; Also wake anyone blocked trying to enqueue more frames so they
    ;; can see the closed flag and bail.
    (bt:with-lock-held ((session-send-queue-lock sess))
      (bt:condition-notify (session-send-queue-cond sess)))))

;;; ---------- reader thread ----------

(defun lookup-stream (sess sid)
  (bt:with-lock-held ((session-state-lock sess))
    (gethash sid (session-streams sess))))

(defun deliver-data (st payload)
  (let ((n (length payload)))
    (bt:with-lock-held ((mux-stream-inbox-lock st))
      (setf (mux-stream-inbox st) (append (mux-stream-inbox st) (list payload)))
      (incf (mux-stream-inbox-bytes st) n)
      (decf (mux-stream-recv-window st) n)
      (bt:condition-notify (mux-stream-inbox-cond st)))
    ;; If our receive window is getting low, top it up so the peer can
    ;; keep sending. We MUST use try-write-frame here, not write-frame:
    ;; this runs on the reader thread, and if a writer is currently
    ;; holding session-write-lock blocked on TCP force-output, a
    ;; blocking write-frame here would freeze the reader, preventing
    ;; any other stream's frames from being dispatched — including
    ;; StartWorkConn replies that pipe-streams writers are waiting for.
    ;; Classic deadlock: writer waits on TCP buffer, reader waits on
    ;; writer, all streams hang for tens of seconds.
    ;;
    ;; Only credit recv-window if the update actually flushed, so our
    ;; tracking stays in sync with what the peer believes.
    (when (< (mux-stream-recv-window st) (floor (mux-stream-max-recv-window st) 2))
      (let ((delta (- (mux-stream-max-recv-window st) (mux-stream-recv-window st))))
        (when (try-write-frame (mux-stream-session st)
                               +t-wupd+ 0 (mux-stream-id st) delta)
          (incf (mux-stream-recv-window st) delta))))))

(defun handle-window-update (st flags length)
  (when (and (logtest flags +f-ack+) (not (mux-stream-syn-acked st)))
    ;; The SYN-ACK carries the peer's initial offered window; replace ours.
    (bt:with-lock-held ((mux-stream-inbox-lock st))
      (when (plusp length) (setf (mux-stream-send-window st) length))
      (setf (mux-stream-syn-acked st) t)
      (bt:condition-notify (mux-stream-syn-cond st))))
  (unless (logtest flags +f-ack+)
    ;; Plain WindowUpdate: peer is granting us more credit. Notify any
    ;; writer blocked in stream-write waiting for room.
    (bt:with-lock-held ((mux-stream-send-lock st))
      (incf (mux-stream-send-window st) length)
      (bt:condition-notify (mux-stream-send-cond st))))
  (when (logtest flags +f-fin+)
    (setf (mux-stream-remote-closed st) t)
    (bt:with-lock-held ((mux-stream-inbox-lock st))
      (bt:condition-notify (mux-stream-inbox-cond st))))
  (when (logtest flags +f-rst+)
    (setf (mux-stream-rst st) t)
    (setf (mux-stream-remote-closed st) t)
    (bt:with-lock-held ((mux-stream-inbox-lock st))
      (bt:condition-notify (mux-stream-inbox-cond st)))))

(defun wake-all-streams (sess)
  "Notify every stream's wait-conds so any thread blocked in stream-read,
   stream-write (send-window), or open-stream (SYN/ACK) wakes up and
   observes the (now-closed) session state."
  (bt:with-lock-held ((session-state-lock sess))
    (maphash (lambda (k st)
               (declare (ignore k))
               (bt:with-lock-held ((mux-stream-inbox-lock st))
                 (bt:condition-notify (mux-stream-inbox-cond st))
                 (bt:condition-notify (mux-stream-syn-cond st)))
               (bt:with-lock-held ((mux-stream-send-lock st))
                 (bt:condition-notify (mux-stream-send-cond st))))
             (session-streams sess))))

(defun reader-loop (sess)
  (unwind-protect
       (handler-case
           (loop
             (multiple-value-bind (typ flags sid len payload) (read-frame (session-conn sess))
               (cond
                 ((= typ +t-ping+)
                  (cond
                    ((logtest flags +f-syn+)
                     ;; Peer pinged us; reply with ACK. Same try-lock
                     ;; rule as deliver-data — never block the reader
                     ;; on a stuck writer. If we drop a ping reply the
                     ;; peer may time us out at the yamux-keepalive
                     ;; layer, but that's still better than freezing
                     ;; the whole reader.
                     (try-write-frame sess +t-ping+ +f-ack+ 0 len))
                    ;; ACK from a ping we sent; we don't track those, ignore.
                    (t nil)))
                 ((= typ +t-go+)
                  (setf (session-go-away-error sess) len
                        (session-closed-p sess) t)
                  (return))
                 ((= typ +t-wupd+)
                  (let ((st (lookup-stream sess sid)))
                    (when st (handle-window-update st flags len))))
                 ((= typ +t-data+)
                  (let ((st (lookup-stream sess sid)))
                    (cond
                      (st
                       (deliver-data st payload)
                       (when (logtest flags +f-fin+)
                         (setf (mux-stream-remote-closed st) t)
                         (bt:with-lock-held ((mux-stream-inbox-lock st))
                           (bt:condition-notify (mux-stream-inbox-cond st)))))
                      (t
                       ;; Unknown stream — RST it so the peer cleans up.
                       (write-frame sess +t-wupd+ +f-rst+ sid 0)))))
                 (t nil))))
         (end-of-file () nil)
         (error (e)
           (yamux-log "~&[yamux] reader died: ~A~%" e)))
    ;; Whatever path we took out of the loop — clean exit, EOF, or a
    ;; surprise SSL/socket error — mark the session dead and wake every
    ;; sleeping stream so callers can observe the close. Also wake the
    ;; writer thread so it observes the close and exits.
    (setf (session-closed-p sess) t)
    (wake-all-streams sess)
    (bt:with-lock-held ((session-send-queue-lock sess))
      (bt:condition-notify (session-send-queue-cond sess)))))

;;; ---------- session lifecycle ----------

(defparameter *keepalive-interval* 30
  "Seconds between yamux PING frames. Matches hashicorp/yamux's
   default KeepAliveInterval. The peer's response (PING+ACK) keeps
   its own keepalive timer happy and our continuing traffic on the
   underlying TLS conn keeps NAT / firewall state alive.")

(defun keepalive-loop (sess)
  "Send a yamux PING every *keepalive-interval* seconds. The PING
   carries an opaque 32-bit value in the length field; the peer
   echoes it back as PING+ACK (reader-loop handles that and ignores
   the value — we don't track round-trip times)."
  (let ((n 0))
    (loop until (session-closed-p sess) do
          (sleep *keepalive-interval*)
          (when (session-closed-p sess) (return))
          (handler-case (write-frame sess +t-ping+ +f-syn+ 0 (incf n))
            (error (e)
              (yamux-log "~&[yamux] keepalive write failed: ~A~%" e)
              (return))))))

(defun make-session (conn)
  "Wrap CONN (a binary I/O stream) in a yamux session and start its
   reader, writer, and keepalive threads.

   History: we used to skip the keepalive ping sender because, under
   cl+ssl, a PING write racing the reader's SSL_read on the same SSL
   handle caused `sslv3 alert bad record mac` deaths. Two things make
   it safe now: (1) the dedicated writer thread is the ONLY thing that
   ever writes the underlying stream — every producer enqueues, so
   there's no concurrent-write race even under cl+ssl; (2) production
   runs the pure-Lisp TLS stack, where the read and write directions
   have independent keys/sequence numbers, so read-vs-write is safe by
   construction. Keepalive matters because idle pooled work-conns were
   going stale (NAT/middlebox idle-timeout, or frps dropping a quiet
   session) — the first request after an idle stretch then got handed
   a dead work-conn and hung. A 30 s yamux PING keeps the whole
   session warm."
  (let ((s (%make-session :conn conn)))
    ;; Writer first — reader's WUPD / PING-ACK and keepalive PINGs all
    ;; enqueue here, so the queue's consumer must exist before any
    ;; producer runs.
    (setf (session-writer-thread s)
          (bt:make-thread (lambda () (writer-loop s)) :name "yamux-writer"))
    (setf (session-reader-thread s)
          (bt:make-thread (lambda () (reader-loop s)) :name "yamux-reader"))
    (setf (session-keepalive-thread s)
          (bt:make-thread (lambda () (keepalive-loop s)) :name "yamux-keepalive"))
    s))

(defun close-session (sess)
  (unless (session-closed-p sess)
    ;; Enqueue GoAway first, then flip the closed flag and wake the
    ;; writer so it flushes the GoAway + exits cleanly. write-frame
    ;; checks session-closed-p, so we must enqueue BEFORE flipping it.
    (ignore-errors (write-frame sess +t-go+ 0 0 0))
    (setf (session-closed-p sess) t)
    (bt:with-lock-held ((session-send-queue-lock sess))
      (bt:condition-notify (session-send-queue-cond sess))))
  (ignore-errors (close (session-conn sess))))

;;; ---------- streams ----------

(defparameter *syn-window-delta* (* 2 1024 1024)
  "Bytes added to frps's recvBuf for each new stream via the SYN
   length field. Bigger value → frps grants us larger WindowUpdates →
   higher per-stream throughput. hashicorp/yamux's MaxStreamWindowSize
   defaults to 16 MB so anything up to that *should* be safe. Earlier
   I tried 6 MB and the work-conn handshake stopped completing — not
   sure if that was actually the delta or some other concurrent
   change. Re-trying at 1 MB; bisect up if this works.")

(defun open-stream (sess)
  "Open a new outbound stream. Sends SYN, blocks for ACK, returns STREAM."
  (let* ((sid (bt:with-lock-held ((session-state-lock sess))
                (let ((id (session-next-id sess)))
                  (incf (session-next-id sess) 2)
                  id)))
         (st  (make-mux-stream :session sess :id sid)))
    (bt:with-lock-held ((session-state-lock sess))
      (setf (gethash sid (session-streams sess)) st))
    (write-frame sess +t-wupd+ +f-syn+ sid *syn-window-delta*)
    ;; Wait for the peer's SYN/ACK (a Window Update with ACK flag).
    (bt:with-lock-held ((mux-stream-inbox-lock st))
      (loop while (and (not (mux-stream-syn-acked st))
                       (not (session-closed-p sess)))
            do (bt:condition-wait (mux-stream-syn-cond st) (mux-stream-inbox-lock st))))
    (when (and (not (mux-stream-syn-acked st)) (session-closed-p sess))
      (error "yamux session closed before stream ~D was acknowledged" sid))
    st))

(defun close-stream (st)
  "Half-close: send FIN. Reads can still drain remaining buffered data."
  (unless (mux-stream-local-closed st)
    (setf (mux-stream-local-closed st) t)
    (ignore-errors
     (write-frame (mux-stream-session st) +t-data+ +f-fin+ (mux-stream-id st) 0))))

;;; ---------- write ----------
;;;
;;; Yamux supports up to 4 GB per data frame but server impls cap it.
;;; 32 KB chunks are safe everywhere and small enough that interleaved
;;; control / heartbeat frames don't wait long for the session
;;; write-lock between chunks.

(defconstant +max-data-frame+ (* 256 1024)
  "Cap on a single Data frame's payload. Yamux allows up to 16 MB but
   larger frames mean a single writer thread holds the underlying
   socket longer per frame, hurting ping latency. 256 KB is a sweet
   spot: ~50 frames per typical bulk response, ~5 ms per frame on a
   100 Mbps link — well below the keepalive timeout.")

(defun stream-write (st bytes &key (start 0) (end (length bytes)))
  "Send BYTES[start:end] on the stream. Honours the peer's send-window:
   if there's no credit, block on send-cond until handle-window-update
   tops us up. The session reader notifies wake-all-streams on close so
   a stuck writer doesn't hang forever on a dead session."
  (when (mux-stream-local-closed st)
    (error "yamux stream ~D already closed" (mux-stream-id st)))
  (let ((sess (mux-stream-session st)))
    (loop with i = start while (< i end) do
          (let* ((max-take (min (- end i) +max-data-frame+))
                 (take 0))
            ;; Block only when the window is fully drained. With a
            ;; partial window (say 100 KB left, max-take 256 KB) the
            ;; old code waited for a full 256 KB grant — bumping every
            ;; chunk into a round-trip. Instead, take whatever credit
            ;; we have right now and only block when there's literally
            ;; none, which keeps the pipe full and reduces sawtooth.
            (bt:with-lock-held ((mux-stream-send-lock st))
              (loop while (and (zerop (mux-stream-send-window st))
                               (not (mux-stream-local-closed st))
                               (not (mux-stream-rst st))
                               (not (session-closed-p sess)))
                    do (bt:condition-wait (mux-stream-send-cond st)
                                          (mux-stream-send-lock st)))
              (when (or (mux-stream-local-closed st)
                        (mux-stream-rst st)
                        (session-closed-p sess))
                (error "yamux stream ~D closed during write" (mux-stream-id st)))
              (setf take (min max-take (mux-stream-send-window st)))
              (decf (mux-stream-send-window st) take))
            (let ((chunk (if (and (= start 0) (= take (length bytes))
                                  (typep bytes '(simple-array (unsigned-byte 8) (*))))
                             bytes
                             (let ((b (make-array take :element-type '(unsigned-byte 8))))
                               (replace b bytes :start2 i :end2 (+ i take))
                               b))))
              (write-frame sess +t-data+ 0 (mux-stream-id st) take chunk))
            (incf i take)))))

;;; ---------- read ----------

(defun stream-read (st buf &key (start 0) (end (length buf)))
  "Read up to (- end start) bytes into BUF. Returns the number of bytes
   actually written. Blocks until at least one byte is available; returns 0
   on clean half-close (FIN from peer)."
  (let ((want (- end start))
        (got 0))
    (when (zerop want) (return-from stream-read 0))
    (bt:with-lock-held ((mux-stream-inbox-lock st))
      (loop while (and (zerop (mux-stream-inbox-bytes st))
                       (not (mux-stream-remote-closed st))
                       (not (session-closed-p (mux-stream-session st))))
            do (bt:condition-wait (mux-stream-inbox-cond st) (mux-stream-inbox-lock st)))
      (when (and (zerop (mux-stream-inbox-bytes st))
                 (or (mux-stream-remote-closed st)
                     (session-closed-p (mux-stream-session st))))
        (return-from stream-read 0))
      (loop while (and (plusp want) (plusp (mux-stream-inbox-bytes st))) do
            (let* ((head (first (mux-stream-inbox st)))
                   (avail (- (length head) (mux-stream-inbox-off st)))
                   (n (min want avail)))
              (replace buf head :start1 (+ start got)
                                :start2 (mux-stream-inbox-off st)
                                :end2 (+ (mux-stream-inbox-off st) n))
              (incf got n)
              (decf want n)
              (decf (mux-stream-inbox-bytes st) n)
              (cond
                ((= n avail)
                 (pop (mux-stream-inbox st))
                 (setf (mux-stream-inbox-off st) 0))
                (t
                 (incf (mux-stream-inbox-off st) n))))))
    got))

;;; ---------- Gray-stream wrapper ----------
;;;
;;; Lets callers treat a yamux mux-stream as an ordinary binary I/O stream
;;; (read-byte, read-sequence, write-sequence, force-output).

(defclass binary-stream (sb-gray:fundamental-binary-input-stream
                         sb-gray:fundamental-binary-output-stream)
  ((mux :initarg :mux :reader bs-mux)))

(defun make-binary-stream (mux-stream)
  (make-instance 'binary-stream :mux mux-stream))

(defmethod stream-element-type ((s binary-stream)) '(unsigned-byte 8))

(defmethod sb-gray:stream-write-byte ((s binary-stream) byte)
  (let ((b (make-array 1 :element-type '(unsigned-byte 8) :initial-element byte)))
    (stream-write (bs-mux s) b))
  byte)

(defmethod sb-gray:stream-write-sequence ((s binary-stream) seq &optional (start 0) end)
  (stream-write (bs-mux s) seq :start (or start 0) :end (or end (length seq)))
  seq)

(defmethod sb-gray:stream-read-byte ((s binary-stream))
  (let ((b (make-array 1 :element-type '(unsigned-byte 8))))
    (let ((n (stream-read (bs-mux s) b)))
      (if (zerop n) :eof (aref b 0)))))

(defmethod sb-gray:stream-read-sequence ((s binary-stream) seq &optional (start 0) end)
  ;; Return as soon as the underlying stream gives us anything. Pipe loops
  ;; ask for full-buffer reads, but blocking until the buffer's full would
  ;; deadlock — the user's HTTP GET is short and the local backend's
  ;; response can't start until we've forwarded those bytes.
  (let* ((start (or start 0))
         (end   (or end (length seq)))
         (n (stream-read (bs-mux s) seq :start start :end end)))
    (+ start n)))

(defmethod sb-gray:stream-finish-output ((s binary-stream)) nil)
(defmethod sb-gray:stream-force-output  ((s binary-stream)) nil)
(defmethod sb-gray:stream-listen ((s binary-stream))
  (let ((st (bs-mux s)))
    (or (plusp (mux-stream-inbox-bytes st))
        (mux-stream-remote-closed st)
        (session-closed-p (mux-stream-session st)))))
(defmethod close ((s binary-stream) &key abort)
  (declare (ignore abort))
  (close-stream (bs-mux s)))

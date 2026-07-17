;;;; src/frpc.lisp — an frp (fatedier/frp) reverse-proxy client, pure Common Lisp.
;;;;
;;;; Implements the frp v0 control protocol: 1B type + 8B big-endian length + JSON body,
;;;; token auth (privilege_key = md5(token+unix_ts)), 30s app-level heartbeats, and on
;;;; ReqWorkConn a fresh work stream is opened (NewWorkConn -> StartWorkConn) and its raw
;;;; bytes are handed to a consumer.  Control + work streams are multiplexed over ONE
;;;; connection with yamux (frp's transport.tcpMux default).  TLS is seal (pure CL, no
;;;; OpenSSL); the outbound connection is a cl-transport DIAL, so the tunnel itself can go
;;;; direct / SOCKS5 / Tor.  Ported from an earlier cl+ssl/jonathan client.

(defpackage #:cl-frpc
  (:use #:cl)
  (:local-nicknames (#:yamux #:yamux) (#:ct #:cl-transport)
                    (#:ic #:ironclad) (#:jzon #:com.inuoe.jzon)
                    (#:bt #:bordeaux-threads))
  (:export #:run #:expose #:say #:tear-down-tunnel
           #:*client-version* #:*last-pong-tsec* #:*last-heartbeat-tsec*))

(in-package #:cl-frpc)

;;; ---------- single-writer logging ----------
;;; Several threads (control reader, work-conn handlers, heartbeat) log at once; a mutex
;;; around one FORMAT + FINISH-OUTPUT keeps each line intact.  yamux resolves SAY lazily.

(defvar *log-lock* (bt:make-lock "cl-frpc-log"))
(defun say (fmt &rest args)
  (bt:with-lock-held (*log-lock*)
    (apply #'format *error-output* fmt args)
    (finish-output *error-output*)))

(defparameter *client-version* "0.55.0"
  "Reported client version; recent enough to match modern frps builds.")

;;; ---------- wire framing ----------

(defun utf8 (string) (sb-ext:string-to-octets string :external-format :utf-8))
(defun utf8->string (bytes) (sb-ext:octets-to-string bytes :external-format :utf-8))

(defun %obj (&rest kv)
  "A plist of string keys -> a jzon object (hash-table).  (%obj) => {}."
  (let ((h (make-hash-table :test 'equal)))
    (loop for (k v) on kv by #'cddr do (setf (gethash k h) v))
    h))

(defun read-msg (s)
  "Read one framed message from S: type(1) + length(8 BE) + JSON body.
   Returns (values type-char parsed-body-hash-table)."
  (let ((hdr (make-array 9 :element-type '(unsigned-byte 8))) (got 0))
    (loop while (< got 9)
          do (let ((n (read-sequence hdr s :start got)))
               (when (= n got) (error 'end-of-file :stream s))
               (setf got n)))
    (let* ((type-byte (aref hdr 0))
           (n (loop with v = 0 for i from 1 to 8
                    do (setf v (logior (ash v 8) (aref hdr i))) finally (return v)))
           (buf (make-array n :element-type '(unsigned-byte 8))) (got 0))
      (loop while (< got n)
            do (let ((r (read-sequence buf s :start got)))
                 (when (= r got) (error 'end-of-file :stream s))
                 (setf got r)))
      (values (code-char type-byte)
              (if (zerop n) (%obj) (jzon:parse (utf8->string buf)))))))

(defun write-msg (s type-char obj)
  "Frame and send one message in ONE write: type(1) + length(8 BE) + JSON body."
  (let* ((body (utf8 (jzon:stringify obj)))
         (n (length body))
         (out (make-array (+ 9 n) :element-type '(unsigned-byte 8))))
    (setf (aref out 0) (char-code type-char))
    (dotimes (i 8) (setf (aref out (1+ i)) (logand #xff (ash n (- (* (- 7 i) 8))))))
    (replace out body :start1 9)
    (write-sequence out s)
    (force-output s)))

;;; ---------- token auth + wire crypto ----------

(defun md5-hex (string)
  (ic:byte-array-to-hex-string (ic:digest-sequence :md5 (utf8 string))))

(defun unix-now () (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)))

(defun compute-privilege-key (token timestamp)
  "frp privilege_key = md5(token + decimal-unix-timestamp)."
  (md5-hex (format nil "~a~d" (or token "") timestamp)))

(defun derive-frp-key (token)
  "The AES key for frp's v0 wire encryption: PBKDF2-HMAC-SHA1(token, salt=\"frp\",
   64 iters, 16 bytes).  frps overrides golib's \"crypto\" default salt to \"frp\" at
   startup (server/service.go), so \"frp\" is what the running binary actually uses."
  (when token
    (ic:derive-key (ic:make-kdf 'ic:pbkdf2 :digest 'ic:sha1)
                   (utf8 token) (utf8 "frp") 64 16)))

;;; AES-128-CFB stream: the first writer emits a random 16-byte IV; the reader consumes
;;; 16 bytes of IV before decrypting.  Cipher state advances per call.

(defun random-iv ()
  (let ((iv (make-array 16 :element-type '(unsigned-byte 8))))
    (dotimes (i 16 iv) (setf (aref iv i) (random 256)))))

(defclass aes-cfb-stream (sb-gray:fundamental-binary-input-stream
                          sb-gray:fundamental-binary-output-stream)
  ((under :initarg :under :reader cfb-under)
   (key   :initarg :key   :reader cfb-key)
   (enc   :initform nil    :accessor cfb-enc)
   (dec   :initform nil    :accessor cfb-dec)))

(defun wrap-aes-cfb (under key) (make-instance 'aes-cfb-stream :under under :key key))
(defmethod stream-element-type ((s aes-cfb-stream)) '(unsigned-byte 8))

(defun ensure-enc (s)
  (or (cfb-enc s)
      (let ((iv (random-iv)))
        (setf (cfb-enc s) (ic:make-cipher :aes :key (cfb-key s) :mode :cfb
                                               :initialization-vector iv))
        (write-sequence iv (cfb-under s)) (force-output (cfb-under s))
        (cfb-enc s))))

(defun ensure-dec (s)
  (or (cfb-dec s)
      (let ((iv (make-array 16 :element-type '(unsigned-byte 8))))
        (read-sequence iv (cfb-under s))
        (setf (cfb-dec s) (ic:make-cipher :aes :key (cfb-key s) :mode :cfb
                                               :initialization-vector iv)))))

(defmethod sb-gray:stream-write-byte ((s aes-cfb-stream) byte)
  (let ((c (ensure-enc s)) (b (make-array 1 :element-type '(unsigned-byte 8)
                                            :initial-element byte)))
    (ic:encrypt-in-place c b) (write-byte (aref b 0) (cfb-under s)))
  byte)

(defmethod sb-gray:stream-write-sequence ((s aes-cfb-stream) seq &optional (start 0) end)
  (let* ((start (or start 0)) (end (or end (length seq))) (c (ensure-enc s))
         (tmp (make-array (- end start) :element-type '(unsigned-byte 8))))
    (replace tmp seq :start2 start :end2 end)
    (ic:encrypt-in-place c tmp)
    (write-sequence tmp (cfb-under s)))
  seq)

(defmethod sb-gray:stream-read-byte ((s aes-cfb-stream))
  (let ((c (ensure-dec s)) (b (make-array 1 :element-type '(unsigned-byte 8))))
    (if (zerop (read-sequence b (cfb-under s))) :eof
        (progn (ic:decrypt-in-place c b) (aref b 0)))))

(defmethod sb-gray:stream-read-sequence ((s aes-cfb-stream) seq &optional (start 0) end)
  (let* ((start (or start 0)) (end (or end (length seq))) (c (ensure-dec s))
         (n (- end start)) (tmp (make-array n :element-type '(unsigned-byte 8))) (got 0))
    (loop while (< got n)
          do (let ((r (read-sequence tmp (cfb-under s) :start got :end n)))
               (when (= r got) (return)) (setf got r)))
    (when (plusp got)
      (let ((sub (subseq tmp 0 got))) (ic:decrypt-in-place c sub) (replace seq sub :start1 start)))
    (+ start got)))

(defmethod sb-gray:stream-finish-output ((s aes-cfb-stream)) (force-output (cfb-under s)))
(defmethod sb-gray:stream-force-output  ((s aes-cfb-stream)) (force-output (cfb-under s)))

;;; ---------- transport: cl-transport dial + seal TLS + yamux ----------

(defstruct frpc-transport raw-stream closer tls-stream mux token-key)
(defstruct frpc-conn transport mux-stream stream)

(defun %seal-transport (stream)
  "Wrap an already-open cl-transport byte STREAM as a seal TLS transport, so seal runs
   over whatever cl-transport dialed (direct / SOCKS5 / Tor) and we keep the raw stream
   for frp's #x17 pre-TLS tag."
  (seal::%make-transport
   :sender (lambda (bytes)
             (write-sequence bytes stream) (force-output stream) t)
   :receiver (lambda ()
               (let ((b0 (read-byte stream nil :eof)))
                 (unless (eq b0 :eof)
                   (let ((buf (make-array 16384 :element-type '(unsigned-byte 8))) (n 1))
                     (setf (aref buf 0) b0)
                     (loop while (and (< n 16384) (listen stream))
                           do (let ((bx (read-byte stream nil :eof)))
                                (when (eq bx :eof) (return))
                                (setf (aref buf n) bx) (incf n)))
                     (subseq buf 0 n)))))
   :closer (lambda () (ignore-errors (close stream)))))

(defun open-transport (host port tls-p token &key (transport :direct) (timeout 15))
  "Dial HOST:PORT via cl-transport, optionally wrap in seal TLS (after frp's #x17 tag),
   and start a yamux session over it."
  (multiple-value-bind (raw closer) (ct:dial host port :transport transport :timeout timeout)
    (let* ((under (cond ((not tls-p) raw)
                        (t (write-byte #x17 raw) (force-output raw)
                           (let ((conn (seal:connect host port :verify nil :timeout timeout
                                                               :transport (%seal-transport raw))))
                             (seal:make-tls-stream conn)))))
           (mux (yamux:make-session under)))
      (make-frpc-transport :raw-stream raw :closer closer :tls-stream under :mux mux
                           :token-key (derive-frp-key token)))))

(defun close-transport (tr)
  (ignore-errors (yamux:close-session (frpc-transport-mux tr)))
  (ignore-errors (close (frpc-transport-tls-stream tr)))
  (ignore-errors (funcall (frpc-transport-closer tr))))

(defun open-stream* (tr)
  "A fresh yamux stream off the shared transport, as a binary Gray stream."
  (let ((s (yamux:open-stream (frpc-transport-mux tr))))
    (make-frpc-conn :transport tr :mux-stream s :stream (yamux:make-binary-stream s))))

(defun close-conn (c) (ignore-errors (close (frpc-conn-stream c))))

;;; ---------- session (dynamic, per RUN) ----------

(defvar *session* nil "Per-RUN plist; rebound in child threads from a captured closure.")
(defun sprop (k) (getf *session* k))
(defun (setf sprop) (v k) (setf (getf *session* k) v))

(defvar *last-run-id* nil)
(defvar *last-pong-tsec* 0)
(defvar *last-heartbeat-tsec* 0)
(defparameter *pong-timeout* 90)
(defparameter *heartbeat-interval* 30)
(defvar *live-transport* nil)

;;; ---------- login / proxy registration ----------

(defun do-login (ctl)
  "Login + LoginResp on the plaintext control stream, then upgrade to AES-128-CFB."
  (let* ((ts (unix-now))
         (login (%obj "version" *client-version* "hostname" "" "os" "linux" "arch" "amd64"
                      "user" "" "privilege_key" (compute-privilege-key (sprop :token) ts)
                      "timestamp" ts "run_id" (or *last-run-id* "")
                      "metas" (%obj) "pool_count" 1)))
    (write-msg (frpc-conn-stream ctl) #\o login)
    (multiple-value-bind (type body) (read-msg (frpc-conn-stream ctl))
      (unless (char= type #\1) (error "expected LoginResp, got ~S" type))
      (let ((err (gethash "error" body)) (rid (gethash "run_id" body)))
        (when (and err (plusp (length err))) (error "login rejected by frps: ~a" err))
        (setf (sprop :run-id) rid *last-run-id* rid)
        (say "~&[cl-frpc] login ok, run_id=~a~%" rid)))
    (let ((key (frpc-transport-token-key (frpc-conn-transport ctl))))
      (when key (setf (frpc-conn-stream ctl) (wrap-aes-cfb (frpc-conn-stream ctl) key))))))

(defun do-new-proxy (ctl)
  (let* ((type (sprop :proxy-type))
         (msg (%obj "proxy_name" (sprop :proxy-name) "proxy_type" type
                    ;; pool_count 0: no pre-allocated work-conns — every request pays one
                    ;; ReqWorkConn RTT, but pooled members go stale and hang.  (Tested.)
                    "pool_count" (or (sprop :pool-count) 0))))
    (cond ((or (string= type "http") (string= type "https"))
           (when (sprop :subdomain)      (setf (gethash "subdomain" msg) (sprop :subdomain)))
           (when (sprop :custom-domains) (setf (gethash "custom_domains" msg) (sprop :custom-domains))))
          ((string= type "tcp")
           (when (sprop :remote-port)    (setf (gethash "remote_port" msg) (sprop :remote-port)))))
    (write-msg (frpc-conn-stream ctl) #\p msg)
    ;; frps may interleave a ReqWorkConn with the NewProxyResp — loop until the response.
    (loop
      (multiple-value-bind (type body) (read-msg (frpc-conn-stream ctl))
        (case (char-code type)
          (#.(char-code #\2)
           (let ((err (gethash "error" body)))
             (when (and err (plusp (length err))) (error "frps rejected NewProxy: ~a" err)))
           (say "~&[cl-frpc] proxy registered: ~a~%" (or (gethash "remote_addr" body) ""))
           (return))
          (#.(char-code #\r) (spawn-work-conn))
          (t nil))))))

;;; ---------- work connections ----------

(defun spawn-work-conn ()
  (let ((session *session*))
    (bt:make-thread (lambda () (let ((*session* session)) (handle-work-conn)))
                    :name "cl-frpc-work")))

(defun handle-work-conn ()
  "Open a fresh yamux stream, send NewWorkConn, expect StartWorkConn, then hand the raw
   work-conn stream to the session's :on-connection consumer."
  (handler-case
      (let* ((tr (sprop :transport)) (wc (open-stream* tr)) (wstream (frpc-conn-stream wc)))
        (unwind-protect
             (progn
               (write-msg wstream #\w (%obj "run_id" (sprop :run-id)
                                            "proxy_name" (sprop :proxy-name)))
               (multiple-value-bind (type body) (read-msg wstream)
                 (declare (ignore body))
                 (unless (char= type #\s) (error "expected StartWorkConn, got ~S" type)))
               (funcall (sprop :on-connection) wstream (list :proxy (sprop :proxy-name))))
          (close-conn wc)))
    (error (e) (say "~&[cl-frpc] work-conn error: ~a~%" e))))

;;; ---------- byte pipe (for the local-backend convenience handler) ----------

(defun pipe-streams (a b label)
  "Copy A->B until EOF.  Block on the first byte, then drain what's already buffered
   (LISTEN) before flushing — so short responses aren't held waiting to fill a buffer."
  (let ((buf (make-array 16384 :element-type '(unsigned-byte 8))))
    (handler-case
        (loop for b1 = (read-byte a nil :eof) until (eq b1 :eof) do
          (setf (aref buf 0) b1)
          (let ((n 1))
            (loop while (and (< n 16384) (listen a))
                  do (let ((bx (read-byte a nil :eof)))
                       (when (eq bx :eof) (return)) (setf (aref buf n) bx) (incf n)))
            (write-sequence buf b :end n) (force-output b)))
      (end-of-file () nil)
      (sb-sys:io-timeout () nil)
      (error (e) (say "~&[cl-frpc] pipe(~a): ~a~%" label e)))))

(defun local-pipe-handler (local-host local-port)
  "An :on-connection that bridges each work-conn to a local backend via cl-transport."
  (lambda (wstream peer)
    (declare (ignore peer))
    (multiple-value-bind (lstream lclose) (ct:dial local-host local-port :timeout 5)
      (unwind-protect
           (let ((up (bt:make-thread (lambda () (pipe-streams wstream lstream "user->local"))
                                     :name "cl-frpc-up"))
                 (dn (bt:make-thread (lambda () (pipe-streams lstream wstream "local->user"))
                                     :name "cl-frpc-dn")))
             (bt:join-thread up)
             ;; up returned (public side closed).  Don't destroy dn mid-write (it may hold
             ;; the yamux write lock); close the local stream so dn reads EOF and exits.
             (ignore-errors (close lstream))
             (bt:join-thread dn))
        (ignore-errors (funcall lclose))))))

;;; ---------- control + heartbeat ----------

(defun control-loop (ctl)
  (let ((stream (frpc-conn-stream ctl)))
    (loop
      (multiple-value-bind (type body) (read-msg stream)
        (declare (ignore body))
        (case (char-code type)
          (#.(char-code #\4) (setf *last-pong-tsec* (unix-now)))      ; Pong
          (#.(char-code #\r) (spawn-work-conn))                       ; ReqWorkConn
          (t nil))))))

(defun heartbeat-loop (ctl)
  "Ping ('h') every *heartbeat-interval*s; if no Pong within *pong-timeout*, tear down so
   the caller reconnects.  The body must be a JSON object ({privilege_key, timestamp})."
  (let ((stream (frpc-conn-stream ctl)) (token (sprop :token)))
    (loop
      (sleep *heartbeat-interval*)
      (handler-case
          (let ((ts (unix-now)))
            (write-msg stream #\h (%obj "privilege_key" (compute-privilege-key token ts)
                                        "timestamp" ts))
            (setf *last-heartbeat-tsec* ts)
            (let ((silence (- ts *last-pong-tsec*)))
              (when (> silence *pong-timeout*)
                (say "~&[cl-frpc] no Pong for ~ds — tearing down~%" silence)
                (tear-down-tunnel) (return))))
        (error (e) (say "~&[cl-frpc] heartbeat failed: ~a~%" e) (return))))))

(defun tear-down-tunnel (&optional reason)
  (declare (ignore reason))
  (let ((tr *live-transport*)) (when tr (ignore-errors (close-transport tr)))))

;;; ---------- run ----------

(defun run (&key host port (tls t) token proxy-name proxy-type
                 subdomain custom-domains remote-port pool-count
                 on-connection local-host local-port (transport :direct))
  "Connect to an frps at HOST:PORT, log in, register a PROXY-TYPE proxy, and service
   inbound work connections until the control stream drops.  Delivery is either
   ON-CONNECTION (called (stream peer) per inbound conn) or, if that's nil, a bridge to
   LOCAL-HOST:LOCAL-PORT.  Blocks; signals/returns when the tunnel ends."
  (let* ((deliver (or on-connection
                      (and local-host local-port (local-pipe-handler local-host local-port))
                      (error "cl-frpc:run needs :on-connection or :local-host/:local-port")))
         (session (list :host host :port port :token token :proxy-name proxy-name
                        :proxy-type proxy-type :subdomain subdomain
                        :custom-domains custom-domains :remote-port remote-port
                        :pool-count pool-count :on-connection deliver :run-id nil))
         (*session* session))
    (say "~&[cl-frpc] connecting to ~a:~a (tls=~a) proxy=~a~%" host port tls proxy-name)
    (let ((tr (open-transport host port tls token :transport transport)))
      (setf (sprop :transport) tr *live-transport* tr)
      (unwind-protect
           (let ((ctl (open-stream* tr)))
             (setf (sprop :ctl) ctl)
             (do-login ctl)
             (do-new-proxy ctl)
             (setf *last-pong-tsec* (unix-now) *last-heartbeat-tsec* (unix-now))
             (bt:make-thread (lambda () (let ((*session* session)) (heartbeat-loop ctl)))
                             :name (format nil "cl-frpc-heartbeat[~a]" proxy-name))
             (control-loop ctl))
        (when (eq *live-transport* tr) (setf *live-transport* nil))
        (ignore-errors (close-transport tr))))))

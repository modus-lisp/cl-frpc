(require :asdf)
(handler-bind ((warning #'muffle-warning)) (ql:quickload "cl-frpc" :silent t))
(defun echo (stream peer) (declare (ignore peer))
  (handler-case (loop for b = (read-byte stream nil :eof) until (eq b :eof)
                      do (write-byte b stream) (force-output stream))
    (error () nil)))
(cl-transport:expose #'echo :backend :frp :server "127.0.0.1" :port 7000 :token "testtoken"
                     :proxy-type "tcp" :remote-port 6000 :tls t :supervise nil)
(sleep 7)
;; The client end dials through cl-transport, which is SBCL-only and no longer brings
;; usocket along -- and a dialled connection is the one the gate expects to see.
(defvar *ok* nil)
(handler-case
    (multiple-value-bind (s closer) (cl-transport:dial "127.0.0.1" 6000 :transport :direct :timeout 5)
      (let ((msg (sb-ext:string-to-octets "PING-THROUGH-FRP-TUNNEL")))
        (write-sequence msg s) (force-output s)
        (let ((buf (make-array (length msg) :element-type '(unsigned-byte 8))))
          (sb-ext:with-timeout 10 (read-sequence buf s))
          (setf *ok* (equalp buf msg))
          (format t "~&@@ TUNNEL-ECHO ok=~a got=~s~%" *ok* (sb-ext:octets-to-string buf))))
      (funcall closer))
  (error (e) (format t "~&@@ CLIENT-ERR: ~a~%" e)))
;; The exit status is the verdict, so a runner that reads only the code is not misled.
(sb-ext:exit :code (if *ok* 0 1))

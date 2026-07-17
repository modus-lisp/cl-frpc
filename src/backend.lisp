;;;; src/backend.lisp — cl-frpc as a cl-transport inbound backend (:frp).
;;;;
;;;; EXPOSE runs the frp client in the background and delivers each inbound connection to
;;;; a handler; loading this file also registers :FRP with cl-transport so a NAT'd host
;;;; gets a public endpoint through (cl-transport:expose handler :backend :frp ...).

(in-package #:cl-frpc)

(defun expose (on-connection &rest opts
               &key server port token proxy-type remote-port subdomain custom-domains
                    (tls t) (proxy-name "cl-frpc") pool-count (transport :direct)
                    (supervise t) (backoff 3) &allow-other-keys)
  "Expose an inbound endpoint via an frp relay: RUN the frp client on a background thread,
   handing each inbound connection to ON-CONNECTION (called (stream peer)).  Returns a
   zero-arg closer thunk.  With :SUPERVISE (default) the tunnel reconnects after BACKOFF
   seconds when it drops.  Keys mirror RUN (:server/:port/:token/:proxy-type/:remote-port
   /:subdomain/:custom-domains/:tls/:proxy-name/:pool-count/:transport)."
  (declare (ignore opts))
  (let ((stop nil) thread)
    (flet ((one ()
             (run :host server :port port :token token :proxy-type proxy-type
                  :remote-port remote-port :subdomain subdomain :custom-domains custom-domains
                  :tls tls :proxy-name proxy-name :pool-count pool-count :transport transport
                  :on-connection on-connection)))
      (setf thread
            (bt:make-thread
             (lambda ()
               (loop
                 (handler-case (one) (error (e) (say "~&[cl-frpc] tunnel down: ~a~%" e)))
                 (when (or stop (not supervise)) (return))
                 (sleep backoff)))
             :name "cl-frpc-expose"))
      (lambda ()
        (setf stop t)
        (tear-down-tunnel)
        (ignore-errors (bt:destroy-thread thread))))))

;; Register :FRP with cl-transport's inbound registry.  OPTS is the plist cl-transport
;; passes through from (cl-transport:expose handler :backend :frp ...).
(ct:register-listener :frp (lambda (on-connection opts) (apply #'expose on-connection opts)))

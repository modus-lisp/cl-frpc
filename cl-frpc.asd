;;;; cl-frpc.asd
;;;;
;;;; An frp (github.com/fatedier/frp) reverse-proxy CLIENT in pure Common Lisp: v0 control
;;;; protocol, token auth, yamux multiplexing, AES-128-CFB wire crypto, TLS via seal (no
;;;; OpenSSL/FFI).  Its outbound connection is a cl-transport DIAL (so the tunnel can go
;;;; direct / SOCKS5 / Tor), and it registers :FRP as a cl-transport INBOUND backend —
;;;; giving a NAT'd host a public endpoint through an frp relay.

(defsystem "cl-frpc"
  :description "frp reverse-proxy client (pure CL): yamux + seal TLS, a :frp inbound
                backend for cl-transport."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("cl-transport" "seal" "ironclad" "com.inuoe.jzon" "bordeaux-threads")
  :serial t
  :components
  ((:module "src"
    :serial t
    :components
    ((:file "yamux")      ; hashicorp/yamux client (framing + flow control + streams)
     (:file "frpc")       ; frp v0 control protocol, auth, wire crypto, work-conns
     (:file "backend")))) ; EXPOSE + register :frp with cl-transport
  :in-order-to ((test-op (test-op "cl-frpc/test"))))

(defsystem "cl-frpc/test"
  :depends-on ("cl-frpc")
  :components ((:module "test" :components ((:file "offline-test"))))
  :perform (test-op (o c) (uiop:symbol-call :cl-frpc.test :run)))

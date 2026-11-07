;;;; test/offline-test.lisp — offline gate for cl-frpc (no network / no frps).
;;;;
;;;; Unit coverage: frp framing round-trip, token auth (privilege_key), wire-key
;;;; derivation, the AES-128-CFB stream round-trip, JSON message shapes, and the :frp
;;;; cl-transport registration.  The full tunnel is exercised live against a real frps by
;;;; test/live-echo.sh (needs the frp binary + a network fetch), not here.

(defpackage :cl-frpc.test
  (:use :cl)
  (:local-nicknames (:f :cl-frpc) (:ct :cl-transport))
  (:export #:run))
(in-package :cl-frpc.test)

;;; a tiny in-memory octet stream (write, then read back) for framing + cipher tests
(defclass mem (sb-gray:fundamental-binary-input-stream sb-gray:fundamental-binary-output-stream)
  ((buf :initform (make-array 0 :element-type '(unsigned-byte 8) :adjustable t :fill-pointer 0))
   (rpos :initform 0)))
(defmethod stream-element-type ((s mem)) '(unsigned-byte 8))
(defmethod sb-gray:stream-write-byte ((s mem) b) (vector-push-extend b (slot-value s 'buf)) b)
(defmethod sb-gray:stream-read-byte ((s mem))
  (with-slots (buf rpos) s (if (< rpos (fill-pointer buf)) (prog1 (aref buf rpos) (incf rpos)) :eof)))
(defmethod sb-gray:stream-force-output ((s mem)) nil)
(defmethod sb-gray:stream-listen ((s mem)) (with-slots (buf rpos) s (< rpos (fill-pointer buf))))

(defparameter *ok* t)
(defun ok (name) (format t "  ok   ~a~%" name))
(defun bad (fmt &rest args) (setf *ok* nil) (format t "  *** FAIL ~a~%" (apply #'format nil fmt args)))
(defun checkt (name c) (if c (ok name) (bad name)))
(defun check (name got want) (if (equalp got want) (ok name) (bad "~a: ~s /= ~s" name got want)))

(defun test-framing ()
  (let ((m (make-instance 'mem)))
    (funcall (intern "WRITE-MSG" :cl-frpc) m #\o
             (funcall (intern "%OBJ" :cl-frpc) "proxy_name" "abc" "pool_count" 3
                      "custom_domains" (list "x.example" "y.example")))
    (multiple-value-bind (type body) (funcall (intern "READ-MSG" :cl-frpc) m)
      (check "framing type" type #\o)
      (check "framing string field" (gethash "proxy_name" body) "abc")
      (check "framing int field" (gethash "pool_count" body) 3)
      (check "framing array field" (coerce (gethash "custom_domains" body) 'list)
             '("x.example" "y.example")))))

(defun test-auth ()
  (let ((pk (funcall (intern "COMPUTE-PRIVILEGE-KEY" :cl-frpc) "mytoken" 1700000000)))
    ;; the expected values were computed with ironclad, before it was dropped
    (check "privilege_key = md5(token+ts)" pk "6e60479127347350b7cc397d8d3e8411"))
  (check "wire key = PBKDF2-HMAC-SHA1(token, \"frp\", 64, 16)"
         (format nil "~(~{~2,'0x~}~)" (coerce (funcall (intern "DERIVE-FRP-KEY" :cl-frpc) "mytoken") 'list))
         "0523eac1f40be937bf5c8e5fcb375557")
  (let ((k1 (funcall (intern "DERIVE-FRP-KEY" :cl-frpc) "tok"))
        (k2 (funcall (intern "DERIVE-FRP-KEY" :cl-frpc) "tok")))
    (check "wire key length 16" (length k1) 16)
    (check "wire key deterministic" k1 k2)))

(defun test-aes-cfb ()
  ;; enc writes [IV | ciphertext] into a shared buffer; dec reads IV then decrypts.
  (let* ((key (funcall (intern "DERIVE-FRP-KEY" :cl-frpc) "secret"))
         (m (make-instance 'mem))
         (enc (funcall (intern "WRAP-AES-CFB" :cl-frpc) m key))
         (plain (map '(vector (unsigned-byte 8)) #'char-code "the quick brown fox jumps 0123456789")))
    (write-sequence plain enc) (force-output enc)
    (let* ((dec (funcall (intern "WRAP-AES-CFB" :cl-frpc) m key))
           (out (make-array (length plain) :element-type '(unsigned-byte 8))))
      (read-sequence out dec)
      (check "aes-128-cfb round-trip" out plain)))
  ;; and the wire bytes themselves, from a fixed IV, in two pieces off the block edge
  (let* ((key (funcall (intern "DERIVE-FRP-KEY" :cl-frpc) "mytoken"))
         (iv (coerce (loop for i below 16 collect i) '(simple-array (unsigned-byte 8) (*))))
         (st (natrium:make-aes-cfb-stream (natrium:make-aes-key key) iv :encrypt))
         (b (sb-ext:string-to-octets "hello frp, this is more than one block of plaintext!")))
    (natrium:aes-stream-xor st b :end 5) (natrium:aes-stream-xor st b :start 5)
    (check "aes-128-cfb ciphertext matches ironclad's"
           (format nil "~(~{~2,'0x~}~)" (coerce b 'list))
           "e2d028c60c48c95d22c04e6df1d8c7b0d8e9f0c9d8d2d36a8d4c9d4d7801aceb9238d8f90190db627a69fd559e7fe21ae6d12335")))

(defun test-registration ()
  (checkt ":frp registered with cl-transport" (ct:listener-available-p :frp))
  (checkt ":tcp inbound available" (ct:listener-available-p :tcp)))

(defun run ()
  (setf *ok* t)
  (format t "~&== cl-frpc offline gate ==~%")
  (test-framing) (test-auth) (test-aes-cfb) (test-registration)
  (format t "~a~%" (if *ok* "ALL OK" "FAILURES ABOVE"))
  *ok*)

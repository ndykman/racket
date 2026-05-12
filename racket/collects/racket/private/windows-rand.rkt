#lang racket/base
(provide crypto-random-windows-bytes)

(require ffi/unsafe
         ffi/unsafe/define)

(define-ffi-definer define-bcrypt (and (eq? (system-type) 'windows) (ffi-lib "bcrypt.dll"))
  #:default-make-fail make-not-available)

; Use the bcrypt version 
(define-bcrypt BCryptGenRandom (_fun _pointer _pointer _ulong _ulong -> _int))

; (: crypto-random-windows-bytes (-> Positive-Integer Bytes))
(define (crypto-random-windows-bytes n)
  (define rand-bytes-buf (make-bytes n))
  (if (= (BCryptGenRandom #f rand-bytes-buf n 2) 0)
      rand-bytes-buf
      (raise (make-exn:fail
              "crypto-random-windows: BCryptGenRandom failed to generate bytes"
              (current-continuation-marks)))))

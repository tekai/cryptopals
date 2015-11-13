;; -*- coding: latin-9 -*-
; Latin 9 aka ISO-8859-15 ensures emacs processes strings as unibyte
; with char = byte

;;; Challenge 1 convert hex string to base64 and back
(defun pack (arr width)
  "Pack ``width'' bits of integers (list ``L'') into one
integer. Note: You shouldn't exceed 32/64bits in total"
  (loop for x across arr
        for I = x then (+ x (lsh I width))
        finally return I))

(defun unpack (I width n)
  "Unpack ``n'' integers of ``width'' bits from integer ``I''"
  (loop with mask = (1- (expt 2 width))
        with arr = (make-string n 0)
        for i below n
        for s = (* (- 0 n -1) width) then (+ s width)
        do (aset arr i (logand mask (lsh I s)))
        finally return arr))

(defun hex-print (bytes)
  (loop for x across bytes
        concat (format "%02x" x)))

(defun unhex (hex)
  (apply
   'string
   (loop for i from 0 below (length hex) by 2
         collect (string-to-number (substring hex i (+ i 2)) 16))))

(defun b64-print (bytes)
  (loop with result = (string)
        with V = (make-vector 3 nil)
        for x across bytes
        for i = 0 then (mod (1+ i) 3)
        do
          (aset V i x)
          when (= i 2)
            concat (encode-triple V) into result
            and if t do (fillarray V nil) end
          end
        finally (progn
                  (when (< i 2 )
                    (setq result (concat result (encode-triple V))))
                  (return result))))

(defun b64-decode (string)
  (loop with bytes = string
        with V = (make-vector 4 nil)
        for x across bytes
        for i = 0 then (mod (1+ i) 4)
        do
          (unless (= x ?=) (aset V i x))
          when (= i 3)
            concat (decode-quad V)
            and if t do (fillarray V nil) end
          end))

(defun encode-triple (V)
  "Encode byte sequence ``V'' into base64"
  (let* ((n (cond ((aref V 2) 3) ((aref V 1) 2) (t 1)))
         (d (- 3 n))
         (I (pack (subseq V 0 n) 8))
         (unpack I 6 (- 4 d))))
    (concat (map 'string 'b64-i2c E) (make-string d ?=)))

(defun decode-quad (V)
  "Decode base64 sequence ``V''"
  (let* ((n (cond ((aref V 3) 4) ((aref V 2) 3) (t 2)))
         (d (- 4 n)) ;0-2
         (DV (map 'string 'b64-c2i (subseq V 0 n)))
         (I (pack DV 6)))
    (unpack I 8 (- 3 d))))

(defun b64-i2c (int)
  (cond
   ((< int 26) (+ 65 int)) ; A-Z
   ((< int 52) (+ 71 int)) ; a-z
   ((< int 62) (- int 4)) ; 0-9
   ((= int 62) ?+)
   ((= int 63) ?/)))

(defun b64-c2i (char)
  (cond
   ((= char ?/) 63)
   ((= char ?+) 62)
   ((< char 58)  (+ char 4))
   ((< char 91)  (- char 65))
   ((< char 123) (- char 71))))


(defun hex-to-b64 (str)
  (b64-encode (unhex str)))

(defun b64-to-hex (str)
  (hex-print (b64-decode str)))

;;; 2. Fixed XOR
(defun fixed-xor (str1 str2)
  "XOR two strings.``str1'' and ``str2'' have to be of the same length"
  (apply 'string
         (loop for a across str1
               for b across str2
               collect (logxor a b))))

;; (hex (fixed-xor (unhex "1c0111001f010100061a024b53535009181c")
;;                 (unhex "686974207468652062756c6c277320657965")))

;;; 3. Single-character XOR Cipher
;;;
;;; I We assume the text contains only Letters numbers and punctuation,
;;; it alreay filters the correct result. But that doesn't incorporate
;;; letter frequencey. I used wikipedia to get relative frequencies of
;;; letters in English. That helped but got the wrong result, so I
;;; counted everything but letters & space as a second score which
;;; finally helped to get the right result.
;;;

;; needed more often
(defconst +alphanum+ "ABCDEFGHIJKLMNOPQRSTVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
(defconst +asciichars+ "ABCDEFGHIJKLMNOPQRSTVWXYZabcdefghijklmnopqrstuvwxyz0123456789 -!?\"\':,.$%&/()=\\#+~@^{}[]<>|`*\r\n")

;; TODO needs cleanup
(defun fruit-loop (txt)
  "Loop through all character keys, xor it with the ``txt'' and
spit out the best match as rated by `textness'. Returns a list of
the best letter, its score (see `textness') and the resulting
text"
  (loop with alnum-regexp = "^[A-Z][A-Za-z0-9 .!'\"!?:;,*\n-]+$"
        with text = ""
        with worst-score = (cons 0  most-positive-fixnum)
        with best = worst-score
        for l across +asciichars+
        do (let* ((tex (fixed-xor txt (make-string (length txt) l)))
                  (ok 0)
                  ;(ok (string-match-p alnum-regexp tex))
                  (score (if (and ok (= ok 0))
                           (textness tex)
                         worst-score)))

             (when (and (>= (car score) (car best))
                        (< (cdr score) (cdr best)))
               (setq best score
                     text tex
                     letter l)))
        finally return (list letter best text)))

(defun textness (text)
  "Rate the likelyness of ``text'' to be an English text using
letter frequenzy and counting non-alphanumeric
characters. Returns a cons of score and no. non-letters"
  (let ((length (length text))
        (space 0) (e 0) (ta 0) (oinsrh 0) (dl 0) (cum 0) (jxqz 0) (bad 0))
    (loop for x across (downcase text)
          do (case x
               ((?\ ) (incf space))
               ((?e ) (incf e))
               ((?t ?a) (incf ta))
               ((?o ?i ?n ?s ?r ?h) (incf oinsrh))
               ((?d ?l) (incf dl))
               ((?c ?u ?m ?f ?y ?w ?g ?p ?b ?v ?k) (incf cum))
               ((?j ?x ?q ?z) (incf jxqz))
               ((?. ?! ?? ?\ ?- ?\n 13  ?\" ?\; ))
               ((?0 ?1 ?2 ?3 ?4 ?5 ?6 ?7 ?8 ?9))
               (t (incf bad))))
    ;; normalize
    (setq ta (/ (/ ta 2) 1)
          oinsrh (/ oinsrh 6.0)
          dl (/ dl 2.0)
          cum (/ cum 11.0)
          jxqz (/ jxqz 4.0))
    (loop with score = 0
          with L = (list space e ta oinsrh dl cum jxqz)
          for n in L
          for l on L
          do (dolist (m l)
               (when (>= n m)
                 (incf score)))
          finally return (cons score bad))))

;; (fruit-loop (unhex "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))

(defmacro between (a b c)
  "Test for a <= b <=c"
  (let ((b-val (gensym)))
    `(let ((,b-val ,b))
       (and (<= ,a ,b-val) (<= ,b-val ,c)))))


;;; 4. Detect single-character XOR

;; Helper because afaik emacs doesn't provide this
(defun file-string (file)
  "Read the contents of a file and return as a string."
  (with-temp-buffer
    (insert-file-contents-literally file)
    (buffer-string)))

(defun challenge-4 ()
  (let* ((raw (file-string "detect-single-character-xor.txt"))
         (lines (split-string raw "\n" t))
         (best (list ?\  (cons 0 most-positive-fixnum) "")))

    (dolist (line lines best)
      (let* ((tmp (fruit-loop line))
             (scores (cadr tmp)))
      (when (and (>= (car scores) (car (cadr best)))
                 (< (cdr scores) (cdr (cadr best))))
        (setq best tmp))))))

; (challenge-4)

;;; 5. Repeating-key XOR Cipher

(defun repeating-key-xor (string key)
  "XOR ``string'' with ``key''"
  (apply 'string
         (loop with l = (length key)
               for a across string
               for i = 0 then (mod (1+ i) l)
               collect (logxor a (aref key i)))))

; (hex-print (repeating-key-xor "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" "ICE"))

;;; 6. Break repeating-key XOR

(defun hammond (clarkson may)
  "Calculates the Hammond distance between Jeremy and James"
  (loop for a across clarkson
        for b across may
        sum (loop repeat 8
                  for rox = (logxor a b) then (lsh rox -1)
                  sum (logand rox 1))))

;;(hammond "this is a test" "wokka wokka!!!")




;; First line of the text
;; HUIfTQsPAh9PE048GmllH0kcDk4TAQsHThsBFkU2AB4BSWQgVB0dQzNTTmVS

(defun gen-key-gen (length)
  "Generates a key generator which can generate all ``length''
keys characters from ``+alphanum''. Funcall the generator to get
the next key"
  (lexical-let
      ((key (make-vector length 0))
       (alnum-max (length +alphanum+))
       (i (1- length))
       (n -1)
       (end nil))

    (lambda ()
      (when (not end)
        (incf n)
        (if (< n alnum-max)
            (aset key i n)
          ;; incf the priors
          (loop for j from i downto 0 do
                (let ((val (1+ (aref key j))))
                  (if (= val alnum-max)
                      (if (> j 0)
                          (aset key j 0)
                        (setq end t))
                    (aset key j val)
                    (return)))))
        ;; return the new key
        (when (not end)
          (apply 'string
                 (loop for i across key
                       collect (aref +alphanum+ i))))))))

(defun edit-distances (min max samples text)
  (loop
   with j = 2
   for i from min to max
   collect
   (cons i (/
     (loop
      for j from 1 to samples
           sum (hammond (subseq text 0 i)
                        (subseq text (* j i) (* (+ 2 j) i)))
           into S
           finally return (/ (float S) (float samples)))
     (float i)))))

;; (sort (edit-distances 2 40 8 (base64-decode-string (file-string "repeating-key-xor.txt")))
;;       (lambda (a b)
;;         (< (cdr a) (cdr b))))


(defun challenge-6 (key-length file)
  (let* ((b64 (replace-regexp-in-string "\n" "" (file-string file)))
         (raw (base64-decode-string b64))
         (n (/ (length raw) key-length))
         (blocks (make-vector key-length nil)))
    ;; set blocks to strings of length key-length
    (loop for i below key-length
          do (aset blocks i (make-string n ?0)))
    (loop for i below n
          do
          (loop for k below key-length
                do (aset (aref blocks k) i
                         (aref raw (+ k (* i key-length))))))
    (loop for i below key-length
          collect (car (fruit-loop (aref blocks i))))))

;; (apply 'string (challenge-6 29 "repeating-key-xor.txt"))
;; (let* ((file "repeating-key-xor.txt")
;;        (key (apply 'string (challenge-6 29 file)))
;;        (b64 (file-string file))
;;        (raw (base64-decode-string b64)))
;;   (repeating-key-xor raw key))


;;; 7. AES in ECB Mode

;;; First we roll our own AES implementation because somehow openssl.exe
;;; won't decrypt the file

(defvar *aes-Nk* 4)
(defvar *aes-Nr* 10)


(defun aes-key-expansion (key w)
  (let (temp
        (i 0))
    (while (< i aes-Nk)
      (setf (aref w i) (aes-word (aref key (* 4 i))
                                 (aref key (+ 1 (* 4 i)))
                                 (aref key (+ 2 (* 4 i)))
                                 (aref key (+ 3 (* 4 i)))))
      (incf i))
    (setq i *aes-Nk*)
    (while (< i (* *aes-Nb* (1+ *aes-Nk)))
      (setq temp (aref w (1- i)))
      (cond ((= (mod i *aes-Nk*))
             (setq temp (aes-xor (aes-subword (aes-rotword temp))
                                 (aes-rcon (/ i *aes-Nk*)))))
            ((and (> *aes-Nk* 6) (= 4 (mod i *aes-Nk*))) 
             (setq temp (aes-subword temp))))
      (setf (aref w i) (aes-xor (aref w (- i *aes-Nk))))
      (incf i))))

(defun aes-word (i)
  (if (< i 256) (vector i 0 0 0)
      (loop for n below 4)))
(defun aes-xor (a-word b-word))
(defun aes-subword (word))
(defun aes-rotword (word)
  (concat (subseq word 3 4) (subseq word 0 3)))

(defun aes-rcon (i)
  (aes-word 
   (if (= i 1) i
       (let ((y (* 2 (aes-rcon (- i 1)))))
         (if (> y 255); 0x100
             (logand 255 (logxor y 27)) ; 0x1b
             y)))))

(defun bit-list (sequence)
  (loop for e across sequence
        append (loop repeat 8
                 for bit = e then (lsh bit -1)
                 collect (logand bit 1))))

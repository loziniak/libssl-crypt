Red [
	File: %libssl-crypt-test.red
	Author: "loziniak"
	License: BSD-3
]

#include %libssl-crypt.red


; test based on: https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption#Ciphertext_Output
text: "The quick brown fox jumps over the lazy dog"
key: to binary! "01234567890123456789012345678901"
iv: to binary! "0123456789012345"
encrypted: encrypt-aes256  to binary! text  key  iv
decrypted: to string! decrypt-aes256 encrypted key iv
either all [
	encrypted = 
		#{E0 6F 63 A7 11 E8 B7 AA   9F 94 40 10 7D 46 80 A1
		  17 99 43 80 EA 31 D2 A2   99 B9 53 02 D4 39 B9 70
		  2C 8E 65 A9 92 36 EC 92   07 04 91 5C F1 A9 8A 44}
	decrypted = text
] [
	print "Low level test passed."
] [
	print "Low level test failed!"
]


text: "The quick brown fox jumps over the lazy dog"
password: "1234"
encrypted: encrypt to binary! text password
decrypted: to string! decrypt encrypted password
either decrypted = text [
	print "High level test passed."
] [
	print "High level test failed!"
]


;write/binary %libssl-crypt.enc encrypt "3453" read/binary %libssl-crypt.red
;write/binary %libssl-crypt.dec decrypt "3453" read/binary %libssl-crypt.enc

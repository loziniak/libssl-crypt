Red [
	File: %libssl-crypt.red
	Author: "loziniak"
	License: BSD-3
]

; clone https://github.com/loziniak/eth-wallet
#include %eth-wallet/pbkdf2.red


#system [

	#switch OS [
		Windows [
			#define LIBCRYPTO-file "libcrypto-1_1.dll"
		]
		macOS [
			#define LIBCRYPTO-file "libcrypto.dylib"
		]
		Linux [
			#define LIBCRYPTO-file "libcrypto.so"
		]
	]

	#import [
		LIBCRYPTO-file cdecl [
			EVP_CIPHER_CTX_new: "EVP_CIPHER_CTX_new" [
				return: [int-ptr!]
			]
			EVP_CIPHER_CTX_free: "EVP_CIPHER_CTX_free" [
				ctx		[int-ptr!]
			]

			EVP_aes_256_cbc: "EVP_aes_256_cbc" [ ; 256-bit-key AES in CBC mode
				return:	[int-ptr!]
			]

			EVP_CipherInit_ex: "EVP_CipherInit_ex" [
				ctx		[int-ptr!]
				type	[int-ptr!]
				engine	[int-ptr!]
				key		[byte-ptr!]
				iv		[byte-ptr!]
				enc		[integer!]
				return:	[integer!]
			]
			EVP_CipherUpdate: "EVP_CipherUpdate" [
				ctx		[int-ptr!]
				out		[byte-ptr!]
				outlen	[int-ptr!]
				in		[byte-ptr!]
				inlen	[integer!]
				return:	[integer!]
			]
			EVP_CipherFinal_ex: "EVP_CipherFinal_ex" [
				ctx		[int-ptr!]
				out		[byte-ptr!]
				outlen	[int-ptr!]
				return:	[integer!]
			]

			ERR_get_error: "ERR_get_error" [
				return:	[integer!]
			]
			ERR_error_string: "ERR_error_string" [
				e		[integer!]
				buf		[byte-ptr!]
				return:	[c-string!]
			]
		]
	]

	fire-error: func [
		msg [c-string!]
		/local	
			s [red-string!]
	] [
		s: string/load "Libssl-crypt error: " 18 UTF-8
		string/concatenate
			s
			string/load  msg  length? msg  UTF-8
			-1 0 yes no
		fire [TO_ERROR(user message) s]
	]

	handle-error: func [
		res [integer!]
		ctx [int-ptr!]
	] [
		if 1 <> res [
			if ctx <> null [EVP_CIPHER_CTX_free(ctx)]
			fire-error ERR_error_string ERR_get_error null
		]
	]

	binary-bytes: func [
		bin	[red-binary!]
		return: [byte-ptr!]
		/local bin-series [series-buffer!]
	] [
		bin-series: GET_BUFFER(bin)
		(as byte-ptr! bin-series/offset) + bin/head
	]

	crypt-process: func [
		in [red-binary!]
		key [red-binary!]
		iv [red-binary!]
		type [int-ptr!]
		encrypt? [logic!]
		/local
			ctx
			in-series in-bytes inlen
			key-series key-bytes iv-series iv-bytes
			buffer max-chunk chunk
			out outlen
	] [
		ctx: EVP_CIPHER_CTX_new
		if ctx = null [
			fire-error ERR_error_string ERR_get_error null
		]

		in-bytes: binary-bytes in
		inlen: binary/rs-length? in

		unless 32 = binary/rs-length? key [		;-- AES256 key size, 32 bytes = 256 bits
			fire-error "AES256 needs 256 bit key."
		]
		key-bytes: binary-bytes key

		unless 16 = binary/rs-length? iv [		;-- AES block size, 16 bytes = 128 bits
			fire-error "AES needs 128 bit iv, equal to AES block size."
		]
		iv-bytes: binary-bytes iv

		handle-error
			EVP_CipherInit_ex ctx type null key-bytes iv-bytes as integer! encrypt?
			ctx

		max-chunk: 1024				;-- 1 KiB
		buffer: allocate max-chunk + 16		;-- with additional padding for EVP_CipherFinal_ex
		out: binary/make-at  as red-value! stack/push*  0
		outlen: 0
		while [inlen > 0] [
			chunk: either inlen < max-chunk [inlen] [max-chunk]
			handle-error
				EVP_CipherUpdate ctx buffer :outlen in-bytes chunk
				ctx
			binary/rs-append out buffer outlen
			inlen: inlen - chunk
			in-bytes: in-bytes + chunk
		]

		handle-error
			EVP_CipherFinal_ex ctx buffer :outlen
			ctx
		binary/rs-append out buffer outlen

		free buffer
		EVP_CIPHER_CTX_free ctx
		stack/set-last as red-value! out
	]


]

encrypt-aes256: routine [
	in [binary!]
	key [binary!]
	iv [binary!]
;	return [binary!]	
] [
	crypt-process in key iv EVP_aes_256_cbc yes
]

decrypt-aes256: routine [
	ciph [binary!]
	key [binary!]
	iv [binary!]
;	return [binary!]	
] [
	crypt-process ciph key iv EVP_aes_256_cbc no
]

urandom: routine [
	size [integer!]
;	return [binary!]
	/local
		s [series!]
		p [byte-ptr!]
		out [red-binary!]	
] [
	out: binary/make-at  as red-value! stack/push*  size
	crypto/urandom  binary-bytes out  size
	s: GET_BUFFER(out)
	p: as byte-ptr! s/tail
	s/tail: as cell! p + size
	stack/set-last as red-value! out
]

encrypt: function [
	data [binary!]
	pass [string!]
	return: [binary!]
] [
	salt: urandom 8
	hash: pbkdf2/derive pass salt 10000 48 'SHA384
	iv: copy at hash 33
	key: copy/part hash 32
	rejoin [
		salt
		encrypt-aes256 data key iv
	]
]

decrypt: function [
	data [binary!]
	pass [string!]
	return: [binary!]
] [
	salt: copy/part data 8
	hash: pbkdf2/derive pass salt 10000 48 'SHA384
	iv: copy at hash 33
	key: copy/part hash 32
	decrypt-aes256  at data 9  key iv
]

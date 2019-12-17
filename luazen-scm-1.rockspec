package = "luazen"
version = "scm-1"
source = {
   url = "git://github.com/philanc/luazen",
}
description = {
   summary = "Simple compression, encoding and cryptographic functions.",
   detailed = [[A small library with various encoding functions (base58, base64), compression functions (LZMA, BriefLZ, LZF), authenticated encryption (Morus, XChacha20/Poly1305, Norx), cryptographic hash (Blake2b, SHA-512), key derivation function (Argon2i), curve25519  and ed25519 public key functions, and legacy cryptographic functions (MD5, RC4). 
   ]],
   homepage = "https://github.com/philanc/luazen",
   license = "MIT",
}
supported_platforms = { 
	"unix", 
}
dependencies = {
   "lua >= 5.3"
}
build = {
   type = "builtin",
   modules = {
      luazen = {
		sources = { 
			"src/ascon.c",
			"src/base58.c",
			"src/base64.c",
			"src/blake2b.c",
			"src/blz.c",
			"src/chacha.c",
			"src/luazen.c",
			"src/lzf.c",
			"src/lzma/Alloc.c",
			"src/lzma/LzFind.c",
			"src/lzma/LzmaDec.c",
			"src/lzma/LzmaEnc.c",
			"src/lzma/LzmaLib.c",
			"src/lzma.c",
			"src/md5.c",
			"src/morus.c",
			"src/norx.c",
			"src/random.c",
			"src/rc4.c",
			"src/sha2.c",
			"src/x25519.c",
			"src/xor.c",
		},
		incdir = {
			"src", "src/lzma"
		},
		defines = {
			"_7ZIP_ST",
			"BASE64", "LZMA", "MD5", "BLAKE", "X25519", "MORUS"
		}
	  }
   },
   copy_directories = { "test" },
}


package = "luazen"
version = "scm-1"
source = {
   url = "git://github.com/philanc/luazen",
}
description = {
   summary = "Simple compression and cryptographic functions.",
   detailed = [[
	  A small library with various encoding functions (base64), 
	  compression functions (LZMA), authenticated encryption
	  (XChacha20/Poly1305), cryptographic hash (Blake2b, 
	  SHA-512, MD5), ec25519 key exchange, ed25519 digital
	  signature, and Argon2i key derivation (KDF). 
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
			"src/luazen.c",
			"src/md5.c",
			"src/base64.c",
			"src/random.c",
			"src/lzma/Alloc.c",
			"src/lzma/LzFind.c",
			"src/lzma/LzmaDec.c",
			"src/lzma/LzmaEnc.c",
			"src/lzma/LzmaLib.c",
			"src/lzma/lualzma.c",
			"src/mono/monocypher.c",
			"src/mono/monocypher-ed25519.c",
			"src/mono/luamonocypher.c"
		},
		incdir = {
			"src", "src/lzma", "src/mono", 
		},
		defines = {
			"_7ZIP_ST",
		}
	  }
   },
   copy_directories = { "test" },
}


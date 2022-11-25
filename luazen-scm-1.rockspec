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
	  (XChacha20/Poly1305), cryptographic hash (Blake3, 
	  SHA-512, md5), ec25519 key exchange and ed25519 digital
	  signature functions. 
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
			"src/lzma/Alloc.c",
			"src/lzma/LzFind.c",
			"src/lzma/LzmaDec.c",
			"src/lzma/LzmaEnc.c",
			"src/lzma/LzmaLib.c",
			"src/lzma/lualzma.c",
			"src/mono/monocypher.c",
			"src/mono/monocypher-ed25519.c",
			"src/mono/randombytes.c",
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


package = "luazen"
version = "0.11-1"
source = {
   url = "git://github.com/philanc/luazen",
    branch = "v0.11",
}
description = {
   summary = "Simple compression, encoding and cryptographic functions.",
   detailed = [[
	  A small library with various encoding functions (base58, base64), 
	  compression functions (BriefLZ, LZF), authenticated encryption (Morus, XChacha20/Poly1305, Norx), 
	  cryptographic hash (Blake2b), curve25519  and ed25519 functions, 
	  and legacy cryptographic functions (MD5, RC4). 
   ]],
   homepage = "https://github.com/philanc/luazen",
   license = "MIT",
}
supported_platforms = { 
	"unix", 
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      luazen = {
		sources = { 
			"src/base58.c",
			"src/base64.c",
			"src/blake2b.c",
			"src/blz.c",
			"src/chacha.c",
			"src/luazen.c",
			"src/lzf.c",
			"src/md5.c",
			"src/morus.c",
			"src/norx.c",
			"src/random.c",
			"src/rc4.c",
			"src/sha2.c",
			"src/x25519.c",
			"src/xor.c",
		},
		incdir = "src"
	  },
   },
   copy_directories = { "test" },
}


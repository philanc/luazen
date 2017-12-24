package = "luazen"
version = "0.9-1"
source = {
   url = "git://github.com/philanc/luazen" 
}
description = {
   summary = "Simple compression, encoding and cryptographic functions.",
   detailed = [[
	  A small library with various encoding functions (base58, base64), 
	  compression functions (LZF), authenticated encryption (Norx), 
	  cryptographic hash (Blake2b), curve25519  and ed25519 functions, 
	  and legacy cryptographic functions (MD5, RC4). 
   ]],
   homepage = "https://github.com/philanc/luazen",
   license = "MIT",
}
supported_platforms = { 
	"unix", "windows" 
}
dependencies = {
   "lua >= 5.1"
}
build = {
   type = "builtin",
   modules = {
      luazen = {
		sources = { 
			"src/luazen.c", "src/base58.c", 
			"src/lzf_c.c", "src/lzf_d.c",
			"src/mono.c", "src/norx.c",
			"src/md5.c", "src/rc4.c",
			"src/brieflz.c", "src/depacks.c",
			"src/randombytes.c",
		},
		incdir = "src"
	  },
   },
   copy_directories = { "test" },
}


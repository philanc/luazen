package = "luazen"
version = "0.7-1"
source = {
   url = "git://github.com/philanc/luazen" 
}
description = {
   summary = "Simple compression, encoding and cryptographic functions.",
   detailed = [[
	  A small library with various encoding functions (base58, base64), 
	  compression functions (LZF), and low-grade cryptographic functions 
	  (MD5, SHA1, RC4). 
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
			"src/md5.c", "src/sha1.c", "src/rc4.c",
		},
		incdir = "src"
	  },
   },
   copy_directories = { "test" },
}


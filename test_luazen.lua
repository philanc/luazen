
-- luazen tests

local lz = require "luazen"

local function stohex(s)  -- return the hex representation of a string
	return s:gsub(".", function(c)
		return string.format("%02x", string.byte(c))
		end)
end

local function hextos(h) -- parse a hex string
	return h:gsub("%s", ""):gsub("..", function(cc)
		return string.char(tonumber(cc, 16))
		end)
end

print("------------------------------------------------------------")
print(_VERSION)


------------------------------------------------------------------------
-- lzf compression
do
	assert(lz.lzf("") == "")
	assert(lz.unlzf("") == "")
	local x
	x = "Hello world"; assert(lz.unlzf(lz.lzf(x)) == x)
	x = ("a"):rep(301); assert(lz.unlzf(lz.lzf(x)) == x)
	assert(#lz.lzf(("a"):rep(301)) < 30)
end

------------------------------------------------------------------------
-- xor
do
	local xor = lz.xor
	pa5 = '\xaa\x55'; p5a = '\x55\xaa'; p00 = '\x00\x00'; pff = '\xff\xff'
	assert(xor(pa5, p00) == pa5)
	assert(xor(pa5, pff) == p5a)
	assert(xor(pa5, pa5) == p00)
	assert(xor(pa5, p5a) == pff)
	-- check that 1. result is always same length as plaintext
	-- and 2. key wraps around as needed
	assert(xor(("\xaa"):rep(1), ("\xff"):rep(31)) == ("\x55"):rep(1))
	assert(xor(("\xaa"):rep(31), ("\xff"):rep(17)) == ("\x55"):rep(31))
	assert(xor(("\xaa"):rep(32), ("\xff"):rep(31)) == ("\x55"):rep(32))
end

------------------------------------------------------------------------
-- rc4
do
	local k = ('1'):rep(16)
	local plain = 'abcdef'
	local encr = lz.rc4(plain, k)
	assert(encr == "\x25\x98\xfa\xe1\x4d\x66")
	encr = lz.rc4raw(plain, k) -- "raw", no drop
	assert(encr == "\x01\x78\xa1\x09\xf2\x21")
	plain = plain:rep(100)
	assert(plain == lz.rc4(lz.rc4(plain, k), k))
end

------------------------------------------------------------------------
-- rabbit
do
	local stx, xts = stohex, hextos

	-- quick test with some eSTREAM test vectors
	local key, iv, txt, exp, ec
	local key0 = ('\0'):rep(16)
	local iv0 = ('\0'):rep(8)
	local txt0 = ('\0'):rep(48)
	ec = lz.rabbit(txt0, key0, iv0)
	exp = xts[[	EDB70567375DCD7CD89554F85E27A7C6
				8D4ADC7032298F7BD4EFF504ACA6295F
				668FBF478ADB2BE51E6CDE292B82DE2A ]]
	assert(ec == exp)
	
	iv = '\x27\x17\xF4\xD2\x1A\x56\xEB\xA6'
	ec = lz.rabbit(txt0, key0, iv)
	exp = xts[[	4D1051A123AFB670BF8D8505C8D85A44
				035BC3ACC667AEAE5B2CF44779F2C896
				CB5115F034F03D31171CA75F89FCCB9F ]]
	assert(ec == exp)
	
	--Set 5, vector# 63
	iv = xts "0000000000000001"
	ec = lz.rabbit(txt0, key0, iv)
	exp = xts[[	55FB0B90A9FB953AE96D372BADBEBD30
				F531A454D31B669BCD8BAAD78C6C9994
				FFCCEC7ACB22F914A072DA22A617C0B7 ]]
	assert(ec == exp)
	
	--Set6, vector# 0
	key = xts "0053A6F94C9FF24598EB3E91E4378ADD"
	iv =  xts "0D74DB42A91077DE"
	ec = lz.rabbit(txt0, key, iv)
	exp = xts[[	75D186D6BC6905C64F1B2DFDD51F7BFC
				D74F926E6976CD0A9B1A3AE9DD8CB43F
				F5CD60F2541FF7F22C5C70CE07613989 ]]
	assert(ec == exp)
end

------------------------------------------------------------------------
-- md5, sha1
do
	local stx, xts = stohex, hextos

	-- md5
	assert(stx(lz.md5('')) == 'd41d8cd98f00b204e9800998ecf8427e')
	assert(stx(lz.md5('abc')) == '900150983cd24fb0d6963f7d28e17f72')

	-- sha1
	assert(stx(lz.sha1(''))
		== 'da39a3ee5e6b4b0d3255bfef95601890afd80709')
	assert(stx(lz.sha1('The quick brown fox jumps over the lazy dog'))
		== '2fd4e1c67a2d28fced849ee1bb76e7391b93eb12')	

end
------------------------------------------------------------------------
-- b64 encode/decode
do 
	local be = lz.b64encode
	local bd = lz.b64decode
	--
	assert(be"" == "")
	assert(be"a" == "YQ==")
	assert(be"aa" == "YWE=")
	assert(be"aaa" == "YWFh")
	assert(be"aaaa" == "YWFhYQ==")
	assert(be(("a"):rep(61)) ==
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
		.. "YWFhYWFh\nYWFhYWFhYQ==") -- produce 72-byte lines
	assert(be(("a"):rep(61), 64) ==
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
		.. "\nYWFhYWFhYWFhYWFhYQ==") -- produce 64-byte lines
	assert(be(("a"):rep(61), 0) ==
		"YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh"
		.. "YWFhYWFhYWFhYWFhYQ==") -- produce one line (no \n inserted)
	assert("" == bd"")
	assert("a" == bd"YQ==")
	assert("aa" == bd"YWE=")
	assert("aaa" == bd"YWFh")
	assert("aaaa" == bd"YWFhYQ==")
	assert(bd"YWFhYWFhYQ" == "aaaaaaa") -- not well-formed (no padding)
	assert(bd"YWF\nhY  W\t\r\nFhYQ" == "aaaaaaa") -- no padding, whitespaces
	assert(bd(be"\x00\x01\x02\x03\x00" ) == "\x00\x01\x02\x03\x00")
end --b64

------------------------------------------------------------------------
-- b58encode  (check on-line at eg. http://lenschulwitz.com/base58)
do
	assert(lz.b58encode('\x01') == '2')
	assert(lz.b58encode('\x00\x01') == '12')
	assert(lz.b58encode('') == '')
	assert(lz.b58encode('\0\0') == '11')
	assert(lz.b58encode('o hai') == 'DYB3oMS')
	assert(lz.b58encode('Hello world') == 'JxF12TrwXzT5jvT')
	local x1 = "\x00\x01\x09\x66\x77\x60\x06\x95\x3D\x55\x67\x43" 
		.. "\x9E\x5E\x39\xF8\x6A\x0D\x27\x3B\xEE\xD6\x19\x67\xF6" 
	local e1 = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
	assert(lz.b58encode(x1) == e1)
	local x2 = "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" 
		.. "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
	local e2 = "thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"
	assert(lz.b58encode(x2) == e2) 
	-- b58decode
	assert(lz.b58decode('') == '')
	assert(lz.b58decode('11') == '\0\0')	
	assert(lz.b58decode('DYB3oMS') == 'o hai')
	assert(lz.b58decode('JxF12TrwXzT5jvT') == 'Hello world')
	assert(lz.b58decode(e1) == x1)
	assert(lz.b58decode(e2) == x2)

end
------------------------------------------------------------------------
print("test_luazen", "ok")

return true

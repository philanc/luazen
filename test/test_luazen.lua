


package.path = "./?.lua"
package.cpath = "./?.so"


local lz = require "luazen"

-- some local definitions

local strf = string.format
local byte, char = string.byte, string.char
local spack, sunpack = string.pack, string.unpack

local app, concat = table.insert, table.concat

local function stohex(s, ln, sep)
	-- stohex(s [, ln [, sep]])
	-- return the hex encoding of string s
	-- ln: (optional) a newline is inserted after 'ln' bytes 
	--	ie. after 2*ln hex digits. Defaults to no newlines.
	-- sep: (optional) separator between bytes in the encoded string
	--	defaults to nothing (if ln is nil, sep is ignored)
	-- example: 
	--	stohex('abcdef', 4, ":") => '61:62:63:64\n65:66'
	--	stohex('abcdef') => '616263646566'
	--
	if #s == 0 then return "" end
	if not ln then -- no newline, no separator: do it the fast way!
		return (s:gsub('.', 
			function(c) return strf('%02x', byte(c)) end
			))
	end
	sep = sep or "" -- optional separator between each byte
	local t = {}
	for i = 1, #s - 1 do
		t[#t + 1] = strf("%02x%s", s:byte(i),
				(i % ln == 0) and '\n' or sep) 
	end
	-- last byte, without any sep appended
	t[#t + 1] = strf("%02x", s:byte(#s))
	return concat(t)	
end --stohex()

local function hextos(hs, unsafe)
	-- decode an hex encoded string. return the decoded string
	-- if optional parameter unsafe is defined, assume the hex
	-- string is well formed (no checks, no whitespace removal).
	-- Default is to remove white spaces (incl newlines)
	-- and check that the hex string is well formed
	local tonumber = tonumber
	if not unsafe then
		hs = string.gsub(hs, "%s+", "") -- remove whitespaces
		if string.find(hs, '[^0-9A-Za-z]') or #hs % 2 ~= 0 then
			error("invalid hex string")
		end
	end
	return (hs:gsub(	'(%x%x)', 
		function(c) return char(tonumber(c, 16)) end
		))
end -- hextos

local stx, xts = stohex, hextos

local function px(s, msg) 
	print("--", msg or "")
	print(stohex(s, 16, " ")) 
end

print("------------------------------------------------------------")
print(_VERSION, lz.VERSION )
print("------------------------------------------------------------")

assert(lz.VERSION == "luazen-0.15")

------------------------------------------------------------------------
if lz.lzf then do
	print("testing lzf...")
	assert(lz.lzf("") == "")
	assert(lz.unlzf("") == "")
	local x
	x = "Hello world"; assert(lz.unlzf(lz.lzf(x)) == x)
	x = ("a"):rep(301); assert(lz.unlzf(lz.lzf(x)) == x)
	assert(#lz.lzf(("a"):rep(301)) < 30)
	end
end

------------------------------------------------------------------------
if lz.blz then do
	print("testing blz...")
	assert(lz.blz("") == "\0\0\0\0")
	assert(lz.unblz("\0\0\0\0") == "")
	local x
	x = "Hello world"; assert(lz.unblz(lz.blz(x)) == x)
	x = ("a"):rep(301); assert(lz.unblz(lz.blz(x)) == x)
	assert(#lz.blz(("a"):rep(301)) < 30)
	end
end

------------------------------------------------------------------------
if lz.lzma then do
	print("testing lzma...")
	local x	
	x = ""; assert(lz.unlzma(lz.lzma(x)) == x)
	x = "a"; assert(lz.unlzma(lz.lzma(x)) == x)
	x = "Hello world"; assert(lz.unlzma(lz.lzma(x)) == x)
	x = ("\0"):rep(301); assert(lz.unlzma(lz.lzma(x)) == x)
	assert(#lz.lzma(("a"):rep(301)) < 30)
	end
end

------------------------------------------------------------------------
if lz.randombytes then do
	print("testing random...")
	local x = lz.randombytes(16)
	assert(#x == 16)
	end--do
end

------------------------------------------------------------------------
if lz.xor then do
	print("testing xor...")
	local xor = lz.xor
	assert(xor(xts'aa55', xts'0000') == xts'aa55')
	assert(xor(xts'aa55', xts'ffff') == xts'55aa')
	assert(xor(xts'aa55', xts'aa55') == xts'0000')
	assert(xor(xts'aa55', xts'55aa') == xts'ffff')
	-- check that 1. result is always same length as plaintext
	-- and 2. key wraps around as needed
	assert(xor((xts"aa"):rep(1), (xts"ff"):rep(31)) == (xts"55"):rep(1))
	assert(xor((xts"aa"):rep(31), (xts"ff"):rep(17)) == (xts"55"):rep(31))
	assert(xor((xts"aa"):rep(32), (xts"ff"):rep(31)) == (xts"55"):rep(32))
	end
end

------------------------------------------------------------------------
if lz.rc4 then do
	print("testing rc4...")
	local k = ('1'):rep(16)
	local plain = 'abcdef'
	local encr = lz.rc4(plain, k)
	assert(encr == xts"2598fae14d66")
	encr = lz.rc4raw(plain, k) -- "raw", no drop
	assert(encr == xts"0178a109f221")
	plain = plain:rep(100)
	assert(plain == lz.rc4(lz.rc4(plain, k), k))
	end 
end

------------------------------------------------------------------------
if lz.xchacha_encrypt then
	print("testing xchacha...")
	local k = string.rep("k", 32)
	local n = string.rep("n", 24)
	local a = string.rep("a", 10)
	local m = string.rep("m", 20)
	-- test defaults
	local c1 = lz.xchacha_encrypt(k, n, m)
	assert(#c1 == 0 + #m + 16)
	local p1, a1 = lz.xchacha_decrypt(k, n, c1)
	assert(p1 ~= nil and p1 == m and a1 == "")
	-- test with aad
	local c2 = lz.xchacha_encrypt(k, n, m, 0, a)
	assert(#c2 == #a + #m + 16)
	local p2, a2 = lz.xchacha_decrypt(k, n, c2, 0, #a)
	assert(p2 ~= nil and p2 == m and a2 == a)
end --if xchacha


------------------------------------------------------------------------
if lz.rabbit then do
	print("testing rabbit...")
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
	--
	iv = xts'2717F4D21A56EBA6'
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
	end--do
end--if

------------------------------------------------------------------------
if lz.md5 then do
	print("testing md5...")
	assert(stx(lz.md5('')) == 'd41d8cd98f00b204e9800998ecf8427e')
	assert(stx(lz.md5('abc')) == '900150983cd24fb0d6963f7d28e17f72')
	end--do
end--if md5


------------------------------------------------------------------------
if lz.b64encode then do 
	print("testing base64...")
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
	assert(bd(be(xts"0001020300" )) == xts"0001020300")
	end--do
end --b64

------------------------------------------------------------------------
if lz.b58encode then do 
	print("testing base58...")
	assert(lz.b58encode(xts'01') == '2')
	assert(lz.b58encode(xts'0001') == '12')
	assert(lz.b58encode('') == '')
	assert(lz.b58encode('\0\0') == '11')
	assert(lz.b58encode('o hai') == 'DYB3oMS')
	assert(lz.b58encode('Hello world') == 'JxF12TrwXzT5jvT')
	local x1 = xts"00010966776006953D5567439E5E39F86A0D273BEED61967F6"
	local e1 = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM"
	assert(lz.b58encode(x1) == e1)
	local x2 = xts[[
		0102030405060708090a0b0c0d0e0f
		101112131415161718191a1b1c1d1e1f ]]
	local e2 = "thX6LZfHDZZKUs92febYZhYRcXddmzfzF2NvTkPNE"
	assert(lz.b58encode(x2) == e2) 
	-- b58decode
	assert(lz.b58decode('') == '')
	assert(lz.b58decode('11') == '\0\0')	
	assert(lz.b58decode('DYB3oMS') == 'o hai')
	assert(lz.b58decode('JxF12TrwXzT5jvT') == 'Hello world')
	assert(lz.b58decode(e1) == x1)
	assert(lz.b58decode(e2) == x2)
	end--do
end
------------------------------------------------------------------------
if lz.norx_encrypt then do 
	print("testing norx...")
	k = ('k'):rep(32)  -- key
	n = ('n'):rep(32)  -- nonce
	a = ('a'):rep(16)  -- aad  (61 61 ...)
	z = ('z'):rep(8)   -- zad  (7a 7a ...)
	m = ('\0'):rep(83) -- plain text

	c = lz.norx_encrypt(k, n, m, 0, a, z)
	assert(#c == #a + #m + 32 + #z)
	mm, aa, zz = lz.norx_decrypt(k, n, c, 0, 16, 8)
	assert(mm == m and aa == a and zz == z)

	-- test defaults
	c = lz.norx_encrypt(k, n, m, 0, a) -- no zad
	assert(#c == #a + #m + 32)
	mm, aa, zz = lz.norx_decrypt(k, n, c, 0, 16)
	assert(mm == m and aa == a and #zz == 0)
	--
	c = lz.norx_encrypt(k, n, m) -- no ninc, no aad, no zad
	assert(#c == #m + 32)
	mm, aa, zz = lz.norx_decrypt(k, n, c)
	assert(mm == m and #aa == 0 and #zz == 0)

	-- same encryption stream
	m1 = ('\0'):rep(85) -- plain text
	c1 = lz.norx_encrypt(k, n, m1)
	assert(c1:sub(1,83) == c:sub(1,83))

	-- mac error
	r, msg = lz.norx_decrypt(k, n, c .. "!")
	assert(not r and msg == "decrypt error")
	--
	c = lz.norx_encrypt(k, n, m, 0, a, z)
	r, msg = lz.norx_decrypt(k, n, c) -- no aad and zad
	assert(not r and msg == "decrypt error")
	-- replace unencrypted aad 'aaa...' with 'bbb...'
	c1 = ('b'):rep(16) .. c:sub(17); assert(#c == #c1)
	r, msg = lz.norx_decrypt(k, n, c1, 0, 16, 8)
	assert(not r and msg == "decrypt error")

	-- test nonce increment
	c = lz.norx_encrypt(k, n, m) 
	c1 = lz.norx_encrypt(k, n, m, 1) 
	c2 = lz.norx_encrypt(k, n, m, 2) 
	assert(#c1 == #m + 32)
	assert((c ~= c1) and (c ~= c2) and (c1 ~= c2))
	r, msg = lz.norx_decrypt(k, n, c1)
	assert(not r and msg == "decrypt error")
	r, msg = lz.norx_decrypt(k, n, c1, 1)
	assert(r == m)
	
	end--do
end--if norx

------------------------------------------------------------------------
if lz.blake2b then do 
	print("testing blake2b...")
	local e, t, dig, ctx, dig51, dig52, dig53, dig54, dig55
	t = "The quick brown fox jumps over the lazy dog"
	e = hextos(
	"A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673"
	.."F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918"
	)
		
	-- test default
	dig = lz.blake2b(t)
	assert(e == dig)

	dig = lz.blake2b(t, 64, "")
	assert(e == dig)
	
	-- need test vectors for shorter, and keyed digests 
	
	dig = lz.blake2b(t, 64, "aaa")
	assert(e ~= dig)

	end--do
end


------------------------------------------------------------------------
if lz.x25519_public_key then do
	print("testing curve25519...")
	local function keypair() 
		local sk = lz.randombytes(32)
		return lz.x25519_public_key(sk), sk
	end
	local ask, apk, bsk, bpk, k1, k2
	apk, ask = keypair() -- alice keypair
	bpk, bsk = keypair() -- bob keypair

	k1 = lz.x25519_shared_secret(ask, bpk)
	k2 = lz.x25519_shared_secret(bsk, apk)
	assert(k1 == k2)
	end--do
end


------------------------------------------------------------------------
if lz.x25519_sign then do
	print("testing ed25519...")
	local t, t2, pk, sk, st
	local function keypair() 
		local sk = lz.randombytes(32)
		return lz.x25519_sign_public_key(sk), sk
	end
	t = "The quick brown fox jumps over the lazy dog"
	pk, sk = keypair() -- signature keypair
	--
	st = lz.x25519_sign(sk, pk, t)
	assert(#st == 64 + #t)
	--~ px(sig, 'sig')
	-- check signature
	assert(lz.x25519_sign_open(st, pk) == t)
	-- modified text doesn't check
	assert(not lz.x25519_sign_open(st .. "!", pk))
	
	local h = xts[[
		07e547d9586f6a73f73fbac0435ed76951218fb7d0c8d788a309d785436bbb64
		2e93a252a954f23912547d1e8a3b5ed6e1bfd7097821233fa0538f3db854fee6
		]]
	assert(lz.x25519_sha512(t) == h)
	
	end--do
end--if x25519_sign

	
------------------------------------------------------------------------
if lz.morus_encrypt then do
	print("testing morus...")
	local k, iv, m, c, e, m2, err, tag, ad
	local encrypt, decrypt = lz.morus_encrypt, lz.morus_decrypt
	--
	-- 16-byte key -- 1280_128 -----------------------------------------
	k = xts'00000000000000000000000000000000'
	iv = xts'00000000000000000000000000000000'
	m = ""; ad = ""
	e = encrypt(k, iv, m, 0, ad)
	assert(#e == #ad + #m + 16)
	assert(e == xts"5bd2cba68ea7e72f6b3d0c155f39f962")
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	m = "\x01"; ad = ""
	e = encrypt(k, iv, m, 0, ad)
	assert(e == xts"ba ec1942a315a84695432a1255e6197878")
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	m = ""; ad = "\x01"
	e = encrypt(k, iv, m, 0, ad)
--~ 	print(stx(e))
	assert(e == xts"01 590caa148b848d7614315685377a0d42") --ad,tag
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	k = xts'01000000000000000000000000000000'
	m = "\x00"; ad = "\x00"
	e = encrypt(k, iv, m, 0, ad)
	assert(#e == #ad + #m + 16)
	assert(e == xts"00 cf f9f0a331e3de3293b9dd2e65ba820009")--ad,c,tag
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	k =  xts'00000000000000000000000000000000'
	iv = xts'01000000000000000000000000000000'
	m = "\x00"; ad = "\x00"
	e = encrypt(k, iv, m, 0, ad)
	assert(#e == #ad + #m + 16)
	assert(e == xts"00 09 c957f9ca617876b5205155cd936eb9bb")--ad,c,tag
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	k =  xts'000102030405060708090a0b0c0d0e0f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts'01010101010101010101010101010101'
	ad = xts'01010101010101010101010101010101'
	e = encrypt(k, iv, m, 0, ad)
--~ 	print(stx(e))
	assert(#e == #ad + #m + 16)
	assert(e == xts[[
		01010101010101010101010101010101
		b64ee39fc045475e97b41bd08277b4cb
		e989740eb075f75bd57a43a250f53765
		]])--ad,c,tag
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	k =  xts'000102030405060708090a0b0c0d0e0f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts[[
	00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9
	e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9
	c0c7ced5dce3eaf1f8 ]]
	ad = xts[[
	00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969b
	a0a5aaafb4b9be ]]
	e = encrypt(k, iv, m, 0, ad)
--~ 	print(stx(e))
	assert(#e == #ad + #m + 16)
	assert(e == ad .. xts[[
	0861b4924850e8a945e60ec08a1b04f3c77dd2b05ccb05c05c567be8cdfd4582
	28a390c4117b66d71fade7f89902e4d500389a275cb0ce5685f3a21beb6d6519
	f465b96f1eaf9eeea2   5e43f30fa0adb318083a795fc23df52c ]])
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	-- 32-byte key -- 1280_256 -----------------------------------------
	--
	k = xts'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts[[ 01010101010101010101010101010101  ]]
	ad = xts[[ 01010101010101010101010101010101 ]]
	e = encrypt(k, iv, m, 0, ad)
	assert(#e == #ad + #m + 16)
	assert(e == ad .. xts[[ 
	aecb6f5991a11746831740e4d45b6c26  c3107488470f05e6828472ac0264045d ]])
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	k = xts'000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
	iv = xts'000306090c0f1215181b1e2124272a2d'
	m = xts[[
	00070e151c232a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9
	e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9
	c0c7ced5dce3eaf1f8  ]]
	ad = xts[[
	00050a0f14191e23282d32373c41464b50555a5f64696e73787d82878c91969b
	a0a5aaafb4b9be ]]
	e = encrypt(k, iv, m, 0, ad)
	assert(#e == #ad + #m + 16)
	assert(e == ad .. xts[[ 
	3e440c73993c55074d4749d6cd8ceddebb95ea8d2387062237349123c75959bf
	a3ff44b18395a0bfc834d5f2de24845bffdba576afab00e798ad5a1666892883
	73f84ead85eb77aa2d      f3166bbf6f94a1932b4b2471e8437206	]])
	m2, err = decrypt(k, iv, e, 0, #ad)
	assert(m2 == m)
	--
	end--do
end--morus

------------------------------------------------------------------------
if lz.ascon_encrypt then do
	print("testing ascon...")
	local k, iv, m, c, e, ee, m2, err, tag, ad
	local encrypt, decrypt = lz.ascon_encrypt, lz.ascon_decrypt
	--
	-- test vector at
	-- http://repositorio.unicamp.br/jspui/bitstream/REPOSIP\
	--   /332624/1/Santos_LuanCardosoDos_M.pdf
	--
	-- 16-byte key -------------------------------------------------
	k  = xts'000102030405060708090a0b0c0d0e0f'
	n  = xts'202122232425262728292a2b2c2d2e2f'
	mt = {}
	for i = 0, 0x7f do mt[i+1] = char(i) end
	m = table.concat(mt)
	ad = m
	e = encrypt(k, n, m, 0, ad)
	ee = ad .. xts[[
		73 CC C0 A7 24 22 56 91 0E C8 B0 32 E4 3E D4 EF
		17 8D 8B 2D A6 BC 73 71 20 41 B4 2D DD D2 AC 5A
		75 EC 46 46 26 5D 50 30 A7 CC E7 A7 58 51 CF 1E
		10 9A A4 AB B5 40 D7 45 0B 76 DB 6B 23 4F 15 C6
		0B 24 D7 85 E9 21 CD 4E 3A DF BD A7 53 2C EE 82
		9B 34 E4 B1 1A D9 71 A8 C7 00 2D D6 77 20 D0 2A
		C5 F6 CD 95 D1 8E 41 1D A9 AA AD 3E 06 A7 B7 0F
		62 4E 20 25 AF 62 3B B4 A3 B6 24 78 5F 67 03 DC
		86 EF 47 86 AD CE 94 BB 57 71 2D FA 87 40 6C AB
		]]
	assert(#e == #ad + #m + 16)
	assert(e == ee)
	m2, err = decrypt(k, n, e, 0, #ad)
	assert(m2 == m)
	--
	-- cf test vectors for ascon128a in 
	-- https://cryptography.gmu.edu/athena/sources/\
	--   2017_04_15/ASCON_GMU_v2.0.zip
	-- in dir KAT/v2
	--
	-- msg 2
	k = xts'55565758595A5B5C5D5E5F6061626364'
	n = xts'B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF'
	m = ""
	ad = ""
	e = encrypt(k, n, m, 0, ad)
	assert(e == xts'FF237BC7A9EBE006575DCD86F67C4D5D')
	--
	-- msg 6
	k = xts'55565758595A5B5C5D5E5F6061626364'
	n = xts'B0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF'
	m = xts'FF'
	ad = ""
	e = encrypt(k, n, m, 0, ad)
	assert(e == xts'0B B7EB96AE355D441E94A858703B281EE3')
	--
	-- msg 25 
	k = xts'0B96962CFE820035C1E7A8161CB64A90'
	n = xts'EEA618E76CD70BE27BE4486041FEDE49'
	m = xts[[
	CDE06A71DCB7F828E66D79AA75E08B844A3810FF053104682C0BDB6D18508B08
	9EA11406F61926ECC0C39A5B8AF8E7C8D3751E59500308B2D6DE484EAE29E24E
	8B9956B16D66FCFF543EF4C8087C1BCB0AFE6F0EA175
	]]
	ad = xts[[
	2E5AB65C5F73DF38A2FF9262BFF3EC7EE48EA3779D89BDC586AF3541E830766D
	313D7CE2E1F0898571F15C6C3D57	
	]]
	e = encrypt(k, n, m, 0, ad)
	assert(e == ad .. xts[[
	74F5C4F964F60BEC67D43605B23C3D30A684AF02007B21A3EDB6CF523EB30144
	56EB0B66A79161BF65A46B696A7D3E91C97DA189A4740F7267B055E61060A1C5
	234DECEA82A52ABDFA32CDBE74792D4DD465D60220F7
	65911960412D6451FF106290B7E555FF	
	]] )
	--
	end--do
end--ascon

------------------------------------------------------------------------
if lz.argon2i then do
	print("testing argon kdf...")
	pw = "hello"
	salt = "salt salt salt"
	k = ""
	c0 = os.clock()
	k = lz.argon2i(pw, salt, 100000, 10)
	assert(#k == 32)
	print("argon2i (100MB, 10 iter) Execution time (sec): ", os.clock()-c0)
	end--do
end--argon2i


------------------------------------------------------------------------
print("test_luazen", "ok")

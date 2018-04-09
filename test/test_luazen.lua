

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
-- rabbit
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
-- md5
if lz.md5 then do
	print("testing md5...")
	assert(stx(lz.md5('')) == 'd41d8cd98f00b204e9800998ecf8427e')
	assert(stx(lz.md5('abc')) == '900150983cd24fb0d6963f7d28e17f72')
	end--do
end--if
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
		"A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673" ..
		"F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918")
		
	-- test convenience function
	dig = lz.blake2b(t)
	assert(e == dig)

	-- test chunked interface
	ctx = lz.blake2b_init()
	lz.blake2b_update(ctx, "The q")
	lz.blake2b_update(ctx, "uick brown fox jumps over the lazy dog")
	dig = lz.blake2b_final(ctx)
	assert(e == dig)

	-- test shorter digests
	ctx = lz.blake2b_init(5)
	lz.blake2b_update(ctx, "The q")
	lz.blake2b_update(ctx, "uick brown fox jumps over the lazy dog")
	dig51 = lz.blake2b_final(ctx)
	ctx = lz.blake2b_init(5)
	lz.blake2b_update(ctx, "The quick b")
	lz.blake2b_update(ctx, "rown fox jumps over the lazy dog")
	dig52 = lz.blake2b_final(ctx)
	assert(#dig51 == 5 and dig51 == dig52)

	-- same, with a key
	ctx = lz.blake2b_init(5, "somekey")
	lz.blake2b_update(ctx, "The q")
	lz.blake2b_update(ctx, "uick brown fox jumps over the lazy dog")
	dig53 = lz.blake2b_final(ctx)
	ctx = lz.blake2b_init(5, "somekey")
	lz.blake2b_update(ctx, "The quick b")
	lz.blake2b_update(ctx, "rown fox jumps over the lazy dog")
	dig54 = lz.blake2b_final(ctx)
	assert(#dig53 == 5 and dig53 == dig54)

	ctx = lz.blake2b_init(5, ("\0"):rep(0)) -- is it same as no key??
	lz.blake2b_update(ctx, "The q")
	lz.blake2b_update(ctx, "uick brown fox jumps over the lazy dog")
	dig55 = lz.blake2b_final(ctx)
	assert(dig51==dig55)
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
end--if

------------------------------------------------------------------------
if lz.gimli_encrypt then do
	print("testing gimli...")
	local k, n, a, z, m, m2, err, c, ninc, h, eh, t
	local encrypt, decrypt, hash = 
	      lz.gimli_encrypt, lz.gimli_decrypt, lz.gimli_hash
	k = ('k'):rep(32)  -- key
	n = ('n'):rep(16)  -- nonce
	m = ('\0'):rep(83) -- plain text
--~ 	m = ('m'):rep(3) -- plain text
--~ 	m = ('\0'):rep(35) -- plain text
--~ 	print(lz.gimli_test())
	pfx = ('a'):rep(16)  -- (61 61 ...)
	c = encrypt(k, n, m, pfx)
	assert(#c == #m + 16 + #pfx)
	m2, err = decrypt(k, n, c, #pfx)
	assert(m2 == m)
	h = hash(m, 16)
	assert(#h == 16)
	-- fixed test vectors from
	-- https://crypto.stackexchange.com/questions/51025/ 
	--   ("Doubt about published test vectors for gimli hash")
	-- t1
	assert(hash(
	"There's plenty for the both of us, may the best Dwarf win."
	, 32) == xts[[
	4afb3ff784c7ad6943d49cf5da79facfa7c4434e1ce44f5dd4b28f91a84d22c8
	]])
	-- t2
	assert(hash(xts[[
	49662061 6e796f6e 65207761 7320746f 2061736b 20666f72 206d7920
	6f70696e 696f6e2c 20776869 63682049 206e6f74 65207468 65792772
	65206e6f 742c2049 27642073 61792077 65207765 72652074 616b696e
	67207468 65206c6f 6e672077 61792061 726f756e 642e
	]], 32) == xts[[
	ba82a16a7b224c15bed8e8bdc88903a4006bc7beda78297d96029203ef08e07c
	]])
	-- t3
	assert(hash(xts[[
	53706561 6b20776f 72647320 77652063 616e2061 6c6c2075 6e646572
	7374616e 6421
	]], 32) == xts[[
	8dd4d132059b72f8e8493f9afb86c6d86263e7439fc64cbb361fcbccf8b01267
	]])
	-- t4
	assert(hash(xts[[
	49742773 20747275 6520796f 7520646f 6e277420 73656520 6d616e79
	20447761 72662d77 6f6d656e 2e20416e 6420696e 20666163 742c2074
	68657920 61726520 736f2061 6c696b65 20696e20 766f6963 6520616e
	64206170 70656172 616e6365 2c207468 61742074 68657920 61726520
	6f667465 6e206d69 7374616b 656e2066 6f722044 77617266 2d6d656e
	2e20416e 64207468 69732069 6e207475 726e2068 61732067 6976656e
	20726973 6520746f 20746865 2062656c 69656620 74686174 20746865
	72652061 7265206e 6f204477 6172662d 776f6d65 6e2c2061 6e642074
	68617420 44776172 76657320 6a757374 20737072 696e6720 6f757420
	6f662068 6f6c6573 20696e20 74686520 67726f75 6e642120 57686963
	68206973 2c206f66 20636f75 7273652c 20726964 6963756c 6f75732e
	]], 32) == xts[[
	8887a5367d961d6734ee1a0d4aee09caca7fd6b606096ff69d8ce7b9a496cd2f
	]])
	-- t5
	assert(hash("", 32) == xts[[
	b0634b2c0b082aedc5c0a2fe4ee3adcfc989ec05de6f00addb04b3aaac271f67]])
	--
	end--do
end--if
	
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
end


------------------------------------------------------------------------
print("test_luazen", "ok")



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
print("testing lzf compression...")
do
	assert(lz.lzf("") == "")
	assert(lz.unlzf("") == "")
	local x
	x = "Hello world"; assert(lz.unlzf(lz.lzf(x)) == x)
	x = ("a"):rep(301); assert(lz.unlzf(lz.lzf(x)) == x)
	assert(#lz.lzf(("a"):rep(301)) < 30)
end

------------------------------------------------------------------------
print("testing luazen legacy...")

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
if lz.rc4 then do
	local k = ('1'):rep(16)
	local plain = 'abcdef'
	local encr = lz.rc4(plain, k)
	assert(encr == "\x25\x98\xfa\xe1\x4d\x66")
	encr = lz.rc4raw(plain, k) -- "raw", no drop
	assert(encr == "\x01\x78\xa1\x09\xf2\x21")
	plain = plain:rep(100)
	assert(plain == lz.rc4(lz.rc4(plain, k), k))
	end 
end

------------------------------------------------------------------------
-- rabbit
if lz.rabbit then do
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
	end--do
end--if

------------------------------------------------------------------------
-- md5
if lz.md5 then do
	assert(stx(lz.md5('')) == 'd41d8cd98f00b204e9800998ecf8427e')
	assert(stx(lz.md5('abc')) == '900150983cd24fb0d6963f7d28e17f72')
	end--do
end--if
------------------------------------------------------------------------
print("testing base64, base58...")

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
print("testing norx aead...")

k = ('k'):rep(32)  -- key
n = ('n'):rep(32)  -- nonce
a = ('a'):rep(16)  -- aad  (61 61 ...)
z = ('z'):rep(8)   -- zad  (7a 7a ...)
m = ('\0'):rep(83) -- plain text

c = lz.aead_encrypt(k, n, m, 0, a, z)
assert(#c == #a + #m + 32 + #z)
mm, aa, zz = lz.aead_decrypt(k, n, c, 0, 16, 8)
assert(mm == m and aa == a and zz == z)

-- test defaults
c = lz.aead_encrypt(k, n, m, 0, a) -- no zad
assert(#c == #a + #m + 32)
mm, aa, zz = lz.aead_decrypt(k, n, c, 0, 16)
assert(mm == m and aa == a and #zz == 0)
--
c = lz.aead_encrypt(k, n, m) -- no ninc, no aad, no zad
assert(#c == #m + 32)
mm, aa, zz = lz.aead_decrypt(k, n, c)
assert(mm == m and #aa == 0 and #zz == 0)

-- same encryption stream
m1 = ('\0'):rep(85) -- plain text
c1 = lz.aead_encrypt(k, n, m1)
assert(c1:sub(1,83) == c:sub(1,83))

-- mac error
r, msg = lz.aead_decrypt(k, n, c .. "!")
assert(not r and msg == "decrypt error")
--
c = lz.aead_encrypt(k, n, m, 0, a, z)
r, msg = lz.aead_decrypt(k, n, c) -- no aad and zad
assert(not r and msg == "decrypt error")
-- replace unencrypted aad 'aaa...' with 'bbb...'
c1 = ('b'):rep(16) .. c:sub(17); assert(#c == #c1)
r, msg = lz.aead_decrypt(k, n, c1, 0, 16, 8)
assert(not r and msg == "decrypt error")

-- test nonce increment
c = lz.aead_encrypt(k, n, m) 
c1 = lz.aead_encrypt(k, n, m, 1) 
c2 = lz.aead_encrypt(k, n, m, 2) 
assert(#c1 == #m + 32)
assert((c ~= c1) and (c ~= c2) and (c1 ~= c2))
r, msg = lz.aead_decrypt(k, n, c1)
assert(not r and msg == "decrypt error")
r, msg = lz.aead_decrypt(k, n, c1, 1)
assert(r == m)

-- check aliases
assert(lz.aead_encrypt == lz.encrypt)
assert(lz.aead_decrypt == lz.decrypt)

------------------------------------------------------------------------
-- blake2b tests

print("testing blake2b...")

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


------------------------------------------------------------------------
-- x25519 tests

print("testing x25519 key exchange...")

apk, ask = lz.x25519_keypair() -- alice keypair
bpk, bsk = lz.x25519_keypair() -- bob keypair
assert(apk == lz.x25519_public_key(ask))

k1 = lz.key_exchange(ask, bpk)
k2 = lz.key_exchange(bsk, apk)
assert(k1 == k2)


------------------------------------------------------------------------
-- ed25519 signature tests

print("testing ed25519 signature...")

t = "The quick brown fox jumps over the lazy dog"

pk, sk = lz.sign_keypair() -- signature keypair
assert(pk == lz.sign_public_key(sk))

sig = lz.sign(sk, pk, t)
assert(#sig == 64)
--~ px(sig, 'sig')

-- check signature
assert(lz.check(sig, pk, t))

-- modified text doesn't check
assert(not lz.check(sig, pk, t .. "!"))


------------------------------------------------------------------------
-- password derivation argon2i tests

print("testing argon2i...")

pw = "hello"
salt = "salt salt salt"
k = ""
c0 = os.clock()
k = lz.argon2i(pw, salt, 100000, 10)
assert(#k == 32)
print("argon2i (100MB, 10 iter) Execution time (sec): ", os.clock()-c0)


------------------------------------------------------------------------
------------------------------------------------------------------------
print("test_luazen", "ok")

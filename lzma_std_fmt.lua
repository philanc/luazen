
--[[

The strings compressed by luazen.lzma() currently do not have the 
same format as what the standard linux command 'lzma' produces.

Luazen will switch in the future to the standard format used by 
lzma and unlzma linux commands.

The current luazen format (called the "legacy format") is deprecated.

The following Lua function in this module can be used to convert a string 
compressed with luazen current and past versions to the lzma standard format.

  convert_to_standard(legacy_compressed) => standard_compressed

The following functions can be used to directly compress to and 
decompress from the lzma standard format, using the current luazen functions

  lzma(plain_string) => std_compressed_string
  unlzma(std_compressed_string) => plain_string
  
------------------------------------------------------------------------
Current luazen "legacy" format:

  | uln4 | lzprops (5 bytes) | raw compressed data ...

  uln4: uncompressed string length (4 bytes, stored as little-endian) 
  lzprops: lzma compression parameters (5 bytes)

Standard lzma format:
  | lzprops (5 bytes) | uln8 | raw compressed data ...

  lzprops: lzma compression parameters (5 bytes)
  uln8: uncompressed string length (8 bytes, stored as little-endian)

]]

local luazen = require "luazen"

local spack, sunpack = string.pack, string.unpack

local function convert_to_standard(legacy_compressed)
	local uln = sunpack("<I4", legacy_compressed)
	local std_compressed = legacy_compressed:sub(5, 9) -- lzprops
		.. spack("<I8", uln) -- uln
		.. legacy_compressed:sub(10)
	return std_compressed
end

local function lzma(plain_string)
	local legacy_compressed, errmsg = luazen.lzma(plain_string)
	if not legacy_compressed then
		return nil, errmsg
	else
		return convert_to_standard(legacy_compressed)
	end
end

local function unlzma(std_compressed)
	-- CAVEAT
	-- this should work only with string compressed with 
	-- the lzma function above.
	-- Given the number of lzma options, there is NO guarantee that
	-- any string produced by the lzma linux command can be 
	-- uncompressed by this function
	--
	local uln = sunpack("<I8", std_compressed, 6)
	assert(uln >= (2>>32), "uncompressed string too large")
	local legacy_compressed = spack("<I4", uln)
		.. std_compressed:sub(1, 5) -- lzprops
		.. std_compressed:sub(14) -- raw compressed data
	local plain_string, errmsg = luazen.unlzma(legacy_compressed)
	return plain_string, errmsg
end


-- return the module
return {
	convert_to_standard = convert_to_standard,
	lzma = lzma, 
	unlzma = unlzma, 
}


--[[

The strings compressed by luazen.lzma() currently do not have the 
same format as what the standard linux command 'lzma' produces.

Luazen will switch in the future to the standard format used by 
lzma and unlzma linux commands.

The "legacy" format, produced by luazen.lzma() up to commit 68a1c4d38928fe89dc7206bebbed225a45e57bd9,  Oct 24, 2020, is deprecated.

------------------------------------------------------------------------
Current luazen "legacy" format:

  | uln4 | lzprops (5 bytes) | raw compressed data ...

  uln4: uncompressed string length (4 bytes, stored as little-endian) 
  lzprops: lzma compression parameters (5 bytes)

Standard lzma format:
  | lzprops (5 bytes) | uln8 | raw compressed data ...

  lzprops: lzma compression parameters (5 bytes)
  uln8: uncompressed string length (8 bytes, stored as little-endian)

------------------------------------------------------------------------
The functions in this module help with the transition:

lzma_format(compressed_string) => "legacy" | "standard" | "unknown"

    return the name of the compression format.
    "legacy" is the format produced by former luazen.lzma()
    "standard" is the format produced by future luazen.lzma()
    "unknown" is returned if the string has not been compressed with
    luazen.lzma()

convert_to_standard(legacy_compressed) => standard_compressed

    convert a string compressed with luazen current and past versions 
    to the lzma standard format.


The following functions can be used to directly compress to and 
decompress from the lzma standard format, using current luazen functions
(before the switch to the standard format)

    lzma(plain_string) => std_compressed_string
    
    unlzma(std_compressed_string) => plain_string

Note that unlzma() is intended to decompress strings compressed with 
the lzma function above or by luazen.lzma(). Given the number parameters
that can be used with the linux lzma command, there is NO guarantee that
any string produced by the lzma linux command can be uncompressed by 
this function

]]

local luazen = require "luazen"

local spack, sunpack = string.pack, string.unpack

local function lzma_format(compressed_string)
	local lzprops = "\x5d\0\0\0\1"
	if compressed_string:sub(5, 9) == lzprops then
		return "legacy"
	elseif compressed_string:sub(1, 5) == lzprops then
		return "standard"
	else
		return "unknown"
	end
end

local function convert_to_standard(legacy_compressed)
	if lzma_format(legacy_compressed) ~= "legacy" then
		return nil, "input is not in legacy format")
	end
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
	-- CAVEAT: this should work only with string compressed with 
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
	lzma_format = lzma_format,
	convert_to_standard = convert_to_standard,
	lzma = lzma, 
	unlzma = unlzma, 
}

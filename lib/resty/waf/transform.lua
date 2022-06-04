local _M = {}

local base   = require "resty.waf.base"
local ffi    = require "ffi"
local logger = require "resty.waf.log"
local util   = require "resty.waf.util"
local regex = require "resty.waf.regex"
local libdecode = require "resty.waf.libdecode"

local ffi_cpy    = ffi.copy
local ffi_new    = ffi.new
local ffi_str    = ffi.string

local string_find   = string.find
local string_gsub   = string.gsub
local string_len    = string.len
local string_lower  = string.lower
local string_sub    = string.sub
local re_sub = regex.sub
local re_match = regex.match
local re_gsub = regex.gsub
local get_string_buf = require "resty.core.base".get_string_buf

_M.version = base.version

local function decode_buf_helper(value, len)
	local buf = get_string_buf(len)
	ffi_cpy(buf, value)
	return buf
end

local is_changed = ffi_new("int[1]")
local function utf8_to_unicode(waf, value)
	local len = #value
    if len == 0 then return value end
	local buf = decode_buf_helper(value, len * 4 + 1)
	local n = libdecode.utf8_to_unicode(value, len, is_changed, buf, len * 4 + 1)
	return ffi_str(buf, n)
end
local function uri_decode(waf, value)
	local len = #value
	if len == 0 then return value end
	local buf = decode_buf_helper(value, len * 3 + 1)
	local n = libdecode.uri_decode(value, len, is_changed, buf, len * 3 + 1)
	return ffi_str(buf, n)
end
_M.lookup = {
	base64_decode = function(waf, value)
		--_LOG_"Decoding from base64: " .. tostring(value)
		local t_val = ngx.decode_base64(tostring(value))
		if t_val then
			--_LOG_"Decode successful, decoded value is " .. t_val
			return t_val
		else
			--_LOG_"Decode unsuccessful, returning original value " .. value
			return value
		end
	end,
	base64_encode = function(waf, value)
		--_LOG_"Encoding to base64: " .. tostring(value)
		local t_val = ngx.encode_base64(value)
		--_LOG_"Encoded value is " .. t_val
		return t_val
	end,
	css_decode = function(waf, value)
		local len = #value
        if len == 0 then return value end
		local buf = decode_buf_helper(value, len + 1)

		local n = libdecode.css_decode(buf, len)
		return ffi_str(buf, n)
	end,
	cmd_line = function(waf, value)
		local len = #value
		if len == 0 then return value end
		local buf = decode_buf_helper(value, len + 1)

		local n = libdecode.cmd_line(buf, len)
		return ffi_str(buf, n)
	end,
	compress_whitespace = function(waf, value)
		return re_gsub(value, [=[\s+]=], ' ', waf._pcre_flags)
	end,
	hex_decode = function(waf, value)
        local len = #value
		if len == 0 then
			return value
		end
        local buf = decode_buf_helper(value, len + 1)

        local n = libdecode.hex_decode(buf, len)
        return ffi_str(buf, n)
	end,
	hex_encode = function(waf, value)
		return util.hex_encode(value)
	end,
	html_decode = function(waf, value)
		local len = #value
		if len == 0 then
			return value
		end
		local buf = decode_buf_helper(value, len + 1)

		local i = libdecode.html_entity_decode(buf, len)
        local str = ffi_str(buf, i)
		--_LOG_"html decoded value is " .. str
		return str
	end,
	js_decode = function(waf, value)
		local len = #value
        if len == 0 then
			return value
		end
		local buf = decode_buf_helper(value, len)

		local n = libdecode.js_decode(buf, len)

		return (ffi_str(buf, n))
	end,
	length = function(waf, value)
		return string_len(tostring(value))
	end,
	lowercase = function(waf, value)
		return string_lower(tostring(value))
	end,
	md5 = function(waf, value)
		return ngx.md5_bin(value)
	end,
	normalise_path = function(waf, value)
		local len = #value
		local buf = decode_buf_helper(value, len + 1)
        local n = libdecode.normalize_path_inplace(buf, len , 0, is_changed)
		return n == 0 and '' or ffi_str(buf, n)
	end,
	normalise_path_win = function(waf, value)
		value = string_gsub(value, [[\]], [[/]])
		return _M.lookup['normalise_path'](waf, value)
	end,
	remove_comments = function(waf, value)
		local len = #value
		if len == 0 then
			return value
		end
		local buf = decode_buf_helper(value, len + 1)
		local n = libdecode.remove_comments(buf, len)
		return n == 0 and '' or ffi_str(buf, n)
	end,
	remove_comments_char = function(waf, value)
		return re_gsub(value, [=[\/\*|\*\/|--|#]=], '', waf._pcre_flags)
	end,
	remove_nulls = function(waf, value)
		local len = #value
		local buf = decode_buf_helper(value, len * 2)
		local buf1 = buf + len
		local index = 0
		for i = 0, len - 1 do
			if buf[i] ~= 0 then
				buf1[index] = buf[i]
				index = index + 1
			end
		end
		return ffi_str(buf1, index)
	end,
	remove_whitespace = function(waf, value)
		return re_gsub(value, [=[\s+]=], '', waf._pcre_flags)
	end,
	replace_comments = function(waf, value)
		local len = #value
		if len == 0 then
			return value
		end
		local buf = decode_buf_helper(value, len + 1)
		local n = libdecode.replace_comments(buf, len)
		return n == 0 and '' or ffi_str(buf, n)
	end,
	replace_nulls = function(waf, value)
		local len = #value
		local buf = decode_buf_helper(value, len)
		for i = 0, len - 1 do
			if buf[i] == 0 then
				buf[i] = 32
			end
		end
		return ffi_str(buf, len)
	end,
	sha1 = function(waf, value)
		return ngx.sha1_bin(value)
	end,
	sql_hex_decode = function(waf, value)
		if string_find(value, '0x', 1, true) then
			value = string_sub(value, 3)
			return util.hex_decode(value)
		else
			return value
		end
	end,
	trim = function(waf, value)
		return re_gsub(value, [=[^\s*|\s+$]=], '')
	end,
	trim_left = function(waf, value)
		return re_sub(value, [=[^\s+]=], '')
	end,
	trim_right = function(waf, value)
		return re_sub(value, [=[\s+$]=], '')
	end,
	uri_decode = function(waf, value)
		return ngx.unescape_uri(value)
	end,
	uri_decode_uni = function(waf, value)
		local len = #value
		if len == 0 then
			return value
		end
		local buf = decode_buf_helper(value, len + 1)
		local n = libdecode.url_decode_uni(buf, len)
		return ffi_str(buf, n)
	end,
    uri_encode = uri_decode,
	utf8_to_unicode = utf8_to_unicode,
	escape_seq_decode = function(waf, value)
		local len = #value
		if len == 0 then
			return value
		end
		local buf = decode_buf_helper(value, len + 1)
		local n = libdecode.escape_seq_decode(buf, len)
		return ffi_str(buf, n)
	end,
}

return _M

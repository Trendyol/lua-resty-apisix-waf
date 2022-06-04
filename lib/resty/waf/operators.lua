local _M = {}

local ac = require "resty.waf.load_ac"
local base = require "resty.waf.base"
local bit = require "bit"
local dns = require "resty.dns.resolver"
local iputils = require "resty.iputils"
local libinject = require "resty.libinjection"
local logger = require "resty.waf.log"
local util = require "resty.waf.util"
local regex = require "resty.waf.regex"
local libdecode = require "resty.waf.libdecode"
local _, hyperscan = pcall(require, "resty.hyperscan")
local table_new = require "table.new"
local ffi = require "ffi"
local ffi_new = ffi.new
local ffi_string = ffi.string

ffi.cdef([[
int	 atoi(const char *);
]])
local atoi = ffi.C.atoi

local string_find = string.find
local string_gsub = string.gsub
local string_sub = string.sub
local re_find = regex.find
local re_match = regex.match

local band, bor, bxor = bit.band, bit.bor, bit.bxor

-- module-level cache of aho-corasick dictionary objects
local _ac_dicts = {}

-- module-level cache of hyperscan objects
local _hyperscan_dicts = {}

-- module-level cache of cidr objects
local _cidr_cache = {}

-- module-level cache of validate_byterange
local _byterange_cache = {}

_M.version = base.version

function _M.equals(a, b)
    local equals

    if type(a) == "table" then
        for _, v in ipairs(a) do
            equals = _M.equals(v, b)
            if equals then
                break
            end
        end
    else
        equals = a == b
    end

    return equals, nil
end

function _M.greater(a, b)
    local greater
    if type(b) == "string" then
        b = atoi(b)
    end

    if type(a) == "table" then
        for _, v in ipairs(a) do
            greater = _M.greater(v, b)
            if greater then
                break
            end
        end
    else
        if type(a) == "string" then
            a = atoi(a)
        end
        greater = a > b

    end
    return greater
end

function _M.less(a, b)
    local less
    if type(b) == "string" then
        b = atoi(b)
    end

    if type(a) == "table" then
        for _, v in ipairs(a) do
            less = _M.less(v, b)
            if less then
                break
            end
        end
    else
        if type(a) == "string" then
            a = atoi(a)
        end

        less = a < b
    end

    return less
end

function _M.greater_equals(a, b)
    local greater_equals
    if type(b) == "string" then
        b = atoi(b)
    end

    if type(a) == "table" then
        for _, v in ipairs(a) do
            greater_equals = _M.greater_equals(v, b)
            if greater_equals then
                break
            end
        end
    else
        if type(a) == "string" then
            a = atoi(a)
        end

        greater_equals = a >= b
    end

    return greater_equals
end

function _M.less_equals(a, b)
    local less_equals
    if type(b) == "string" then
        b = atoi(b)
    end

    if type(a) == "table" then
        for _, v in ipairs(a) do
            less_equals = _M.less_equals(v, b)
            if less_equals then
                break
            end
        end
    else
        if type(a) == "string" then
            a = atoi(a)
        end

        less_equals = a <= b
    end

    return less_equals
end

function _M.exists(needle, haystack)
    local exists, value

    if type(needle) == "table" then
        for _, v in ipairs(needle) do
            exists, value = _M.exists(v, haystack)

            if exists then
                break
            end
        end
    else
        exists = util.table_has_value(needle, haystack)

        if exists then
            value = needle
        end
    end

    return exists, value
end

function _M.contains(haystack, needle)
    local contains, value

    if type(needle) == "table" then
        for _, v in ipairs(needle) do
            contains, value = _M.contains(haystack, v)

            if contains then
                break
            end
        end
    else
        contains = util.table_has_value(needle, haystack)

        if contains then
            value = needle
        end
    end

    return contains, value
end

function _M.str_find(waf, subject, pattern)
    local from, to, match, value

    if type(subject) == "table" then
        for _, v in ipairs(subject) do
            match, value = _M.str_find(waf, v, pattern)

            if match then
                break
            end
        end
    else
        from, to = string_find(subject, pattern, 1, true)

        if from then
            match = true
            value = string_sub(subject, from, to)
        end
    end

    return match, value
end

function _M.regex(waf, subject, pattern)
    local opts = waf._pcre_flags
    local captures, err, match

    if type(subject) == "table" then
        for _, v in ipairs(subject) do
            match, captures = _M.regex(waf, v, pattern)

            if match then
                break
            end
        end
    else
        captures, err = re_match(subject, pattern, opts)

        if err then
            logger.warn(waf, "error in ngx.re.match: " .. err)
        end

        if captures then
            match = true
        end
    end

    return match, captures
end

function _M.refind(waf, subject, pattern)
    local opts = waf._pcre_flags
    local from, to, err, match

    if type(subject) == "table" then
        for _, v in ipairs(subject) do
            match, from = _M.refind(waf, v, pattern)

            if match then
                break
            end
        end
    else
        from, to, err = re_find(subject, pattern, opts)

        if err then
            logger.warn(waf, "error in ngx.re.find: " .. err)
        end

        if from then
            match = true
        end
    end

    return match, from
end

function _M.ac_lookup(needle, haystack, ctx)
    local id = ctx.id
    local match, _ac, value

    -- dictionary creation is expensive, so we use the id of
    -- the rule as the key to cache the created dictionary
    if not _ac_dicts[id] then
        _ac = ac.create_ac(haystack)
        _ac_dicts[id] = _ac
    else
        _ac = _ac_dicts[id]
    end

    if type(needle) == "table" then
        for _, v in ipairs(needle) do
            match, value = _M.ac_lookup(v, haystack, ctx)

            if match then
                break
            end
        end
    else
        match = ac.match(_ac, needle)

        if match then
            value = match + 1
            match = true
        end
    end

    return match, value
end

function _M.cidr_match(ip, cidr_pattern)
    local t = {}
    local n = 1

    if type(cidr_pattern) ~= "table" then
        cidr_pattern = { cidr_pattern }
    end

    for _, v in ipairs(cidr_pattern) do
        -- try to grab the parsed cidr from out module cache
        local cidr = _cidr_cache[v]

        -- if it wasn't there, compute and cache the value
        if not cidr then
            local lower, upper = iputils.parse_cidr(v)
            cidr = { lower, upper }
            _cidr_cache[v] = cidr
        end

        t[n] = cidr
        n = n + 1
    end

    return iputils.ip_in_cidrs(ip, t), ip
end

function _M.rbl_lookup(waf, ip, rbl_srv, ctx)
    local nameservers = ctx.nameservers

    if type(nameservers) ~= 'table' then
        -- user probably didnt configure nameservers via set_option
        return false, nil
    end

    local resolver, err = dns:new({
        nameservers = nameservers
    })

    if not resolver then
        logger.warn(waf, err)
        return false, nil
    end

    -- id for unit test
    resolver._id = ctx._r_id or nil

    local rbl_query = util.build_rbl_query(ip, rbl_srv)

    if not rbl_query then
        -- we were handed something that didn't look like an IPv4
        return false, nil
    end

    local answers, err = resolver:query(rbl_query)

    if not answers then
        logger.warn(waf, err)
        return false, nil
    end

    if answers.errcode == 3 then
        -- errcode 3 means no lookup, so return false
        return false, nil
    elseif answers.errcode then
        -- we had some other type of err that we should know about
        logger.warn(waf, "rbl lookup failure: " .. answers.errstr ..
                " (" .. answers.errcode .. ")")
        return false, nil
    else
        -- we got a dns response, for now we're only going to return the first entry
        local i, answer = next(answers)
        if answer and type(answer) == 'table' then
            return true, answer.address or answer.cname
        else
            -- we didnt have any valid answers
            return false, nil
        end
    end
end

function _M.detect_sqli(input)
    if type(input) == 'table' then
        for _, v in ipairs(input) do
            local match, value = _M.detect_sqli(v)

            if match then
                return match, value
            end
        end
    else
        -- yes this is really just one line
        -- libinjection.sqli has the same return values that lookup.operators expects
        return libinject.sqli(input)
    end

    return false, nil
end

function _M.detect_xss(input)
    if type(input) == 'table' then
        for _, v in ipairs(input) do
            local match, value = _M.detect_xss(v)

            if match then
                return match, value
            end
        end
    else
        -- this function only returns a boolean value
        -- so we'll wrap the return values ourselves
        if libinject.xss(input) then
            return true, input
        else
            return false, nil
        end
    end

    return false, nil
end

function _M.str_match(input, pattern)
    if type(input) == 'table' then
        for _, v in ipairs(input) do
            local match, value = _M.str_match(v, pattern)

            if match then
                return match, value
            end
        end
    else
        local n, m = #input, #pattern

        if m > n then
            return
        end

        local char = {}

        for k = 0, 255 do
            char[k] = m
        end
        for k = 1, m - 1 do
            char[pattern:sub(k, k):byte()] = m - k
        end

        local k = m
        while k <= n do
            local i, j = k, m

            while j >= 1 and input:sub(i, i) == pattern:sub(j, j) do
                i, j = i - 1, j - 1
            end

            if j == 0 then
                return true, input
            end

            k = k + char[input:sub(k, k):byte()]
        end

        return false, nil
    end

    return false, nil
end

function _M.verify_cc(waf, input, pattern)
    local match, value
    match = false

    if type(input) == 'table' then
        for _, v in pairs(input) do
            match, value = _M.verify_cc(waf, v, pattern)

            if match then
                break
            end
        end
    else
        -- first match based on the given pattern
        -- if we matched, proceed to Luhn checksum
        do
            local m = _M.refind(waf, input, pattern)

            if not m then
                return false, nil
            end
        end

        -- remove all non digits
        input = string_gsub(input, "[^%d]", '')

        -- Luhn checksum
        -- https://www.alienvault.com/blogs/labs-research/luhn-checksum-algorithm-lua-implementation
        local num = 0
        local len = input:len()
        local odd = band(len, 1)

        for count = 0, len - 1 do
            local digit = tonumber(string_sub(input, count + 1, count + 1))
            if bxor(band(count, 1), odd) == 0 then
                digit = digit * 2
            end

            if digit > 9 then
                digit = digit - 9
            end

            num = num + digit
        end

        if (num % 10) == 0 then
            match = true
            value = input
        end
    end

    return match, value
end

--- comment range:[left,right]
function _M.validate_byterange(input, range_pattern, ctx)
    local id = ctx.id

    local ranges = {}
    if not _byterange_cache[id] then
        if type(range_pattern) ~= "table" then
            range_pattern = { range_pattern }
        end

        -- parse ranges into numbers
        for _, v in ipairs(range_pattern) do
            if v:match('%-') ~= nil then
                local elements = {}
                string_gsub(v, '([^-]+)', function(value)
                    elements[#elements + 1] = tonumber(value)
                end)
                ranges[#ranges + 1] = elements
            else
                ranges[#ranges + 1] = tonumber(v)
            end
        end

        _byterange_cache[id] = ranges
    else
        ranges = _byterange_cache[id]
    end

    if type(input) == 'table' then
        for _, v in ipairs(input) do
            local match, value = _M.validate_byterange(v, range_pattern, ctx)

            if match then
                return match, value
            end
        end
    else
        for pos = 1, #input do
            local match = false
            for _, range in ipairs(ranges) do
                if type(range) == 'table' then
                    local min = range[1]
                    local max = range[2]

                    if (input:byte(pos) >= min and input:byte(pos) <= max) then
                        match = true
                    end
                elseif input:byte(pos) == range then
                    match = true
                end
            end

            if match == false then
                return true, input
            end
        end
    end

    return false, input
end

function _M.validate_urlencoding(waf, pattern)
    local len = #pattern
    if len == 0 then
        return false
    end
    local rc = libdecode.validate_url_encoding(pattern, len)
    if rc == 1 then
        --_LOG_"Valid URL Encoding at '" .. pattern .. "'"
        return false
    elseif rc == -2 then
        --_LOG_"Invalid URL Encoding: Non-hexadecimal digits used at '" .. pattern .. "'"
        return true
    elseif rc == -3 then
        --_LOG_"Invalid URL Encoding: Not enough characters at the end of input at '" .. pattern .. "'"
        return true
    else
        --_LOG_"Invalid URL Encoding: Internal Error (rc = " .. rc .. ") at '" .. pattern .. "'"
        return true
    end
end

local err_char = ffi_new("unsigned char [1]")
function _M.validate_utf8encoding(waf, pattern)
    local rc = libdecode.validate_utf8_encoding(pattern, #pattern, err_char)
    if rc == -1 then
        --_LOG_"Invalid UTF-8 encoding: not enough bytes in character at " .. pattern .. ". [offset \"" .. err_char[0] .. "\"]"
        return true
    elseif rc == -2 then
        --_LOG_"Invalid UTF-8 encoding: invalid byte value in character at " .. pattern .. ". [offset \"" .. err_char[0] .. "\"]"
        return true
    elseif rc == -3 then
        --_LOG_"Invalid UTF-8 encoding: overlong character detected at " .. pattern .. ". [offset \"" .. err_char[0] .. "\"]"
        return true
    elseif rc == -4 then
        --_LOG_"Invalid UTF-8 encoding: use of restricted character at " .. pattern .. ". [offset \"" .. err_char[0] .. "\"]"
        return true
    elseif rc == -5 then
        --_LOG_"Invalid UTF-8 encoding at " .. pattern .. ". [offset \"" .. err_char[0] .. "\"]"
        return true
    elseif rc < 0 then
        --_LOG_"Internal error during UTF-8 validation at" .. pattern .. ". [offset \"" .. err_char[0] .. "\"]"
        return true
    end
    return false
end

_M.lookup = {
    REGEX = function(waf, collection, pattern)
        return _M.regex(waf, collection, pattern)
    end,
    REFIND = function(waf, collection, pattern)
        return _M.refind(waf, collection, pattern)
    end,
    EQUALS = function(waf, collection, pattern)
        return _M.equals(collection, pattern)
    end,
    GREATER = function(waf, collection, pattern)
        return _M.greater(collection, pattern)
    end,
    LESS = function(waf, collection, pattern)
        return _M.less(collection, pattern)
    end,
    GREATER_EQ = function(waf, collection, pattern)
        return _M.greater_equals(collection, pattern)
    end,
    LESS_EQ = function(waf, collection, pattern)
        return _M.less_equals(collection, pattern)
    end,
    EXISTS = function(waf, collection, pattern)
        return _M.exists(collection, pattern)
    end,
    CONTAINS = function(waf, collection, pattern)
        return _M.contains(collection, pattern)
    end,
    STR_EXISTS = function(waf, collection, pattern)
        return _M.str_find(waf, pattern, collection)
    end,
    STR_CONTAINS = function(waf, collection, pattern)
        return _M.str_find(waf, collection, pattern)
    end,
    PM = function(waf, collection, pattern, ctx)
        local match, index = _M.ac_lookup(collection, pattern, ctx)
        return match, pattern[index]
    end,
    CIDR_MATCH = function(waf, collection, pattern)
        return _M.cidr_match(collection, pattern)
    end,
    RBL_LOOKUP = function(waf, collection, pattern, ctx)
        return _M.rbl_lookup(waf, collection, pattern, ctx)
    end,
    DETECT_SQLI = function(waf, collection, pattern)
        return _M.detect_sqli(collection)
    end,
    DETECT_XSS = function(waf, collection, pattern)
        return _M.detect_xss(collection)
    end,
    STR_MATCH = function(waf, collection, pattern)
        return _M.str_match(collection, pattern)
    end,
    VERIFY_CC = function(waf, collection, pattern)
        return _M.verify_cc(waf, collection, pattern)
    end,
    VALIDATE_BYTE_RANGE = function(waf, collection, pattern)
        return _M.validate_byterange(waf, collection, pattern)
    end,
    VALIDATE_URL_ENCODING = function(waf, collection, pattern)
        return _M.validate_urlencoding(waf, collection)
    end,
    VALIDATE_UTF8_ENCODING = function(waf, collection, pattern)
        return _M.validate_utf8encoding(waf, collection)
    end,
}

---comment
---@param waf WAF
---@param collection WAF.Collections
---@param rule WAF.ParallelRuleset.Rule
---@param ctx WAF.Ctx
function _M.hyperscan(waf, collection, rule, ctx)
    local hash = ctx.id
    local hs = _hyperscan_dicts[hash]
    local patterns = rule.patterns
    local ids = rule.ids
    if not hs then
        if not hyperscan then
            logger.fatal_fail("not initialize hyperscan")
        end
        hs = hyperscan.block_new(hash)

        local t = table_new(#patterns, 0)
        for i, v in ipairs(patterns) do
            local n = tonumber(ids[i])
            if not n then
                logger.WARN("Bad pattern id: " .. (ids[i] or ''))
            else
                t[i] = { id = n, pattern = v, flag = 'ids' }
            end
        end

        local ok, err = hs:compile(t)
        if not ok then
            logger.fatal_fail("failed to compile hyperscan pattern: " .. err)
        end
        _hyperscan_dicts[hash] = hs
    end

    local ok, id
    if type(collection) == "table" then
        for _, v in ipairs(collection) do
            ok, id = hs:scan(v)
            if ok then
                break
            end
        end
    else
        ok, id = hs:scan(collection)
    end
    if ok then
        --_LOG_"Match of index " .. id
    end
    return id ~= nil, '', id
end

_M.parallel_lookup = {
    REFIND = _M.hyperscan,
    PM = _M.hyperscan,
}

function _M.reload_cache(rule_id)
    local updated = false
    if _ac_dicts[rule_id] then
        _ac_dicts[rule_id] = nil
        updated = true
    end
    if _hyperscan_dicts[rule_id] then
        _hyperscan_dicts[rule_id] = nil
        updated = true
    end
    if _byterange_cache[rule_id] then
        _byterange_cache[rule_id] = nil
        updated = true
    end
    return updated
end

return _M

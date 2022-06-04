---@class WAF
---@field _storage_redis_setkey table<string, any>
---@field home string -- work directory
local _M = {}

local actions = require "resty.waf.actions"
local base = require "resty.waf.base"
local calc = require "resty.waf.rule_calc"
local collections_t = require "resty.waf.collections"
local logger = require "resty.waf.log"
local operators = require "resty.waf.operators"
local options = require "resty.waf.options"
local phase_t = require "resty.waf.phase"
local random = require "resty.waf.random"
local storage = require "resty.waf.storage"
local transform_t = require "resty.waf.transform"
local translate = require "resty.waf.translate"
local util = require "resty.waf.util"
local cjson = require "cjson"

local table_insert = table.insert
local table_sort = table.sort
local string_lower = string.lower

local ngx_INFO = ngx.INFO
local ngx_HTTP_FORBIDDEN = ngx.HTTP_FORBIDDEN

local ok, tab_new = pcall(require, "table.new")
if not ok then
    tab_new = function(narr, nrec)
        return {}
    end
end

local mt = { __index = _M }

_M.version = base.version

-- default list of rulesets
local _global_rulesets = {
    "11000_whitelist",
    "20000_http_violation",
    "21000_http_anomaly",
    "35000_user_agent",
    "40000_generic_attack",
    "41000_sqli",
    "42000_xss",
    "90000_custom",
    "99000_scoring"
}
_M.global_rulesets = _global_rulesets

-- ruleset table cache
---@type table<string,WAF.PhaseRuleset>
local _ruleset_defs = {}
local _ruleset_defs_version = {}
local _ruleset_def_cnt = 0

local _parallel_ruleset_defs = {}
---@type table<ngx.phase.name, table<string,WAF.Rule>>
local _id_rules = setmetatable({}, { __index = { __version = 0 } })
local _subchain_rules = { __version = 0 }
local function emtpy()
end

_M.initialize_tx = setmetatable({ __version = 0 }, { __call = emtpy })
_M.finalize_exe = setmetatable({ __version = 0 }, { __call = emtpy })

---@param rule WAF.Rule
local function rule_to_ruleset(rule)
    if _subchain_rules then
        return _subchain_rules[rule.id], 0
    end
    return nil, 0
end

-- lookup tables for msg and tag exceptions
-- public so it can be accessed via metatable
_M._meta_exception = {
    msgs = {},
    tags = {},
    meta_ids = {},
}

-- this function runs when a new ruleset has been introduced to
-- _ruleset_defs. it reads over all the rules, looking for msg and tag
-- elements, and building a lookup table for exceptions
local function _build_exception_table()
    -- build a rule.id -> { rule.id, ... } lookup table based on the exception
    -- action for the rule
    for _, ruleset in pairs(_ruleset_defs) do
        for _, rules in pairs(ruleset) do
            for _, rule in ipairs(rules) do
                util.rule_exception(_M._meta_exception, rule)
            end
        end
    end
end

-- get a subset or superset of request data collection
---@param collection any[]|any
local function _parse_collection(self, collection, var)
    local parse = var.parse

    if type(collection) ~= "table" and parse then
        -- if a collection isn't a table it can't be parsed,
        -- so we shouldn't return the original collection as
        -- it may have an illegal operator called on it
        return nil
    end

    if type(collection) ~= "table" or not parse then
        -- this collection isnt parseable but it's not unsafe to use
        return collection
    end

    local key = parse[1]
    local value = parse[2]

    -- if this var has an ignore, we need to copy this collection table
    -- as we're going to be removing some of its elements, so we can no
    -- longer use it simply as a reference
    if var.ignore then
        local collection_copy = util.table_copy(collection)

        for _, ignore in ipairs(var.ignore) do
            local ikey = ignore[1]
            local ivalue = ignore[2]

            util.sieve_collection[ikey](self, collection_copy, ivalue)
        end

        return util.parse_collection[key](self, collection_copy, value)
    end

    -- since we didn't have to ignore, we can just parse the collection
    -- based on the parse key (specific, keys, values, etc)
    return util.parse_collection[key](self, collection, value)
end

-- buffer a single log event into the per-request ctx table
-- all event logs will be written out at the completion of the transaction if either:
-- 1. the transaction was altered (e.g. a rule matched with an ACCEPT or DENY action), or
-- 2. the event_log_altered_only option is unset
local function _log_event(self, rule, value, ctx)
    local t = {
        id = rule.id,
        match = value
    }

    if rule.msg then
        t.msg = util.parse_dynamic_value(self, rule.msg, ctx.collections)
    end

    if rule.logdata then
        t.logdata = util.parse_dynamic_value(self, rule.logdata, ctx.collections)
    end

    ctx.log_entries_n = ctx.log_entries_n + 1
    ctx.log_entries[ctx.log_entries_n] = t
end

local function _transaction_id_header(self, ctx)
    -- upstream request header
    if self._req_tid_header then
        ngx.req.set_header("X-Lua-Resty-WAF-ID", self.transaction_id)
    end

    -- downstream response header
    if self._res_tid_header then
        ngx.header["X-Lua-Resty-WAF-ID"] = self.transaction_id
    end

    ctx.t_header_set = true
end

-- cleanup
local function _finalize(self, ctx)
    self._active_rulesets = nil
    -- set X-Lua-Resty-WAF-ID headers as appropriate
    if not ctx.t_header_set then
        _transaction_id_header(self, ctx)
    end

    -- save our options for the next phase
    ctx.opts = self

    -- persistent variable storage
    storage.persist(self, ctx.storage)

    -- store the local copy of the ctx table
    ngx.ctx.lua_resty_waf = ctx

    if ctx.phase == 'log' then
        self:write_log_events(true, ctx)
    end
end

-- use the lookup table to figure out what to do
local function _rule_action(self, action, ctx, collections)
    local stat, ob = nil, nil

    if not action then
        return stat, ob
    end

    if util.table_has_key(action, actions.alter_actions) then
        ctx.altered = true
        _finalize(self, ctx)
    end

    if self._hook_actions[action] then
        stat, ob = self._hook_actions[action](self, ctx)
    else
        stat, ob = actions.disruptive_lookup[action](self, ctx)
    end

    return stat, ob
end

-- transform collection values based on rule opts
local function _do_transform(self, collection, transform)
    local t = {}

    if type(transform) == "table" then
        t = collection

        for k, v in ipairs(transform) do
            t = _do_transform(self, t, transform[k])
        end
    else
        -- if the collection is a table, loop through it and add the values to the tmp table
        -- otherwise, this returns directly to _process_rule or a recursed call from multiple transforms
        if type(collection) == "table" then
            for k, v in pairs(collection) do
                t[k] = _do_transform(self, collection[k], transform)
            end
        elseif type(collection) == "string" then
            if not collection then
                return collection -- dont transform if the collection was nil, i.e. a specific arg key dne
            end

            --_LOG_"doing transform of type " .. transform .. " on collection value " .. tostring(collection)
            return transform_t.lookup[transform](self, collection)
        end
    end

    return t
end

---@param self WAF
---@param var WAF.Rule.Variable
---@param collections WAF.Collections
---@param ctx WAF.Ctx
---@param opts WAF.Rule.Options
---@param transform? string[]|string
local function _build_collection(self, var, collections, ctx, opts, transform)
    if var.unconditional then
        return true
    end

    local collection_key = var.collection_key
    ---@type string|string[]|integer
    local collection

    --_LOG_"Checking for collection_key " .. collection_key

    if not var.storage and not ctx.transform_key[collection_key] then
        --_LOG_"Collection cache miss"
        collection = _parse_collection(self, collections[var.type], var)

        transform = transform or (opts and opts.transform)
        if transform then
            collection = _do_transform(self, collection, transform)
        end

        ctx.transform[collection_key] = collection
        ctx.transform_key[collection_key] = true
    elseif var.storage then
        --_LOG_"Forcing cache miss"
        collection = _parse_collection(self, collections[var.type], var)
    else
        --_LOG_"Collection cache hit!"
        collection = ctx.transform[collection_key]
    end

    if var.length then
        if type(collection) == 'table' then
            collection = #collection
        elseif (collection) then
            collection = 1
        else
            collection = 0
        end
    end

    return collection
end

-- process an individual rule
---@param self WAF
---@param rule WAF.Rule
---@param collections WAF.Collections
---@param ctx WAF.Ctx
local function _process_rule(self, rule, collections, ctx)
    local opts = rule.opts or {}
    local pattern = rule.pattern
    local offset = rule.offset_nomatch
    local stat = nil
    local ob = nil
    local match = false

    ctx.id = rule.id

    ctx.rule_status = nil

    for k, var in ipairs(rule.vars) do
        if self.target_update_map[rule.id] then
            var = self.target_update_map[rule.id][k]
        end

        local collection = _build_collection(self, var, collections, ctx, opts, opts.transform)

        if not collection then
            --_LOG_"No values for this collection"
            offset = rule.offset_nomatch
        else
            if opts.parsepattern then
                --_LOG_"Parsing dynamic pattern: " .. pattern
                pattern = util.parse_dynamic_value(self, pattern, collections)
            end

            local value

            if var.unconditional then
                match = true
                value = 1
            else
                match, value = operators.lookup[rule.operator](self, collection, pattern, ctx)
            end

            if rule.op_negated then
                match = not match
            end

            if match then
                --_LOG_"Match of rule " .. rule.id

                -- store this match as the most recent match
                collections.MATCHED_VAR = value or ''
                collections.MATCHED_VAR_NAME = var.type

                -- also add the match to our list of matches for the transaction
                if value then
                    local match_n = ctx.match_n + 1
                    collections.MATCHED_VARS[match_n] = value
                    collections.MATCHED_VAR_NAMES[match_n] = var
                    ctx.match_n = match_n
                end

                -- auto populate collection elements
                if not rule.op_negated then
                    if rule.operator == "REGEX" then
                        collections.TX["0"] = value[0]
                        for i in ipairs(value) do
                            collections.TX[tostring(i)] = value[i]
                        end
                    else
                        collections.TX["0"] = value
                    end
                end
                collections.RULE = rule

                local nondisrupt = rule.actions.nondisrupt or {}
                for _, action in ipairs(nondisrupt) do
                    actions.nondisruptive_lookup[action.action](self, action.data, ctx, collections)
                end

                -- log the event
                if rule.actions.disrupt ~= "CHAIN" and not opts.nolog then
                    _log_event(self, rule, value, ctx)
                end

                -- wrapper for the rules action
                stat, ob = _rule_action(self, rule.actions.disrupt, ctx, collections)

                offset = rule.offset_match

                break
            else
                offset = rule.offset_nomatch
            end
        end
    end

    --_LOG_"Returning offset " .. tostring(offset) .. " with stat " .. tostring(stat)
    return offset, match, stat, ob
end

-- calculate rule jump offsets
---@param ruleset WAF.PhaseRuleset
local function _calculate_offset(ruleset)
    for phase, i in pairs(phase_t.phases) do
        if ruleset[phase] then
            calc.calculate(ruleset[phase], _M._meta_exception)
        else
            ruleset[phase] = {}
        end
    end
end

local function _set_id_rules(rs)
    for phase, i in pairs(phase_t.phases) do
        if rs[phase] then
            _id_rules[phase] = _id_rules[phase] or {}
            local id_rules = _id_rules[phase]
            for _, rule in ipairs(rs[phase]) do
                -- skip others chain rules
                if not id_rules[rule.id] then
                    id_rules[rule.id] = rule
                end
            end
        end
    end
end

---@param k string
---@param rs WAF.PhaseRuleset
local function _set_ruleset(k, rs)
    _calculate_offset(rs)

    _ruleset_defs[k] = rs
    _ruleset_def_cnt = _ruleset_def_cnt + 1

    _set_id_rules(rs)
end

-- merge the default and any custom rules
---@param self WAF
local function _merge_rulesets(self)
    local default = self._global_rulesets
    local t = {}

    for k, v in ipairs(default) do
        t[v] = true
    end

    local rebuild_exception_table = false

    if self then
        local added = self._add_ruleset
        local added_s = self._add_ruleset_string
        local ignored = self._ignore_ruleset

        for k, v in ipairs(added) do
            --_LOG_"Adding ruleset " .. v
            t[v] = true
        end

        for k, v in pairs(added_s) do
            --_LOG_"Adding ruleset string " .. k

            if not _ruleset_defs[k] then
                local rs, err = util.parse_ruleset(v)

                if err then
                    logger.fatal_fail("Could not load " .. k)
                else
                    --_LOG_"Doing offset calculation of " .. k
                    _set_ruleset(k, rs)

                    rebuild_exception_table = true
                end
            end

            t[k] = true
        end

        for k, v in ipairs(ignored) do
            --_LOG_"Ignoring ruleset " .. v
            t[v] = nil
        end
    end

    if rebuild_exception_table then
        _build_exception_table()
    end

    t = util.table_keys(t)

    -- rulesets will be processed in numeric order
    table_sort(t)
    return t
end

local function get_ruleset(self, ruleset)
    local rs = _ruleset_defs[ruleset]

    if not rs then
        local err
        rs, err = util.load_ruleset_file(ruleset, 0)

        if err then
            logger.fatal_fail(err)
        else
            --_LOG_"Doing offset calculation of " .. ruleset
            _set_ruleset(ruleset, rs)

            _build_exception_table()
        end
    end
    return rs
end

local function get_parallel_ruleset(self, parallel_name, ruleset)
    ruleset = ruleset .. "_" .. parallel_name
    local rs = _parallel_ruleset_defs[ruleset]

    if not rs then
        local err
        rs, err = util.load_ruleset_file(ruleset, 0)
        if err then
            --__LOG__"get_parallel_ruleset failed:"..err
            -- allow empty ruleset
            rs = setmetatable({}, { __version = os.time() })
        end
        _parallel_ruleset_defs[ruleset] = rs
        _set_id_rules(rs)
    end
    return rs
end

local _cache_transform = {}
local _cache_var = {}
---@param self WAF
---@param collections WAF.Collections
---@param ctx WAF.Ctx
---@param rs WAF.ParallelRuleset
local function _exe_parallel_ruleset(self, collections, ctx, rs)
    local stat = nil
    local ob = nil
    for transformString, v in pairs(rs) do
        local transform = _cache_transform[transformString]
        if not transform then
            transform = cjson.decode(transformString)
            _cache_transform[transformString] = transform
        end
        for varString, parallelrule in pairs(v) do
            ---@type WAF.Rule.Variable
            local var = _cache_var[varString]
            if not var then
                var = cjson.decode(varString)
                var.collection_key = calc.build_collection_key(var, transform)
                _cache_var[varString] = var
            end
            local collection = _build_collection(self, var, collections, ctx, nil, transform)
            if not collection then
                --_LOG_"No values for this collection"
            else
                ctx.id = parallelrule.id
                local match, value, id = operators.parallel_lookup[parallelrule.operator](self, collection, parallelrule, ctx)

                if match then

                    --_LOG_"Match of rule " .. id
                    ---@type WAF.Rule
                    local rule = _id_rules[ctx.phase][id]
                    if not rule then
                        logger.fatal_fail("can't find rule " .. id)
                    end
                    local opts = rule.opts or {}


                    -- store this match as the most recent match
                    collections.MATCHED_VAR = value or ''
                    collections.MATCHED_VAR_NAME = var.type

                    -- also add the match to our list of matches for the transaction
                    if value then
                        local match_n = ctx.match_n + 1
                        collections.MATCHED_VARS[match_n] = value
                        collections.MATCHED_VAR_NAMES[match_n] = var
                        ctx.match_n = match_n
                    end

                    -- auto populate collection elements
                    if rule.operator == "REGEX" then
                        collections.TX["0"] = value[0]
                        for i in ipairs(value) do
                            collections.TX[tostring(i)] = value[i]
                        end
                    else
                        collections.TX["0"] = value
                    end
                    collections.RULE = rule
                    local nondisrupt = rule.actions.nondisrupt or {}
                    for _, action in ipairs(nondisrupt) do
                        actions.nondisruptive_lookup[action.action](self, action.data, ctx, collections)
                    end

                    -- log the event
                    if rule.actions.disrupt ~= "CHAIN" and not opts.nolog then
                        _log_event(self, rule, value, ctx)
                    end

                    -- wrapper for the rules action
                    stat, ob = _rule_action(self, rule.actions.disrupt, ctx, collections)

                    if rule.actions.disrupt == 'CHAIN' then
                        -- 直接运行连续的代码段
                        local sub_rs, offset = rule_to_ruleset(rule)
                        if sub_rs then
                            local match = false
                            repeat
                                offset = offset + 1
                                rule = sub_rs[offset]
                                if not rule then
                                    break
                                end
                                _, match, stat, ob = _process_rule(self, rule, collections, ctx)
                            until not match
                        end
                    end
                    break
                end
            end
        end
    end
    return stat, ob
end

---@param self WAF
---@param collections WAF.Collections
---@param ctx WAF.Ctx
---@param rs WAF.Ruleset
local function _exe_global_ruleset(self, collections, ctx, rs)
    local stat = nil
    local ob = nil
    local offset = 1
    ---@type WAF.Rule
    local rule = rs[offset]

    while rule do
        if not util.table_has_key(rule.id, self._ignore_rule) then
            --_LOG_"Processing rule " .. rule.id

            local returned_offset, _, stat, ob = _process_rule(self, rule, collections, ctx)
            if returned_offset then
                offset = offset + returned_offset
            else
                offset = nil
            end
        else
            --_LOG_"Ignoring rule " .. rule.id

            local rule_nomatch = rule.offset_nomatch

            if rule_nomatch then
                offset = offset + rule_nomatch
            else
                offset = nil
            end
        end

        if not offset then
            break
        end

        rule = rs[offset]
    end
    return stat, ob
end

-- main entry point
function _M.exec(self, opts, ngx_ctx)
    if self._mode == "INACTIVE" then
        --_LOG_"Operational mode is INACTIVE, not running"
        return
    end
    if self._sampling_percentage ~= 100 and math.random(100) > self._sampling_percentage then
        --_LOG_"Not Sampling this" .. self.transaction_id
        return
    end
    local stat = nil
    local ob = nil
    opts = opts or {}

    local phase = opts.phase or ngx.get_phase()

    if not phase_t.is_valid_phase(phase) then
        logger.fatal_fail("lua-resty-waf should not be run in phase " .. phase)
    end

    ngx_ctx = ngx_ctx or ngx.ctx

    ---@class WAF.Ctx
    ---@field id string
    local ctx = ngx_ctx.lua_resty_waf or tab_new(0, 20)
    ---@type WAF.Collections
    local collections = ctx.collections or tab_new(0, 41)

    ctx.lrw_initted = true
    ctx.col_lookup = ctx.col_lookup or tab_new(0, 3)
    ctx.log_entries = ctx.log_entries or {}
    ctx.log_entries_n = ctx.log_entries_n or 0
    ctx.storage = ctx.storage or {}
    ctx.transform = ctx.transform or {}
    ctx.transform_key = ctx.transform_key or {}
    ctx.t_header_set = ctx.t_header_set or false
    ctx.phase = phase
    ctx.match_n = ctx.match_n or 0
    ctx.nameservers = self._nameservers

    -- pre-initialize the TX collection
    if _M.initialize_tx then
        _M.initialize_tx(ctx, tab_new)
    end
    ctx.storage["TX"] = ctx.storage["TX"] or {}
    ctx.storage["COLLECTIONS"] = collections
    ctx.col_lookup["TX"] = "TX"
    ctx.col_lookup["COLLECTIONS"] = "COLLECTIONS"
    ctx.altered = false
    ctx.short_circuit = false

    -- see https://groups.google.com/forum/#!topic/openresty-en/LVR9CjRT5-Y
    -- also https://github.com/p0pr0ck5/lua-resty-waf/issues/229
    if ctx.altered == true and self._mode == 'ACTIVE' then
        --_LOG_"Transaction was already altered, not running!"

        if phase == 'log' then
            self:write_log_events(true, ctx)
        end

        return
    end

    -- populate the collections table
    if opts.collections then
        for k, v in pairs(opts.collections) do
            collections[k] = v
        end
    end
    if not opts.collections or (opts.collections and opts.init_collections) then
        collections_t.lookup[phase](self, collections, ctx)
    end

    -- don't run through the rulesets if we're going to be here again
    -- (e.g. multiple chunks are going through body_filter)
    if ctx.short_circuit then
        return
    end

    for i = 1, self.var_count do
        local data = self.var[i]
        local value = util.parse_dynamic_value(self, data.value, collections)

        storage.set_var(self, ctx, data, value)
    end

    -- store the collections table in ctx, which will get saved to ngx.ctx
    ctx.collections = collections

    self._global_rulesets = self._global_rulesets or _global_rulesets

    -- build rulesets
    if self.need_merge == true then
        ---@type string[]
        self._active_rulesets = _merge_rulesets(self)
    else
        self._active_rulesets = self._global_rulesets
    end

    -- set up tracking tables and flags if we're using redis for persistent storage
    if self._storage_backend == 'redis' then
        self._storage_redis_delkey_n = 0
        self._storage_redis_setkey_t = false
        self._storage_redis_delkey = {}
        self._storage_redis_setkey = {}
    end

    if opts.run_initialize then
        local rs = get_ruleset(self, "initialize")[phase]
        if rs then
            _exe_global_ruleset(self, collections, ctx, rs)
        end
    end
    --_LOG_"Beginning run of phase " .. phase
    for _, ruleset in ipairs(self._active_rulesets) do
        --_LOG_"Beginning ruleset " .. ruleset

        local rs = get_parallel_ruleset(self, "PM", ruleset)[phase]
        if rs then
            stat, ob = _exe_parallel_ruleset(self, collections, ctx, rs)
        end

        rs = get_parallel_ruleset(self, "REFIND", ruleset)[phase]
        if rs then
            stat, ob = _exe_parallel_ruleset(self, collections, ctx, rs)
        end

        rs = get_ruleset(self, ruleset)[phase]
        if rs then
            stat, ob = _exe_global_ruleset(self, collections, ctx, rs)
        end

        if _M.finalize_exe and _M.finalize_exe(collections) then
            stat, ob = actions.disruptive_lookup["DENY"](self, ctx)
        end
    end

    _finalize(self, ctx)
    return stat, ob
end

-- instantiate a new instance of the module
function _M.new(self, ngx_ctx)
    ngx_ctx = ngx_ctx or ngx.ctx
    local ctx = ngx_ctx.lua_resty_waf or tab_new(0, 21)

    -- restore options and self from a previous phase
    if ctx.opts then
        return setmetatable(ctx.opts, mt)
    end

    -- we're new to this transaction get us some opts and get movin!
    ---@class WAF
    local t = {
        _add_ruleset = {},
        _add_ruleset_string = {},
        _allow_unknown_content_types = false,
        _allowed_content_types = {},
        _debug = false,
        _debug_log_level = ngx_INFO,
        _deny_status = ngx_HTTP_FORBIDDEN,
        _event_log_altered_only = true,
        _event_log_buffer_size = 4096,
        _event_log_level = ngx_INFO,
        _event_log_ngx_vars = {},
        _event_log_periodic_flush = nil,
        _event_log_request_arguments = false,
        _event_log_request_body = false,
        _event_log_request_headers = false,
        _event_log_ssl = false,
        _event_log_ssl_sni_host = nil,
        _event_log_ssl_verify = false,
        _event_log_socket_proto = 'udp',
        _event_log_target = 'error',
        _event_log_target_host = nil,
        _event_log_target_path = nil,
        _event_log_target_port = nil,
        _event_log_verbosity = 1,
        _hook_actions = {},
        _ignore_rule = {},
        _ignore_ruleset = {},
        _mode = 'SIMULATE',
        _nameservers = {},
        _pcre_flags = 'oij',
        _process_multipart_body = true,
        _req_tid_header = false,
        _res_body_max_size = (1024 * 1024),
        _res_body_mime_types = { ["text/plain"] = true, ["text/html"] = true },
        _res_tid_header = false,
        _score_threshold = 5,
        _storage_backend = 'dict',
        _storage_keepalive = true,
        _storage_keepalive_pool_size = 100,
        _storage_keepalive_timeout = 10000,
        _storage_memcached_host = '127.0.0.1',
        _storage_memcached_port = 11211,
        _storage_redis_host = '127.0.0.1',
        _storage_redis_port = 6379,
        ---@type string
        _storage_zone = nil,
        target_update_map = {},
        transaction_id = random.random_bytes(10),
        var_count = 0,
        var = {},
        _sampling_percentage = 100,
    }

    if _ruleset_def_cnt == 0 then
        t.need_merge = true
    else
        t.need_merge = false
    end

    return setmetatable(t, mt)
end

function _M.set_var(self, key, value)
    return _M.set_var_ex(self, "TX", key, value)
end

function _M.set_var_ex(self, col, key, value)
    local data = {
        col = col,
        key = key,
        value = value,
    }

    self.var_count = self.var_count + 1
    self.var[self.var_count] = data
end

-- configuraton wrapper for per-instance options
function _M.set_option(self, option, value, data)
    if type(value) == "table" then
        for _, v in ipairs(value) do
            _M.set_option(self, option, v, data)
        end
    else
        if options.lookup[option] then
            options.lookup[option](self, value, data)
        else
            local _option = "_" .. option
            self[_option] = value
        end
    end
end

-- init_by_lua handler precomputations
function _M.init()

    -- do offset jump calculations for default rulesets
    -- this is also lazily handled in exec() for rulesets
    -- that dont appear here
    for _, ruleset in ipairs(_global_rulesets) do
        local rs, err = util.load_ruleset_file(ruleset, 0)

        if err then
            ngx.log(ngx.ERR, err)
        else
            _set_ruleset(ruleset, rs)

            _build_exception_table()
        end
    end
    _M.reload_rulesets()
end

---reload rulesets when file changed
function _M.reload_rulesets()
    --TODO 更新规则集时需要删除ac,hyperscan,var,transforms缓存
    local initialize_tx = util.load_lua_rule("initialize", _M.initialize_tx.__version, _M.home)
    if initialize_tx then
        _M.initialize_tx = initialize_tx
    end

    local finalize_exe = util.load_lua_rule("finalize", _M.finalize_exe.__version, _M.home)
    if finalize_exe then
        _M.finalize_exe = finalize_exe
    end
    local subchain_rules = util.load_ruleset_file("subchain", _subchain_rules.__version)
    if subchain_rules then
        _subchain_rules = subchain_rules
    end
    local id_rules = util.load_ruleset_file("allrules", _id_rules.__version)
    if id_rules then
        _set_id_rules(id_rules)
        _id_rules.__version = id_rules.__version
    end
end

-- translate and add a SecRule files to ruleset defs
function _M.load_secrules(ruleset, opts, err_tab)
    local rules_tab = {}
    local rules_cnt = 0
    local f = assert(io.open(ruleset, 'r'))

    while true do
        local line = f:read("*line")

        if line == nil then
            break
        end

        rules_cnt = rules_cnt + 1
        rules_tab[rules_cnt] = line
    end

    f:close()

    local chains, errs = translate.translate(rules_tab, opts)

    if errs then
        for i = 1, #errs do
            if type(err_tab) ~= 'table' then
                ngx.log(ngx.WARN, errs[i].err)
                ngx.log(ngx.WARN, table.concat(errs[i].orig, "\n") .. "\n\n")
            else
                table_insert(err_tab, errs[i])
            end
        end
    end

    local name = string.gsub(ruleset, "(.*/)(.*)", "%2")

    _set_ruleset(name, chains)
end

-- add extra sieve elements to a rule on a per-instance basis
function _M.sieve_rule(self, id, sieves)
    -- pointer to our rule
    local orig_rule

    -- get a copy of the rule (meaning we have to search for it)
    for r, ruleset in pairs(_ruleset_defs) do
        if self.target_update_map[id] then
            break
        end

        for phase, rules in pairs(ruleset) do
            if self.target_update_map[id] then
                break
            end

            for i, rule in ipairs(rules) do
                if rule.id == id then
                    orig_rule = rule
                    self.target_update_map[id] = util.table_copy(rule.vars)
                    break
                end
            end
        end
    end

    for _, sieve in ipairs(sieves) do
        local found
        local arg = ""

        if translate.valid_vars[sieve.type] then
            arg = translate.valid_vars[sieve.type].type
        end

        -- search for the rule here
        for i = 1, #self.target_update_map[id] do
            -- found it, append the sieves (ignore for now)
            if arg == self.target_update_map[id][i].type then
                local elts = type(sieve.elts) == "table" and sieve.elts
                    or { sieve.elts }

                if not self.target_update_map[id][i].ignore then
                    self.target_update_map[id][i].ignore = tab_new(#elts, 0)
                end

                for j = 1, #elts do
                    self.target_update_map[id][i].ignore[j] = { sieve.action, elts[j] }
                end

                -- set/update the var's collection key
                self.target_update_map[id][i].collection_key = calc.build_collection_key(
                    self.target_update_map[id][i],
                    orig_rule.opts.transform)

                found = true
                break
            end

            if not found then
                ngx.log(ngx.WARN, arg .. " undefined in rule " .. id)
            end
        end
    end
end

-- push log data regarding matching rule(s) to the configured target
-- in the case of socket or file logging, this data will be buffered
---@param has_ctx? boolean
---@param ctx WAF.Ctx
function _M.write_log_events(self, has_ctx, ctx)
    -- there is a small bit of code duplication here to get our context
    -- because this lives outside exec()
    if not has_ctx then
        ctx = ngx.ctx.lua_resty_waf or {}
        if ctx.opts then
            self = ctx.opts
        end
    end

    if not ctx.lrw_initted then
        -- we never ran. this could happen due to something like #157
        ngx.log(ngx.DEBUG, "Not attempting to write log as lua-resty-waf was never exec'd")
        return
    end

    if ctx.altered ~= true and self._event_log_altered_only then
        --_LOG_"Not logging a request that wasn't altered"
        return
    end

    if ctx.log_entries_n == 0 then
        --_LOG_"Not logging a request that had no rule alerts"
        return
    end

    local entry = {
        timestamp = ngx.time(),
        client = ctx.collections["REMOTE_ADDR"],
        method = ctx.collections["METHOD"],
        uri = ctx.collections["URI"],
        alerts = ctx.log_entries,
        id = self.transaction_id,
    }

    if self._event_log_request_arguments then
        entry.uri_args = ctx.collections["URI_ARGS"]
    end

    if self._event_log_request_headers then
        entry.request_headers = ctx.collections["REQUEST_HEADERS"]
    end

    if self._event_log_request_body then
        entry.request_body = ctx.collections["REQUEST_BODY"]
    end

    if #util.table_keys(self._event_log_ngx_vars) ~= 0 then
        entry.ngx = {}
        for k, v in pairs(self._event_log_ngx_vars) do
            entry.ngx[k] = ngx.var[k]
        end
    end

    logger.write_log_events[self._event_log_target](self, entry)
end

return _M

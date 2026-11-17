-- SPDX-License-Identifier: Apache-2.0
--
-- voidgate client for OpenResty (and OpenResty-based gateways such as
-- Kong and APISIX). Talks to the daemon's Unix socket with a non-blocking
-- ngx.socket.tcp cosocket. Cosockets yield, so the methods and M.ban_now()
-- run in rewrite, access, content or timer context; from log,
-- header_filter, body_filter, set, balancer or init_worker use M.ban(),
-- which runs in a timer. Neither works in init_by_lua (the master
-- process). A method called where cosockets are disabled returns
-- nil, err instead of raising.
--
-- Lua cannot install a permanent block: every block needs a ttl. A
-- permanent block is an operator's decision (voidgatectl block <cidr>).
--
-- M.ban() and M.ban_now() use the ban socket, /run/voidgate-ban.sock
-- (group voidgate_ban), which takes only one address's block with a ttl
-- (a network or a block without one is refused). The other
-- methods, through M.new(), use the control socket, /run/voidgate.sock
-- (group voidgate), the whole protocol.

local ngx = ngx

local M = {}
local client = {}
client.__index = client

local MAX_TTL = 31536000    -- one year, as the daemon

-- Keep uint64 counters as strings so LuaJIT does not round them.
local counters = {
    rx_pkts = true, rx_bytes = true, passed = true, dropped = true,
    non_ip = true, map_full = true, parse_err = true, reply_passed = true,
}

-- One command per connection: the daemon replies and closes.
local function request(self, cmd)
    -- ngx_lua raises, rather than returns, where cosockets are disabled.
    local created, sock = pcall(ngx.socket.tcp)
    if not created then
        return nil, "no cosocket in this phase, use ban(): " .. tostring(sock)
    end

    sock:settimeout(self.timeout * 1000)

    local ok, err = sock:connect("unix:" .. self.path)
    if not ok then
        return nil, err
    end

    local data
    ok, err = sock:send(cmd .. "\n")
    if ok then
        data, err = sock:receive("*a")
    end
    sock:close()

    if not data then
        return nil, err
    end
    if data:find("^error") then
        return nil, (data:gsub("\n+$", ""))
    end
    return data
end

local function kv(data)
    local t = {}
    for k, v in data:gmatch("([%w_]+)=(%S+)") do
        if counters[k] then
            t[k] = v
        elseif k == "armed" then
            t[k] = v == "1"
        else
            t[k] = tonumber(v) or v
        end
    end
    return t
end

local function check_ttl(ttl)
    ttl = tonumber(ttl)
    if not ttl or ttl ~= math.floor(ttl) or ttl < 1 or ttl > MAX_TTL then
        return nil
    end
    return ttl
end

function client:status()
    local data, err = request(self, "status")
    if not data then
        return nil, err
    end
    return kv(data)
end

function client:stats()
    local data, err = request(self, "stats")
    if not data then
        return nil, err
    end
    return kv(data)
end

-- Every listed block, oldest first, read page by page: { id, cidr,
-- reason ("manual", "policy", "aggregate", "timed"), inserted, expires }
-- (Unix seconds). expires is a timed block's lift time, else 0: a manual
-- block never expires, a policy or aggregate one ban_time after inserted.
-- A voidgate restarted between pages is an error: its ids start over.
function client:blocks()
    local out, cmd, after, first = {}, "blocks", 0, nil

    while true do
        local data, err = request(self, cmd)
        if not data then
            return nil, err
        end

        local epoch, next_id = data:match("^epoch=(%x+) [^\n]* next=(%S+)\n")
        if not next_id then
            return nil, "unexpected response"
        end
        first = first or epoch
        if epoch ~= first then
            return nil, "voidgate restarted while the blocks were read"
        end

        for line in data:gmatch("\n(id=[^\n]+)") do
            local b = kv(line)
            if not b.cidr then
                return nil, "unexpected response"
            end
            out[#out + 1] = b
        end

        if next_id == "end" then
            return out
        end

        -- ids only grow: a next not past the last one would never end
        local n = tonumber(next_id)
        if not n or n <= after then
            return nil, "unexpected response"
        end
        after = n
        cmd = "blocks after " .. next_id
    end
end

local function commit(self, cmd)
    local data, err = request(self, cmd)
    if not data then
        return nil, err
    end
    if data ~= "ok\n" then
        return nil, "unexpected response"
    end
    return true
end

function client:arm()
    return commit(self, "arm")
end

function client:disarm()
    return commit(self, "disarm")
end

function client:reload()
    return commit(self, "reload")
end

-- Block a prefix for ttl seconds (required, 1 .. one year); the daemon
-- lifts it itself. No ttl is "bad ttl": a permanent block is not for Lua.
function client:block(cidr, ttl)
    if type(cidr) ~= "string" or cidr:find("%s") then
        return nil, "bad cidr"
    end
    ttl = check_ttl(ttl)
    if not ttl then
        return nil, "bad ttl"
    end
    return commit(self, string.format("block %s ttl=%d", cidr, ttl))
end

function client:unblock(cidr)
    if type(cidr) ~= "string" or cidr:find("%s") then
        return nil, "bad cidr"
    end
    return commit(self, "unblock " .. cidr)
end

-- opt: path (default /run/voidgate.sock), timeout in seconds (default 1).
function M.new(opt)
    opt = opt or {}
    return setmetatable({
        path = opt.path or "/run/voidgate.sock",
        timeout = opt.timeout or 1,
    }, client)
end

local default = M.new()
-- ban() and ban_now()'s, unless opt.client is given
local ban_default = M.new({ path = "/run/voidgate-ban.sock" })
for _, name in ipairs({
    "status", "stats", "blocks", "arm", "disarm", "block", "unblock",
    "reload",
}) do
    M[name] = function(...)
        return default[name](default, ...)
    end
end

-- "<ip>/32" or "<ip>/128" for a bare address, else nil.
local function host_cidr(ip)
    if type(ip) ~= "string" or ip == "" or ip:find("[%s/]") then
        return nil
    end
    return ip .. (ip:find(":", 1, true) and "/128" or "/32")
end

local function ban_timer(premature, c, cidr, ttl)
    if premature then
        return
    end

    local ok, err = c:block(cidr, ttl)
    if not ok then
        ngx.log(ngx.ERR, "voidgate: block ", cidr, " ttl=", ttl, ": ", err)
    end
end

-- Ban one client address at XDP for ttl seconds, from any phase but
-- init_by_lua.
-- Returns true once the ban is queued (or was queued within the window);
-- the daemon's answer is logged, not returned. Options:
--   dict    lua_shared_dict name. With it, an address is sent at most once
--           per window, so the burst of requests before XDP takes over
--           does not queue one timer per request. Recommended.
--   window  seconds, default 10.
--   client  a client from M.new(); default /run/voidgate-ban.sock.
-- ip must be the real peer: ngx.var.remote_addr, or the realip module's
-- result only when set_real_ip_from lists your proxies.
function M.ban(ip, ttl, opt)
    opt = opt or {}

    local cidr = host_cidr(ip)
    if not cidr then
        return nil, "bad ip"
    end

    ttl = check_ttl(ttl)
    if not ttl then
        return nil, "bad ttl"
    end

    if opt.dict then
        local dict = ngx.shared[opt.dict]
        if not dict then
            return nil, "no lua_shared_dict " .. opt.dict
        end

        local ok, err = dict:add(cidr, true, opt.window or 10)
        if not ok then
            if err == "exists" then
                return true
            end
            return nil, err
        end
    end

    return ngx.timer.at(0, ban_timer, opt.client or ban_default, cidr, ttl)
end

-- Ban one client address for ttl seconds now and return the daemon's
-- answer: true, or nil, err (refused, bad input, daemon down, or a phase
-- without cosockets). Same ip and ttl rules as M.ban(), no deduplication.
-- Only where cosockets work (rewrite, access, content, timers); elsewhere
-- use M.ban(). opt.client: a client from M.new(); default
-- /run/voidgate-ban.sock.
function M.ban_now(ip, ttl, opt)
    local cidr = host_cidr(ip)
    if not cidr then
        return nil, "bad ip"
    end
    return ((opt and opt.client) or ban_default):block(cidr, ttl)
end

return M

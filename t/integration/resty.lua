-- SPDX-License-Identifier: Apache-2.0
-- Client methods against a real daemon. Run by resty.sh as a content
-- handler; prints TAP. ngx.var.vg_conf is the daemon's config file.

local vg = require("resty.voidgate")
local n = 0

local function ok(cond, name)
    n = n + 1
    ngx.say((cond and "ok " or "not ok ") .. n .. " - " .. name)
end

local conn = vg.new({ timeout = 0.5 })
local pass, err

local status = conn:status()
ok(status and status.state == "idle" and status.armed == false
    and status.iface == "test0", "idle status")
ok(type(status.rx_pps) == "number" and status.blocked == 0,
    "idle counters")
ok(conn:arm() and conn:status().armed == true, "arm")
ok(conn:disarm() and conn:status().armed == false, "disarm")
local stats = conn:stats()
ok(stats and type(stats.rx_pkts) == "string" and stats.rx_pkts:match("^%d+$")
    and stats.dropped == "0" and type(stats.reply_passed) == "string"
    and stats.state == nil and stats.rx_pps == nil,
    "stats: the counters only")

ok(#assert(conn:blocks()) == 0, "empty blocks")
ok(conn:block("203.0.113.0/24", 60), "block v4")
local blocks = conn:blocks()
ok(blocks and #blocks == 1 and blocks[1].cidr == "203.0.113.0/24"
    and blocks[1].reason == "timed" and blocks[1].id >= 1
    and blocks[1].inserted > 0 and blocks[1].expires > blocks[1].inserted,
    "list v4 block")
ok(conn:unblock("203.0.113.0/24") and #assert(conn:blocks()) == 0, "unblock v4")
ok(conn:block("2001:db8::/64", 60)
    and conn:blocks()[1].cidr == "2001:db8::/64", "block v6")
ok(conn:unblock("2001:db8::/64"), "unblock v6")
pass, err = conn:block("bad-cidr", 60)
ok(pass == nil and err == "error: bad cidr", "reject bad cidr")
ok(conn:block() == nil and conn:block(123) == nil and conn:block("a b") == nil
    and conn:block("203.0.113.0/24\narm") == nil, "block rejects locally")
ok(conn:block("203.0.113.0/24", 60) and conn:block("2001:db8::/64", 60)
    and conn:disarm() and #assert(conn:blocks()) == 0
    and conn:status().armed == false, "disarm clears blocks")

ok(conn:block("203.0.113.9/32", 60) and conn:blocks()[1].reason == "timed"
    and conn:status().armed == true, "ttl block")
ok(conn:disarm(), "disarm after ttl block")

-- No permanent block from Lua: a missing ttl is refused before sending.
pass, err = conn:block("203.0.113.9/32")
ok(pass == nil and err == "bad ttl" and #assert(conn:blocks()) == 0
    and conn:status().armed == false, "block without ttl refused locally")

-- ban_now: a bare ip, a required ttl, the daemon's answer returned.
ok(vg.ban_now("203.0.113.10", 60) and conn:blocks()[1].cidr
    == "203.0.113.10/32" and conn:blocks()[1].reason == "timed", "ban_now v4")
ok(vg.ban_now("2001:db8::10", 60, { client = conn }), "ban_now v6")
pass, err = vg.ban_now("127.0.0.1", 60)
ok(pass == nil and err == "error: refused or map update failed",
    "ban_now returns the refusal")
ok(vg.ban_now("203.0.113.0/24", 60) == nil
    and select(2, vg.ban_now("203.0.113.0/24", 60)) == "bad ip"
    and select(2, vg.ban_now("203.0.113.11")) == "bad ttl"
    and #assert(conn:blocks()) == 2, "ban_now rejects locally")
ok(conn:disarm(), "disarm after ban_now")

-- the ban socket, which ban() and ban_now() use, takes one address's block
-- with a ttl and nothing else
local banc = vg.new({ path = "/run/voidgate-ban.sock", timeout = 0.5 })
pass, err = banc:disarm()
ok(pass == nil and err:find("^error: denied"), "ban socket: no disarm")
pass, err = banc:status()
ok(pass == nil and err:find("^error: denied"), "ban socket: no status")
ok(banc:block("203.0.113.12/32", 60), "ban socket: a block with a ttl")
pass, err = banc:block("203.0.113.0/24", 60)
ok(pass == nil and err:find("^error: denied"), "ban socket: no network")
ok(conn:disarm(), "disarm after the ban socket")
for _, ttl in ipairs({ 0, -1, 1.5, "x", 31536001 }) do
    pass, err = conn:block("203.0.113.9/32", ttl)
    ok(pass == nil and err == "bad ttl", "reject ttl " .. tostring(ttl))
end

local config_path = ngx.var.vg_conf
local file = assert(io.open(config_path, "r"))
local config = file:read("*a")
file:close()
local function write_config(contents)
    local output = assert(io.open(config_path, "w"))
    assert(output:write(contents))
    assert(output:close())
end
write_config(config .. "allow_networks = 203.0.113.0/24,2001:db8::/64\n")
ok(conn:reload(), "reload allow_networks")
for _, cidr in ipairs({ "203.0.113.1/32", "2001:db8::1/128" }) do
    pass, err = conn:block(cidr, 60)
    ok(pass == nil and err == "error: refused or map update failed",
        "refuse block of " .. cidr)
end
write_config(config .. "wake_pps = invalid\n")
pass, err = conn:reload()
ok(pass == nil and err == "error: reload failed", "reload invalid config")
write_config(config)
ok(conn:reload() and conn:block("203.0.113.1/32", 60)
    and conn:block("2001:db8::1/128", 60) and conn:disarm(), "reload restored")

local missing = vg.new({ path = "/run/voidgate.sock.missing" })
pass, err = missing:status()
ok(pass == nil and type(err) == "string", "missing socket")

ngx.say("1.." .. n)

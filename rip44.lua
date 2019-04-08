#!/usr/bin/lua
-- Basic RIP44-LUA Implementation. (Ver: Alpha)
-- Does minimal error checking and tries to keep going on failure.
-- Does not support RIPv2 any more than required to handle the packets sent by the main AMRPNet gateway.
-- If you are not a 44/8 gateway operator, this is useless to you. Use a proper routing protocol.

dofile("/etc/rip44.conf")

if CONFIGURE_NETWORK then
    -- these commands should get basic source routing working
    -- it has a go at cleaning up and ignores errors, in case everything is already configured

    -- packets to the local subnet use the normal routing table
    os.execute("ip rule del to " .. LOCAL_SUBNET .. " table main priority 20 >/dev/null 2>&1")
    os.execute("ip rule add to " .. LOCAL_SUBNET .. " table main priority 20")
    -- packets from the local subnet that didn't find a route above will use table ROUTING_TABLE
    os.execute("ip rule del from " .. LOCAL_SUBNET .. " table " .. ROUTING_TABLE .. " priority 25 >/dev/null 2>&1")
    os.execute("ip rule add from " .. LOCAL_SUBNET .. " table " .. ROUTING_TABLE .. " priority 25")
    -- bring up interface
    os.execute("ip tun del tunl0  >/dev/null 2>&1")
    os.execute("ip tun add tunl0 mode ipip")
    os.execute("ip link set dev tunl0 down >/dev/null 2>&1")
    os.execute("ip tun change tunl0 pmtudisc ttl 64 mode ipip")
    os.execute("ip link set dev tunl0 up")
    -- this is an ugly hack to work around the luasock requirement that there be a dedicated IP for the listening interface
    -- (why can't I get multicast without specifying an interface by IP address? am i missing something?)
    -- if there is already an IP configured these will be secondary IPs so should not impact anything
    -- if there is not, it will configure the network address on the interface, and also the multicast address so it can be used as the socket target interface
    os.execute("ip addr add " .. LOCAL_SUBNET .. " dev tunl0")
    os.execute("ip addr add " .. LISTEN_IP .. "/32 dev tunl0")
    if DEFAULT_GATEWAY then os.execute("ip route replace default via " .. DEFAULT_GATEWAY .. " onlink dev tunl0 table " .. ROUTING_TABLE) end
end

-- this seemed nicer than bitshift loops
local netmask_conversion_table = {}
netmask_conversion_table["255.255.255.255"]=32
netmask_conversion_table["255.255.255.254"]=31
netmask_conversion_table["255.255.255.252"]=30
netmask_conversion_table["255.255.255.248"]=29
netmask_conversion_table["255.255.255.240"]=28
netmask_conversion_table["255.255.255.224"]=27
netmask_conversion_table["255.255.255.192"]=26
netmask_conversion_table["255.255.255.128"]=25
netmask_conversion_table["255.255.255.0"]=24
netmask_conversion_table["255.255.254.0"]=23
netmask_conversion_table["255.255.252.0"]=22
netmask_conversion_table["255.255.248.0"]=21
netmask_conversion_table["255.255.240.0"]=20
netmask_conversion_table["255.255.224.0"]=19
netmask_conversion_table["255.255.192.0"]=18
netmask_conversion_table["255.255.128.0"]=17
netmask_conversion_table["255.255.0.0"]=16
netmask_conversion_table["255.254.0.0"]=15
netmask_conversion_table["255.252.0.0"]=14
netmask_conversion_table["255.248.0.0"]=13
netmask_conversion_table["255.240.0.0"]=12
netmask_conversion_table["255.224.0.0"]=11
netmask_conversion_table["255.192.0.0"]=10
netmask_conversion_table["255.128.0.0"]=9
netmask_conversion_table["255.0.0.0"]=8

local routing_table = {}
function garbage_collect()
    for prefix, route in pairs(routing_table) do
        if os.time() - route['timestamp'] > ROUTE_EXPIRE_TIME then
            if DEBUG then print("Expire", prefix) end
            os.execute("ip route del " .. prefix .. " via " .. route['gateway'] .. " onlink dev tunl0 table " .. ROUTING_TABLE)
            routing_table[prefix] = nil
        end
    end
end

function process_route(network, netmask, gateway)
    if network:sub(1,3) == "44." and netmask_conversion_table[netmask] then
        local prefix = network .. "/" .. netmask_conversion_table[netmask]
        if not routing_table[prefix] or routing_table[prefix]['gateway'] ~= gateway then
            if DEBUG then print("Added route.", prefix .. " via " .. gateway) end
            os.execute("ip route replace " .. prefix .. " via " .. gateway .. " onlink dev tunl0 table " .. ROUTING_TABLE)
            routing_table[prefix] = {
                        network=network,
                        netmask=netmask,
                        gateway=gateway,
                        timestamp=os.time()
                }
            return true
        else
            routing_table[prefix]['timestamp']=os.time()
            if DEBUG then print("Route Refresh.", network, netmask, gateway) end
        end
    else
        print("Invalid Route.", network, netmask, gateway)
    end
    return false
end

function save_routes()
    file = io.open(SAVE_FILE, "w")
    if not file then print("Error opening route file.", SAVE_FILE) return end
    if RIP_PASSWORD then file:write("PASSWD\t" .. RIP_PASSWORD .. "\n") end
    for prefix, route in pairs(routing_table) do
        if DEBUG then print("Save", route['network'] .. "\t" .. route['netmask'] .. "\t" .. route['gateway']) end
        file:write("ROUTE\t" .. route['network'] .. "\t" .. route['netmask'] .. "\t" .. route['gateway'] .. "\n")
    end
    file:close()
    print(os.date(), "Saved routes.")
end

-- Compatibility: Lua-5.1
function split(str, pat)
   local t = {}  -- NOTE: use {n = 0} in Lua-5.0
   local fpat = "(.-)" .. pat
   local last_end = 1
   local s, e, cap = str:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
         table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
   end
   if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
   end
   return t
end

function load_routes()
    if not os.rename(SAVE_FILE,SAVE_FILE) then print("Unable to load " .. SAVE_FILE) return end 
    local done, count = 0,0
    for line in io.lines(SAVE_FILE) do
        local row = split(line, "\t")
        if row[1] == "PASSWD" and not RIP_PASSWORD then
            RIP_PASSWORD = row[2]
            print("Loaded password.", RIP_PASSWORD)
        elseif row[1] == "ROUTE" then
            count = count + 1
            if process_route(row[2], row[3], row[4]) then
                done = done + 1
            end
        end
    end
    print ("Loaded " .. count .. " routes from " .. SAVE_FILE .. ".")
end

load_routes()

local socket_module = require "socket"
local udp = socket_module.udp()
assert(udp:settimeout(5))
udp:setoption("reuseport", true)
assert(udp:setsockname("*", 520))
assert(udp:setoption("ip-multicast-loop", false))
assert(udp:setoption("ip-multicast-if", LISTEN_IP))
assert(udp:setoption("ip-add-membership", {multiaddr = LISTEN_IP, interface = LISTEN_IP}))
local SAVE_DELAY = 5

local gc_time = os.time()
local save_time = 0

while 1 do
    if os.time() - gc_time >= GC_INTERVAL then garbage_collect() gc_time = os.time() end
    if save_time ~= 0 and os.time() - save_time >= SAVE_DELAY then save_routes() save_time = 0 end

    dgram, ip, port = udp:receivefrom()
    if ip == "44.0.0.1" and port == 520 then
        if dgram:byte(1) == 2 and dgram:byte(2) == 2 and dgram:byte(3) == 0 and dgram:byte(4) == 0 then
            dgram = dgram:sub(5)
            if dgram:byte(1) == 255 and dgram:byte(2) == 255 and dgram:byte(3) == 0 and dgram:byte(4) == 2 then
                dgram = dgram:sub(5)
                local recvdPassword = dgram:sub(1, dgram:find("\0") - 1)
                if not RIP_PASSWORD then
                    RIP_PASSWORD = recvdPassword
                    print(os.date(), ip..":"..port, "Received Password.", recvdPassword)
                end
                if recvdPassword == RIP_PASSWORD then
                    local done, count = 0,0
                    dgram = dgram:sub(RIP_PASSWORD:len()+2)
                    while dgram:byte(1) == 0 and dgram:byte(2) == 2 and dgram:byte(3) == 0 and dgram:byte(4) == 4 do
                        local network = string.format("%d.%d.%d.%d", dgram:byte(5), dgram:byte(6), dgram:byte(7), dgram:byte(8))
                        local netmask = string.format("%d.%d.%d.%d", dgram:byte(9), dgram:byte(10), dgram:byte(11), dgram:byte(12))
                        local gateway = string.format("%d.%d.%d.%d", dgram:byte(13), dgram:byte(14), dgram:byte(15), dgram:byte(16))
                        if process_route(network, netmask, gateway) then
                            save_time = os.time()
                            done = done + 1
                        end
                        count = count + 1
                        dgram = dgram:sub(21)
                    end
                    print(os.date(), ip..":"..port, done .."/" .. count .. " updates processed.")
                else
                    print(os.date(), ip..":"..port, "Received incorrect password.", recvdPassword)
                end
            else
                print(os.date(), ip..":"..port, "No password.")
            end
        else
            print(os.date(), ip..":"..port, "Not RIPv2 Packet.")
        end
    elseif ip ~= "timeout" then
        print(os.date(), ip..":"..port, "Rejected packet.")
    end
end

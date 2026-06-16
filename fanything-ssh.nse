local base64 = require "base64"
local match = require "match"
local nmap = require "nmap"
local openssl = require "openssl"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts FAN/1 fingerprints from live SSH services.

The output mirrors fanfp.py fields: mode, protocol, role, fingerprint, features,
sha256, and flow. The probe sends an SSH identification string, reads the server
identification string and SSH_MSG_KEXINIT when available, then emits the SSH
peer canonical feature string used by fanfp.py.
]]

---
-- @usage
-- nmap -sV --script ./fanything-ssh.nse <target>
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | fanything-ssh:
-- |   protocol: ssh
-- |   role: peer
-- |   fingerprint: fan1:ssh:peer:active:...
-- |   features: ssh|peer|id=OpenSSH_9.6|kex=...
-- |   sha256: ...
-- |   flow:
-- |     src: 192.0.2.10
-- |     sport: 22
-- |     dst: 198.51.100.5
-- |_    dport: 51234
--
-- @args fanything-ssh.timeout Socket timeout in milliseconds. Default: 5000.
-- @args fanything-ssh.client-id SSH client identification string. Default:
-- SSH-2.0-Nmap-FANFP.
-- @args fanything-ssh.force Run on any open TCP port. Useful for tests on high
-- local ports.

author = "FAN/1 contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local SSH_MSG_KEXINIT = 20

portrule = function(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then
    return false
  end
  if stdnse.get_script_args(SCRIPT_NAME .. ".force") then
    return true
  end
  return shortport.port_or_service(22, "ssh", "tcp", "open")(host, port)
end

local function timeout()
  return tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5000
end

local function client_id()
  local value = stdnse.get_script_args(SCRIPT_NAME .. ".client-id") or "SSH-2.0-Nmap-FANFP"
  return (value:gsub("[\r\n]", ""))
end

local function base64url(s)
  return (base64.enc(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

local function fan1(protocol, role, mode, features)
  local digest = stdnse.tohex(openssl.digest("sha256", features))
  return ("fan1:%s:%s:%s:%s:sha256:%s"):format(protocol, role, mode, base64url(features), digest), digest
end

local function socket_flow(sock, fallback_host, fallback_port)
  local flow = {
    src = fallback_host and fallback_host.ip or "",
    sport = fallback_port and fallback_port.number or "",
    dst = "",
    dport = "",
  }

  local ok, lhost, lport, rhost, rport = pcall(function()
    local status, local_host, local_port, remote_host, remote_port = sock:get_info()
    if not status then return nil end
    return local_host, local_port, remote_host, remote_port
  end)
  if ok and lhost then
    flow.src = rhost or flow.src
    flow.sport = rport or flow.sport
    flow.dst = lhost or ""
    flow.dport = lport or ""
  end

  return flow
end

local function empty_ssh_features(software)
  return ("ssh|peer|id=%s|kex=|hostkey=|enc_c2s=|enc_s2c=|mac_c2s=|mac_s2c="
      .. "|comp_c2s=|comp_s2c=|lang_c2s=|lang_s2c=|follows="):format(software)
end

local function ssh_name_list(packet, i)
  if i + 3 > #packet then return nil end
  local len = packet:byte(i) * 16777216 + packet:byte(i + 1) * 65536
      + packet:byte(i + 2) * 256 + packet:byte(i + 3)
  i = i + 4
  if i + len - 1 > #packet then return nil end
  return packet:sub(i, i + len - 1), i + len
end

local function parse_ssh_kexinit(packet)
  if not packet or #packet < 18 or packet:byte(1) ~= SSH_MSG_KEXINIT then return nil end
  local i = 18
  local names = {
    "kex", "hostkey", "enc_c2s", "enc_s2c", "mac_c2s", "mac_s2c",
    "comp_c2s", "comp_s2c", "lang_c2s", "lang_s2c"
  }
  local values = {}
  for _, name in ipairs(names) do
    values[name], i = ssh_name_list(packet, i)
    if not values[name] then return nil end
  end
  values.follows = i <= #packet and (packet:byte(i) ~= 0 and "True" or "False") or ""
  return values
end

local function ssh_packet_payload(raw)
  if not raw or #raw < 6 then return nil end
  local packet_len = raw:byte(1) * 16777216 + raw:byte(2) * 65536
      + raw:byte(3) * 256 + raw:byte(4)
  local pad_len = raw:byte(5)
  if packet_len + 4 > #raw or packet_len <= pad_len + 1 then return nil end
  return raw:sub(6, 4 + packet_len - pad_len)
end

local function read_ssh_banner(sock)
  for _ = 1, 20 do
    local ok, line = sock:receive_buf(match.pattern_limit("\n", 512), true)
    if not ok then return nil end
    local banner = line:match("^(SSH%-[^\r\n]+)")
    if banner then return banner end
  end
  return nil
end

local function full_ssh_features(software, k)
  return ("ssh|peer|id=%s|kex=%s|hostkey=%s|enc_c2s=%s|enc_s2c=%s"
      .. "|mac_c2s=%s|mac_s2c=%s|comp_c2s=%s|comp_s2c=%s"
      .. "|lang_c2s=%s|lang_s2c=%s|follows=%s"):format(
      software, k.kex, k.hostkey, k.enc_c2s, k.enc_s2c,
      k.mac_c2s, k.mac_s2c, k.comp_c2s, k.comp_s2c,
      k.lang_c2s, k.lang_s2c, k.follows)
end

local function get_ssh_features(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout())
  if not sock:connect(host, port) then return nil end
  local flow = socket_flow(sock, host, port)

  local status = sock:send(client_id() .. "\r\n")
  if not status then sock:close(); return nil end

  local banner = read_ssh_banner(sock)
  if not banner then sock:close(); return nil end
  local software = banner:match("^SSH%-%S+%-(.+)$") or banner

  local ok, data = sock:receive_buf(function(buf)
    if #buf < 4 then return nil end
    local len = buf:byte(1) * 16777216 + buf:byte(2) * 65536
        + buf:byte(3) * 256 + buf:byte(4)
    if #buf < len + 4 then return nil end
    return len + 4, len + 4
  end, true)
  sock:close()

  if not ok then return empty_ssh_features(software), flow end
  local k = parse_ssh_kexinit(ssh_packet_payload(data))
  if not k then return empty_ssh_features(software), flow end
  return full_ssh_features(software, k), flow
end

local function result(protocol, role, features, flow)
  local mode = "active"
  local fingerprint, digest = fan1(protocol, role, mode, features)
  return {
    mode = mode,
    protocol = protocol,
    role = role,
    fingerprint = fingerprint,
    features = features,
    sha256 = digest,
    flow = flow,
  }
end

action = function(host, port)
  local features, fp_flow = get_ssh_features(host, port)
  if not features then return nil end
  return result("ssh", "peer", features, fp_flow)
end

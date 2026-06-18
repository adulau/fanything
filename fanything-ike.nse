local base64 = require "base64"
local nmap = require "nmap"
local openssl = require "openssl"
local rand = require "rand"
local shortport = require "shortport"
local stdnse = require "stdnse"
local table = require "table"

description = [[
Extracts FAN/1 fingerprints from live IKEv2 services.

The output mirrors fanfp.py fields: mode, protocol, role, fingerprint, features,
sha256, and flow. The probe sends an IKEv2 IKE_SA_INIT request on UDP/500 or
UDP/4500, then fingerprints the responder header and payload sequence.
]]

---
-- @usage
-- nmap -sU -p500,4500 --script ./fanything-ike.nse <target>
--
-- @output
-- PORT    STATE SERVICE
-- 500/udp open  isakmp
-- | fanything-ike:
-- |   protocol: ike
-- |   role: responder
-- |   fingerprint: fan1:ike:responder:active:...
-- |   features: ike|responder|v=2.0|ex=34|flags=32|np=33|p=33-34-40|sa=1:1=12.256,2=5,3=12,4=14|ke=14|n=
-- |   sha256: ...
-- |   flow:
-- |     src: 192.0.2.10
-- |     sport: 500
-- |     dst: 198.51.100.5
-- |_    dport: 53539
--
-- @args fanything-ike.timeout Socket timeout in milliseconds. Default: 5000.
-- @args fanything-ike.force Run on any open UDP port. Useful for tests on high
-- local ports.

author = "FAN/1 contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local IKEV2_SA = 33
local IKEV2_KE = 34
local IKEV2_NONCE = 40
local IKEV2_NOTIFY = 41
local IKEV2_IKE_SA_INIT = 34
local IKEV2_INITIATOR = 0x08

portrule = function(host, port)
  if port.protocol ~= "udp" or port.state == "closed" then
    return false
  end
  if stdnse.get_script_args(SCRIPT_NAME .. ".force") then
    return true
  end
  return shortport.port_or_service({500, 4500}, {"isakmp", "ipsec-nat-t"}, "udp")(host, port)
end

local function timeout()
  return tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5000
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

local function u16(s, i)
  local a, b = s:byte(i, i + 1)
  if not a or not b then return nil end
  return a * 256 + b
end

local function u32(s, i)
  local a, b, c, d = s:byte(i, i + 3)
  if not a or not b or not c or not d then return nil end
  return ((a * 256 + b) * 256 + c) * 256 + d
end

local function join(values)
  return table.concat(values, "-")
end

local function payload(next_payload, body)
  return string.char(next_payload, 0) .. string.pack(">I2", #body + 4) .. body
end

local function transform(next_type, transform_type, transform_id, attrs)
  attrs = attrs or ""
  local body = string.char(next_type, 0) .. string.pack(">I2BBI2", 8 + #attrs, transform_type, 0, transform_id) .. attrs
  return body
end

local function key_length_attr(bits)
  return string.pack(">I2I2", 0x800e, bits)
end

local function proposal(next_type, proposal_num, transforms, transform_count)
  local proposal_len = 8 + #transforms
  return string.char(next_type, 0) .. string.pack(">I2BBBB", proposal_len, proposal_num, 1, 0, transform_count) .. transforms
end

local function transforms(items)
  local out = {}
  for i, item in ipairs(items) do
    local next_type = i < #items and 3 or 0
    out[#out + 1] = transform(next_type, item[1], item[2], item[3])
  end
  return table.concat(out)
end

local function build_sa_body()
  local proposals = {
    proposal(2, 1, transforms({
      {1, 12, key_length_attr(256)}, -- AES-CBC-256
      {2, 5},                        -- PRF_HMAC_SHA2_256
      {3, 12},                       -- AUTH_HMAC_SHA2_256_128
      {4, 14},                       -- MODP 2048
    }), 4),
    proposal(2, 2, transforms({
      {1, 12, key_length_attr(128)}, -- AES-CBC-128
      {2, 2},                        -- PRF_HMAC_SHA1
      {3, 2},                        -- AUTH_HMAC_SHA1_96
      {4, 14},                       -- MODP 2048
    }), 4),
    proposal(0, 3, transforms({
      {1, 20, key_length_attr(256)}, -- AES-GCM-16-256
      {2, 5},                        -- PRF_HMAC_SHA2_256
      {4, 14},                       -- MODP 2048
    }), 3),
  }
  return table.concat(proposals)
end

local function build_ke_body()
  return string.pack(">I2I2", 14, 0) .. string.rep("\0", 255) .. "\4"
end

local function build_probe(spi)
  local sa = payload(IKEV2_KE, build_sa_body())
  local ke = payload(IKEV2_NONCE, build_ke_body())
  local nonce = payload(0, rand.random_string(32))
  local body = sa .. ke .. nonce
  local len = 28 + #body
  return spi .. string.rep("\0", 8) .. string.char(IKEV2_SA, 0x20, IKEV2_IKE_SA_INIT, IKEV2_INITIATOR)
      .. string.pack(">I4I4", 0, len) .. body
end

local function parse_sa_payload(body)
  local proposals, i = {}, 1
  while i + 7 <= #body do
    local proposal_len = u16(body, i + 2)
    if not proposal_len or proposal_len < 8 or i + proposal_len - 1 > #body then break end

    local proposal_num = body:byte(i + 4)
    local protocol_id = body:byte(i + 5)
    local spi_size = body:byte(i + 6)
    local num_transforms = body:byte(i + 7)
    local ti = i + 8 + spi_size
    local transforms = {}

    for _ = 1, num_transforms do
      if ti + 7 > i + proposal_len - 1 then break end
      local transform_len = u16(body, ti + 2)
      local transform_type = body:byte(ti + 4)
      local transform_id = u16(body, ti + 6)
      if not transform_len or transform_len < 8 or ti + transform_len - 1 > i + proposal_len - 1 then break end

      local value = tostring(transform_type or "") .. "=" .. tostring(transform_id or "")
      local ai = ti + 8
      while ai + 3 <= ti + transform_len - 1 do
        local attr_type = u16(body, ai)
        local attr_value = u16(body, ai + 2)
        if attr_type == 0x800e and attr_value then
          value = value .. "." .. tostring(attr_value)
        end
        ai = ai + 4
      end
      transforms[#transforms + 1] = value
      ti = ti + transform_len
    end

    proposals[#proposals + 1] = ("%d:%s"):format(protocol_id or proposal_num or 0, table.concat(transforms, ","))
    i = i + proposal_len
  end
  return table.concat(proposals, ";")
end

local function parse_response(packet)
  if #packet >= 4 and packet:sub(1, 4) == "\0\0\0\0" then
    packet = packet:sub(5)
  end
  if #packet < 28 then return nil end

  local next_payload = packet:byte(17)
  local version = packet:byte(18)
  local exchange_type = packet:byte(19)
  local flags = packet:byte(20)
  local total_len = u32(packet, 25) or #packet
  local major = version >> 4
  local minor = version & 0x0f
  local offset = 29
  local payloads, notify_types = {}, {}
  local sa, ke_group = "", ""

  while next_payload ~= 0 and offset + 3 <= #packet and offset <= total_len do
    local current = next_payload
    local this_next = packet:byte(offset)
    local payload_len = u16(packet, offset + 2)
    if not payload_len or payload_len < 4 or offset + payload_len - 1 > #packet then break end
    local body = packet:sub(offset + 4, offset + payload_len - 1)

    payloads[#payloads + 1] = tostring(current)
    if current == IKEV2_SA then
      sa = parse_sa_payload(body)
    elseif current == IKEV2_KE and #body >= 4 then
      ke_group = tostring(u16(body, 1) or "")
    elseif current == IKEV2_NOTIFY and #body >= 4 then
      local ntype = u16(body, 3)
      if ntype then notify_types[#notify_types + 1] = tostring(ntype) end
    end

    next_payload = this_next
    offset = offset + payload_len
  end

  if #payloads == 1 and payloads[1] == tostring(IKEV2_NOTIFY) then
    for _, notify_type in ipairs(notify_types) do
      if notify_type == "7" or notify_type == "14" then
        return nil
      end
    end
  end

  return ("ike|responder|v=%d.%d|ex=%d|flags=%d|np=%d|p=%s|sa=%s|ke=%s|n=%s"):format(
    major, minor, exchange_type, flags, packet:byte(17), join(payloads), sa, ke_group, join(notify_types))
end

local function get_ike_features(host, port)
  local sock = nmap.new_socket("udp")
  sock:set_timeout(timeout())
  if not sock:connect(host, port) then return nil end

  local spi = rand.random_string(8)
  local marker = port.number == 4500 and string.rep("\0", 4) or ""
  local status = sock:send(marker .. build_probe(spi))
  if not status then sock:close(); return nil end
  local flow = socket_flow(sock, host, port)

  local ok, data = sock:receive()
  sock:close()
  if not ok or not data then return nil end

  local features = parse_response(data)
  if not features then return nil end
  return features, flow
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
  local features, fp_flow = get_ike_features(host, port)
  if not features then return nil end
  nmap.set_port_state(host, port, "open")
  return result("ike", "responder", features, fp_flow)
end

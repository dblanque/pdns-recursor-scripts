-- ip-translate.lua - Should work for both IPv4 and IPv6
require "ip-helpers"

function translate_ip(ip, src_cidr, dst_cidr)
    local function parse_cidr(cidr)
        local net, bits = cidr:match("([^/]+)/?(%d*)")
        if not net then return nil, "Invalid CIDR: " .. cidr end
        bits = tonumber(bits)
        if not bits then
            bits = net:find(":") and 128 or 32
        else
            bits = tonumber(bits)
        end
        return net, bits
    end

    local src_net, src_bits = parse_cidr(src_cidr)
    local dst_net, dst_bits = parse_cidr(dst_cidr)

    if not src_net then return nil, src_bits end
    if not dst_net then return nil, dst_bits end

    -- Use IPv6 logic if either is IPv6
    if ip:find(":") or src_net:find(":") or dst_net:find(":") then
        return translate_ipv6(ip, src_net, src_bits, dst_net, dst_bits)
    else
        return translate_ipv4(ip, src_net, src_bits, dst_net, dst_bits)
    end
end

function translate_ipv4(ip, src_net, src_bits, dst_net, dst_bits)
    local function ip_to_int(ip)
        local a, b, c, d = ip:match("(%d+)%.(%d+)%.(%d+)%.(%d+)")
        if not a then return nil end
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a > 255 or b > 255 or c > 255 or d > 255 then return nil end
        return a * 16777216 + b * 65536 + c * 256 + d
    end

    local function int_to_ip(n)
        return string.format("%d.%d.%d.%d", math.floor(n / 16777216),
                             math.floor((n % 16777216) / 65536),
                             math.floor((n % 65536) / 256), n % 256)
    end

    local ip_int = ip_to_int(ip)
    local src_int = ip_to_int(src_net)
    local dst_int = ip_to_int(dst_net)

    if not ip_int or not src_int or not dst_int then
        return nil, "Invalid IPv4 address"
    end

    if src_bits ~= dst_bits then return nil, "Prefix lengths must match" end

    local host_bits = 32 - src_bits
    local host_mask = (2 ^ host_bits) - 1 -- This replaces (1 << host_bits) - 1

    local host_offset = ip_int % (2 ^ host_bits) -- Same as bit32.band(ip_int, host_mask)
    local network_prefix = dst_int - (dst_int % (2 ^ host_bits)) -- Clear host bits

    local result = network_prefix + host_offset

    return int_to_ip(result)
end

function translate_ipv6(ip, src_cidr, dst_cidr)
  local function parse_cidr(cidr)
    local net, bits = cidr:match("([^/]+)/?(%d*)")
    bits = tonumber(bits) or (net:find(":") and 128 or 32)
    return net, bits
  end

  local src_net, src_bits = parse_cidr(src_cidr)
  local dst_net, dst_bits = parse_cidr(dst_cidr)

  if src_bits ~= dst_bits then
    return nil, "Prefix lengths must match"
  end

  -- Expand and parse
  local ip_parts = ipv6_expand(ip)
  local src_parts = ipv6_expand(src_net)
  local dst_parts = ipv6_expand(dst_net)

  if not ip_parts or not src_parts or not dst_parts then
    return nil, "Invalid IPv6 address"
  end

  local total_bits = 128
  local host_bits = total_bits - dst_bits
  local result_parts = {}

  local bits_left = dst_bits  -- How many network bits remain

  for i = 1, 8 do
    local group = 0  -- 16-bit group
    if bits_left <= 0 then
      -- Entire group is host part -> take from original IP
      group = ip_parts[i]
    else
      -- This group is partially or fully in network part
      local bits_in_group = math.min(16, bits_left)

      -- Network bits: take from dst_net
      local network_mask = 2^(16 - bits_in_group) - 1  -- e.g., /12 -> top 4 bits are network
      local network_part = bit_and(dst_parts[i], (0xFFFF - network_mask))

      -- Host bits: take from IP
      local host_mask = network_mask
      local host_part = bit_and(ip_parts[i], host_mask)

      group = network_part + host_part
    end
    table.insert(result_parts, group)
    bits_left = bits_left - 16
  end

  -- Convert back to hex string
  return ipv6_compress(table.concat(result_parts, ":"))
end

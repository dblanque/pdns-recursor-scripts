-- translate_ip.lua - Works for both IPv4 and IPv6

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

function translate_ip(ip, src_cidr, dst_cidr)
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
    return (a << 24) + (b << 16) + (c << 8) + d
  end

  local function int_to_ip(n)
    return string.format("%d.%d.%d.%d",
      (n >> 24) & 0xFF,
      (n >> 16) & 0xFF,
      (n >> 8) & 0xFF,
      n & 0xFF
    )
  end

  local ip_int = ip_to_int(ip)
  local src_int = ip_to_int(src_net)
  local dst_int = ip_to_int(dst_net)

  if not ip_int or not src_int or not dst_int then
    return nil, "Invalid IPv4 address"
  end

  if src_bits ~= dst_bits then
    return nil, "IPv4: Source and destination prefix lengths must match"
  end

  local host_bits = 32 - src_bits
  local host_mask = host_bits == 32 and 0xFFFFFFFF or ((1 << host_bits) - 1)

  local host_offset = bit32.band(ip_int, host_mask)
  local new_network = bit32.band(dst_int, bit32.bnot(host_mask))
  local result = bit32.bor(new_network, host_offset)

  return int_to_ip(result)
end

function translate_ipv6(ip, src_net, src_bits, dst_net, dst_bits)
  local function expand_ipv6(ip)
    ip = ip:gsub("::", ":" .. string.rep("0:", 9 - select(2, ip:gsub(":", ""))) ):gsub("^:", "0:"):gsub(":$", "")
    local parts = {}
    for part in ip:gmatch("[^:]+") do
      table.insert(parts, tonumber(part, 16))
    end
    while #parts < 8 do
      table.insert(parts, 0)
    end
    return parts  -- 8-element array of 16-bit integers
  end

  local ip_parts = expand_ipv6(ip)
  local src_parts = expand_ipv6(src_net)
  local dst_parts = expand_ipv6(dst_net)

  -- Total bits: 128
  local host_bits = 128 - dst_bits
  if src_bits ~= dst_bits then
    return nil, "IPv6: Source and destination prefix lengths must match"
  end

  local result = {}
  local bits_remaining = dst_bits

  -- Copy full 16-bit chunks from dst_net while we're in network part
  for i = 1, 8 do
    local bits_in_chunk = math.min(16, bits_remaining)
    if bits_in_chunk <= 0 then
      -- Host part: use offset from original IP
      result[i] = ip_parts[i]
    else
      -- Network part: use dst_net
      if bits_in_chunk == 16 then
        result[i] = dst_parts[i]
      else
        -- Partial chunk: mix dst_net (network) and ip (host)
        local mask = 0xFFFF << (16 - bits_in_chunk)
        mask = bit32.band(mask, 0xFFFF)
        local network_part = bit32.band(dst_parts[i], mask)
        local host_part = bit32.band(ip_parts[i], bit32.bnot(mask))
        result[i] = bit32.bor(network_part, host_part)
      end
    end
    bits_remaining = bits_remaining - 16
  end

  -- Convert back to compressed IPv6
  local hex = {}
  for _, v in ipairs(result) do
    table.insert(hex, string.format("%x", v))
  end

  -- Simple compression: replace longest 0-run with ::
  local s = table.concat(hex, ":")
  local longest = ""
  s = s:gsub(":", ":0")  -- ensure all are 0
  s = s:gsub("^0", ""):gsub("0:", "")  -- normalize
  -- For brevity, skip full compression; use a simple form
  return compress_ipv6(table.concat(hex, ":"))
end

-- Basic IPv6 compression (replace first longest zero run with ::)
function compress_ipv6(ip)
  local parts = {}
  for part in ip:gmatch("[^:]+") do
    table.insert(parts, part)
  end
  -- Find longest run of zeros
  local max_run = 0
  local run_start = -1
  local current_run = 0
  local current_start = 1

  for i, p in ipairs(parts) do
    if tonumber(p) == 0 then
      current_run = current_run + 1
    else
      if current_run > max_run then
        max_run = current_run
        run_start = current_start
      end
      current_run = 0
      current_start = i + 1
    end
  end
  if current_run > max_run then
    max_run = current_run
    run_start = current_start
  end

  if max_run > 1 then
    local compressed = {}
    for i = 1, run_start - 1 do
      table.insert(compressed, parts[i])
    end
    table.insert(compressed, "")
    for i = run_start + max_run, #parts do
      table.insert(compressed, parts[i])
    end
    return table.concat(compressed, ":")
  end

  return table.concat(parts, ":")
end

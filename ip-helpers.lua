-- ip-helpers.lua

function ipv6_expand(ip)
  local parts = {}
  local expanded = ip
    :gsub("^::", "0:")
    :gsub("::$", ":0")
    :gsub("::", ":0:")
  
  local chunks = {}
  for part in expanded:gmatch("[^:]+") do
    table.insert(chunks, part)
  end

  local zeros = {}
  local pos = 1
  for i = 1, 8 do
    if pos <= #chunks then
      if chunks[pos] == "" then
        -- Insert zeros to fill gap
        local fill_count = 8 - #chunks + 1
        for j = 1, fill_count do
          table.insert(parts, 0)
        end
        pos = pos + 1
        break
      else
        local val = tonumber(chunks[pos], 16)
        if not val or val < 0 or val > 0xFFFF then return nil end
        table.insert(parts, val)
        pos = pos + 1
      end
    else
      table.insert(parts, 0)  -- fill with zeros
    end
  end

  if #parts ~= 8 then return nil end
  return parts
end

function bit_and(a, b)
  local result = 0
  local factor = 1
  while a > 0 or b > 0 do
    if a % 2 == 1 and b % 2 == 1 then
      result = result + factor
    end
    a = math.floor(a / 2)
    b = math.floor(b / 2)
    factor = factor * 2
  end
  return result
end

function ipv6_compress(hex)
  local parts = {}
  for part in hex:gmatch("([^:]+)") do
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

  if max_run < 2 then
    return table.concat(parts, ":")
  end

  local compressed = {}
  for i = 1, run_start - 1 do
    table.insert(compressed, parts[i])
  end
  table.insert(compressed, "")
  for i = run_start + max_run, #parts do
    table.insert(compressed, parts[i])
  end

  local s = table.concat(compressed, ":")
  s = s:gsub("^:", "::"):gsub(":$", "::"):gsub(":::", "::")
  return s
end
-- ============================================================================
-- Cheat Engine MCP Bridge :: 24_pointer_analysis
-- Pointer analysis (UNIT-24)
-- Loaded in order by ../ce_mcp_bridge.lua with the shared namespace B as its
-- argument. Imports below are the shared helpers this module uses; exports at
-- the end publish this module's top-level locals to later modules.
-- ============================================================================
local B = ...

local toHex = B.toHex

-- >>> BEGIN UNIT-24 Pointer Analysis <<<

-- Bidirectional 32<->64-bit general-purpose register name aliases (uppercase keys).
-- Global (not local) to avoid the >200-local chunk compile limit.
POINTER_REG_ALIASES = {
    RAX="EAX", EAX="RAX", RBX="EBX", EBX="RBX", RCX="ECX", ECX="RCX",
    RDX="EDX", EDX="RDX", RSI="ESI", ESI="RSI", RDI="EDI", EDI="RDI",
    RBP="EBP", EBP="RBP", RSP="ESP", ESP="RSP", RIP="EIP", EIP="RIP",
    R8="R8D", R8D="R8", R9="R9D", R9D="R9", R10="R10D", R10D="R10",
    R11="R11D", R11D="R11", R12="R12D", R12D="R12", R13="R13D", R13D="R13",
    R14="R14D", R14D="R14", R15="R15D", R15D="R15",
}

function isPointerRegister(name)
    return name ~= nil and POINTER_REG_ALIASES[name:upper()] ~= nil
end

-- Parse a signed hex displacement string like "+1A" or "-08" -> integer.
function parseHexDisp(s)
    local sign, hex = s:match("^([%+%-])(%x+)$")
    if not hex then return nil end
    local v = tonumber(hex, 16)
    if sign == "-" then return -v end
    return v
end

-- Parse the first [...] memory operand of an instruction string.
-- Returns a table { form, base, index, scale, disp } or (nil, errmsg).
-- Displacements are hex (CE disassembly convention).
function parseMemoryOperand(instruction)
    if type(instruction) ~= "string" then
        return nil, "instruction must be a string"
    end
    local raw = instruction:match("%[([^%]]+)%]")
    if not raw then
        return nil, "no memory operand found in: " .. instruction
    end
    -- Normalize: drop spaces, lowercase, strip segment override (e.g. ds:).
    local op = raw:gsub("%s+", ""):lower():gsub("^[cdsefg]s:", "")

    local b, i, s, d

    -- [base+index*scale+disp] / [base+index*scale-disp]
    b, i, s, d = op:match("^(%w+)%+(%w+)%*(%d+)([%+%-]%x+)$")
    if b then
        return { form="indexed", base=b, index=i, scale=tonumber(s), disp=parseHexDisp(d) }
    end
    -- [base+index*scale]
    b, i, s = op:match("^(%w+)%+(%w+)%*(%d+)$")
    if b then
        return { form="indexed", base=b, index=i, scale=tonumber(s), disp=0 }
    end
    -- [base+disp] / [base-disp]  (base must be a register)
    b, d = op:match("^(%w+)([%+%-]%x+)$")
    if b and isPointerRegister(b) then
        local form = (b=="rip" or b=="eip") and "rip_relative" or "register_indirect"
        return { form=form, base=b, index=nil, scale=nil, disp=parseHexDisp(d) }
    end
    -- [base]  (register)
    b = op:match("^(%w+)$")
    if b and isPointerRegister(b) then
        return { form="register_indirect", base=b, index=nil, scale=nil, disp=0 }
    end
    -- [disp]  (absolute / direct address; all hex digits)
    local abs = op:match("^(%x+)$")
    if abs then
        return { form="absolute", base=nil, index=nil, scale=nil, disp=tonumber(abs, 16) }
    end

    return nil, "unrecognized memory operand: " .. raw
end

-- Coerce a hex-string ("0x..."), decimal string, or number to a number.
function toNumberAny(v)
    if type(v) == "number" then return v end
    if type(v) == "string" then return tonumber(v) or tonumber(v, 16) end
    return nil
end

-- Look up a register value from a hit snapshot, trying the 32/64-bit alias.
function resolveRegisterValue(registers, regName)
    local up = regName:upper()
    local v = registers[up]
    if v == nil then
        local alias = POINTER_REG_ALIASES[up]
        if alias then v = registers[alias] end
    end
    return toNumberAny(v)
end

-- Format a signed displacement as "+0xN" / "-0xN".
function formatHexDisp(disp)
    if disp == nil then return nil end
    if disp < 0 then return string.format("-0x%X", -disp) end
    return string.format("+0x%X", disp)
end

-- Turn one captured memory access into pointer-walk-back facts. Pure: no CE API calls.
function cmd_analyze_pointer_access(params)
    local instruction = params.instruction
    local registers = params.registers
    if type(instruction) ~= "string" then
        return { success=false, error="instruction (string) is required", error_code="INVALID_PARAMS" }
    end
    if type(registers) ~= "table" then
        return { success=false, error="registers (object) is required", error_code="INVALID_PARAMS" }
    end

    local op, err = parseMemoryOperand(instruction)
    if not op then
        return { success=false, error=err, error_code="INVALID_PARAMS" }
    end

    local warnings = {}
    local result = {
        success = true,
        access_type = op.form,
        base_register = op.base and op.base:upper() or nil,
        index_register = op.index and op.index:upper() or nil,
        scale = op.scale,
        displacement = op.disp,
        hex_displacement = formatHexDisp(op.disp),
        struct_base = nil,
        accessed_address = nil,
        next_scan_value = nil,
        is_static = (op.form == "rip_relative" or op.form == "absolute"),
        has_dynamic_index = (op.form == "indexed"),
        warnings = warnings,
    }
    if params.is_64bit ~= nil then
        result.scan_type = params.is_64bit and "qword" or "dword"
    end

    -- Static roots terminate the chain; nothing to scan for.
    if op.form == "absolute" then
        result.accessed_address = toHex(op.disp)
        result.note = "Absolute/global address. Chain root: map with get_address_info."
        return result
    end
    if op.form == "rip_relative" then
        if params.accessed_address ~= nil then
            result.accessed_address = toHex(toNumberAny(params.accessed_address) or 0)
        else
            table.insert(warnings, "rip_relative: accessed_address not provided and cannot be computed without instruction length")
        end
        result.note = "RIP-relative/global. Chain root: map with get_address_info."
        return result
    end

    -- register_indirect / indexed: climb one level.
    local baseVal = resolveRegisterValue(registers, op.base)
    if baseVal == nil then
        return { success=false, error="register value not provided: " .. result.base_register, error_code="INVALID_PARAMS" }
    end
    result.struct_base = toHex(baseVal)
    result.next_scan_value = toHex(baseVal)

    local accessed = baseVal + (op.disp or 0)
    if op.form == "indexed" then
        local idxVal = resolveRegisterValue(registers, op.index)
        if idxVal ~= nil then
            accessed = baseVal + idxVal * (op.scale or 1) + (op.disp or 0)
        else
            accessed = nil
            table.insert(warnings, "index register value not provided; accessed_address not computed")
        end
        table.insert(warnings, "indexed access: this level's offset (index*scale+disp) is index-dependent")
    end
    if accessed ~= nil then
        result.accessed_address = toHex(accessed)
    end

    if params.accessed_address ~= nil and accessed ~= nil then
        local given = toNumberAny(params.accessed_address)
        if given ~= nil and given ~= accessed then
            table.insert(warnings, "computed accessed_address differs from provided value; register state may lag the access")
        end
    end

    result.note = "Scan for a pointer equal to next_scan_value to find the holder one level up. Repeat until struct_base lands in a static module (check with get_address_info)."
    return result
end

-- Resolve a pointer chain (CE convention: deref, then add offset). Uses CE's
-- readPointer / getAddressSafe. Returns a table: ok + (final_address number,
-- final_address_hex, final_value, chain) or (error, chain, failed_at).
function resolveChain(base, offsets)
    local baseNum = base
    if type(baseNum) == "string" then baseNum = getAddressSafe(baseNum) end
    if not baseNum then
        return { ok=false, error="Invalid base address" }
    end
    local cur = baseNum
    local chain = { { step=0, address=toHex(cur), description="base" } }
    for i, offset in ipairs(offsets or {}) do
        local ptr = readPointer(cur)
        if not ptr then
            return { ok=false, error="Failed to read pointer at step " .. i, chain=chain, failed_at=toHex(cur) }
        end
        cur = ptr + offset
        table.insert(chain, {
            step=i, address=toHex(cur), offset=offset,
            hex_offset=string.format("+0x%X", offset), pointer_value=toHex(ptr),
        })
    end
    local finalValue = nil
    pcall(function() finalValue = readPointer(cur) end)
    return { ok=true, base=toHex(baseNum), final_address=cur, final_address_hex=toHex(cur), final_value=finalValue, chain=chain }
end

-- Resolve many candidate chains; report which land on target (matches only by default).
function cmd_validate_pointer_chains(params)
    local chains = params.chains
    if type(chains) ~= "table" then
        return { success=false, error="chains (array) is required", error_code="INVALID_PARAMS" }
    end
    if #chains > 5000 then
        return { success=false, error="Too many chains (max 5000); page the input.", error_code="INVALID_PARAMS" }
    end
    local target = params.target
    if type(target) == "string" then target = getAddressSafe(target) end
    if not target then
        return { success=false, error="Invalid target address", error_code="INVALID_ADDRESS" }
    end
    local includeMisses = params.include_misses == true

    local matched, unreadable = 0, 0
    local matches = {}
    local misses = includeMisses and {} or nil

    for _, c in ipairs(chains) do
        local offs = c.offsets or {}
        local r = resolveChain(c.base, offs)
        if not r.ok then
            unreadable = unreadable + 1
            if includeMisses then
                table.insert(misses, { base=c.base, offsets=offs, error=r.error })
            end
        elseif r.final_address == target then
            matched = matched + 1
            table.insert(matches, { base=r.base, offsets=offs, final_address=r.final_address_hex, final_value=r.final_value })
        elseif includeMisses then
            table.insert(misses, { base=r.base, offsets=offs, final_address=r.final_address_hex, final_value=r.final_value })
        end
    end

    local out = {
        success = true,
        target = toHex(target),
        total = #chains,
        matched = matched,
        unreadable = unreadable,
        matches = matches,
    }
    if includeMisses then out.misses = misses end
    return out
end

-- >>> END UNIT-24 <<<

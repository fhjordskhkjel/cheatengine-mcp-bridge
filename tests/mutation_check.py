"""Mutation check: break the bridge on purpose and make sure the offline suites notice.

Each mutant is a copy of ce_mcp_bridge.lua with one small, plausible bug applied. The matching suite must fail
(or crash) on it. A surviving mutant means a behaviour is not covered by a test.

    python tests/mutation_check.py

The mutations are anchored on exact source text; if the bridge code is edited and an anchor disappears the
mutant is reported as STALE - update the anchor here rather than ignoring it.
"""
import subprocess
import sys
import tempfile
from pathlib import Path

import testkit
from testkit import BRIDGE_LUA, EXIT_SKIP

TESTS = Path(__file__).resolve().parent

ROBUST, JOBS, ANALYSIS = "test_lua_robustness.py", "test_lua_jobs.py", "test_lua_analysis.py"

# (name, suite, old text, new text, expected) - expected "caught" unless the bug cannot change any observable result
MUTANTS = [
    # --- JSON codec, replies and breakpoint recording
    ("int64_numbers_lossy", ROBUST, 'if math.type(val) == "integer" then return string.format("%d", val) end', 'if false then return string.format("%d", val) end', "caught"),
    ("invalid_utf8_not_sanitized", ROBUST, "sanitize_utf8(val):gsub('[%z\\1-\\31\\\\\"]', escape_char)", "val:gsub('[%z\\1-\\31\\\\\"]', escape_char)", "caught"),
    ("bp_callback_can_leave_target_halted", ROBUST, "local ok, err = pcall(body)", "local ok, err = true, body()", "caught"),
    ("bp_hit_buffer_uncapped", ROBUST, "if n >= MAX_HITS_PER_BP then", "if false then", "caught"),
    # --- UNIT-25 (jobs, reads, batch)
    ("scan_busy_guard_removed", JOBS, '    if serverState.scan_job_id then\n        return { success = false, error = "Scan job "', '    if false then\n        return { success = false, error = "Scan job "', "caught"),
    ("find_references_not_time_sliced", JOBS, 'if os.clock() >= deadline then jb.progress.current = jb._i; return false end\n            end\n            return finishList(jb, "references"', 'if false then jb.progress.current = jb._i; return false end\n            end\n            return finishList(jb, "references"', "caught"),
    ("poll_completion_disabled", JOBS, "and (p.CurrentlyScanned or 0) >= p.TotalAddressesToScan then", "and false then", "caught"),
    ("base64_padding_broken", JOBS, '(b and B64_CHARS[(n >> 6) & 63] or "=")', '(b and B64_CHARS[(n >> 6) & 63] or "")', "caught"),
    ("cleanup_skips_jobs", JOBS, "    if serverState.jobs then\n        for _, job in pairs(serverState.jobs) do\n            if job._fl then", "    if false then\n        for _, job in pairs(serverState.jobs) do\n            if job._fl then", "caught"),
    ("job_cap_removed", JOBS, "if running >= MAX_RUNNING_JOBS then", "if false then", "caught"),
    ("next_scan_job_destroys_shared_session", JOBS, "        j._ms = nil\n        j.progress = { current = 1, total = 1 }\n        jobFinish(j, \"done\", { result = { fields = { count = count } } })\n    end\n    ms.nextScan",
     "        j.progress = { current = 1, total = 1 }\n        j._temp = true\n        jobFinish(j, \"done\", { result = { fields = { count = count } } })\n    end\n    ms.nextScan", "caught"),
    ("batch_stop_on_error_ignored", JOBS, "if stopOnError then break end", "if false then break end", "caught"),
    # --- UNIT-26 (analysis)
    ("string_ref_carry_removed", ANALYSIS, "stages[#stages + 1] = { ranges = codeRanges, carry = 7, onStart", "stages[#stages + 1] = { ranges = codeRanges, carry = 0, onStart", "caught"),
    ("cave_run_not_continued_across_chunks", ANALYSIS, 'if run.nextAddr == dbase then\n                local s, e = data:find("^" .. pat)', 'if false then\n                local s, e = data:find("^" .. pat)', "caught"),
    ("cave_at_section_end_dropped", ANALYSIS, "stages = { { ranges = ranges, onDone = closeRun,", "stages = { { ranges = ranges,", "caught"),
    ("pointer_offsets_in_wrong_order", ANALYSIS, "local offs, cost = { entry.t - val }, entry.t - val\n                for _, o in ipairs(entry.offs) do offs[#offs + 1] = o; cost = cost + o end",
     "local offs, cost = {}, entry.t - val\n                for _, o in ipairs(entry.offs) do offs[#offs + 1] = o; cost = cost + o end\n                offs[#offs + 1] = entry.t - val", "caught"),
    ("diff_ignores_unchanged_pairs", ANALYSIS, 'if (pc[k] == "C" and same) or (pc[k] == "U" and not same) then ok = false; break end', 'if (pc[k] == "C" and same) then ok = false; break end', "caught"),
    ("export_forwarders_undetected", ANALYSIS, "local function isForwarder(rva) return rva >= dir.rva and rva < dir.rva + dir.size end", "local function isForwarder(rva) return false end", "caught"),
    ("rtti_base_classes_dropped", ANALYSIS, "for i = 0, math.min(nb, 64) - 1 do", "for i = 0, -1 do", "caught"),
    ("snapshot_budget_ignored", ANALYSIS, "if total + size > U26.SNAP_MAX_TOTAL then", "if false then", "caught"),
    ("string_match_start_ignored", ANALYSIS, "if anyMatch or s == 1 or data:byte(s - 1) == 0 then", "if true then", "caught"),
    ("import_ordinals_misread", ANALYSIS, "if (e.thunk & ordBit) ~= 0 then", "if false then", "caught"),
    ("section_flags_swapped", ANALYSIS, '((chars & 0x80000000) ~= 0 and "w" or "-") .. ((chars & 0x20000000) ~= 0 and "x" or "-")', '((chars & 0x20000000) ~= 0 and "w" or "-") .. ((chars & 0x80000000) ~= 0 and "x" or "-")', "caught"),
    # --- UNIT-27 part A (.pdata)
    ("pdata_end_treated_as_inclusive", ANALYSIS, "        elseif rva >= e then lo = mid + 1\n", "        elseif rva > e then lo = mid + 1\n", "caught"),
    ("pdata_chained_fragments_not_followed", ANALYSIS, "while primaryInfo and primaryInfo.chain and hops < 8 do", "while false do", "caught"),
    ("analyze_function_stops_at_first_ret", ANALYSIS, "if (b1 == 0xC3 or b1 == 0xC2) and not pd then", "if (b1 == 0xC3 or b1 == 0xC2) then", "caught"),
    ("find_function_boundaries_ignores_pdata", ANALYSIS, "        if okPd and pd then\n            return {\n                success = true, found = true, query_address", "        if false and pd then\n            return {\n                success = true, found = true, query_address", "caught"),
    ("exception_handler_not_read", ANALYSIS, "    elseif (flags & 3) ~= 0 then\n        local h = U26.u32(mod.base + tail)", "    elseif false then\n        local h = U26.u32(mod.base + tail)", "caught"),
    # --- UNIT-27 part B (struct recovery)
    ("recover_pointer_detection_off", ANALYSIS, "            if anyPtr and onlyPtrOrNull then", "            if false then", "caught"),
    ("recover_mixed_classes_accepted", ANALYSIS, "elseif one.raw_name ~= info.raw_name or one.vtable ~= info.vtable then", "elseif false then", "caught"),
    ("recover_tail_not_trimmed", ANALYSIS, "    size = math.max(P, ((last + 3) // 4) * 4)", "    size = size", "caught"),
    ("recover_floats_become_ints", ANALYSIS, "            elseif allFloat then", "            elseif false then", "caught"),
    ("recover_zero_runs_not_merged", ANALYSIS, 'if prev and prev.kind == "unknown" and prev.offset + prev.size == off then', "if false then", "caught"),
    ("recover_inline_text_missed", ANALYSIS, "            if len >= 4 and off + len < size and s1:byte(off + len + 1) == 0 then", "            if false then", "caught"),
    ("recover_string_pointers_untyped", ANALYSIS, "    local text = U26.printableAt(v)\n    if text then return \"string\", text end", "    local text = nil\n    if text then return \"string\", text end", "caught"),
    ("recover_int_next_to_float_read_as_double", ANALYSIS, "if low ~= 0 and (low <= 0xFFFF or low >= 0xFFFF0000) then return false end", "if false then return false end", "caught"),
    ("rtti_bases_offsets_ignored", ANALYSIS, 'bases[#bases + 1] = { name = U26.demangle(nm), offset = mdisp, virtual = (pdisp ~= -1), contained = contained }', 'bases[#bases + 1] = { name = U26.demangle(nm), offset = 99, virtual = true, contained = contained }', "caught"),
    # Defensive only: a false x86 locator is harmless unless something points at it, so no result changes.
    ("x86_locator_sanity_check_removed", ANALYSIS, "ok = nb >= 1 and nb <= 64 and arr >= mod.base and arr < mod.base + mod.size", "ok = true", "survives"),
]


def main():
    source = BRIDGE_LUA.read_bytes().decode("utf-8").replace("\r\n", "\n")
    stale = bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, suite, old, new, expected in MUTANTS:
            if source.count(old) != 1:
                print("STALE     %-40s anchor found %d times" % (name, source.count(old)))
                stale += 1
                continue
            mutant = Path(tmp) / ("mut_%s.lua" % name)
            mutant.write_bytes(source.replace(old, new, 1).encode("utf-8"))
            proc = subprocess.run([sys.executable, str(TESTS / suite), str(mutant)], capture_output=True, text=True,
                                  encoding="utf-8", errors="replace", cwd=TESTS, timeout=600)
            if proc.returncode == EXIT_SKIP:
                print("SKIP      Lua DLL not available")
                sys.exit(EXIT_SKIP)
            caught = proc.returncode != 0
            verdict = {(True, "caught"): "caught   ", (False, "survives"): "survives*", (False, "caught"): "SURVIVED ", (True, "survives"): "caught(!)"}[(caught, expected)]
            if (caught, expected) in ((False, "caught"),):
                bad += 1
            print("%s %-40s [%s]" % (verdict, name, suite))
    total = len(MUTANTS)
    print("\n%d mutants: %d unexpected survivors, %d stale anchors  (* = documented survivor)" % (total, bad, stale))
    sys.exit(1 if bad or stale else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""validate_jmp.py — re-parse a .JMP with the same state machine jayxbox's
tool_apply-magic-patch.html uses, and sanity-check records."""
import sys, re

def parse(path):
    lines = [l.strip() for l in open(path).read().split("\n")]
    assert lines[0] == "#Jay's Magic Patcher (www.jayxbox.com)", "bad magic line"
    hdr = {}
    for i, key in enumerate(["system", "game-title", "region", "version",
                             "author", "notes"], start=1):
        assert lines[i].startswith(key + "="), f"line {i}: expected {key}="
        hdr[key] = lines[i].split("=", 1)[1]
    records, groups = [], {}
    i = 7
    while i < len(lines):
        line = lines[i]
        if not line:
            i += 1
            continue
        comment, enabled = "No Comment", True
        if line.startswith("#"):
            comment = line[1:].strip()
            if "[-]" in comment:
                enabled = False
                comment = comment.replace("[-]", "").strip()
            i += 1
            line = lines[i] if i < len(lines) else ""
        if line.upper().startswith("APPEND:"):
            rec = ("append", None, line.split(":", 1)[1])
        elif ":" in line:
            off, data = line.split(":", 1)
            off = int(off[2:] if off.startswith("0x") else off, 16)
            assert re.fullmatch(r"[0-9A-Fa-f]+", data) and len(data) % 2 == 0, \
                f"bad hex at line {i}: {data!r}"
            rec = ("offset", off, data)
        else:
            rec = ("search-replace", line, lines[i + 1])
            i += 1
        records.append((comment, enabled, rec))
        groups.setdefault(comment, []).append(rec)
        i += 1
    return hdr, records, groups

def main():
    for path in sys.argv[1:]:
        hdr, records, groups = parse(path)
        print(f"== {path} ==")
        print(f"  {hdr['game-title']} | {hdr['region']} | {hdr['version']} | author {hdr['author']}")
        print(f"  {len(records)} records in {len(groups)} toggle groups:")
        for g, recs in groups.items():
            for kind, off, data in recs:
                loc = f"0x{off:X}" if kind == "offset" else "(sr)"
                print(f"    [{'on ' if any(r[0]==g and r[1] for r in records) else 'off'}] {g:32s} {loc}  {data}")
        # overlap check between records of different groups
        seen = {}
        for comment, _, (kind, off, data) in records:
            if kind != "offset":
                continue
            for j in range(len(data) // 2):
                a = off + j
                if a in seen and seen[a] != comment:
                    print(f"  NOTE: 0x{a:X} written by both '{seen[a]}' and '{comment}'")
                seen[a] = comment
        print(f"  max offset: 0x{max(r[2][1] for r in records if r[2][0]=='offset'):X}")
        print("  PARSE OK\n")

if __name__ == "__main__":
    main()

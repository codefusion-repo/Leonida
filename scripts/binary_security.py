"""Static, bounded PE32+ policy for the freshly built diagnostic executable.

Not a general PE loader, malware scanner, or transitive dependency resolver.
No third-party Python package, subprocess, mapping, or executable invocation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct

MAX_FILE = 64 * 1024 * 1024
MAX_IMAGE = 256 * 1024 * 1024
MAX_IMPORTS = 8192
EXEC = 0x20000000
READ = 0x40000000
WRITE = 0x80000000
DLLS = frozenset({
    "kernel32.dll", "msvcp140.dll", "vcruntime140.dll", "vcruntime140_1.dll",
    "ucrtbase.dll",
    *("api-ms-win-crt-" + part + "-l1-1-0.dll" for part in (
        "conio", "convert", "environment", "filesystem", "heap", "locale",
        "math", "multibyte", "private", "process", "runtime", "stdio",
        "string", "time", "utility")),
})
# Scope-limited denylist for explicit remote-process primitives; not malware detection.
DENIED = frozenset(x.lower() for x in (
    "CreateRemoteThread", "CreateRemoteThreadEx", "WriteProcessMemory",
    "VirtualAllocEx", "VirtualAllocExNuma", "VirtualProtectEx",
    "NtWriteVirtualMemory", "NtCreateThreadEx", "QueueUserAPC"))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def span(start, length, limit):
    return 0 <= start <= limit and 0 <= length <= limit - start


def power2(value):
    return value > 0 and value & (value - 1) == 0


class PE:
    def __init__(self, data):
        self.data = data
        require(64 <= len(data) <= MAX_FILE and data[:2] == b"MZ", "invalid DOS header or size")
        nt = self.u32(0x3c)
        require(nt >= 64 and span(nt, 24, len(data)) and data[nt:nt+4] == b"PE\0\0", "invalid PE header")
        machine, count, _, _, _, optlen, chars = self.unpack("<HHIIIHH", nt + 4)
        require(machine == 0x8664 and 1 <= count <= 32, "not bounded AMD64")
        require(chars & 2 and not chars & (1 | 0x2000), "not relocatable executable")
        opt = nt + 24
        require(optlen == 240 and span(opt, optlen + 40 * count, len(data)), "invalid optional/section headers")
        require(self.u16(opt) == 0x20b and self.u32(opt+108) == 16, "unsupported PE32+ layout")
        self.entry = self.u32(opt+16)
        self.image_base = self.u64(opt+24)
        sa, fa = self.unpack("<II", opt+32)
        self.image_size, headers = self.unpack("<II", opt+56)
        self.flags = self.u16(opt+70)
        require(self.flags & 0x4160 == 0x4160, "ASLR/high entropy/DEP/CFG flags missing")
        require(power2(fa) and 512 <= fa <= 65536 and power2(sa) and sa >= max(4096, fa), "unsupported alignment")
        require(0 < self.image_size <= MAX_IMAGE and self.image_size % sa == 0, "invalid image size")
        require(opt+optlen+40*count <= headers <= len(data) and headers % fa == 0, "invalid header size")
        require(self.image_base > 0 and self.image_base % 65536 == 0, "invalid image base")
        self.dirs = [self.unpack("<II", opt+112+8*i) for i in range(16)]
        self.sections = []
        raw_ranges, virtual_ranges = [], []
        for i in range(count):
            off = opt + optlen + i*40
            name = data[off:off+8].split(b"\0", 1)[0].decode("ascii")
            vs, va, rs, rp = self.unpack("<IIII", off+8)
            flags = self.u32(off+36)
            require(name and re.fullmatch(r"[.A-Za-z0-9_$-]+", name) and name not in {s["name"] for s in self.sections}, "invalid section name")
            require(not (flags & EXEC and flags & WRITE), "writable executable section")
            extent = max(vs, rs)
            rounded = (extent + sa - 1) & ~(sa - 1)
            require(extent > 0 and va >= headers and va % sa == 0 and span(va, rounded, self.image_size), "invalid virtual section range")
            if rs:
                require(rp >= headers and rp % fa == 0 and rs % fa == 0 and span(rp, rs, len(data)), "invalid raw section range")
                raw_ranges.append((rp, rp+rs))
            else:
                require(rp == 0, "empty section has raw pointer")
            virtual_ranges.append((va, va+rounded))
            self.sections.append(dict(name=name, rva=va, virtual_size=vs, raw_offset=rp, raw_size=rs,
                                      characteristics=flags, read=bool(flags&READ), write=bool(flags&WRITE), execute=bool(flags&EXEC)))
        for ranges in (raw_ranges, virtual_ranges):
            ordered = sorted(ranges)
            require(all(a[1] <= b[0] for a,b in zip(ordered,ordered[1:])), "overlapping sections")
        self.executable(self.entry)
        # The audit profile deliberately excludes unsupported bound/delay imports and CLR images.
        for i in (11, 13, 14):
            require(self.dirs[i] == (0,0), "unsupported bound/delay/CLR directory")
        for i,(rva,size) in enumerate(self.dirs):
            require(bool(rva) == bool(size), "incomplete data directory")
            if not size:
                continue
            if i == 4:  # certificate table uses file offset
                require(rva % 8 == 0 and span(rva,size,len(data)) and rva >= headers and
                        all(rva+size <= a or rva >= b for a,b in raw_ranges), "invalid certificate table")
            else:
                self.map(rva,size)
        self.relocations()
        self.cfg = self.guard_config()
        self.imports = self.read_imports()

    def unpack(self, fmt, off):
        require(span(off, struct.calcsize(fmt), len(self.data)), "truncated structure")
        return struct.unpack_from(fmt, self.data, off)

    def u16(self,o): return self.unpack("<H",o)[0]
    def u32(self,o): return self.unpack("<I",o)[0]
    def u64(self,o): return self.unpack("<Q",o)[0]

    def section(self, rva, size):
        require(size > 0, "zero-sized mapping")
        for s in self.sections:
            delta = rva - s["rva"]
            if span(delta,size,max(s["raw_size"],s["virtual_size"])):
                return s
        raise ValueError("RVA not in section")

    def map(self, rva, size):
        s = self.section(rva,size)
        delta = rva-s["rva"]
        require(span(delta,size,s["raw_size"]), "RVA not file backed")
        return s["raw_offset"] + delta

    def executable(self,rva):
        s = self.section(rva,1)
        require(s["execute"] and not s["write"], "non-executable code target")
        self.map(rva,1)

    def cstring(self,rva):
        s = self.section(rva,1)
        off = self.map(rva,1)
        end = min(off+513,s["raw_offset"]+s["raw_size"])
        nul = self.data.find(b"\0",off,end)
        require(nul > off, "invalid bounded import string")
        value = self.data[off:nul].decode("ascii")
        require(all(32 < ord(c) < 127 for c in value), "invalid import characters")
        return value

    def relocations(self):
        rva,size = self.dirs[5]
        require(size >= 8 and size <= 4*1024*1024, "missing or oversized base relocations")
        off = self.map(rva,size)
        end = off+size
        useful = False
        while off < end:
            require(span(off,8,end), "truncated relocation block")
            page, n = self.unpack("<II",off)
            require(page % 4096 == 0 and page < self.image_size and n >= 8 and n % 4 == 0 and span(off,n,end), "invalid relocation block")
            for pos in range(off+8,off+n,2):
                value = self.u16(pos)
                kind = value >> 12
                require(kind in (0,10), "unexpected AMD64 relocation type")
                if kind == 10:
                    self.map(page+(value&4095),8)
                    useful = True
            off += n
        require(useful, "no DIR64 relocations")

    def guard_config(self):
        rva,size = self.dirs[10]
        require(148 <= size <= 4096, "missing or unsupported CFG load config")
        off = self.map(rva,size)
        require(148 <= self.u32(off) <= size, "truncated CFG load config")
        check, dispatch, table, count = self.unpack("<QQQQ",off+112)
        flags = self.u32(off+144)
        require(flags & 0x500 == 0x500, "CFG instrumentation/function table missing")
        require(0 < count <= 262144 and table >= self.image_base, "invalid CFG function table")
        for ptr in (check,dispatch):
            require(ptr >= self.image_base, "missing CFG pointer slot")
            slot = ptr-self.image_base
            require(self.section(slot,8)["read"], "unreadable CFG pointer slot")
            self.map(slot,8)
        stride = 4 + (flags >> 28)
        start = self.map(table-self.image_base,count*stride)
        require(self.section(table-self.image_base,count*stride)["read"] and
                not self.section(table-self.image_base,count*stride)["write"], "writable CFG table")
        last = -1
        for i in range(count):
            target = self.u32(start+i*stride)
            require(target > last, "unordered CFG targets")
            self.executable(target)
            last = target
        return dict(guard_flags=flags, function_count=count, entry_size=stride,
                    check_pointer_rva=check-self.image_base, dispatch_pointer_rva=dispatch-self.image_base,
                    table_rva=table-self.image_base)

    def read_imports(self):
        rva,size = self.dirs[1]
        require(40 <= size <= 65536, "missing or oversized imports")
        start = self.map(rva,size)
        result, total = {}, 0
        for off in range(start,start+size-19,20):
            lookup,stamp,forward,name,iat = self.unpack("<IIIII",off)
            if not any((lookup,stamp,forward,name,iat)):
                require(result and not any(self.data[off:start+size]), "invalid import terminator")
                return result
            require(not stamp and not forward and lookup and name and iat, "unsupported import descriptor")
            dll = self.cstring(name).lower()
            require(dll in DLLS and dll not in result, "unreviewed or duplicate DLL: "+dll)
            symbols = []
            for i in range(MAX_IMPORTS+1):
                value = self.u64(self.map(lookup+i*8,8))
                iat_value = self.u64(self.map(iat+i*8,8))
                require(value == iat_value, "unexpected prebound IAT")
                if value == 0:
                    break
                require(total < MAX_IMPORTS and value < 2**32, "ordinal or oversized import inventory")
                self.map(value,2)
                symbol = self.cstring(value+2)
                require(symbol.lower() not in DENIED, "denied direct import: "+symbol)
                require(symbol not in symbols, "duplicate import symbol")
                symbols.append(symbol)
                total += 1
            else:
                raise ValueError("unterminated thunk table")
            require(symbols, "empty import descriptor")
            result[dll] = sorted(symbols)
        raise ValueError("unterminated import descriptors")


def analyze(data):
    pe = PE(data)
    return dict(size=len(data), sha256=digest(data), machine="AMD64", format="PE32+",
                dll_characteristics=pe.flags, mitigations=dict(aslr=True, high_entropy_va=True, dep=True, cfg=True),
                cfg=pe.cfg, sections=pe.sections, direct_imports=pe.imports,
                delay_imports="absent", bound_imports="absent")


def make_sbom(report, sha, build):
    ref = "leonida:gta6rt:"+sha+":"+build
    dlls = sorted(report["direct_imports"])
    return {"bomFormat":"CycloneDX", "specVersion":"1.5", "version":1,
            "metadata":{"component":{"type":"application","name":"gta6rt.exe","version":sha,
                                      "bom-ref":ref,"hashes":[{"alg":"SHA-256","content":report["sha256"]}]},
                        "properties":[{"name":"leonida:inventory:scope","value":"direct PE DLL imports only"}]},
            "components":[{"type":"library","name":dll,"bom-ref":"pe-import:"+dll} for dll in dlls],
            "dependencies":[{"ref":ref,"dependsOn":["pe-import:"+dll for dll in dlls]}]}


def read_bounded(path, limit):
    require(not path.is_symlink() and stat.S_ISREG(path.stat().st_mode), "not a regular input")
    with path.open("rb") as stream:
        data = stream.read(limit+1)
    require(len(data) <= limit, "oversized input")
    return data


def json_bytes(value):
    return (json.dumps(value,sort_keys=True,indent=2)+"\n").encode("utf-8")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--binary",type=Path,required=True)
    ap.add_argument("--toolchain",type=Path,required=True)
    ap.add_argument("--sha",required=True)
    ap.add_argument("--build",choices=("cmake","direct"),required=True)
    ap.add_argument("--output",type=Path,required=True)
    args = ap.parse_args()
    require(re.fullmatch(r"[0-9a-f]{40}",args.sha) and args.binary.name == "gta6rt.exe", "unexpected identity")
    args.output.mkdir(parents=True,exist_ok=True)
    target = args.output/(args.build+".report.json")
    bom = args.output/(args.build+".cdx.json")
    require(not target.exists() and not bom.exists(), "stale evidence")
    data = read_bounded(args.binary,MAX_FILE)
    identity = {"candidate":args.sha,"build":args.build,**{k:os.environ.get(k,"") for k in (
        "GITHUB_REPOSITORY","GITHUB_RUN_ID","GITHUB_RUN_ATTEMPT","GITHUB_WORKFLOW_SHA","GITHUB_EVENT_NAME","GITHUB_REF","ImageOS","ImageVersion")}}
    if os.environ.get("GITHUB_ACTIONS") == "true":
        require(all(identity[k] for k in ("GITHUB_REPOSITORY","GITHUB_RUN_ID","GITHUB_RUN_ATTEMPT","GITHUB_WORKFLOW_SHA","GITHUB_EVENT_NAME","GITHUB_REF")), "missing CI identity")
        require(os.environ.get("CANDIDATE_SHA") == args.sha, "candidate mismatch")
    try:
        toolchain = read_bounded(args.toolchain,4096).decode("ascii").strip()
        require(toolchain.startswith("compiler=MSVC ") and "sdk=" in toolchain, "unexpected toolchain metadata")
        report = analyze(data)
        sbom = json_bytes(make_sbom(report,args.sha,args.build))
        with bom.open("xb") as stream:
            stream.write(sbom)
        evidence = {"status":"PASS","identity":identity,"toolchain":toolchain,
                    "binary":report,"sbom_sha256":digest(sbom),"scope":"direct imports and static mitigations only"}
    except (ValueError, OSError) as exc:
        evidence = {"status":"FAIL","identity":identity,"size":len(data),"sha256":digest(data),"error":str(exc)}
        with target.open("xb") as stream:
            stream.write(json_bytes(evidence))
        raise SystemExit("Native PE policy FAIL: "+str(exc))
    with target.open("xb") as stream:
        stream.write(json_bytes(evidence))
    print("Native PE policy PASS",args.build,report["sha256"],"DLLs:",", ".join(sorted(report["direct_imports"])))


if __name__ == "__main__":
    main()

import sys
import re
import json
from pathlib import Path

D_K = {
    74:0,51:1,93:2,33:3,57:4,55:5,64:6,60:7,120:8,102:9,
    108:10,70:11,117:12,63:13,53:14,124:15,100:16,105:17,79:18,68:19,
    49:20,87:21,110:22,112:23,104:24,114:25,62:26,122:27,41:28,118:29,
    71:30,89:31,67:32,113:33,76:34,80:35,84:36,52:37,96:38,88:39,
    40:40,35:41,116:42,42:43,107:44,77:45,106:46,78:47,126:48,59:49,
    54:50,86:51,65:52,125:53,75:54,69:55,43:56,103:57,36:58,47:59,
    90:60,45:61,98:62,85:63,37:64,119:65,61:66,73:67,66:68,58:69,
    115:70,48:71,91:72,46:73,101:74,81:75,95:76,44:77,94:78,56:79,
    111:80,97:81,123:82,99:83,72:84,109:85,82:86,38:87,83:88,50:89,
    121:90,
}

# ----------------------------------------------------------------------
# string handling
# ----------------------------------------------------------------------

def parse_lua_string_bytes(s):
    out = []
    i = 0
    n = len(s)
    while i < n:
        if s[i] == '\\':
            i += 1
            num = ""
            while i < n and s[i].isdigit() and len(num) < 3:
                num += s[i]
                i += 1
            if num:
                out.append(int(num, 8) & 0xFF)
            elif i < n:
                ch = s[i]
                if ch == 'n': out.append(10)
                elif ch == 't': out.append(9)
                elif ch == 'r': out.append(13)
                elif ch == '\\': out.append(92)
                elif ch == '"': out.append(34)
                else: out.append(ord(ch))
                i += 1
        else:
            out.append(ord(s[i]))
            i += 1
    return out

# ----------------------------------------------------------------------
# static extractors
# ----------------------------------------------------------------------

def extract_bW(src):
    entries = {}
    for m in re.finditer(r'\[(\d+)\]\s*=\s*"((?:[^"\\]|\\.)*)"', src):
        entries[int(m.group(1))] = parse_lua_string_bytes(m.group(2))
    if not entries:
        arr = re.search(r'local\s+\w+\s*=\s*\{\s*("(?:[^"\\]|\\.)*"\s*,?\s*)+\}', src)
        if arr:
            for i, m in enumerate(re.finditer(r'"((?:[^"\\]|\\.)*)"', arr.group(0)), 1):
                entries[i] = parse_lua_string_bytes(m.group(1))
    out = []
    for i in sorted(entries):
        out.extend(entries[i])
    return bytes(out)

def extract_j0(src):
    m = re.search(r'local\s+j0\s*=\s*"((?:[^"\\]|\\.)*)"', src)
    if not m:
        return None
    return bytes(parse_lua_string_bytes(m.group(1)))

def decode_j0(data):
    out = bytearray()
    dq = 0
    dl = -1
    dD = 0
    dI = 0
    dA = 0
    n = len(data)
    while dA < n:
        dw = D_K.get(data[dA])
        if dw is not None:
            if dl < 0:
                dl = dw
            else:
                dl = dl + dw * 91
                dD = dD + dl * (2 ** dI)
                if (dl % 8192) > 88:
                    dI += 13
                else:
                    dI += 14
                while dI >= 8:
                    out.append(dD % 256)
                    dq += 1
                    dD //= 256
                    dI -= 8
                dl = -1
        dA += 1
    if dl >= 0:
        dD = dD + dl * (2 ** dI)
        dI += 7
        while dI >= 8:
            out.append(dD % 256)
            dq += 1
            dD //= 256
            dI -= 8
    return bytes(out)

def extract_handlers(src):
    out = []
    for m in re.finditer(
        r'if\s+\w+\s*<\s*(0[xX][0-9A-Fa-f]+|0[bB][01]+|\d+)\s+then\s+(.*?)(?=elseif\s+\w+\s*<|else\s|end\b)',
        src, re.DOTALL,
    ):
        out.append((m.group(1), m.group(2).strip()))
    return out

def extract_loader_constants(src):
    out = {}
    for name, expr in re.findall(r'local\s+(\w+)\s*=\s*\(\(([^)]*)\)', src):
        try:
            out[name] = eval(expr) % 2147483647
        except Exception:
            pass
    return out

def extract_antitamper(src):
    return {
        "getfenv": "getfenv" in src,
        "getgenv": "getgenv" in src,
        "setfenv": "setfenv" in src,
        "getmetatable": "getmetatable" in src,
        "rawset": "rawset" in src,
        "pcall": "pcall" in src,
        "hP_probe": "hP=false" in src,
        "dr_probe": "dr=false" in src,
        "df_probe": "df=false" in src,
        "frida_url_check": "FRIDA_SERVER_URL" in src,
        "frida_helper_check": "FRIDA_HELPER_PATH" in src,
    }

# ----------------------------------------------------------------------
# probe defeat + dynamic trace
# ----------------------------------------------------------------------

def patch_probes(src):
    src = re.sub(r'\blocal\s+hP\s*=\s*false\b', 'local hP = true', src)
    src = re.sub(r'\blocal\s+dr\s*=\s*false\b', 'local dr = true', src)
    src = re.sub(r'\blocal\s+df\s*=\s*false\b', 'local df = true', src)
    src = re.sub(r'if\s+hP\s+then\s+by\s*=\s*1', 'if false then by = 1', src)
    src = re.sub(r'if\s+dr\s+then\s+by\s*=\s*1', 'if false then by = 1', src)
    src = re.sub(r'if\s+df\s+then\s+by\s*=\s*1', 'if false then by = 1', src)
    return src

PRELUDE = r"""
_KF_TRACE = { n = 0, entries = {} }
_KF_TRACE_LOG = function(kind, payload)
    _KF_TRACE.n = _KF_TRACE.n + 1
    _KF_TRACE.entries[_KF_TRACE.n] = { kind = kind, payload = payload }
end

_KF_HOOK_TABLE = function(t, tag)
    local mt = getmetatable(t) or {}
    local old_newindex = mt.__newindex
    mt.__newindex = function(tbl, k, v)
        if type(v) == "function" then
            local name = tostring(k)
            local wrapped = function(...)
                local args = { ... }
                _KF_TRACE_LOG("op", { tag = name, args = { n = #args, ... } })
                local r = v(...)
                local e = _KF_TRACE.entries[_KF_TRACE.n]
                if e then e.payload.ret = r end
                return r
            end
            rawset(tbl, k, wrapped)
        else
            rawset(tbl, k, v)
        end
        if old_newindex then old_newindex(tbl, k, v) end
    end
    setmetatable(t, mt)
    return t
end
"""

def run_instrumented(src):
    try:
        import lupa.lua51 as lupa
    except ImportError:
        print("[!] pip install lupa")
        return []

    lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    lua.globals().py_log = lambda *a: print("[lua]", *a)
    lua.execute(PRELUDE)

    try:
        chunk = lua.execute("return function()\n" + src + "\nend")
        chunk()
    except Exception as e:
        print("[!] runtime error:", e)

    try:
        t = lua.eval("_KF_TRACE")
        n = int(t["n"]) if t and t["n"] else 0
        entries = []
        for i in range(1, n + 1):
            e = t["entries"][i]
            if e is None:
                continue
            entries.append({
                "kind": str(e["kind"]),
                "tag": str(e["payload"]["tag"]),
                "ret": str(e["payload"].get("ret", "")),
            })
        return entries
    except Exception as e:
        print("[!] trace pull failed:", e)
        return []

def static_walk(bytecode):
    out = []
    for i in range(0, len(bytecode), 4):
        chunk = bytecode[i:i + 4]
        if len(chunk) < 4:
            break
        out.append((i, chunk[0], chunk[1], chunk[2], chunk[3]))
    return out

# ----------------------------------------------------------------------
# hex helpers
# ----------------------------------------------------------------------

def hex_dump(data, width=16):
    lines = []
    for i in range(0, len(data), width):
        row = data[i:i + width]
        hexs = " ".join(f"{b:02x}" for b in row)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append(f"{i:08x}  {hexs:<{width*3}}  {asc}")
    return "\n".join(lines)

# ----------------------------------------------------------------------
# driver
# ----------------------------------------------------------------------

def deobf(input_path, out_dir=None):
    src = Path(input_path).read_text(encoding="utf-8", errors="ignore")
    out_dir = Path(out_dir) if out_dir else Path("deobf_out")
    out_dir.mkdir(parents=True, exist_ok=True)

    bW = extract_bW(src)
    (out_dir / "bW.bin").write_bytes(bW)
    (out_dir / "bW.hex").write_text(hex_dump(bW), encoding="utf-8")

    j0 = extract_j0(src)
    if j0:
        (out_dir / "j0.bin").write_bytes(j0)
        (out_dir / "j0.hex").write_text(hex_dump(j0), encoding="utf-8")
        dec = decode_j0(j0)
        (out_dir / "bytecode.bin").write_bytes(dec)
        (out_dir / "bytecode.hex").write_text(hex_dump(dec), encoding="utf-8")

    handlers = extract_handlers(src)
    with (out_dir / "handlers.txt").open("w", encoding="utf-8") as f:
        for i, (bound, body) in enumerate(handlers, 1):
            f.write(f"# {i} u < {bound}\n{body}\n\n")

    consts = extract_loader_constants(src)
    with (out_dir / "loader_consts.txt").open("w", encoding="utf-8") as f:
        for k, v in consts.items():
            f.write(f"{k} = {v}\n")

    probes = extract_antitamper(src)
    with (out_dir / "antitamper.txt").open("w", encoding="utf-8") as f:
        for k, v in probes.items():
            f.write(f"{k}: {v}\n")

    patched = patch_probes(src)
    (out_dir / "patched.lua").write_text(patched, encoding="utf-8")

    entries = run_instrumented(patched)
    with (out_dir / "opcode_trace.jsonl").open("w", encoding="utf-8") as f:
        for e in entries:
            f.write(json.dumps(e) + "\n")

    if not entries and j0:
        walk = static_walk(decode_j0(j0))
        with (out_dir / "bytecode_walk.txt").open("w", encoding="utf-8") as f:
            for off, op, a, b, c in walk:
                f.write(f"{off:06x}  op={op:02x}  a={a:02x}  b={b:02x}  c={c:02x}\n")

    print(f"bW: {len(bW)}b")
    print(f"handlers: {len(handlers)}")
    print(f"trace: {len(entries)}")
    print(f"-> {out_dir}")

if __name__ == "__main__":
    src_file = sys.argv[1] if len(sys.argv) > 1 else "input.lua"
    out = sys.argv[2] if len(sys.argv) > 2 else "deobf_out"
    deobf(src_file, out)

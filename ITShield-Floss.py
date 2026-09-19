#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════╗
║   🛡️  ITShield-Floss v1.0  —  Light Edition (All-in-One)         ║
║   Advanced String Extraction & Malware Analysis Tool             ║
║   Inspired by FLARE-FLOSS (Mandiant) —                           ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
    python ITShield-Floss.py                          # GUI
    python ITShield-Floss.py <file>                   # CLI
    python ITShield-Floss.py <file> --export csv|json|txt|yara
    python ITShield-Floss.py <file> --find "ITS" --debug
    python ITShield-Floss.py --selftest

Optional deps:
    pip install numpy pefile capstone unicorn tkinterdnd2
"""

import sys
import os
import re
import csv
import json
import time
import struct
import base64
import hashlib
import datetime
import threading
import importlib.util
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple, Optional, Callable
import warnings
warnings.filterwarnings('ignore', category=DeprecationWarning)
try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False

try:
    import unicorn
    try:
        from unicorn import x86_const as UC
    except ImportError:
        import unicorn.x86_const as UC
    HAS_UNICORN = True
except ImportError:
    HAS_UNICORN = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

APP_NAME    = "ITShield-Floss"
APP_VERSION = "1.0"
APP_ICON    = "(-!-)"
APP_AUTHOR  = "ITShield Team"
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))

def load_external_patterns() -> list:
    extra = []
    try:
        path = os.path.join(SCRIPT_DIR, "its_patterns.json")
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                for item in json.load(f):
                    pat = item.get("pattern")
                    if pat:
                        extra.append((
                            pat.encode() if isinstance(pat, str) else pat,
                            float(item.get("score", 0.8)),
                            item.get("label", "External IOC")))
    except Exception:
        pass
    return extra


EXTRA_PATTERNS = load_external_patterns()


def rc4(key: bytes, data: bytes) -> bytes:
    if not key:
        return data
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) & 0xFF
        S[i], S[j] = S[j], S[i]
    out = bytearray()
    i = j = 0
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out)


CUSTOM_DECODERS: Dict[str, Callable] = {}


def load_plugins():
    try:
        path = os.path.join(SCRIPT_DIR, "its_plugins.py")
        if os.path.exists(path):
            spec = importlib.util.spec_from_file_location(
                "its_plugins", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "register"):
                mod.register(CUSTOM_DECODERS)
    except Exception as e:
        print(f"[plugin] load failed: {e}")


class Theme:
    BG_MAIN      = "#f6f8fa"
    BG_CARD      = "#ffffff"
    BG_HOVER     = "#eaeef2"
    BG_SELECTED  = "#dbeafe"
    BORDER       = "#d0d7de"
    TEXT_PRIMARY = "#1f2328"
    TEXT_SECOND  = "#57606a"
    TEXT_MUTED   = "#8c959f"

    ACCENT        = "#0969da"
    ACCENT_HOVER  = "#0757ba"
    ACCENT_GREEN  = "#1a7f37"
    ACCENT_RED    = "#cf222e"
    WARN_BG       = "#fff8c5"
    WARN_BORDER   = "#d4a72c"
    WARN_TEXT     = "#7d4e00"

    TYPE_COLORS = {
        "Static ASCII":         "#57606a",
        "Static Unicode":       "#0969da",
        "Stack String":         "#bc4c00",
        "Tight String":         "#bf3989",
        "DotNet String":        "#0550ae",
        "Decoded (XOR)":        "#cf222e",
        "Decoded (Base64)":     "#8250df",
        "Decoded (Reversed)":   "#1a7f37",
        "Decoded (ROT13)":      "#9a6700",
        "Decoded (MultiXOR)":   "#b35900",
        "Decoded (Additive)":   "#116329",
        "Decoded (RollingXOR)": "#6639ba",
        "Decoded (Emulated)":   "#e16f24",
        "Decoded (Manual)":     "#0550ae",
        "Decoded (Plugin)":     "#0550ae",
        "Suspicious Pattern":   "#cf222e",
        "Sensitive / Secret":   "#a40e26",
    }

    FONT_HEADER = ("Segoe UI", 16, "bold")
    FONT_NORMAL = ("Segoe UI", 9)
    FONT_SMALL  = ("Segoe UI", 8)
    FONT_MONO   = ("Consolas", 9)

    @classmethod
    def apply(cls, root: tk.Tk):
        root.configure(bg=cls.BG_MAIN)
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TFrame', background=cls.BG_MAIN)
        style.configure('TLabel', background=cls.BG_MAIN,
                        foreground=cls.TEXT_PRIMARY, font=cls.FONT_NORMAL)
        style.configure('Treeview', background=cls.BG_CARD,
                        foreground=cls.TEXT_PRIMARY,
                        fieldbackground=cls.BG_CARD,
                        borderwidth=0, rowheight=24, font=cls.FONT_MONO)
        style.map('Treeview',
                  background=[('selected', cls.ACCENT)],
                  foreground=[('selected', '#ffffff')])
        style.configure('Treeview.Heading', background=cls.BG_MAIN,
                        foreground=cls.TEXT_SECOND,
                        font=("Segoe UI", 9, "bold"),
                        borderwidth=0, relief='flat')
        style.map('Treeview.Heading',
                  background=[('active', cls.BG_HOVER)])
        style.configure('TScrollbar', background=cls.BG_HOVER,
                        troughcolor=cls.BG_CARD, bordercolor=cls.BG_CARD,
                        arrowcolor=cls.TEXT_SECOND)
        style.configure('TProgressbar', background=cls.ACCENT,
                        troughcolor=cls.BG_HOVER, borderwidth=0,
                        lightcolor=cls.ACCENT, darkcolor=cls.ACCENT)
        style.configure('TCombobox', fieldbackground=cls.BG_CARD,
                        foreground=cls.TEXT_PRIMARY,
                        background=cls.BG_HOVER,
                        arrowcolor=cls.TEXT_SECOND,
                        bordercolor=cls.BORDER)
        style.map('TCombobox', fieldbackground=[('readonly', cls.BG_CARD)])


#  Data types

class StringType(Enum):
    STATIC_ASCII     = "Static ASCII"
    STATIC_UNICODE   = "Static Unicode"
    STACK_STRING     = "Stack String"
    TIGHT_STRING     = "Tight String"
    DOTNET_STRING    = "DotNet String"
    DECODED_XOR      = "Decoded (XOR)"
    DECODED_B64      = "Decoded (Base64)"
    DECODED_REVERSE  = "Decoded (Reversed)"
    DECODED_ROT13    = "Decoded (ROT13)"
    DECODED_MULTIXOR = "Decoded (MultiXOR)"
    DECODED_ADDITIVE = "Decoded (Additive)"
    DECODED_ROLLING  = "Decoded (RollingXOR)"
    DECODED_EMULATED = "Decoded (Emulated)"
    DECODED_MANUAL   = "Decoded (Manual)"
    DECODED_PLUGIN   = "Decoded (Plugin)"
    SUSPICIOUS       = "Suspicious Pattern"
    SENSITIVE        = "Sensitive / Secret"

    @classmethod
    def from_value(cls, v: str) -> "StringType":
        try:
            return cls(v)
        except ValueError:
            return cls.STATIC_ASCII


@dataclass
class ExtractedString:
    value: str
    type: StringType
    offset: int = 0
    virtual_address: int = 0
    section: str = ""
    score: float = 0.5
    encoding: str = "ascii"
    length: int = 0
    context: str = ""

    def to_dict(self) -> dict:
        return {"value": self.value, "type": self.type.value,
                "offset": hex(self.offset),
                "virtual_address": hex(self.virtual_address),
                "section": self.section, "score": round(self.score, 2),
                "encoding": self.encoding, "length": self.length,
                "context": self.context}

    @classmethod
    def from_dict(cls, d: dict) -> "ExtractedString":
        def _int(x):
            try:
                if isinstance(x, str) and x.startswith("0x"):
                    return int(x, 16)
                return int(x or 0)
            except Exception:
                return 0
        return cls(value=d.get("value", ""),
                   type=StringType.from_value(d.get("type", "")),
                   offset=_int(d.get("offset")),
                   virtual_address=_int(d.get("virtual_address")),
                   section=d.get("section", ""),
                   score=float(d.get("score", 0.5)),
                   encoding=d.get("encoding", "ascii"),
                   length=int(d.get("length", 0)),
                   context=d.get("context", ""))


@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    characteristics: int
    entropy: float = 0.0

    @property
    def is_code(self) -> bool:
        return bool(self.characteristics & 0x20000000)


@dataclass
class PEInfo:
    is_valid: bool = False
    machine: str = ""
    is_64bit: bool = False
    entry_point: int = 0
    image_base: int = 0
    subsystem: str = ""
    compile_time: str = ""
    sections: List[PESection] = field(default_factory=list)
    imports: Dict[str, List[str]] = field(default_factory=dict)
    exports: List[str] = field(default_factory=list)


@dataclass
class AnalysisOptions:
    extract_static: bool = True
    extract_unicode: bool = True
    extract_stack: bool = True
    extract_decoded: bool = True
    extract_suspicious: bool = True
    scan_dotnet: bool = True
    scan_resources: bool = True
    scan_multixor: bool = True
    scan_additive: bool = True
    scan_rolling: bool = True
    use_emulation: bool = True
    min_length: int = 4
    max_length: int = 4096
    min_score: float = 0.0
    max_results: int = 200000
    xor_limit: int = 0            # 0 = whole file
    disasm_timeout: float = 20.0
    emu_max_functions: int = 300
    emu_total_timeout: float = 90.0


@dataclass
class AnalysisResult:
    filepath: str = ""
    file_size: int = 0
    pe_info: Optional[PEInfo] = None
    strings: List[ExtractedString] = field(default_factory=list)
    packer_indicators: List[str] = field(default_factory=list)
    phase_stats: Dict[str, int] = field(default_factory=dict)
    info_notes: List[str] = field(default_factory=list)   
    duration: float = 0.0
    errors: List[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.strings)

    @property
    def counts_by_type(self) -> dict:
        counts = {}
        for s in self.strings:
            counts[s.type.value] = counts.get(s.type.value, 0) + 1
        return counts


def _score_meaningful(value: str) -> float:
    if not value:
        return 0.0
    score = 0.2
    common_letters = 'etaoinshrdlucmfwypvbgkjqxz'
    ls = {c: i for i, c in enumerate(common_letters)}
    total = sum((26 - ls[c]) / 26 for c in value.lower() if c in ls)
    score += (total / len(value)) * 0.4
    for w in ('the', 'and', 'ing', 'ion', 'ent', 'tio', 'for', 'her',
              'dll', 'exe', 'http', 'file', 'pass', 'key'):
        if w in value.lower():
            score += 0.15
            break
    return min(score, 1.0)


def _word_count(value: str) -> int:
    return len(re.findall(r'[A-Za-z]{3,}', value))


def _looks_like_real_text(value: str) -> bool:
    """Signature of genuine text: several 3+ letter words in a
    sufficiently long run. Random XOR junk rarely matches."""
    return _word_count(value) >= 3 and len(value) >= 15


def _score_decoded(value: str, key: int = 0) -> float:
    """Random junk can no longer reach 0.9-1.0 via a lucky keyword."""
    if not value:
        return 0.0
    score = 0.25
    if len(set(value)) >= len(value) * 0.4:
        score += 0.1
    words = re.findall(r'[A-Za-z]{3,}', value)
    if len(words) >= 2:
        score += 0.15
    if len(words) >= 3:
        score += 0.1
    common = ('http', 'file', 'open', 'read', 'dll', 'exe', 'cmd',
              'exec', 'load', 'lib', 'proc', 'addr', 'kernel', 'pass')
    lower = value.lower()
    if len(value) >= 12 and any(w in lower for w in common):
        score += 0.25
    elif any(w in lower for w in common):
        score += 0.05
    letters = [c.lower() for c in value if c.isalpha()]
    if letters:
        freq = 'etaoinshrdlucmfwypvbgkjqxz'
        ls = {c: i for i, c in enumerate(freq)}
        eng = sum((26 - ls[c]) / 26
                  for c in letters if c in ls) / len(letters)
        if eng >= 0.62:
            score += 0.1
        elif eng < 0.55:
            score -= 0.2
    alnum = sum(c.isalnum() for c in value) / max(len(value), 1)
    if alnum > 0.6:
        score += 0.1
    if re.search(r'(.)\1{3,}', value):
        score -= 0.15
    if key in (0xFF, 0xAA, 0x55):
        score -= 0.1
    if len(words) <= 1:
        score = min(score, 0.75)
    return max(0.0, min(score, 1.0))


def _dedupe(results: List[ExtractedString]) -> List[ExtractedString]:
    seen, out = set(), []
    for r in results:
        k = (r.value, r.encoding)
        if k not in seen:
            seen.add(k)
            out.append(r)
    return out


def _ranked(results: List[ExtractedString], n: int
            ) -> List[ExtractedString]:
    """Score-ranked truncation WITH reservation: multi-word real text
    always keeps up to half the quota — lucky junk can never evict it."""
    if len(results) <= n:
        return results
    real, other = [], []
    for s in results:
        (real if _looks_like_real_text(s.value) else other).append(s)
    keyf = lambda s: (s.score, s.length)
    real.sort(key=keyf, reverse=True)
    other.sort(key=keyf, reverse=True)
    keep_real = max(250, n // 2)
    merged = real[:keep_real] + other
    merged.sort(key=keyf, reverse=True)
    return merged[:n]


def _max_printable_run(data) -> int:
    """Longest printable-ASCII streak (numpy fast path)."""
    if HAS_NUMPY:
        a = data if isinstance(data, np.ndarray) \
            else np.frombuffer(bytes(data), dtype=np.uint8)
        if a.size == 0:
            return 0
        mask = (a >= 0x20) & (a <= 0x7e)
        if not mask.any():
            return 0
        d = np.diff(np.concatenate(([False], mask, [False]))
                    .astype(np.int8))
        starts = np.flatnonzero(d == 1)
        ends = np.flatnonzero(d == -1)
        return int((ends - starts).max()) if starts.size else 0
    best = cur = 0
    for b in data[:262144]:
        if 32 <= b <= 126:
            cur += 1
            if cur > best:
                best = cur
        else:
            cur = 0
    return best


def hexdump(data: bytes, offset: int, before: int = 64,
            after: int = 256, width: int = 16) -> str:
    if not data or offset < 0 or offset >= len(data):
        return "(no data at this offset)"
    start = max(0, offset - before)
    end = min(len(data), offset + after)
    chunk = data[start:end]
    lines = []
    for i in range(0, len(chunk), width):
        row = chunk[i:i + width]
        hexs = ' '.join(f'{b:02x}' for b in row)
        asc = ''.join(chr(b) if 32 <= b <= 126 else '·' for b in row)
        marker = ('  <-- here'
                  if start + i <= offset < start + i + len(row) else '')
        lines.append(f'{start + i:08x}  {hexs:<{width * 3 - 1}}  '
                     f'|{asc}|{marker}')
    return '\n'.join(lines)


class PEAnalyzer:

    @staticmethod
    def is_pe(filepath: str) -> bool:
        try:
            with open(filepath, 'rb') as f:
                if f.read(2) != b'MZ':
                    return False
                f.seek(0x3C)
                pe_offset = struct.unpack('<I', f.read(4))[0]
                f.seek(pe_offset)
                return f.read(4) == b'PE\x00\x00'
        except Exception:
            return False

    @staticmethod
    def parse(filepath: str) -> PEInfo:
        info = PEInfo()
        if not HAS_PEFILE:
            return info
        try:
            pe = pefile.PE(filepath, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            ])
        except Exception:
            return info

        info.is_valid = True
        machine = pe.FILE_HEADER.Machine
        if machine == 0x8664:
            info.machine, info.is_64bit = "x64", True
        elif machine == 0x014C:
            info.machine = "x86"
        elif machine == 0xAA64:
            info.machine = "ARM64"
        else:
            info.machine = hex(machine)

        info.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        info.image_base = pe.OPTIONAL_HEADER.ImageBase
        subsystem_map = {1: "Native", 2: "Windows GUI",
                         3: "Windows CUI", 10: "EFI Application"}
        info.subsystem = subsystem_map.get(
            pe.OPTIONAL_HEADER.Subsystem, "Unknown")

        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            info.compile_time = datetime.datetime.fromtimestamp(
                ts, tz=datetime.timezone.utc
            ).strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            info.compile_time = "Unknown"

        for section in pe.sections:
            name = section.Name.decode('utf-8',
                                       errors='ignore').rstrip('\x00')
            info.sections.append(PESection(
                name=name,
                virtual_address=section.VirtualAddress,
                virtual_size=section.Misc_VirtualSize,
                raw_offset=section.PointerToRawData,
                raw_size=section.SizeOfRawData,
                characteristics=section.Characteristics,
                entropy=section.get_entropy()))

        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore')
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode('utf-8',
                                                     errors='ignore'))
                    else:
                        funcs.append(f"Ordinal_{imp.ordinal}")
                info.imports[dll] = funcs

        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    info.exports.append(
                        exp.name.decode('utf-8', errors='ignore'))
        pe.close()
        return info

    @staticmethod
    def compute_hashes(filepath: str) -> Tuple[str, str]:
        md5, sha256 = hashlib.md5(), hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                md5.update(chunk)
                sha256.update(chunk)
        return md5.hexdigest(), sha256.hexdigest()


class PackerDetector:
    SIGNATURES = ['upx', 'themida', 'vmp', 'vmprotect', 'aspack',
                  'petite', 'nspack', 'enigma', 'mpress', 'pecompact',
                  'obsidium']

    @staticmethod
    def detect(pe_info: Optional[PEInfo]) -> List[str]:
        if not pe_info or not pe_info.is_valid:
            return []
        out = []
        names = [s.name.lower() for s in pe_info.sections]
        for n in names:
            for sig in PackerDetector.SIGNATURES:
                if sig in n:
                    out.append(f"Packer section: '{n}' "
                               f"(matches '{sig}')")
                    break
        code_secs = [s for s in pe_info.sections if s.is_code]
        if code_secs:
            hi = max(s.entropy for s in code_secs)
            if hi >= 7.2:
                out.append(f"High entropy code section "
                           f"({hi:.2f}/8.00) — packed?")
        total_imports = sum(len(v) for v in pe_info.imports.values())
        if total_imports == 0:
            out.append("No imports at all — strongly indicates packing")
        elif total_imports < 8:
            out.append(f"Very few imports ({total_imports}) — "
                       f"possible packing")
        weird = [s.name for s in pe_info.sections
                 if s.raw_size == 0 and s.virtual_size > 0
                 and s.name.lower() not in ('.bss', '.tbss')]
        if weird:
            out.append(f"Sections with no raw data: "
                       f"{', '.join(weird[:3])}")
        return out


class StaticStringExtractor:

    SUSPICIOUS_PATTERNS = [
        (rb'(?i)(https?|ftp)://[^\x00\s]{5,}', 0.90, "URL"),
        (rb'(?i)[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
         0.80, "Email"),
        (rb'(?i)(cmd|powershell|wscript|cscript)\.exe',
         0.95, "Shell execution"),
        (rb'(?i)(HKEY_[A-Z_]+)', 0.85, "Registry key"),
        (rb'(?i)(CreateProcess|VirtualAlloc|WriteProcessMemory|'
         rb'LoadLibrary|GetProcAddress|SetWindowsHookEx)',
         0.90, "Suspicious API"),
        (rb'(?i)(\\Windows\\|\\System32\\|\\Temp\\|\\AppData\\)',
         0.85, "Filesystem path"),
        (rb'(?i)(%APPDATA%|%TEMP%|%SYSTEMROOT%|%PROGRAMFILES%)',
         0.85, "Env path"),
        (rb'(?i)(SOFTWARE\\Microsoft\\Windows)', 0.80, "Registry path"),
        (rb'(?i)(ransom|encrypt|decrypt|bitcoin|wallet|tor\b)',
         0.75, "Malware keyword"),
        (rb'(?i)(keylog|screenshot|persistence|backdoor)',
         0.75, "Malware keyword"),
        (rb'(?i)(\.onion|\.tk|\.ml|\.ga|\.cf)', 0.80, "Suspicious TLD"),
        (rb'(?i)(taskkill|netsh|attrib|vssadmin|bcdedit|wbadmin)',
         0.85, "Defense evasion"),
    ]

    SENSITIVE_PATTERNS = [
        (rb'AKIA[0-9A-Z]{16}', 0.99, "AWS Access Key"),
        (rb'-----BEGIN [A-Z ]*PRIVATE KEY-----', 1.00, "Private Key"),
        (rb'sk_live_[0-9a-zA-Z]{24}', 0.99, "Stripe Secret Key"),
        (rb'ghp_[A-Za-z0-9]{36}', 0.99, "GitHub Token"),
        (rb'xox[baprs]-[A-Za-z0-9\-]{10,}', 0.95, "Slack Token"),
        (rb'AIza[0-9A-Za-z_\-]{35}', 0.95, "Google API Key"),
        (rb'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', 0.80, "Bitcoin Address"),
        (rb'bc1[a-z0-9]{20,62}', 0.80, "Bitcoin (Bech32)"),
        (rb'(?i)xmr:[0-9A-Za-z]{90,110}', 0.90, "Monero Address"),
        (rb'(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]'
         rb'\s*["\']?[A-Za-z0-9_\-]{16,}', 0.85, "Embedded Secret"),
    ]

    COMMON_WORDS = ['the', 'and', 'for', 'not', 'with', 'from', 'this',
                    'error', 'file', 'open', 'read', 'write', 'close',
                    'kernel', 'system', 'driver', 'module', 'process',
                    'http', 'https', 'www', 'com', 'org', 'net']

    def __init__(self, min_length: int = 4, max_length: int = 4096):
        self.min_length = min_length
        self.max_length = max_length
        self.all_suspicious = (list(self.SUSPICIOUS_PATTERNS)
                               + EXTRA_PATTERNS)

    def extract_ascii(self, data: bytes,
                      base_offset: int = 0) -> List[ExtractedString]:
        results = []
        pattern = (rb'[\x20-\x7e]{' +
                   str(self.min_length).encode() + rb',}')
        for match in re.finditer(pattern, data):
            raw = match.group()
            if len(raw) > self.max_length:
                continue
            value = raw.decode('ascii', errors='ignore')
            results.append(ExtractedString(
                value=value, type=StringType.STATIC_ASCII,
                offset=base_offset + match.start(),
                score=self._score_string(value),
                encoding="ascii", length=len(value)))
        return results

    def extract_unicode(self, data: bytes,
                        base_offset: int = 0) -> List[ExtractedString]:
        results = []
        pattern = (rb'(?:[\x20-\x7e]\x00){' +
                   str(self.min_length).encode() + rb',}')
        for match in re.finditer(pattern, data):
            raw = match.group()
            if len(raw) > self.max_length * 2:
                continue
            try:
                value = raw.decode('utf-16-le', errors='ignore')
            except Exception:
                continue
            results.append(ExtractedString(
                value=value, type=StringType.STATIC_UNICODE,
                offset=base_offset + match.start(),
                score=self._score_string(value),
                encoding="utf-16-le", length=len(value)))
        return results

    def find_suspicious(self, data: bytes,
                        base_offset: int = 0) -> List[ExtractedString]:
        results, seen = [], set()

        def emit(match, score, label, stype):
            value = match.group().decode('ascii', errors='ignore')
            k = (value, label)
            if k in seen:
                return
            seen.add(k)
            results.append(ExtractedString(
                value=value, type=stype,
                offset=base_offset + match.start(),
                score=score, encoding="ascii", length=len(value),
                context=label))

        for pattern, score, label in self.all_suspicious:
            try:
                it = re.finditer(pattern, data)
            except re.error:
                continue
            for match in it:
                emit(match, score, label, StringType.SUSPICIOUS)
        for pattern, score, label in self.SENSITIVE_PATTERNS:
            for match in re.finditer(pattern, data):
                emit(match, score, label, StringType.SENSITIVE)
        return results

    def _score_string(self, value: str) -> float:
        score = 0.3
        if len(value) >= 8:
            score += 0.1
        if len(value) >= 16:
            score += 0.1
        lower = value.lower()
        if any(w in lower for w in self.COMMON_WORDS):
            score += 0.1
        if len(set(value)) >= len(value) * 0.5:
            score += 0.15
        if re.search(r'(.)\1{4,}', value):
            score -= 0.2
        if sum(c.isalnum() for c in value) / max(len(value), 1) > 0.7:
            score += 0.15
        if '\\' in value or '/' in value:
            score += 0.05
        return min(score, 1.0)

class DotNetStringExtractor:

    @staticmethod
    def extract(data: bytes,
                min_length: int = 4) -> List[ExtractedString]:
        results = []
        us_idx = data.find(b'#US\x00')
        if us_idx < 8:
            return results
        bsjb = data.rfind(b'BSJB', 0, us_idx)
        if bsjb == -1:
            return results
        try:
            us_off = struct.unpack_from('<I', data, us_idx - 8)[0]
            us_size = struct.unpack_from('<I', data, us_idx - 4)[0]
        except struct.error:
            return results

        pos = bsjb + us_off
        end = min(pos + us_size, len(data))
        n = len(data)

        while pos < end - 1:
            try:
                b0 = data[pos]
                if b0 & 0x80 == 0:
                    length, pos = b0, pos + 1
                elif b0 & 0xC0 == 0x80:
                    length = ((b0 & 0x3F) << 8) | data[pos + 1]
                    pos += 2
                else:
                    length = ((b0 & 0x1F) << 24) | \
                             (data[pos + 1] << 16) | \
                             (data[pos + 2] << 8) | data[pos + 3]
                    pos += 4
            except IndexError:
                break
            if length <= 1 or pos + length > n:
                break

            raw = data[pos:pos + length - 1]
            blob_start = pos
            pos += length
            try:
                value = raw.decode('utf-16-le', errors='ignore')
            except Exception:
                continue
            if len(value) >= min_length:
                ratio = sum(c.isalnum() or c.isspace()
                            for c in value) / len(value)
                if ratio >= 0.5:
                    results.append(ExtractedString(
                        value=value, type=StringType.DOTNET_STRING,
                        offset=blob_start, score=0.85,
                        encoding="utf-16-le", length=len(value),
                        context=".NET #US user-string heap"))
        return results


class ResourceStringExtractor:

    @staticmethod
    def extract(filepath: str,
                min_length: int = 6) -> List[ExtractedString]:
        if not HAS_PEFILE:
            return []
        out = []
        try:
            pe = pefile.PE(filepath, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                pe.close()
                return []

            def walk(entries, path=""):
                for entry in entries:
                    if getattr(entry, 'name', None):
                        label = entry.name.string.decode(
                            'utf-8', errors='ignore')
                    else:
                        rid = entry.struct.Id
                        label = (str(pefile.RESOURCE_TYPE.get(rid, rid))
                                 if path == "" else str(rid))
                    cur = f"{path}/{label}"
                    if hasattr(entry, 'directory'):
                        walk(entry.directory.entries, cur)
                    elif hasattr(entry, 'data'):
                        try:
                            blob = pe.get_data(
                                entry.data.struct.OffsetToData,
                                entry.data.struct.Size)
                        except Exception:
                            continue
                        ex = StaticStringExtractor(
                            min_length=min_length)
                        for s in (ex.extract_ascii(blob) +
                                  ex.extract_unicode(blob)):
                            s.section = f"RSRC:{cur}"
                            s.score = min(s.score + 0.15, 1.0)
                            s.context = f"PE Resource {cur}"
                            out.append(s)

            walk(pe.DIRECTORY_ENTRY_RESOURCE.entries)
            pe.close()
        except Exception:
            pass
        return out



class StackStringAnalyzer:

    KNOWN_NAMES = ['dll', 'exe', 'sys', 'kernel32', 'ntdll', 'user32',
                   'advapi', 'ws2_32', 'wininet', 'crypt', 'shell',
                   'cmd', 'process', 'thread', 'file', 'alloc']

    SIZE_MAP = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8}

    STACK_WRITE_RE = re.compile(
        r'(byte|word|dword|qword) ptr \[(?:r|e)(?:sp|bp)'
        r'(?:\s*([+-])\s*(0x[0-9a-fA-F]+))?\],\s*(0x[0-9a-fA-F]+)')

    def __init__(self, min_length: int = 4):
        self.min_length = min_length
        self._md32 = self._md64 = None
        if HAS_CAPSTONE:
            self._md32 = capstone.Cs(capstone.CS_ARCH_X86,
                                     capstone.CS_MODE_32)
            self._md64 = capstone.Cs(capstone.CS_ARCH_X86,
                                     capstone.CS_MODE_64)

    def analyze(self, code: bytes, base_va: int = 0,
                is_64bit: bool = False, time_budget: float = 20.0,
                cancel_check: Optional[Callable] = None
                ) -> Tuple[List[ExtractedString], bool]:
        if not HAS_CAPSTONE:
            return [], False
        md = self._md64 if is_64bit else self._md32
        start, stack_writes = time.time(), {}
        count, truncated = 0, False
        try:
            for insn in md.disasm(code, base_va):
                count += 1
                if count % 2048 == 0:
                    if cancel_check and cancel_check():
                        truncated = True
                        break
                    if time.time() - start > time_budget:
                        truncated = True
                        break
                if insn.mnemonic != 'mov':
                    continue
                m = self.STACK_WRITE_RE.match(insn.op_str)
                if not m:
                    continue
                size_s, sign, off_s, val_s = m.groups()
                size = self.SIZE_MAP[size_s]
                off = int(off_s, 16) if off_s else 0
                if sign == '-':
                    off = -off
                val = int(val_s, 16)
                if val == 0:
                    continue
                for k in range(size):
                    bv = (val >> (8 * k)) & 0xFF
                    if bv:
                        stack_writes.setdefault(off + k, []).append(
                            (bv, insn.address))
        except Exception:
            pass
        return self._reconstruct(stack_writes, base_va), truncated

    def find_tight_strings(self, code: bytes, base_va: int = 0,
                           is_64bit: bool = False,
                           time_budget: float = 20.0,
                           cancel_check: Optional[Callable] = None
                           ) -> Tuple[List[ExtractedString], bool]:
        if not HAS_CAPSTONE:
            return [], False
        md = self._md64 if is_64bit else self._md32
        start, results = time.time(), []
        buf, addrs, count, truncated = [], [], 0, False
        try:
            for insn in md.disasm(code, base_va):
                count += 1
                if count % 2048 == 0:
                    if cancel_check and cancel_check():
                        truncated = True
                        break
                    if time.time() - start > time_budget:
                        truncated = True
                        break
                if insn.mnemonic == 'mov':
                    m = re.match(
                        r'([a-d][lh]|[sil]l|[bd]l|r\d+b),'
                        r'\s*(0x[0-9a-fA-F]+)',
                        insn.op_str)
                    if m:
                        val = int(m.group(2), 16)
                        if 0x20 <= val <= 0x7e:
                            buf.append(val)
                            addrs.append(insn.address)
                        elif len(buf) < self.min_length:
                            buf, addrs = [], []
                elif insn.mnemonic in ('call', 'ret', 'jmp'):
                    if len(buf) >= self.min_length:
                        try:
                            value = bytes(buf).decode('ascii')
                            results.append(ExtractedString(
                                value=value,
                                type=StringType.TIGHT_STRING,
                                offset=addrs[0],
                                virtual_address=addrs[0],
                                section="code", score=0.6,
                                encoding="ascii", length=len(value),
                                context="Register-based construction"))
                        except Exception:
                            pass
                    buf, addrs = [], []
        except Exception:
            pass
        return results, truncated

    def _reconstruct(self, stack_writes,
                     base_va) -> List[ExtractedString]:
        results = []
        if not stack_writes:
            return results
        offsets = sorted(stack_writes.keys())
        groups, current = [], []
        for i, offset in enumerate(offsets):
            if current and offset - offsets[i - 1] > 8:
                if len(current) >= self.min_length:
                    groups.append(current)
                current = []
            current.append(offset)
        if len(current) >= self.min_length:
            groups.append(current)

        for group in groups:
            blist, addresses = [], []
            for offset in group:
                value, addr = stack_writes[offset][-1]
                if 0x20 <= value <= 0x7e:
                    blist.append(value)
                    addresses.append(addr)
            if len(blist) >= self.min_length:
                try:
                    value = bytes(blist).decode('ascii')
                    results.append(ExtractedString(
                        value=value, type=StringType.STACK_STRING,
                        offset=addresses[0] if addresses else 0,
                        virtual_address=(addresses[0] if addresses
                                         else base_va),
                        section="code", score=self._score(value),
                        encoding="ascii", length=len(value),
                        context=f"{len(addresses)} stack writes"))
                except Exception:
                    pass
        return results

    def _score(self, value: str) -> float:
        score = 0.4
        if len(set(value)) >= len(value) * 0.6:
            score += 0.2
        if re.search(r'[a-zA-Z]{3,}', value):
            score += 0.2
        if any(n in value.lower() for n in self.KNOWN_NAMES):
            score += 0.3
        return min(score, 1.0)


class FastDecoder:

    XOR_CHUNK    = 4 * 1024 * 1024
    XOR_OVERLAP  = 64 * 1024
    XOR_TOP_N    = 1200
    PER_KEY_KEEP = 4

    def __init__(self, min_length: int = 4, xor_limit: int = 0):
        self.min_length = min_length
        self.xor_limit = xor_limit or 0

    def analyze(self, data: bytes, base_offset: int = 0,
                cancel_check: Optional[Callable] = None
                ) -> List[ExtractedString]:
        results = []
        for fn in (self.find_xor, self.find_base64, self.find_reversed,
                   self.find_rot13, self._run_plugins):
            if cancel_check and cancel_check():
                break
            results += fn(data, base_offset, cancel_check)
        return results

    @staticmethod
    def _cap_per_key(by_key: Dict[int, list], keep: int
                     ) -> List[ExtractedString]:
        capped = []
        for _k, lst in by_key.items():
            if len(lst) > keep:
                lst.sort(key=lambda s: (s.score, s.length), reverse=True)
                lst = lst[:keep]
            capped.extend(lst)
        return capped

    def find_xor(self, data, base_offset=0, cancel_check=None):
        if HAS_NUMPY:
            r = self._xor_numpy(data, base_offset, cancel_check)
            if r is not None:
                return r
        return self._xor_python(data, base_offset, cancel_check)

    def _xor_numpy(self, data, base_offset, cancel_check):
        try:
            by_key: Dict[int, list] = {}
            total = 0
            n = len(data)
            if self.xor_limit:
                n = min(n, self.xor_limit)
            step, overlap = self.XOR_CHUNK, self.XOR_OVERLAP
            i = 0
            while i < n:
                if cancel_check and cancel_check():
                    break
                seg_start = max(0, i - overlap) if i else 0
                seg_end = min(n, i + step)
                seg = data[seg_start:seg_end]
                arr = np.frombuffer(seg, dtype=np.uint8)
                is_last = seg_end >= n
                for key in range(1, 256):
                    if cancel_check and cancel_check():
                        break
                    decoded = np.bitwise_xor(arr, np.uint8(key))
                    mask = (decoded >= 0x20) & (decoded <= 0x7E)
                    padded = np.concatenate(([False], mask, [False]))
                    diffs = np.diff(padded.astype(np.int8))
                    starts = np.flatnonzero(diffs == 1)
                    ends = np.flatnonzero(diffs == -1)
                    lst = by_key.setdefault(key, [])
                    for s, e in zip(starts, ends):
                        if not is_last and int(e) == len(decoded):
                            continue
                        ln = int(e - s)
                        if self.min_length <= ln <= 4096:
                            value = decoded[s:e].tobytes()\
                                .decode('ascii')
                            score = _score_decoded(value, key)
                            if score >= 0.5:
                                lst.append(ExtractedString(
                                    value=value,
                                    type=StringType.DECODED_XOR,
                                    offset=base_offset + seg_start
                                    + int(s),
                                    score=score,
                                    encoding=f"xor-0x{key:02x}",
                                    length=ln,
                                    context=f"XOR key: 0x{key:02x}"))
                                total += 1
                i += step
                if total > 200_000:
                    by_key = {k: self._cap_per_key(
                        {k: v}, self.PER_KEY_KEEP * 4)
                        for k, v in by_key.items()}
                    total = sum(len(v) for v in by_key.values())
            return _ranked(_dedupe(self._cap_per_key(
                by_key, self.PER_KEY_KEEP)), self.XOR_TOP_N)
        except Exception:
            return None

    def _xor_python(self, data, base_offset, cancel_check):
        by_key: Dict[int, list] = {}
        n = len(data)
        if self.xor_limit:
            n = min(n, self.xor_limit)
        chunk, back = 1024 * 1024, 64 * 1024
        i = 0
        while i < n:
            if cancel_check and cancel_check():
                break
            seg_start = max(0, i - back) if i else 0
            seg_end = min(n, i + chunk)
            seg = data[seg_start:seg_end]
            is_last = seg_end >= n
            for key in range(1, 256):
                decoded = bytes(b ^ key for b in seg)
                lst = by_key.setdefault(key, [])
                for m in re.finditer(
                        rb'[\x20-\x7e]{%d,}' % self.min_length, decoded):
                    if not is_last and m.end() == len(decoded):
                        continue
                    value = m.group().decode('ascii')
                    if len(value) > 4096:
                        continue
                    score = _score_decoded(value, key)
                    if score >= 0.5:
                        lst.append(ExtractedString(
                            value=value, type=StringType.DECODED_XOR,
                            offset=base_offset + seg_start + m.start(),
                            score=score,
                            encoding=f"xor-0x{key:02x}",
                            length=len(value),
                            context=f"XOR key: 0x{key:02x}"))
            i += chunk
        return _ranked(_dedupe(self._cap_per_key(
            by_key, self.PER_KEY_KEEP)), self.XOR_TOP_N)

    def find_base64(self, data, base_offset=0, cancel_check=None):
        results = []
        for n, match in enumerate(
                re.finditer(rb'[A-Za-z0-9+/=]{16,}', data)):
            if n > 20000 or (n % 512 == 0 and cancel_check
                             and cancel_check()):
                break
            raw = match.group()
            try:
                padding = 4 - len(raw) % 4
                padded = (raw + b'=' * padding
                          if padding != 4 else raw)
                decoded = base64.b64decode(padded)
                if all(0x20 <= b <= 0x7e or b in (10, 13, 9)
                       for b in decoded) \
                        and len(decoded) >= self.min_length:
                    value = decoded.decode('ascii', errors='replace')
                    score = _score_decoded(value, 0)
                    if score >= 0.4:
                        results.append(ExtractedString(
                            value=value, type=StringType.DECODED_B64,
                            offset=base_offset + match.start(),
                            score=score, encoding="base64",
                            length=len(value),
                            context="B64: "
                                    f"{raw[:30].decode('ascii','ignore')}"
                                    f"..."))
            except Exception:
                continue
        return _ranked(results, 200)


    def find_reversed(self, data, base_offset=0, cancel_check=None):
        results = []
        for n, match in enumerate(re.finditer(rb'[\x20-\x7e]{6,}', data)):
            if n > 150000 or (n % 2048 == 0 and cancel_check
                              and cancel_check()):
                break
            try:
                original = match.group().decode('ascii')
                value = original[::-1]
                if value == original or \
                        sum(c.isalpha() for c in value) < 4:
                    continue
                score = _score_meaningful(value)
                if score >= 0.6:
                    results.append(ExtractedString(
                        value=value, type=StringType.DECODED_REVERSE,
                        offset=base_offset + match.start(), score=score,
                        encoding="reversed", length=len(value),
                        context=f"Reversed: {original[:30]}..."))
            except Exception:
                continue
            if len(results) >= 2000:
                break
        return _ranked(results, 100)


    def find_rot13(self, data, base_offset=0, cancel_check=None):
        results = []
        for n, match in enumerate(re.finditer(rb'[a-zA-Z]{5,}', data)):
            if n > 150000 or (n % 2048 == 0 and cancel_check
                              and cancel_check()):
                break
            raw = match.group().decode('ascii')
            value = self._rot13(raw)
            score = _score_meaningful(value)
            if score >= 0.7:
                results.append(ExtractedString(
                    value=value, type=StringType.DECODED_ROT13,
                    offset=base_offset + match.start(), score=score,
                    encoding="rot13", length=len(value),
                    context=f"ROT13 of: {raw}"))
            if len(results) >= 500:
                break
        return _ranked(results, 50)


    def _run_plugins(self, data, base_offset=0, cancel_check=None):
        if not CUSTOM_DECODERS:
            return []
        results = []
        chunk = data[:min(len(data), self.xor_limit or len(data))]
        for name, fn in CUSTOM_DECODERS.items():
            if cancel_check and cancel_check():
                break
            try:
                decoded = fn(chunk)
                if not isinstance(decoded, (bytes, bytearray)):
                    continue
                for m in re.finditer(
                        rb'[\x20-\x7e]{%d,}' % self.min_length,
                        bytes(decoded)):
                    value = m.group().decode('ascii')
                    score = _score_meaningful(value)
                    if score >= 0.6:
                        results.append(ExtractedString(
                            value=value,
                            type=StringType.DECODED_PLUGIN,
                            offset=base_offset + m.start(),
                            score=score,
                            encoding=f"plugin:{name}",
                            length=len(value),
                            context=f"Custom decoder '{name}'"))
            except Exception:
                continue
        return _ranked(results, 100)

    @staticmethod
    def _rot13(text: str) -> str:
        out = []
        for c in text:
            if 'a' <= c <= 'z':
                out.append(chr((ord(c) - ord('a') + 13)
                               % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                out.append(chr((ord(c) - ord('A') + 13)
                               % 26 + ord('A')))
            else:
                out.append(c)
        return ''.join(out)


class StatisticalDecoder:

    DEFAULT_SCAN = 2 * 1024 * 1024
    RUN_GATE = 16
    PER_SCAN_KEEP = 5

    def __init__(self, min_length: int = 5, scan_limit: int = 0):
        self.min_length = max(min_length, 5)
        self.scan_limit = scan_limit or self.DEFAULT_SCAN

    @staticmethod
    def _cap(lst, n):
        if len(lst) > n:
            lst.sort(key=lambda s: (s.score, s.length), reverse=True)
            lst = lst[:n]
        return lst


    def find_multibyte_xor(self, data, base=0, cancel=None):
        results = []
        limit = min(len(data), self.scan_limit)
        if limit < 32:
            return results
        if HAS_NUMPY:
            arr = np.frombuffer(data[:limit], dtype=np.uint8)
            for klen in range(2, 9):
                if cancel and cancel():
                    break
                for shift in range(klen):
                    sub = arr[shift:]
                    n = (len(sub) // klen) * klen
                    if n < 16:
                        continue
                    a = sub[:n].reshape(-1, klen)
                    key = np.zeros(klen, np.uint8)
                    for c in range(klen):
                        counts = np.bincount(a[:, c], minlength=256)
                        key[c] = np.argmax(counts) ^ 0x20
                    dec = sub[:n] ^ np.tile(key, n // klen)
                    if _max_printable_run(dec) < self.RUN_GATE:
                        continue
                    ctx = f"XOR key[{klen}]: {bytes(key).hex(' ')}"
                    results += self._cap(
                        self._collect(dec.tobytes(), base + shift, ctx,
                                      StringType.DECODED_MULTIXOR,
                                      f"multixor-{klen}b", cancel),
                        self.PER_SCAN_KEEP)
        else:
            from collections import Counter
            blob = data[:min(limit, 256 * 1024)]
            for klen in range(2, 9):
                if cancel and cancel():
                    break
                for shift in range(klen):
                    sub = blob[shift:]
                    n = (len(sub) // klen) * klen
                    if n < 16:
                        continue
                    key = bytearray(klen)
                    for c in range(klen):
                        col = sub[c::klen]
                        key[c] = Counter(col).most_common(1)[0][0] ^ 0x20
                    dec = bytes(sub[i] ^ key[i % klen]
                                for i in range(n))
                    if _max_printable_run(dec) < self.RUN_GATE:
                        continue
                    ctx = f"XOR key[{klen}]: {bytes(key).hex(' ')}"
                    results += self._cap(
                        self._collect(dec, base + shift, ctx,
                                      StringType.DECODED_MULTIXOR,
                                      f"multixor-{klen}b", cancel),
                        self.PER_SCAN_KEEP)
        return _ranked(_dedupe(results), 400)


    def find_additive(self, data, base=0, cancel=None):
        results = []
        limit = min(len(data),
                    self.scan_limit if HAS_NUMPY else 128 * 1024)
        blob = data[:limit]
        if len(blob) < 16:
            return results
        if HAS_NUMPY:
            arr = np.frombuffer(blob, dtype=np.uint8)
        for s in range(1, 256):
            if cancel and cancel():
                break
            if HAS_NUMPY:
                dec = ((arr.astype(np.uint16) + s) & 0xFF)\
                    .astype(np.uint8)
                if _max_printable_run(dec) < self.RUN_GATE:
                    continue
                decb = dec.tobytes()
            else:
                decb = bytes((b + s) & 0xFF for b in blob)
                if _max_printable_run(decb) < self.RUN_GATE:
                    continue
            results += self._cap(
                self._collect(decb, base, f"ADD 0x{s:02x}",
                              StringType.DECODED_ADDITIVE,
                              f"add-0x{s:02x}", cancel),
                self.PER_SCAN_KEEP)
        return _ranked(_dedupe(results), 400)


    def find_rolling(self, data, base=0, cancel=None):
        results = []
        limit = min(len(data),
                    self.scan_limit if HAS_NUMPY else 128 * 1024)
        blob = data[:limit]
        if len(blob) < 16:
            return results
        if HAS_NUMPY:
            arr = np.frombuffer(blob, dtype=np.uint8)
            idx = np.arange(len(arr), dtype=np.uint32)
            for start in range(256):
                if cancel and cancel():
                    break
                key = ((idx + np.uint32(start))
                       & 0xFF).astype(np.uint8)
                dec = arr ^ key
                if _max_printable_run(dec) < self.RUN_GATE:
                    continue
                results += self._cap(
                    self._collect(dec.tobytes(), base,
                                  f"Rolling XOR start 0x{start:02x}",
                                  StringType.DECODED_ROLLING,
                                  f"roll-0x{start:02x}", cancel),
                    self.PER_SCAN_KEEP)
        else:
            for start in range(256):
                if cancel and cancel():
                    break
                dec = bytes(b ^ ((start + i) & 0xFF)
                            for i, b in enumerate(blob))
                if _max_printable_run(dec) < self.RUN_GATE:
                    continue
                results += self._cap(
                    self._collect(dec, base,
                                  f"Rolling XOR start 0x{start:02x}",
                                  StringType.DECODED_ROLLING,
                                  f"roll-0x{start:02x}", cancel),
                    self.PER_SCAN_KEEP)
        return _ranked(_dedupe(results), 400)

    def _collect(self, decoded: bytes, base_off, context, stype,
                 enc, cancel):
        out = []
        for m in re.finditer(rb'[\x20-\x7e]{%d,}' % self.min_length,
                             decoded):
            if cancel and cancel():
                break
            value = m.group().decode('ascii')
            if len(set(value)) < 3:
                continue
            score = _score_decoded(value)
            if score >= 0.55:
                out.append(ExtractedString(
                    value=value, type=stype,
                    offset=base_off + m.start(),
                    score=score, encoding=enc, length=len(value),
                    context=context))
        return out

class EmulationAnalyzer:

    STACK_BASE = 0x00200000
    STACK_SIZE = 0x00100000
    OUT_BASE   = 0x00300000
    RET_PAGE   = 0x7F000000
    MAX_STEPS  = 400_000
    PER_FUNC_TIMEOUT = 2.0
    MAX_REFS_PER_BLOB = 6
    MAX_DISASM_INSNS  = 300_000
    MAX_TOTAL_FUNCS   = 600
    MAX_CALL_TARGETS  = 500
    STACK_SCAN_MIN    = 6

    ARG_LAYOUTS = [('ptr', 'len', 'out'), ('out', 'ptr', 'len')]

    PROLOGUES_32 = [b'\x55\x8b\xec', b'\x83\xec']
    PROLOGUES_64 = [b'\x55\x48\x89\xe5', b'\x48\x89\x5c\x24',
                    b'\x48\x83\xec', b'\x4c\x89\x4c\x24']

    def __init__(self, min_length=4, max_functions=300,
                 total_timeout=90.0):
        self.min_length = min_length
        self.max_funcs = max(50, max_functions)
        self.total_timeout = total_timeout
        self._md32 = self._md64 = None
        if HAS_CAPSTONE:
            self._md32 = capstone.Cs(capstone.CS_ARCH_X86,
                                     capstone.CS_MODE_32)
            self._md64 = capstone.Cs(capstone.CS_ARCH_X86,
                                     capstone.CS_MODE_64)


    def analyze(self, data: bytes, pe_info: Optional[PEInfo],
                cancel_check: Optional[Callable] = None,
                progress_cb: Optional[Callable] = None
                ) -> Tuple[List[ExtractedString], str]:
        if not (HAS_UNICORN and HAS_CAPSTONE):
            return [], "needs unicorn + capstone"
        if not (pe_info and pe_info.is_valid):
            return [], "needs a valid PE"

        is64 = pe_info.is_64bit
        t0 = time.time()
        sections = [(pe_info.image_base + s.virtual_address,
                     data[s.raw_offset:s.raw_offset + s.raw_size], s)
                    for s in pe_info.sections if s.raw_size > 0]
        code_secs = [(va, b) for va, b, s in sections if s.is_code]
        starts_map = {va: self._function_starts(b, is64)
                      for va, b in code_secs}
        rip_map = self._build_rip_ref_map(code_secs, is64)

        results, notes = [], []
        tried = set()
        done = 0

        def budget_left():
            return (time.time() - t0) < self.total_timeout


        blobs = self._candidate_blobs(sections)
        a_funcs = 0
        for blob in blobs:
            if (cancel_check and cancel_check()) or not budget_left():
                break
            refs = (self._find_refs(code_secs, blob['va'], is64)
                    + rip_map.get(blob['va'], [])
                    )[:self.MAX_REFS_PER_BLOB]
            for sec_va, ref_off in refs:
                foff = self._enclosing(starts_map.get(sec_va, []),
                                       ref_off)
                if foff is None:
                    continue
                fva = sec_va + foff
                if fva in tried:
                    continue
                tried.add(fva)
                convs = ['msx64'] if is64 else ['cdecl', 'fastcall']
                for conv in convs:
                    hit = False
                    for layout in self.ARG_LAYOUTS:
                        if cancel_check and cancel_check():
                            break
                        got = self._emulate(sections, fva, blob,
                                            conv, layout, is64)
                        results += got
                        if got:
                            hit = True
                            break
                    if hit:
                        break
                a_funcs += 1
            done += 1
            if progress_cb:
                progress_cb(done, len(blobs) + 1)
        if blobs:
            notes.append(f"strategy A: {len(blobs)} blob candidates, "
                         f"{a_funcs} funcs emulated")


        cand = []
        for va, starts in starts_map.items():
            cand.extend(va + s for s in starts)
        cand.extend(self._call_targets(code_secs))
        cand = [f for f in dict.fromkeys(cand)
                if f not in tried and self._in_image(sections, f)]
        scored = sorted(
            ((self._decoder_score(sections, f, is64), f)
             for f in cand[:self.MAX_TOTAL_FUNCS]),
            key=lambda x: -x[0])

        b_done = 0
        for _sc, fva in scored[:self.max_funcs]:
            if (cancel_check and cancel_check()) or not budget_left():
                notes.append("budget exhausted")
                break
            results += self._emulate(sections, fva, None, None,
                                     None, is64)
            b_done += 1
            done += 1
            if progress_cb:
                progress_cb(done, len(blobs) + 1 +
                            min(len(scored), self.max_funcs))
        notes.append(f"strategy B: {b_done} functions emulated")

        return _dedupe(results)[:600], "; ".join(notes)


    @staticmethod
    def _in_image(sections, va):
        return any(va0 <= va < va0 + len(b)
                   for va0, b, _s in sections)

    def _call_targets(self, code_secs):
        targets = set()
        for va, b in code_secs:
            k = b.find(b'\xe8')
            while k != -1 and k + 5 <= len(b):
                rel = struct.unpack('<i', b[k + 1:k + 5])[0]
                targets.add(va + k + 5 + rel)
                k = b.find(b'\xe8', k + 1)
        return list(targets)[:self.MAX_CALL_TARGETS]

    def _decoder_score(self, sections, fva, is64):
        md = self._md64 if is64 else self._md32
        for va, b, _s in sections:
            if va <= fva < va + len(b):
                code = b[fva - va: fva - va + 2048]
                break
        else:
            return 0.0
        ops = {'xor', 'add', 'sub', 'rol', 'ror', 'not', 'neg'}
        n = hits = loops = 0
        try:
            for insn in md.disasm(code, fva):
                n += 1
                if insn.mnemonic in ops:
                    hits += 1
                if insn.mnemonic[0] == 'j':
                    m = re.match(r'0x([0-9a-f]+)', insn.op_str)
                    if m and int(m.group(1), 16) <= insn.address:
                        loops += 1
                if insn.mnemonic == 'ret' or n >= 200:
                    break
        except Exception:
            pass
        if n < 8:
            return 0.0
        return hits / n + (0.2 if loops else 0.0)

    def _build_rip_ref_map(self, code_secs, is64) -> Dict[int, list]:
        md = self._md64 if is64 else self._md32
        rip: Dict[int, list] = {}
        if md is None:
            return rip
        count = 0
        for sec_va, b in code_secs:
            try:
                for insn in md.disasm(b, sec_va):
                    count += 1
                    if count > self.MAX_DISASM_INSNS:
                        break
                    op = insn.op_str
                    if '[rip' not in op:
                        continue
                    m = re.search(
                        r'\[rip\s*([+-])\s*(0x[0-9a-f]+)\]', op)
                    if not m:
                        continue
                    disp = int(m.group(2), 16)
                    if m.group(1) == '-':
                        disp = -disp
                    target = insn.address + insn.size + disp
                    rip.setdefault(target, []).append(
                        (sec_va, insn.address - sec_va))
            except Exception:
                continue
        return rip

    def _find_refs(self, code_secs, blob_va, is64):
        refs = []
        pats = [struct.pack('<I', blob_va & 0xFFFFFFFF)]
        if is64:
            pats.append(struct.pack('<Q', blob_va))
        for sec_va, b in code_secs:
            for p in pats:
                k = b.find(p)
                while k != -1:
                    refs.append((sec_va, k))
                    if len(refs) > 64:
                        return refs
                    k = b.find(p, k + 1)
        return refs

    def _candidate_blobs(self, sections):
        blobs = []
        pat = re.compile(
            rb'[\x20-\x7e]{%d,}' % max(self.min_length, 4))
        for va, b, s in sections:
            if s.is_code:
                continue
            b = b[:512 * 1024]
            pos = 0
            while pos < len(b) and len(blobs) < self.max_funcs:
                m = pat.search(b, pos)
                end = m.start() if m else len(b)
                run = b[pos:end][:4096]
                if len(run) >= 12 and self._looks_encoded(run):
                    blobs.append({'va': va + pos, 'data': run})
                if not m:
                    break
                pos = m.end()
        return blobs

    @staticmethod
    def _looks_encoded(blob):
        if blob.count(0) > len(blob) * 0.5:
            return False
        return len(set(blob)) >= max(6, len(blob) // 8)

    def _function_starts(self, code, is64):
        starts = set()
        for p in (self.PROLOGUES_64 if is64 else self.PROLOGUES_32):
            for m in re.finditer(re.escape(p), code):
                starts.add(m.start())
        return sorted(starts)

    @staticmethod
    def _enclosing(starts, ref_off):
        best = None
        for s in starts:
            if s <= ref_off:
                best = s
            else:
                break
        return best


    def _emulate(self, sections, func_va, blob, conv, layout, is64):
        try:
            mu = unicorn.Uc(unicorn.UC_ARCH_X86,
                            unicorn.UC_MODE_64 if is64
                            else unicorn.UC_MODE_32)
        except Exception:
            return []

        for va, b, _s in sections:
            page = va & ~0xFFF
            size = (len(b) + 0xFFF) & ~0xFFF
            try:
                mu.mem_map(page, size + (va & 0xFFF))
            except Exception:
                pass
            try:
                mu.mem_write(va, b)
            except Exception:
                pass

        mu.mem_map(self.STACK_BASE, self.STACK_SIZE)
        mu.mem_map(self.OUT_BASE, 0x100000)
        mu.mem_map(self.RET_PAGE, 0x1000)
        mu.mem_write(self.RET_PAGE, b'\xc3' * 0x100)

        sp = self.STACK_BASE + self.STACK_SIZE - 0x2000
        bva = blob['va'] if blob else self.OUT_BASE + 0x8000
        blen = len(blob['data']) if blob else 0x100
        out_va = self.OUT_BASE + 0x1000
        vals = {'ptr': bva, 'len': max(blen, 1), 'out': out_va}

        if is64:
            mu.reg_write(UC.UC_X86_REG_RSP, sp)
            mu.mem_write(sp, struct.pack('<Q', self.RET_PAGE))
            if blob:
                for role, reg in (('ptr', UC.UC_X86_REG_RCX),
                                  ('len', UC.UC_X86_REG_RDX),
                                  ('out', UC.UC_X86_REG_R8)):
                    mu.reg_write(reg, vals[role])
                mu.reg_write(UC.UC_X86_REG_R9, vals['len'])
            else:
                mu.reg_write(UC.UC_X86_REG_RCX, vals['out'])
                mu.reg_write(UC.UC_X86_REG_RDX, 0x100)
                mu.reg_write(UC.UC_X86_REG_R8, vals['out'])
                mu.reg_write(UC.UC_X86_REG_R9, 0x100)
        else:
            mu.reg_write(UC.UC_X86_REG_ESP, sp)
            if blob and conv == 'fastcall':
                mu.reg_write(UC.UC_X86_REG_ECX, vals[layout[0]])
                mu.reg_write(UC.UC_X86_REG_EDX, vals[layout[1]])
                mu.mem_write(sp, struct.pack('<II', self.RET_PAGE,
                                             vals[layout[2]]))
            else:
                args = [self.RET_PAGE] + \
                       [vals[r] for r in (layout
                                          or ('ptr', 'len', 'out'))]
                mu.mem_write(sp, struct.pack('<IIII', *args))

        writes = []

        def on_write(uc_, access, address, size_, value, user):
            if len(writes) < 200_000:
                writes.append((address, size_, value))
            return True

        def on_unmapped(uc_, access, address, size_, value, user):
            if access == unicorn.UC_MEM_FETCH_UNMAPPED:
                try:
                    if is64:
                        rsp = uc_.reg_read(UC.UC_X86_REG_RSP)
                        ret = struct.unpack('<Q',
                                            uc_.mem_read(rsp, 8))[0]
                        uc_.reg_write(UC.UC_X86_REG_RSP, rsp + 8)
                        uc_.reg_write(UC.UC_X86_REG_RIP, ret)
                        uc_.reg_write(UC.UC_X86_REG_RAX, 1)
                    else:
                        esp = uc_.reg_read(UC.UC_X86_REG_ESP)
                        ret = struct.unpack('<I',
                                            uc_.mem_read(esp, 4))[0]
                        uc_.reg_write(UC.UC_X86_REG_ESP, esp + 4)
                        uc_.reg_write(UC.UC_X86_REG_EIP, ret)
                        uc_.reg_write(UC.UC_X86_REG_EAX, 1)
                    return True
                except Exception:
                    uc_.emu_stop()
                    return False
            try:
                mu.mem_map(address & ~0xFFF, 0x1000)
                return True
            except Exception:
                uc_.emu_stop()
                return False

        mu.hook_add(unicorn.UC_HOOK_MEM_WRITE, on_write)
        mu.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, on_unmapped)

        try:
            mu.emu_start(func_va, self.RET_PAGE,
                         timeout=int(self.PER_FUNC_TIMEOUT
                                     * 1_000_000),
                         count=self.MAX_STEPS)
        except Exception:
            pass

        extra = {}
        if blob:
            for va, n in ((bva, min(blen, 4096)), (out_va, 4096)):
                try:
                    extra[va] = bytes(mu.mem_read(va, n))
                except Exception:
                    pass
        try:
            stack_img = bytes(mu.mem_read(self.STACK_BASE,
                                          self.STACK_SIZE))
        except Exception:
            stack_img = b''

        return self._strings_from(writes, extra, stack_img, blob)

    def _strings_from(self, writes, extra, stack_img, blob):
        results, seen = [], set()
        ctx = (f"emulated @blob {hex(blob['va'])}" if blob
               else "emulated function")

        def scan(data, label, min_run):
            for m in re.finditer(
                    rb'[\x20-\x7e]{%d,}' % min_run, data):
                raw = m.group().decode('ascii')
                if raw in seen:
                    continue
                seen.add(raw)
                score = max(_score_meaningful(raw), 0.55)
                if score >= 0.55:
                    results.append(ExtractedString(
                        value=raw, type=StringType.DECODED_EMULATED,
                        offset=0, section="emulated", score=score,
                        encoding="emulated", length=len(raw),
                        context=f"{ctx} [{label}]"))

        if writes:
            mem = {}
            for addr, size_, value in writes:
                v = value
                for i in range(size_):
                    mem[addr + i] = v & 0xFF
                    v >>= 8
            addrs, runs, cur = sorted(mem), [], []
            for a in addrs:
                if cur and a - cur[-1] > 1:
                    runs.append(cur)
                    cur = []
                cur.append(a)
            if cur:
                runs.append(cur)
            for run in runs:
                if len(run) >= self.min_length:
                    scan(bytes(mem[a] for a in run),
                         "memory writes", self.min_length)

        if stack_img:
            scan(stack_img, "stack", self.STACK_SCAN_MIN)

        for _va, data in extra.items():
            scan(data, "transformed buffer", self.min_length)
        return results


def generate_yara_rule(result: AnalysisResult, min_score: float = 0.7,
                       max_strings: int = 10) -> str:
    def esc(s):
        return s.replace('\\', '\\\\').replace('"', '\\"')

    base = os.path.basename(result.filepath).split('.')[0] or "sample"
    rule_name = "ITShield_" + re.sub(r'[^A-Za-z0-9_]', '_', base)
    candidates = sorted(
        [s for s in result.strings
         if s.score >= min_score and 6 <= len(s.value) <= 128
         and all(32 <= ord(ch) <= 126 for ch in s.value)],
        key=lambda x: x.score, reverse=True)[:max_strings]
    if not candidates:
        return ""

    lines = [f'rule {rule_name}', '{', '    meta:',
             '        author = "ITShield-Floss v2.5"',
             f'        date = "{datetime.date.today()}"',
             f'        source = '
             f'"{esc(os.path.basename(result.filepath))}"',
             '    strings:']
    for i, s in enumerate(candidates):
        mods = ("ascii wide" if s.type in (StringType.STATIC_ASCII,
                                           StringType.SUSPICIOUS)
                else "ascii")
        lines.append(f'        $s{i} = "{esc(s.value)}" {mods}')
    lines += ['    condition:',
              f'        {max(1, len(candidates) * 2 // 3)} of them',
              '}']
    return '\n'.join(lines)



class ITShieldEngine:

    def __init__(self):
        self._progress_callback: Optional[Callable] = None
        self._cancel = False

    def set_progress_callback(self, cb: Callable[[float, str], None]):
        self._progress_callback = cb

    def cancel(self):
        self._cancel = True

    def is_cancelled(self) -> bool:
        return self._cancel

    def _report(self, progress: float, message: str):
        if self._progress_callback:
            self._progress_callback(progress, message)

    def _add(self, result: AnalysisResult, label: str,
             found: List[ExtractedString], pe_info: Optional[PEInfo]):
        self._annotate(found, pe_info)
        result.strings.extend(found)
        result.phase_stats[label] = \
            result.phase_stats.get(label, 0) + len(found)

    def analyze(self, filepath: str,
                options: Optional[AnalysisOptions] = None
                ) -> AnalysisResult:
        if options is None:
            options = AnalysisOptions()
        self._cancel = False
        t0 = time.time()
        result = AnalysisResult(filepath=filepath)

        if not os.path.exists(filepath):
            result.errors.append(f"File not found: {filepath}")
            return result
        result.file_size = os.path.getsize(filepath)

        self._report(0.03, "Reading file...")
        try:
            with open(filepath, 'rb') as f:
                data = f.read()
        except Exception as e:
            result.errors.append(f"Failed to read: {e}")
            return result

        pe_info = None
        if PEAnalyzer.is_pe(filepath):
            self._report(0.07, "Parsing PE headers...")
            pe_info = PEAnalyzer.parse(filepath)
        result.pe_info = pe_info

        self._report(0.10, "Detecting packers...")
        try:
            result.packer_indicators = PackerDetector.detect(pe_info)
        except Exception as e:
            result.errors.append(f"Packer detect: {e}")

        if options.scan_dotnet and not self._cancel:
            self._report(0.14, "Scanning .NET #US heap...")
            try:
                self._add(result, "DotNet #US",
                          DotNetStringExtractor.extract(
                              data, options.min_length), pe_info)
            except Exception as e:
                result.errors.append(f"DotNet: {e}")

        if options.scan_resources and not self._cancel:
            self._report(0.19, "Scanning PE resources...")
            try:
                self._add(result, "Resources",
                          ResourceStringExtractor.extract(
                              filepath, max(options.min_length, 6)),
                          pe_info)
            except Exception as e:
                result.errors.append(f"Resources: {e}")

        static_ex = StaticStringExtractor(options.min_length,
                                          options.max_length)

        if options.extract_static and not self._cancel:
            self._report(0.28, "Extracting ASCII strings...")
            try:
                self._add(result, "ASCII",
                          static_ex.extract_ascii(data), pe_info)
            except Exception as e:
                result.errors.append(f"ASCII: {e}")

        if options.extract_unicode and not self._cancel:
            self._report(0.36, "Extracting Unicode strings...")
            try:
                self._add(result, "Unicode",
                          static_ex.extract_unicode(data), pe_info)
            except Exception as e:
                result.errors.append(f"Unicode: {e}")

        if options.extract_suspicious and not self._cancel:
            self._report(0.44, "Matching IOC / secret patterns...")
            try:
                self._add(result, "IOC/Secrets",
                          static_ex.find_suspicious(data), pe_info)
            except Exception as e:
                result.errors.append(f"Suspicious: {e}")

        if options.extract_stack and not self._cancel:
            self._report(0.52,
                         "Analyzing stack strings (disassembly)...")
            try:
                stack_an = StackStringAnalyzer(options.min_length)
                found, trunc = self._analyze_stack(
                    data, pe_info, stack_an, options)
                self._add(result, "Stack/Tight", found, pe_info)
                if trunc:
                    result.errors.append(
                        "Disassembly truncated: " + trunc)
            except Exception as e:
                result.errors.append(f"Stack: {e}")

        if options.extract_decoded and not self._cancel:
            self._report(0.58,
                         "Decoding (XOR / B64 / ROT13 / plugins)...")
            try:
                fast = FastDecoder(options.min_length,
                                   options.xor_limit)
                self._add(result, "FastDecoded (XOR/B64/...)",
                          fast.analyze(data, 0, self.is_cancelled),
                          pe_info)
            except Exception as e:
                result.errors.append(f"Decoded: {e}")

        stat = StatisticalDecoder(max(options.min_length, 5),
                                  options.xor_limit)
        if options.extract_decoded and options.scan_multixor \
                and not self._cancel:
            self._report(0.64, "Multi-byte XOR key recovery...")
            try:
                self._add(result, "MultiXOR",
                          stat.find_multibyte_xor(
                              data, 0, self.is_cancelled), pe_info)
            except Exception as e:
                result.errors.append(f"MultiXOR: {e}")

        if options.extract_decoded and options.scan_additive \
                and not self._cancel:
            self._report(0.69, "Additive cipher scan...")
            try:
                self._add(result, "Additive",
                          stat.find_additive(
                              data, 0, self.is_cancelled), pe_info)
            except Exception as e:
                result.errors.append(f"Additive: {e}")

        if options.extract_decoded and options.scan_rolling \
                and not self._cancel:
            self._report(0.73, "Rolling-XOR scan...")
            try:
                self._add(result, "RollingXOR",
                          stat.find_rolling(
                              data, 0, self.is_cancelled), pe_info)
            except Exception as e:
                result.errors.append(f"Rolling: {e}")

        if options.use_emulation and not self._cancel:
            if HAS_UNICORN and HAS_CAPSTONE:
                self._report(0.78, "Emulating code (Unicorn)...")
                try:
                    emu = EmulationAnalyzer(
                        min_length=options.min_length,
                        max_functions=options.emu_max_functions,
                        total_timeout=options.emu_total_timeout)

                    def emu_progress(done, total):
                        frac = done / max(total, 1)
                        self._report(
                            0.78 + 0.19 * frac,
                            f"Emulating decoders... {done}/{total}")

                    found, note = emu.analyze(
                        data, pe_info, self.is_cancelled, emu_progress)
                    self._add(result, "Emulated", found, pe_info)
                    if note:
                        result.info_notes.append(f"Emulation: {note}")
                except Exception as e:
                    result.errors.append(f"Emulation: {e}")
            else:
                result.errors.append(
                    "Emulation skipped: 'unicorn' not installed "
                    "(pip install unicorn)")

        if options.min_score > 0:
            result.strings = [s for s in result.strings
                              if s.score >= options.min_score]
        result.strings.sort(key=lambda x: x.score, reverse=True)
        if options.max_results and \
                len(result.strings) > options.max_results:
            result.strings = result.strings[:options.max_results]

        result.duration = time.time() - t0
        self._report(1.0, "Analysis complete!")
        return result

    def _analyze_stack(self, data, pe_info, stack_an, options
                       ) -> Tuple[List[ExtractedString], str]:
        results, truncated = [], []
        if pe_info and pe_info.is_valid:
            for section in pe_info.sections:
                if self._cancel:
                    truncated.append("cancelled")
                    break
                if not section.is_code:
                    continue
                if section.raw_offset + section.raw_size > len(data):
                    continue
                code_data = data[section.raw_offset:
                                 section.raw_offset
                                 + section.raw_size]
                if not code_data:
                    continue
                base_va = pe_info.image_base + section.virtual_address
                found, t1 = stack_an.analyze(
                    code_data, base_va, pe_info.is_64bit,
                    time_budget=options.disasm_timeout,
                    cancel_check=self.is_cancelled)
                if t1:
                    truncated.append(f"{section.name}/stack")
                for s in found:
                    s.section = section.name
                results.extend(found)

                tight, t2 = stack_an.find_tight_strings(
                    code_data, base_va, pe_info.is_64bit,
                    time_budget=options.disasm_timeout,
                    cancel_check=self.is_cancelled)
                if t2:
                    truncated.append(f"{section.name}/tight")
                for s in tight:
                    s.section = section.name
                results.extend(tight)
        else:
            sample = data[:512 * 1024]
            for is64 in (False, True):
                if self._cancel:
                    truncated.append("cancelled")
                    break
                found, t = stack_an.analyze(
                    sample, 0, is64,
                    time_budget=options.disasm_timeout,
                    cancel_check=self.is_cancelled)
                if t:
                    truncated.append("raw")
                results.extend(found)
        return results, ", ".join(dict.fromkeys(truncated))

    @staticmethod
    def _annotate(strings: List[ExtractedString],
                  pe_info: Optional[PEInfo]):
        if not pe_info or not pe_info.is_valid:
            return
        for s in strings:
            for section in pe_info.sections:
                if section.raw_offset <= s.offset < \
                        section.raw_offset + section.raw_size:
                    delta = s.offset - section.raw_offset
                    s.virtual_address = (pe_info.image_base +
                                         section.virtual_address
                                         + delta)
                    s.section = section.name
                    break


    @staticmethod
    def save_session(result: AnalysisResult, path: str):
        data = {"tool": APP_NAME, "version": APP_VERSION,
                "file": result.filepath,
                "file_size": result.file_size,
                "duration": result.duration,
                "packer_indicators": result.packer_indicators,
                "phase_stats": result.phase_stats,
                "info_notes": result.info_notes,
                "strings": [s.to_dict() for s in result.strings]}
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def load_session(path: str) -> AnalysisResult:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        result = AnalysisResult(
            filepath=data.get("file", ""),
            file_size=int(data.get("file_size", 0)),
            duration=float(data.get("duration", 0)),
            packer_indicators=data.get("packer_indicators", []),
            phase_stats=data.get("phase_stats", {}),
            info_notes=data.get("info_notes", []))
        for d in data.get("strings", []):
            result.strings.append(ExtractedString.from_dict(d))
        return result


    @staticmethod
    def export(result: AnalysisResult, filepath: str,
               fmt: str = "csv"):
        if fmt == "csv":
            with open(filepath, 'w', newline='',
                      encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(["Value", "Type", "Offset",
                            "Virtual Address", "Section", "Score",
                            "Encoding", "Length", "Context"])
                for s in result.strings:
                    w.writerow([s.value, s.type.value, hex(s.offset),
                                hex(s.virtual_address), s.section,
                                f"{s.score:.2f}", s.encoding,
                                s.length, s.context])
        elif fmt == "json":
            data = {"tool": APP_NAME, "version": APP_VERSION,
                    "file": result.filepath,
                    "file_size": result.file_size,
                    "duration": result.duration,
                    "packer_indicators": result.packer_indicators,
                    "phase_stats": result.phase_stats,
                    "info_notes": result.info_notes,
                    "total_strings": result.total_count,
                    "counts_by_type": result.counts_by_type,
                    "strings": [s.to_dict() for s in result.strings]}
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        elif fmt == "yara":
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(generate_yara_rule(result) + "\n")
        elif fmt == "txt":
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(f"{APP_NAME} Analysis Report\n{'=' * 60}\n")
                f.write(f"File: {result.filepath}\n")
                f.write(f"Size: {result.file_size:,} bytes\n")
                f.write(f"Duration: {result.duration:.2f}s\n")
                f.write(f"Total strings: {result.total_count}\n")
                if result.packer_indicators:
                    f.write("Packer indicators:\n")
                    for ind in result.packer_indicators:
                        f.write(f"  ! {ind}\n")
                if result.phase_stats:
                    f.write("Phase statistics:\n")
                    for k, v in result.phase_stats.items():
                        f.write(f"  {k}: {v}\n")
                f.write(f"{'=' * 60}\n")
                for stype, count in result.counts_by_type.items():
                    f.write(f"\n--- {stype} ({count}) ---\n")
                    for s in result.strings:
                        if s.type.value == stype:
                            f.write(f"  [{s.score:.2f}] {s.value}\n")



class SearchableTreeview(ttk.Frame):

    MAX_DISPLAY = 5000

    def __init__(self, parent, columns: list, **kwargs):
        super().__init__(parent, **kwargs)
        self.columns = columns
        self._rows: List[Tuple[str, tuple]] = []
        self.type_filter = "All"
        self._sort_column = None
        self._sort_reverse = False
        self._setup_ui()

    def _setup_ui(self):
        bar = tk.Frame(self, bg=Theme.BG_CARD)
        bar.pack(fill=tk.X, padx=5, pady=(5, 2))
        tk.Label(bar, text="🔍", bg=Theme.BG_CARD,
                 fg=Theme.TEXT_SECOND).pack(side=tk.LEFT, padx=(0, 5))
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *a: self._refresh())
        self.search_entry = tk.Entry(
            bar, textvariable=self.search_var, width=40,
            bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY,
            insertbackground=Theme.TEXT_PRIMARY, relief='solid',
            bd=1, font=Theme.FONT_MONO)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.result_label = tk.Label(bar, text="", bg=Theme.BG_CARD,
                                     fg=Theme.TEXT_MUTED,
                                     font=Theme.FONT_SMALL)
        self.result_label.pack(side=tk.RIGHT, padx=5)

        tree_frame = tk.Frame(self, bg=Theme.BG_CARD)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=(2, 5))
        self.tree = ttk.Treeview(tree_frame, columns=self.columns,
                                 show='headings')
        for col in self.columns:
            self.tree.heading(col, text=col,
                              command=lambda c=col: self._sort(c))
            self.tree.column(col, width=120, minwidth=50)
        vsb = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL,
                            command=self.tree.yview)
        hsb = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL,
                            command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,
                            xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        vsb.grid(row=0, column=1, sticky='ns')
        hsb.grid(row=1, column=0, sticky='ew')
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.context_menu = tk.Menu(
            self, tearoff=0, bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY,
            activebackground=Theme.BG_HOVER,
            activeforeground=Theme.TEXT_PRIMARY, relief='solid', bd=1)
        self.context_menu.add_command(label="Copy Value",
                                      command=self._copy_value)
        self.context_menu.add_command(label="Copy All Info",
                                      command=self._copy_full)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All",
                                      command=self._select_all)
        self.tree.bind('<Button-3>', self._show_context_menu)
        self.tree.bind('<Control-c>', lambda e: self._copy_value())

    def set_column_widths(self, widths: dict):
        for col, width in widths.items():
            if col in self.columns:
                self.tree.column(col, width=width)

    def set_type_filter(self, value: str):
        self.type_filter = value
        self._refresh()

    def insert_data(self, rows: list):
        self._rows = [(f"i{n}", row) for n, row in enumerate(rows)]
        self._refresh()

    def clear(self):
        self._rows = []
        self.tree.delete(*self.tree.get_children())
        self.result_label.config(text="")

    def _refresh(self):
        self.tree.delete(*self.tree.get_children())
        rows = self._rows
        if self.type_filter != "All":
            rows = [x for x in rows if x[1][1] == self.type_filter]
        text = self.search_var.get().lower()
        if text:
            rows = [x for x in rows
                    if any(text in str(c).lower()
                           for c in x[1][:len(self.columns)])]
        for n, (iid, row) in enumerate(rows[:self.MAX_DISPLAY]):
            stripe = 'even' if n % 2 else 'odd'
            tag = row[-1] if len(row) > len(self.columns) else ''
            self.tree.insert('', tk.END, iid=iid,
                             values=row[:len(self.columns)],
                             tags=(stripe, tag))
        total, filtered = len(self._rows), len(rows)
        if self.type_filter != "All" or text:
            note = f"Showing {min(filtered, self.MAX_DISPLAY)}/" \
                   f"{filtered}"
            if filtered != total:
                note += f" (of {total})"
        else:
            note = f"{total} results"
            if total > self.MAX_DISPLAY:
                note += f" (displaying first {self.MAX_DISPLAY})"
        self.result_label.config(text=note)

    def _sort(self, column):
        if self._sort_column == column:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_column, self._sort_reverse = column, False
        idx = self.columns.index(column)

        def key(item):
            val = item[1][idx] if idx < len(item[1]) else ""
            try:
                return (0, float(str(val).replace(',', '')))
            except (ValueError, TypeError):
                return (1, str(val).lower())

        self._rows.sort(key=key, reverse=self._sort_reverse)
        self._refresh()

    def _show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _copy_value(self):
        sel = self.tree.selection()
        if sel:
            values = self.tree.item(sel[0])['values']
            if values:
                self.clipboard_clear()
                self.clipboard_append(str(values[0]))

    def _copy_full(self):
        sel = self.tree.selection()
        if sel:
            values = self.tree.item(sel[0])['values']
            self.clipboard_clear()
            self.clipboard_append(' | '.join(str(v) for v in values))

    def _select_all(self):
        for item in self.tree.get_children():
            self.tree.selection_add(item)


class StatCard(tk.Frame):

    def __init__(self, parent, title: str, color: str, **kwargs):
        super().__init__(parent, bg=Theme.BG_CARD, bd=1,
                         relief='solid', highlightthickness=0,
                         **kwargs)
        self.value_label = tk.Label(self, text="0",
                                    font=("Segoe UI", 18, "bold"),
                                    bg=Theme.BG_CARD, fg=color)
        self.value_label.pack(pady=(8, 0))
        self.title_label = tk.Label(self, text=title,
                                    font=Theme.FONT_SMALL,
                                    bg=Theme.BG_CARD,
                                    fg=Theme.TEXT_SECOND)
        self.title_label.pack(pady=(0, 8))

    def set_value(self, v):
        self.value_label.config(text=str(v))


class ManualDecoderDialog(tk.Toplevel):

    MAX_DECODE_LEN = 4096

    def __init__(self, parent, file_data: Optional[bytes],
                 selected_offset: Optional[int],
                 on_result: Callable[[ExtractedString], None]):
        super().__init__(parent)
        self.title("Manual Decoder")
        self.geometry("640x560")
        self.configure(bg=Theme.BG_CARD, bd=1, relief='solid')
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()
        self.file_data = file_data
        self.on_result = on_result

        pad = dict(padx=12, pady=4)

        top = tk.Frame(self, bg=Theme.BG_CARD)
        top.pack(fill=tk.X, **pad)
        tk.Label(top, text="Offset (hex):", bg=Theme.BG_CARD,
                 fg=Theme.TEXT_SECOND, font=Theme.FONT_SMALL
                 ).pack(side=tk.LEFT)
        self.offset_var = tk.StringVar(
            value=hex(selected_offset) if selected_offset else "0x0")
        tk.Entry(top, textvariable=self.offset_var, width=12,
                 bg=Theme.BG_CARD, relief='solid', bd=1,
                 font=Theme.FONT_MONO, fg=Theme.TEXT_PRIMARY,
                 insertbackground=Theme.TEXT_PRIMARY
                 ).pack(side=tk.LEFT, padx=(4, 12), ipady=1)
        tk.Label(top, text="Length (max 4096):", bg=Theme.BG_CARD,
                 fg=Theme.TEXT_SECOND, font=Theme.FONT_SMALL
                 ).pack(side=tk.LEFT)
        self.length_var = tk.StringVar(value="64")
        tk.Entry(top, textvariable=self.length_var, width=8,
                 bg=Theme.BG_CARD, relief='solid', bd=1,
                 font=Theme.FONT_MONO, fg=Theme.TEXT_PRIMARY,
                 insertbackground=Theme.TEXT_PRIMARY
                 ).pack(side=tk.LEFT, padx=4, ipady=1)

        if file_data is None:
            tk.Label(self,
                     text="⚠ No file data loaded — open/analyze "
                          "a file first.",
                     bg=Theme.WARN_BG, fg=Theme.WARN_TEXT,
                     font=Theme.FONT_NORMAL).pack(fill=tk.X, padx=12,
                                                  pady=8)

        mid = tk.Frame(self, bg=Theme.BG_CARD)
        mid.pack(fill=tk.X, **pad)
        tk.Label(mid, text="Transform:", bg=Theme.BG_CARD,
                 fg=Theme.TEXT_SECOND, font=Theme.FONT_SMALL
                 ).pack(side=tk.LEFT)
        self.transform_var = tk.StringVar(value="XOR (hex key)")
        self.transform_combo = ttk.Combobox(
            mid, textvariable=self.transform_var, state='readonly',
            width=18,
            values=["XOR (hex key)", "ADD (int)", "SUB (int)",
                    "RC4 (text key)", "Reverse", "ROT13",
                    "Custom expression"])
        self.transform_combo.pack(side=tk.LEFT, padx=4)
        self.transform_combo.bind(
            '<<ComboboxSelected>>',
            lambda e: self._update_key_hint())
        tk.Label(mid, text="Key / Expr:", bg=Theme.BG_CARD,
                 fg=Theme.TEXT_SECOND, font=Theme.FONT_SMALL
                 ).pack(side=tk.LEFT, padx=(10, 0))
        self.key_var = tk.StringVar(value="37")
        self.key_entry = tk.Entry(mid, textvariable=self.key_var,
                                  width=24, bg=Theme.BG_CARD,
                                  relief='solid', bd=1,
                                  font=Theme.FONT_MONO,
                                  fg=Theme.TEXT_PRIMARY,
                                  insertbackground=Theme.TEXT_PRIMARY)
        self.key_entry.pack(side=tk.LEFT, padx=4, ipady=1)

        btns = tk.Frame(self, bg=Theme.BG_CARD)
        btns.pack(fill=tk.X, **pad)
        tk.Button(btns, text="Decode", command=self._decode,
                  bg=Theme.ACCENT, fg='white',
                  activebackground=Theme.ACCENT_HOVER, relief='flat',
                  bd=0, padx=16, pady=4,
                  font=("Segoe UI", 9, "bold"),
                  cursor='hand2').pack(side=tk.LEFT)

        tk.Label(self, text="Preview:", bg=Theme.BG_CARD,
                 fg=Theme.TEXT_SECOND, font=Theme.FONT_SMALL
                 ).pack(anchor='w', padx=12, pady=(8, 0))

        self.preview = tk.Text(self, height=10, font=Theme.FONT_MONO,
                               bg=Theme.BG_MAIN,
                               fg=Theme.TEXT_PRIMARY,
                               relief='solid', bd=1, wrap='none')
        self.preview.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)

        bottom = tk.Frame(self, bg=Theme.BG_CARD)
        bottom.pack(fill=tk.X, padx=12, pady=(0, 10))
        self.add_btn = tk.Button(
            bottom, text="＋ Add to Results", command=self._add_result,
            state=tk.DISABLED, bg=Theme.BG_HOVER,
            fg=Theme.TEXT_PRIMARY, activebackground=Theme.BG_HOVER,
            relief='solid', bd=1, padx=14, pady=4,
            font=Theme.FONT_NORMAL, cursor='hand2')
        self.add_btn.pack(side=tk.LEFT)
        self.status = tk.Label(bottom, text="", bg=Theme.BG_CARD,
                               fg=Theme.TEXT_MUTED,
                               font=Theme.FONT_SMALL)
        self.status.pack(side=tk.LEFT, padx=10)

        self._decoded: Optional[bytes] = None
        self._offset = 0
        self._update_key_hint()
        self.bind('<Return>', lambda e: self._decode())

    def _update_key_hint(self):
        hints = {"XOR (hex key)": "37   or   DE AD BE EF",
                 "ADD (int)": "5", "SUB (int)": "5",
                 "RC4 (text key)": "my-secret-key",
                 "Reverse": "(no key needed)",
                 "ROT13": "(no key needed)",
                 "Custom expression": "bytes(b ^ 0x5A for b in d)"}
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(
            0, hints.get(self.transform_var.get(), ""))

    def _parse_region(self) -> Optional[Tuple[int, bytes]]:
        if self.file_data is None:
            self.status.config(text="No file data",
                               fg=Theme.ACCENT_RED)
            return None
        off_s = self.offset_var.get().strip()
        try:
            offset = int(off_s, 16)
        except ValueError:
            self.status.config(text="Invalid offset (use hex)",
                               fg=Theme.ACCENT_RED)
            return None
        if offset < 0 or offset >= len(self.file_data):
            self.status.config(text="Offset out of range",
                               fg=Theme.ACCENT_RED)
            return None
        try:
            length = int(self.length_var.get())
        except ValueError:
            length = 64
        length = max(1, min(length, self.MAX_DECODE_LEN,
                            len(self.file_data) - offset))
        return offset, self.file_data[offset:offset + length]

    def _decode(self):
        region = self._parse_region()
        if not region:
            return
        offset, data = region
        transform = self.transform_var.get()
        keytext = self.key_var.get().strip()
        try:
            if transform == "XOR (hex key)":
                parts = re.findall(r'[0-9a-fA-F]{1,2}',
                                   keytext.replace("0x", " "))
                if not parts:
                    raise ValueError("empty key")
                key = bytes(int(p.zfill(2), 16) for p in parts)
                self._decoded = bytes(b ^ key[i % len(key)]
                                      for i, b in enumerate(data))
                desc = f"XOR key {key.hex(' ')}"
            elif transform == "ADD (int)":
                s = int(keytext, 0) & 0xFF
                self._decoded = bytes((b + s) & 0xFF
                                      for b in data)
                desc = f"ADD 0x{s:02x}"
            elif transform == "SUB (int)":
                s = int(keytext, 0) & 0xFF
                self._decoded = bytes((b - s) & 0xFF
                                      for b in data)
                desc = f"SUB 0x{s:02x}"
            elif transform == "RC4 (text key)":
                self._decoded = rc4(keytext.encode('utf-8'), data)
                desc = f"RC4('{keytext[:16]}')"
            elif transform == "Reverse":
                self._decoded = data[::-1]
                desc = "Reverse"
            elif transform == "ROT13":
                self._decoded = bytes(
                    ((b - 0x41 + 13) % 26 + 0x41)
                    if 0x41 <= b <= 0x5A
                    else ((b - 0x61 + 13) % 26 + 0x61)
                    if 0x61 <= b <= 0x7A else b
                    for b in data)
                desc = "ROT13"
            else:
                ns = {'d': data, 'len': len, 'bytes': bytes,
                      'bytearray': bytearray, 'range': range,
                      'int': int, 'abs': abs, 'rc4': rc4}
                res = eval(keytext, {"__builtins__": {}}, ns)
                if isinstance(res, str):
                    res = res.encode('utf-8', errors='replace')
                if not isinstance(res, (bytes, bytearray)):
                    raise ValueError(
                        "expression must return bytes")
                self._decoded = bytes(res)
                desc = "custom expression"
        except Exception as e:
            self._decoded = None
            self.add_btn.config(state=tk.DISABLED)
            self.status.config(text=f"Error: {e}",
                               fg=Theme.ACCENT_RED)
            return

        self._offset = offset
        printable = ''.join(chr(b) if 32 <= b <= 126 else '·'
                            for b in self._decoded)
        self.preview.config(state=tk.NORMAL)
        self.preview.delete('1.0', tk.END)
        self.preview.insert('1.0',
                            hexdump(self._decoded, 0, before=0,
                                    after=len(self._decoded)))
        self.preview.insert('end',
                            "\n\n--- as text ---\n" + printable)
        self.preview.config(state=tk.DISABLED)
        self.add_btn.config(state=tk.NORMAL)
        self.status.config(text=f"OK — {desc}",
                           fg=Theme.ACCENT_GREEN)

    def _add_result(self):
        if self._decoded is None:
            return
        enc = self.transform_var.get().lower().split(' ')[0]
        added = 0
        for m in re.finditer(rb'[\x20-\x7e]{4,}', self._decoded):
            value = m.group().decode('ascii')
            self.on_result(ExtractedString(
                value=value, type=StringType.DECODED_MANUAL,
                offset=self._offset + m.start(), score=0.9,
                encoding=enc, length=len(value),
                context=f"Manual: {self.transform_var.get()} "
                        f"({self.key_var.get()[:24]})"))
            added += 1
            if added >= 20:
                break
        if added:
            self.status.config(text=f"Added {added} string(s) ✓",
                               fg=Theme.ACCENT_GREEN)
        else:
            self.status.config(text="No printable runs found",
                               fg=Theme.ACCENT_RED)

class MainWindow:

    def __init__(self):
        self.root = self._make_root()
        self.root.title(f"{APP_NAME} v{APP_VERSION} — "
                        f"Advanced String Extraction Tool")
        self.root.geometry("1400x940")
        self.root.minsize(1050, 660)
        Theme.apply(self.root)

        self.engine = ITShieldEngine()
        self.analysis_result: Optional[AnalysisResult] = None
        self.is_analyzing = False
        self._file_data: Optional[bytes] = None
        self._display_strings: List[ExtractedString] = []

        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)

        self._create_menu()
        self._create_header()
        self._create_main_content()
        self._create_statusbar()
        self._bind_keys()
        self._enable_dragdrop()

    @staticmethod
    def _make_root() -> tk.Tk:
        if HAS_DND:
            try:
                return TkinterDnD.Tk()
            except Exception:
                pass
        return tk.Tk()

    def _enable_dragdrop(self):
        if not HAS_DND:
            return
        try:
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind('<<Drop>>', self._on_drop)
        except Exception:
            pass

    def _on_drop(self, event):
        try:
            files = self.root.tk.splitlist(event.data)
            if files and os.path.exists(files[0]):
                self._set_file(files[0])
        except Exception:
            pass


    def _create_menu(self):
        mb = tk.Menu(self.root, bg=Theme.BG_CARD,
                     fg=Theme.TEXT_PRIMARY,
                     activebackground=Theme.BG_HOVER,
                     activeforeground=Theme.TEXT_PRIMARY,
                     relief='flat', bd=0)

        m_file = tk.Menu(mb, tearoff=0, bg=Theme.BG_CARD,
                         fg=Theme.TEXT_PRIMARY,
                         activebackground=Theme.BG_HOVER,
                         activeforeground=Theme.TEXT_PRIMARY)
        m_file.add_command(label="Open File...",
                           command=self._browse_file,
                           accelerator="Ctrl+O")
        m_file.add_separator()
        m_file.add_command(label="Save Session...",
                           command=self._save_session,
                           accelerator="Ctrl+S")
        m_file.add_command(label="Load Session...",
                           command=self._load_session,
                           accelerator="Ctrl+L")
        m_file.add_separator()
        m_file.add_command(label="Export CSV",
                           command=lambda: self._export("csv"))
        m_file.add_command(label="Export JSON",
                           command=lambda: self._export("json"))
        m_file.add_command(label="Export Report (TXT)",
                           command=lambda: self._export("txt"))
        m_file.add_command(label="Export YARA Rule",
                           command=self._export_yara)
        m_file.add_separator()
        m_file.add_command(label="Exit", command=self.root.quit)
        mb.add_cascade(label="File", menu=m_file)

        m_tools = tk.Menu(mb, tearoff=0, bg=Theme.BG_CARD,
                          fg=Theme.TEXT_PRIMARY,
                          activebackground=Theme.BG_HOVER,
                          activeforeground=Theme.TEXT_PRIMARY)
        m_tools.add_command(label="Manual Decoder...",
                            command=self._open_manual_decoder,
                            accelerator="Ctrl+D")
        m_tools.add_command(label="Hex Context of Selection",
                            command=self._show_hex)
        mb.add_cascade(label="Tools", menu=m_tools)

        m_an = tk.Menu(mb, tearoff=0, bg=Theme.BG_CARD,
                       fg=Theme.TEXT_PRIMARY,
                       activebackground=Theme.BG_HOVER,
                       activeforeground=Theme.TEXT_PRIMARY)
        m_an.add_command(label="Start Analysis",
                         command=self._start_analysis,
                         accelerator="F5")
        m_an.add_command(label="Cancel",
                         command=self._cancel_analysis)
        m_an.add_separator()
        m_an.add_command(label="Clear Results",
                         command=self._clear_results)
        mb.add_cascade(label="Analysis", menu=m_an)

        m_help = tk.Menu(mb, tearoff=0, bg=Theme.BG_CARD,
                         fg=Theme.TEXT_PRIMARY,
                         activebackground=Theme.BG_HOVER,
                         activeforeground=Theme.TEXT_PRIMARY)
        m_help.add_command(label="Dependencies...",
                           command=self._show_dependencies)
        m_help.add_command(label="About", command=self._show_about)
        mb.add_cascade(label="Help", menu=m_help)
        self.root.config(menu=mb)

    def _bind_keys(self):
        self.root.bind('<Control-o>', lambda e: self._browse_file())
        self.root.bind('<Control-s>', lambda e: self._save_session())
        self.root.bind('<Control-l>', lambda e: self._load_session())
        self.root.bind('<Control-d>',
                       lambda e: self._open_manual_decoder())
        self.root.bind('<F5>', lambda e: self._start_analysis())


    def _create_header(self):
        header = tk.Frame(self.root, bg=Theme.BG_MAIN)
        header.grid(row=0, column=0, sticky='ew', padx=12,
                    pady=(10, 4))
        left = tk.Frame(header, bg=Theme.BG_MAIN)
        left.pack(side=tk.LEFT)
        tk.Label(left, text=f"{APP_ICON} {APP_NAME}",
                 font=Theme.FONT_HEADER, bg=Theme.BG_MAIN,
                 fg=Theme.TEXT_PRIMARY).pack(anchor='w')
        tk.Label(left,
                 text="Advanced String Extraction & Malware Analysis",
                 font=Theme.FONT_SMALL, bg=Theme.BG_MAIN,
                 fg=Theme.TEXT_SECOND).pack(anchor='w')
        right = tk.Frame(header, bg=Theme.BG_MAIN)
        right.pack(side=tk.RIGHT)
        self.file_label = tk.Label(
            right, text="No file loaded — drag & drop a file here",
            font=Theme.FONT_MONO, bg=Theme.BG_MAIN,
            fg=Theme.TEXT_SECOND)
        self.file_label.pack(anchor='e')
        self.file_hash_label = tk.Label(right, text="",
                                        font=Theme.FONT_SMALL,
                                        bg=Theme.BG_MAIN,
                                        fg=Theme.TEXT_MUTED)
        self.file_hash_label.pack(anchor='e')


    def _create_main_content(self):
        main = tk.Frame(self.root, bg=Theme.BG_MAIN)
        main.grid(row=1, column=0, sticky='nsew', padx=12, pady=4)
        for r, w in ((0, 0), (1, 0), (2, 0), (3, 1)):
            main.grid_rowconfigure(r, weight=w)
        main.grid_columnconfigure(0, weight=1)
        self._create_options_card(main)
        self._create_packer_banner(main)
        self._create_stats_row(main)
        self._create_results_card(main)

    def _create_options_card(self, parent):
        card = tk.Frame(parent, bg=Theme.BG_CARD, bd=1,
                        relief='solid')
        card.grid(row=0, column=0, sticky='ew', pady=(0, 8))
        inner = tk.Frame(card, bg=Theme.BG_CARD)
        inner.pack(fill=tk.X, padx=14, pady=10)

        fr = tk.Frame(inner, bg=Theme.BG_CARD)
        fr.pack(fill=tk.X, pady=(0, 8))
        tk.Label(fr, text="📁 Target:", font=Theme.FONT_NORMAL,
                 bg=Theme.BG_CARD, fg=Theme.TEXT_SECOND
                 ).pack(side=tk.LEFT, padx=(0, 8))
        self.file_path_var = tk.StringVar()
        self.file_entry = tk.Entry(
            fr, textvariable=self.file_path_var, bg=Theme.BG_CARD,
            fg=Theme.TEXT_PRIMARY,
            insertbackground=Theme.TEXT_PRIMARY,
            relief='solid', bd=1, font=Theme.FONT_MONO)
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True,
                             padx=(0, 8), ipady=3)
        tk.Button(fr, text="Browse...", command=self._browse_file,
                  bg=Theme.BG_MAIN, fg=Theme.TEXT_PRIMARY,
                  activebackground=Theme.BG_HOVER, relief='solid',
                  bd=1, padx=14, pady=4, font=Theme.FONT_NORMAL,
                  cursor='hand2').pack(side=tk.LEFT, padx=(0, 6))
        self.analyze_btn = tk.Button(
            fr, text="⚡ Analyze", command=self._start_analysis,
            bg=Theme.ACCENT, fg='white',
            activebackground=Theme.ACCENT_HOVER, relief='flat',
            bd=0, padx=20, pady=5,
            font=("Segoe UI", 10, "bold"), cursor='hand2')
        self.analyze_btn.pack(side=tk.LEFT)

        self.var_static = tk.BooleanVar(value=True)
        self.var_unicode = tk.BooleanVar(value=True)
        self.var_stack = tk.BooleanVar(value=True)
        self.var_decoded = tk.BooleanVar(value=True)
        self.var_suspicious = tk.BooleanVar(value=True)
        self.var_dotnet = tk.BooleanVar(value=True)
        self.var_resources = tk.BooleanVar(value=True)
        self.var_emulation = tk.BooleanVar(value=True)
        self.var_multixor = tk.BooleanVar(value=True)
        self.var_additive = tk.BooleanVar(value=True)
        self.var_rolling = tk.BooleanVar(value=True)

        row1 = tk.Frame(inner, bg=Theme.BG_CARD)
        row1.pack(fill=tk.X)
        for text, var in (("ASCII", self.var_static),
                          ("Unicode", self.var_unicode),
                          ("Stack", self.var_stack),
                          ("Decoded", self.var_decoded),
                          ("IOC/Secrets", self.var_suspicious),
                          (".NET #US", self.var_dotnet),
                          ("Resources", self.var_resources)):
            self._checkbox(row1, text, var).pack(side=tk.LEFT,
                                                 padx=6)

        row2 = tk.Frame(inner, bg=Theme.BG_CARD)
        row2.pack(fill=tk.X, pady=(2, 0))
        for text, var in (("Emulation (Unicorn)",
                           self.var_emulation),
                          ("Multi-XOR", self.var_multixor),
                          ("Additive", self.var_additive),
                          ("Rolling", self.var_rolling)):
            self._checkbox(row2, text, var).pack(side=tk.LEFT,
                                                 padx=6)
        tk.Button(row2, text="🛠 Manual Decoder...",
                  command=self._open_manual_decoder,
                  bg=Theme.BG_MAIN, fg=Theme.TEXT_PRIMARY,
                  activebackground=Theme.BG_HOVER, relief='solid',
                  bd=1, padx=10, pady=1, font=Theme.FONT_SMALL,
                  cursor='hand2').pack(side=tk.LEFT, padx=(14, 0))

        params = tk.Frame(row2, bg=Theme.BG_CARD)
        params.pack(side=tk.RIGHT)
        tk.Label(params, text="Min Len:", font=Theme.FONT_SMALL,
                 bg=Theme.BG_CARD, fg=Theme.TEXT_SECOND
                 ).pack(side=tk.LEFT, padx=(0, 3))
        self.min_length_var = tk.StringVar(value="4")
        tk.Entry(params, textvariable=self.min_length_var, width=4,
                 bg=Theme.BG_CARD, relief='solid', bd=1,
                 font=Theme.FONT_MONO, fg=Theme.TEXT_PRIMARY,
                 insertbackground=Theme.TEXT_PRIMARY
                 ).pack(side=tk.LEFT, padx=(0, 12), ipady=1)
        tk.Label(params, text="Min Score:", font=Theme.FONT_SMALL,
                 bg=Theme.BG_CARD, fg=Theme.TEXT_SECOND
                 ).pack(side=tk.LEFT, padx=(0, 3))
        self.min_score_var = tk.StringVar(value="0.0")
        tk.Entry(params, textvariable=self.min_score_var, width=4,
                 bg=Theme.BG_CARD, relief='solid', bd=1,
                 font=Theme.FONT_MONO, fg=Theme.TEXT_PRIMARY,
                 insertbackground=Theme.TEXT_PRIMARY
                 ).pack(side=tk.LEFT, ipady=1)

    @staticmethod
    def _checkbox(parent, text, var):
        return tk.Checkbutton(parent, text=text, variable=var,
                              bg=Theme.BG_CARD,
                              fg=Theme.TEXT_PRIMARY,
                              activebackground=Theme.BG_CARD,
                              activeforeground=Theme.TEXT_PRIMARY,
                              selectcolor=Theme.BG_SELECTED,
                              font=Theme.FONT_NORMAL,
                              highlightthickness=0, bd=0)

    def _create_packer_banner(self, parent):
        self.packer_banner = tk.Frame(parent, bg=Theme.WARN_BG,
                                      bd=1, relief='solid',
                                      highlightbackground=
                                      Theme.WARN_BORDER)
        self.packer_label = tk.Label(
            self.packer_banner, text="", bg=Theme.WARN_BG,
            fg=Theme.WARN_TEXT, font=("Segoe UI", 9, "bold"),
            anchor='w', justify=tk.LEFT, wraplength=1300)
        self.packer_label.pack(fill=tk.X, padx=10, pady=6)

    def _create_stats_row(self, parent):
        stats = tk.Frame(parent, bg=Theme.BG_MAIN)
        stats.grid(row=2, column=0, sticky='ew', pady=(0, 8))
        for i in range(8):
            stats.grid_columnconfigure(i, weight=1)
        self.stat_cards = {
            "total":      StatCard(stats, "Total", Theme.ACCENT),
            "ascii":      StatCard(stats, "ASCII", "#57606a"),
            "unicode":    StatCard(stats, "Unicode", Theme.ACCENT),
            "stack":      StatCard(stats, "Stack/Tight", "#bc4c00"),
            "dotnet":     StatCard(stats, ".NET #US", "#0550ae"),
            "decoded":    StatCard(stats, "Decoded*", "#8250df"),
            "suspicious": StatCard(stats, "Suspicious",
                                   Theme.ACCENT_RED),
            "secrets":    StatCard(stats, "Secrets", "#a40e26"),
        }
        for i, card in enumerate(self.stat_cards.values()):
            card.grid(row=0, column=i, sticky='nsew', padx=3)

    def _create_results_card(self, parent):
        card = tk.Frame(parent, bg=Theme.BG_CARD, bd=1,
                        relief='solid')
        card.grid(row=3, column=0, sticky='nsew')

        header = tk.Frame(card, bg=Theme.BG_CARD)
        header.pack(fill=tk.X, padx=12, pady=(8, 4))
        tk.Label(header, text="📊 Analysis Results",
                 font=("Segoe UI", 11, "bold"), bg=Theme.BG_CARD,
                 fg=Theme.TEXT_PRIMARY).pack(side=tk.LEFT)

        tf = tk.Frame(header, bg=Theme.BG_CARD)
        tf.pack(side=tk.RIGHT)
        self.type_combo = ttk.Combobox(
            tf, state='readonly', width=20,
            values=["All"] + [t.value for t in StringType])
        self.type_combo.set("All")
        self.type_combo.bind(
            '<<ComboboxSelected>>',
            lambda e: self.results_tree.set_type_filter(
                self.type_combo.get()))
        self.type_combo.pack(side=tk.RIGHT, padx=(8, 0))
        tk.Label(tf, text="Type:", font=Theme.FONT_SMALL,
                 bg=Theme.BG_CARD, fg=Theme.TEXT_SECOND
                 ).pack(side=tk.RIGHT)

        for fmt, label in (("yara", "YARA"), ("csv", "CSV"),
                           ("json", "JSON"), ("txt", "Report")):
            cmd = (self._export_yara if fmt == "yara"
                   else lambda f=fmt: self._export(f))
            tk.Button(header, text=label, command=cmd,
                      bg=Theme.BG_MAIN, fg=Theme.TEXT_PRIMARY,
                      activebackground=Theme.BG_HOVER,
                      relief='solid', bd=1, padx=10, pady=2,
                      font=Theme.FONT_SMALL,
                      cursor='hand2').pack(side=tk.RIGHT, padx=(0, 6))

        columns = ["String Value", "Type", "Offset", "VA",
                   "Section", "Score", "Length"]
        self.results_tree = SearchableTreeview(card, columns)
        self.results_tree.pack(fill=tk.BOTH, expand=True, padx=8,
                               pady=(0, 6))
        self.results_tree.set_column_widths({
            "String Value": 420, "Type": 150, "Offset": 90,
            "VA": 110, "Section": 110, "Score": 60, "Length": 60})
        self.results_tree.tree.bind(
            '<Double-Button-1>', lambda e: self._show_hex())
        self.results_tree.tree.bind(
            '<Return>', lambda e: self._show_hex())

        self.results_tree.tree.tag_configure(
            'odd', background=Theme.BG_CARD)
        self.results_tree.tree.tag_configure(
            'even', background=Theme.BG_MAIN)
        for tname, color in Theme.TYPE_COLORS.items():
            self.results_tree.tree.tag_configure(
                tname, foreground=color)

        self.empty_label = tk.Label(
            card,
            text=f"{APP_ICON}  {APP_NAME} v{APP_VERSION}\n\n"
                 f"Select a file and click Analyze to begin\n\n"
                 f" Dual-strategy emulation (arg-driven + full"
                 f" enumeration)\n"
                 f"Per-key quotas in XOR — real strings never evicted",
            font=("Segoe UI", 11), bg=Theme.BG_CARD,
            fg=Theme.TEXT_MUTED, justify=tk.CENTER)
        self.empty_label.pack(fill=tk.BOTH, expand=True, padx=10,
                              pady=20)

        self._create_hex_viewer(card)

    def _create_hex_viewer(self, parent):
        box = tk.Frame(parent, bg=Theme.BG_CARD)
        box.pack(fill=tk.X, padx=8, pady=(0, 8))
        bar = tk.Frame(box, bg=Theme.BG_CARD)
        bar.pack(fill=tk.X)
        tk.Label(bar, text=" Hex Context",
                 font=("Segoe UI", 9, "bold"),
                 bg=Theme.BG_CARD,
                 fg=Theme.TEXT_PRIMARY).pack(side=tk.LEFT)
        self.hex_info = tk.Label(
            bar, text="double-click a result row to view hex context",
            font=Theme.FONT_SMALL, bg=Theme.BG_CARD,
            fg=Theme.TEXT_MUTED)
        self.hex_info.pack(side=tk.LEFT, padx=12)
        tk.Button(bar, text="Show Hex", command=self._show_hex,
                  bg=Theme.BG_MAIN, fg=Theme.TEXT_PRIMARY,
                  activebackground=Theme.BG_HOVER, relief='solid',
                  bd=1, padx=8, pady=1, font=Theme.FONT_SMALL,
                  cursor='hand2').pack(side=tk.RIGHT)
        tk.Button(bar, text="Clear", command=self._clear_hex,
                  bg=Theme.BG_MAIN, fg=Theme.TEXT_PRIMARY,
                  activebackground=Theme.BG_HOVER, relief='solid',
                  bd=1, padx=8, pady=1, font=Theme.FONT_SMALL,
                  cursor='hand2').pack(side=tk.RIGHT, padx=(0, 4))
        self.hex_text = tk.Text(box, height=8, font=Theme.FONT_MONO,
                                bg=Theme.BG_MAIN,
                                fg=Theme.TEXT_PRIMARY,
                                relief='solid', bd=1, wrap='none',
                                state=tk.DISABLED)
        self.hex_text.pack(fill=tk.X)

    def _create_statusbar(self):
        bar = tk.Frame(self.root, bg=Theme.BG_HOVER, bd=1,
                       relief='flat')
        bar.grid(row=2, column=0, sticky='ew', padx=12, pady=(0, 8))
        self.status_label = tk.Label(bar, text="Ready", anchor='w',
                                     font=Theme.FONT_SMALL,
                                     bg=Theme.BG_HOVER,
                                     fg=Theme.TEXT_SECOND)
        self.status_label.pack(side=tk.LEFT, padx=10, pady=4,
                               fill=tk.X, expand=True)
        self.duration_label = tk.Label(bar, text="",
                                       font=Theme.FONT_SMALL,
                                       bg=Theme.BG_HOVER,
                                       fg=Theme.TEXT_MUTED)
        self.duration_label.pack(side=tk.RIGHT, padx=10)
        self.progress_var = tk.DoubleVar()
        ttk.Progressbar(bar, variable=self.progress_var,
                        mode='determinate', length=220
                        ).pack(side=tk.RIGHT, padx=10, pady=4)


    def _browse_file(self):
        filetypes = [
            ("All supported",
             "*.exe *.dll *.sys *.bin *.dat *.scr *.cpl *.ocx *.drv"),
            ("Executables",
             "*.exe *.dll *.sys *.scr *.cpl *.ocx *.drv"),
            ("Binary files", "*.bin *.dat *.raw"),
            ("All files", "*.*")]
        path = filedialog.askopenfilename(
            title="Select file to analyze", filetypes=filetypes)
        if path:
            self._set_file(path)

    def _set_file(self, path: str):
        self.file_path_var.set(path)
        try:
            size = os.path.getsize(path)
            self.file_label.config(
                text=f"📄 {os.path.basename(path)} "
                     f"({self._fmt_size(size)})")
            md5, sha256 = PEAnalyzer.compute_hashes(path)
            self.file_hash_label.config(
                text=f"MD5 {md5[:20]}…  SHA256 {sha256[:20]}…")
            self.status_label.config(text=f"Loaded: {path}")
        except Exception as e:
            self.status_label.config(text=f"Load error: {e}")

    def _start_analysis(self):
        path = self.file_path_var.get().strip()
        if not path:
            messagebox.showwarning("Warning",
                                   "Please select a file.")
            return
        if not os.path.exists(path):
            messagebox.showerror("Error",
                                 f"File not found:\n{path}")
            return
        if self.is_analyzing:
            messagebox.showinfo("Info",
                                "Analysis already in progress.")
            return

        self.empty_label.pack_forget()
        try:
            with open(path, 'rb') as f:
                self._file_data = f.read()
        except Exception:
            self._file_data = None

        try:
            min_len = int(self.min_length_var.get())
        except ValueError:
            min_len = 4
        try:
            min_score = float(self.min_score_var.get())
        except ValueError:
            min_score = 0.0

        options = AnalysisOptions(
            extract_static=self.var_static.get(),
            extract_unicode=self.var_unicode.get(),
            extract_stack=self.var_stack.get(),
            extract_decoded=self.var_decoded.get(),
            extract_suspicious=self.var_suspicious.get(),
            scan_dotnet=self.var_dotnet.get(),
            scan_resources=self.var_resources.get(),
            scan_multixor=self.var_multixor.get(),
            scan_additive=self.var_additive.get(),
            scan_rolling=self.var_rolling.get(),
            use_emulation=self.var_emulation.get(),
            min_length=min_len, min_score=min_score)

        self.is_analyzing = True
        self.analyze_btn.config(state=tk.DISABLED,
                                text="⏳ Analyzing...")
        self.status_label.config(text="Analyzing...")
        self.progress_var.set(0)
        threading.Thread(target=self._run_analysis,
                         args=(path, options),
                         daemon=True).start()

    def _run_analysis(self, path, options):
        try:
            self.engine.set_progress_callback(self._on_progress)
            result = self.engine.analyze(path, options)
            self.analysis_result = result
            self.root.after(0, self._render_result, result, True)
        except Exception as e:
            self.root.after(0, self._on_error, str(e))
        finally:
            self.is_analyzing = False

    def _on_progress(self, p, msg):
        self.root.after(0, self._update_progress, p, msg)

    def _update_progress(self, p, msg):
        self.progress_var.set(p * 100)
        self.status_label.config(text=msg)


    def _decoded_sum(self, counts: dict) -> int:
        return sum(v for k, v in counts.items()
                   if k.startswith("Decoded"))

    def _update_stats_and_rows(self, result: AnalysisResult):
        c = result.counts_by_type
        self.stat_cards["total"].set_value(result.total_count)
        self.stat_cards["ascii"].set_value(
            c.get("Static ASCII", 0))
        self.stat_cards["unicode"].set_value(
            c.get("Static Unicode", 0))
        self.stat_cards["stack"].set_value(
            c.get("Stack String", 0) + c.get("Tight String", 0))
        self.stat_cards["dotnet"].set_value(
            c.get("DotNet String", 0))
        self.stat_cards["decoded"].set_value(self._decoded_sum(c))
        self.stat_cards["suspicious"].set_value(
            c.get("Suspicious Pattern", 0))
        self.stat_cards["secrets"].set_value(
            c.get("Sensitive / Secret", 0))

        if result.packer_indicators:
            self.packer_label.config(
                text="⚠  " + "    |    ".join(
                    result.packer_indicators[:5]))
            self.packer_banner.grid(row=1, column=0, sticky='ew',
                                    pady=(0, 8))
        else:
            self.packer_banner.grid_remove()

        self._display_strings = result.strings
        rows = [(s.value[:200], s.type.value, hex(s.offset),
                 hex(s.virtual_address) if s.virtual_address else "-",
                 s.section or "-", f"{s.score:.2f}", str(s.length),
                 s.type.value)
                for s in result.strings]
        self.results_tree.clear()
        self.results_tree.insert_data(rows)

    def _render_result(self, result: AnalysisResult,
                       show_warnings=True):
        self._update_stats_and_rows(result)
        stats_txt = ""
        if result.phase_stats:
            stats_txt = "   |   " + ", ".join(
                f"{k}: {v}"
                for k, v in result.phase_stats.items())
        info_txt = ""
        if result.info_notes:
            info_txt = "   |   " + "; ".join(result.info_notes)
        self.status_label.config(
            text=f"✅ Analysis complete: "
                 f"{result.total_count} strings found"
                 f"{stats_txt}{info_txt}")
        self.duration_label.config(
            text=f"⏱ {result.duration:.2f}s")
        self.progress_var.set(100)
        self.analyze_btn.config(state=tk.NORMAL, text="⚡ Analyze")
        if show_warnings and result.errors:
            messagebox.showwarning(
                "Analysis Warnings",
                "Some issues occurred:\n" +
                "\n".join(result.errors[:8]))

    def _on_error(self, err):
        self.status_label.config(text=f"❌ Error: {err}")
        self.analyze_btn.config(state=tk.NORMAL, text="⚡ Analyze")
        messagebox.showerror("Analysis Error", err)

    def _cancel_analysis(self):
        self.engine.cancel()
        self.status_label.config(text="Cancelling...")

    def _clear_results(self):
        self.results_tree.clear()
        self.analysis_result = None
        self._display_strings = []
        self._file_data = None
        for card in self.stat_cards.values():
            card.set_value(0)
        self.packer_banner.grid_remove()
        self._clear_hex()
        self.empty_label.pack(fill=tk.BOTH, expand=True, padx=10,
                              pady=20)
        self.status_label.config(text="Ready")
        self.progress_var.set(0)
        self.duration_label.config(text="")


    def _show_hex(self):
        sel = self.results_tree.tree.selection()
        if not sel:
            return
        try:
            idx = int(sel[0][1:])
            s = self._display_strings[idx]
        except (ValueError, IndexError):
            return
        if self._file_data is None or s.offset == 0:
            self.hex_info.config(
                text="File data not available for this row "
                     "(emulated results have no file offset)")
            return
        self.hex_text.config(state=tk.NORMAL)
        self.hex_text.delete('1.0', tk.END)
        self.hex_text.insert('1.0',
                             hexdump(self._file_data, s.offset))
        self.hex_text.config(state=tk.DISABLED)
        va = hex(s.virtual_address) if s.virtual_address else "-"
        self.hex_info.config(
            text=f"{s.type.value}  |  offset {hex(s.offset)}  |  "
                 f"VA {va}  |  {s.section or '-'}  |  "
                 f"score {s.score:.2f}")

    def _clear_hex(self):
        self.hex_text.config(state=tk.NORMAL)
        self.hex_text.delete('1.0', tk.END)
        self.hex_text.config(state=tk.DISABLED)
        self.hex_info.config(
            text="double-click a result row to view hex context")


    def _open_manual_decoder(self):
        selected_offset = None
        sel = self.results_tree.tree.selection()
        if sel and self._display_strings:
            try:
                selected_offset = \
                    self._display_strings[int(sel[0][1:])].offset
            except (ValueError, IndexError):
                pass
        ManualDecoderDialog(self.root, self._file_data,
                            selected_offset,
                            self._add_manual_string)

    def _add_manual_string(self, es: ExtractedString):
        if self.analysis_result is None:
            self.analysis_result = AnalysisResult(
                filepath=self.file_path_var.get())
        self.analysis_result.strings.append(es)
        self.analysis_result.strings.sort(
            key=lambda x: x.score, reverse=True)
        self.empty_label.pack_forget()
        self._update_stats_and_rows(self.analysis_result)
        self.status_label.config(
            text=f"＋ Manual decode added: {es.value[:50]}")


    def _save_session(self):
        if not self.analysis_result or \
                not self.analysis_result.strings:
            messagebox.showwarning("Warning", "No results to save.")
            return
        path = filedialog.asksaveasfilename(
            title="Save session", defaultextension=".json",
            filetypes=[("Session files", "*.json")])
        if path:
            try:
                ITShieldEngine.save_session(self.analysis_result,
                                            path)
                self.status_label.config(
                    text=f"Session saved: {path}")
            except Exception as e:
                messagebox.showerror("Error", f"Save failed:\n{e}")

    def _load_session(self):
        path = filedialog.askopenfilename(
            title="Load session",
            filetypes=[("Session files", "*.json"),
                       ("All files", "*.*")])
        if not path:
            return
        try:
            result = ITShieldEngine.load_session(path)
        except Exception as e:
            messagebox.showerror("Error", f"Load failed:\n{e}")
            return
        self.analysis_result = result
        self.file_path_var.set(result.filepath)
        if os.path.exists(result.filepath):
            self._set_file(result.filepath)
            try:
                with open(result.filepath, 'rb') as f:
                    self._file_data = f.read()
            except Exception:
                self._file_data = None
        else:
            self._file_data = None
        self.empty_label.pack_forget()
        self._render_result(result, show_warnings=False)
        self.status_label.config(
            text=f"Session loaded: {result.total_count} strings")


    def _export(self, fmt: str):
        if not self.analysis_result or \
                not self.analysis_result.strings:
            messagebox.showwarning(
                "Warning", "No results. Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(
            title=f"Export as {fmt.upper()}",
            defaultextension=f".{fmt}",
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}")])
        if path:
            try:
                ITShieldEngine.export(self.analysis_result, path,
                                      fmt)
                messagebox.showinfo("Export Complete",
                                    f"Saved to:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def _export_yara(self):
        if not self.analysis_result or \
                not self.analysis_result.strings:
            messagebox.showwarning(
                "Warning", "No results. Run an analysis first.")
            return
        rule = generate_yara_rule(self.analysis_result)
        if not rule:
            messagebox.showwarning(
                "Warning",
                "No high-score printable strings (>=0.7).")
            return
        path = filedialog.asksaveasfilename(
            title="Export YARA rule", defaultextension=".yar",
            filetypes=[("YARA rules", "*.yar")])
        if path:
            try:
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(rule + "\n")
                messagebox.showinfo("Export Complete",
                                    f"YARA rule saved to:\n{path}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))


    def _show_dependencies(self):
        rows = [("numpy (fast XOR/scanning)", HAS_NUMPY),
                ("pefile (PE parsing)", HAS_PEFILE),
                ("capstone (disassembly + RIP refs)", HAS_CAPSTONE),
                ("unicorn (EMULATION — catches any decoder!)",
                 HAS_UNICORN),
                ("tkinterdnd2 (drag & drop)", HAS_DND)]
        missing = [n for n, ok in rows if not ok]
        text = "\n".join(f"{'✅' if ok else '❌'}  {name}"
                         for name, ok in rows)
        extra = ("\n\nInstall missing:\n  pip install " +
                 " ".join(n.split(' ')[0] for n in missing)) \
            if missing else \
            "\n\nAll optional dependencies installed. 🎉"
        if not HAS_UNICORN:
            extra += ("\n\n⚠ Without 'unicorn', decoded strings "
                      "made by custom algorithms (like FLOSS "
                      "finds) may be missed!")
        messagebox.showinfo("Dependencies", text + extra)

    def _show_about(self):
        dlg = tk.Toplevel(self.root)
        dlg.title("About")
        dlg.geometry("540x580")
        dlg.configure(bg=Theme.BG_CARD, bd=1, relief='solid')
        dlg.resizable(False, False)
        dlg.transient(self.root)
        dlg.grab_set()
        text = (
            f"{APP_ICON}  {APP_NAME} v{APP_VERSION}\n\n"
            f"Decoding engines:\n"
            f"  • Unicorn EMULATION (dual-strategy)\n"
            f"  • Multi-byte XOR w/ auto key recovery\n"
            f"  • Additive & Rolling-XOR ciphers\n"
            f"  • Single-byte XOR, Base64, ROT13, Reversed\n"
            f"  • Manual Decoder: XOR/RC4/ADD/custom expr\n\n"
            f"Also:\n"
            f"  • Static ASCII/Unicode, .NET #US, PE resources\n"
            f"  • Stack & tight strings (byte/dword writes)\n"
            f"  • IOC & secret detection, packer detection\n"
            f"  • Hex viewer, YARA export, sessions, drag&drop\n\n"
            f"Inspired by FLARE-FLOSS (Mandiant)\n"
            f"Akhzari\n\n"
            f"Telegram : @itshield\n\n"
            f"© 2024 {APP_AUTHOR}")
        tk.Label(dlg, text=text, font=Theme.FONT_NORMAL,
                 bg=Theme.BG_CARD, fg=Theme.TEXT_PRIMARY,
                 justify=tk.LEFT, anchor='nw'
                 ).pack(fill=tk.BOTH, expand=True, padx=20, pady=16)
        tk.Button(dlg, text="Close", command=dlg.destroy,
                  bg=Theme.ACCENT, fg='white',
                  activebackground=Theme.ACCENT_HOVER, relief='flat',
                  bd=0, padx=20, pady=5,
                  font=("Segoe UI", 10, "bold"),
                  cursor='hand2').pack(pady=(0, 12))

    @staticmethod
    def _fmt_size(size: int) -> str:
        for unit in ('B', 'KB', 'MB', 'GB'):
            if size < 1024:
                return (f"{size} B" if unit == 'B'
                        else f"{size:.1f} {unit}")
            size /= 1024
        return f"{size:.1f} TB"

    def run(self):
        self.root.mainloop()


def check_dependencies() -> dict:
    return {"numpy": HAS_NUMPY, "pefile": HAS_PEFILE,
            "capstone": HAS_CAPSTONE, "unicorn": HAS_UNICORN,
            "tkinterdnd2": HAS_DND}


def _print_deps():
    deps = check_dependencies()
    missing = [k for k, v in deps.items()
               if not v and k != "tkinterdnd2"]
    if missing:
        print(f" Missing optional deps: {', '.join(missing)}")
        print(f"    Install: pip install {' '.join(missing)}")
        if 'unicorn' in missing:
            print("     Without 'unicorn', custom decoders "
                  "will be missed!")
        print("    Continuing with reduced functionality...\n")


def run_cli(filepath: str, options: AnalysisOptions,
            export_format: Optional[str] = None,
            save_session: Optional[str] = None,
            debug: bool = False, find_text: Optional[str] = None):
    if sys.platform == 'win32':
        os.system('')
    print(f"\n{APP_ICON} {APP_NAME} v{APP_VERSION} — CLI Mode")
    print("=" * 64)
    print(f"Analyzing: {filepath}")
    print("=" * 64)

    engine = ITShieldEngine()
    engine.set_progress_callback(
        lambda p, m: print(f"\r  [{int(p * 100):3d}%] {m:<46}",
                           end="", flush=True))
    result = engine.analyze(filepath, options)
    print("\n")

    print(f"  File:      {result.filepath}")
    print(f"  Size:      {result.file_size:,} bytes")
    print(f"  Duration:  {result.duration:.2f}s")
    print(f"  Found:     {result.total_count} strings")
    if result.pe_info and result.pe_info.is_valid:
        pe = result.pe_info
        print(f"  Machine:   {pe.machine}  |  "
              f"Subsystem: {pe.subsystem}")
    if result.packer_indicators:
        print("\n  ⚠  PACKER INDICATORS:")
        for ind in result.packer_indicators:
            print(f"     - {ind}")

    if result.errors:
        print("\n  ⚠  PHASE ERRORS / NOTES:")
        for e in result.errors:
            print(f"     - {e}")

    if debug and result.phase_stats:
        print("\n  Phase statistics:")
        for k, v in result.phase_stats.items():
            print(f"     {k:<28} {v:>6}")
    if debug and result.info_notes:
        print("\n  Info notes:")
        for n in result.info_notes:
            print(f"     - {n}")
    if find_text:
        needle = find_text.lower()
        hits = [s for s in result.strings
                if needle in s.value.lower()]
        print(f"\n  🔎 Search '{find_text}': "
              f"{len(hits)} match(es)")
        for s in hits[:40]:
            print(f"     [{s.score:.2f}] [{s.type.value}] "
                  f"@{hex(s.offset)} enc={s.encoding}")
            print(f"        -> {s.value[:100]}")
        if not hits:
            print("        (nothing found — check phase stats "
                  "above)")

    print("\n" + "─" * 64)
    print("  Top results (by score):")
    print("─" * 64)
    for s in result.strings[:60]:
        color = reset = ""
        if sys.platform != 'win32':
            if s.type == StringType.SENSITIVE or s.score >= 0.8:
                color, reset = "\033[91m", "\033[0m"
            elif s.score >= 0.6:
                color, reset = "\033[93m", "\033[0m"
            else:
                color, reset = "\033[92m", "\033[0m"
        short = s.type.value.replace("Static ", "")\
            .replace("Decoded ", "D:")
        print(f"  [{s.score:.2f}] {color}[{short:>19}]{reset} "
              f"{s.value[:66]}")
    if len(result.strings) > 60:
        print(f"\n  ... and {len(result.strings) - 60} more")

    if export_format:
        out = os.path.splitext(filepath)[0] + \
            f"_strings.{export_format}"
        ITShieldEngine.export(result, out, export_format)
        print(f"\n  ✅ Exported to: {out}")
    if save_session:
        ITShieldEngine.save_session(result, save_session)
        print(f"  ✅ Session saved: {save_session}")
    print()


def run_session(path: str, export_format: Optional[str] = None):
    result = ITShieldEngine.load_session(path)
    print(f"\n{APP_ICON} Loaded session: {path}")
    print(f"  File:   {result.filepath}")
    print(f"  Total:  {result.total_count} strings\n")
    for s in result.strings[:50]:
        short = s.type.value.replace("Static ", "")
        print(f"  [{s.score:.2f}] [{short:>19}] {s.value[:66]}")
    if export_format:
        out = os.path.splitext(path)[0] + \
            f"_export.{export_format}"
        ITShieldEngine.export(result, out, export_format)
        print(f"\n  ✅ Exported to: {out}")
    print()




SELFTEST_XOR_BLOB = bytes([          # exact array from the C sample
    0x13, 0x0E, 0x09, 0x32, 0x33, 0x3F, 0x33, 0x36,
    0x3E, 0x7A, 0x02, 0x15, 0x08, 0x7A, 0x3E, 0x3F,
    0x39, 0x35, 0x3E, 0x3F, 0x3E, 0x7A, 0x37, 0x3F,
    0x29, 0x29, 0x3B, 0x3D, 0x3F])


def run_selftest() -> int:
    print(f"\n{APP_ICON} {APP_NAME} — decoder self-test (with noise)")
    print("=" * 60)
    noise = bytes((i * 37 + 11) % 251 for i in range(100_000))
    ok_all = True

    # 1) single-byte XOR — exact C-sample bytes inside 100KB noise
    expected = bytes(b ^ 0x5A
                     for b in SELFTEST_XOR_BLOB).decode('ascii')
    results1 = FastDecoder(4).find_xor(
        noise + SELFTEST_XOR_BLOB + noise)
    hits = [s for s in results1 if expected in s.value]
    ok = bool(hits)
    ok_all &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] single-byte XOR "
          f"(key 0x5A, inside 100KB noise)")
    print(f"         expected : {expected}")
    if hits:
        found = hits[0]
        extra_len = len(found.value) - len(expected)
        note = (f"  (+{extra_len} boundary byte(s) merged — "
                f"normal)") if extra_len > 0 else ""
        print(f"         found    : {found.value}  "
              f"({found.encoding}, score {found.score:.2f}){note}")
    else:
        near = [s for s in results1
                if 'its' in s.value.lower()][:3]
        for s in near:
            print(f"         near-miss: {s.value[:80]}")

    # 2) multi-byte XOR — repeating text so the space-frequency
    #    assumption holds
    key = bytes([0xDE, 0xAD, 0xBE, 0xEF])
    secret = b"the quick brown fox jumps over the lazy dog. " * 10
    enc = bytes(b ^ key[i % 4]
                for i, b in enumerate(secret))
    blob = noise[:2000] + enc + noise[2000:4000]
    hits2 = [s for s in StatisticalDecoder(5)
             .find_multibyte_xor(blob)
             if 'quick brown fox' in s.value]
    ok = bool(hits2)
    ok_all &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] multi-byte XOR "
          f"(DE AD BE EF)")
    if hits2:
        print(f"         found    : {hits2[0].value[:60]}...")

    # 3) additive — inside noise
    secret3 = b"the quick brown fox jumps over the lazy dog. " * 5
    enc3 = bytes((b + 0x11) & 0xFF for b in secret3)
    hits3 = [s for s in StatisticalDecoder(5).find_additive(
                 noise + enc3 + noise)
             if 'quick brown fox' in s.value]
    ok = bool(hits3)
    ok_all &= ok
    print(f"  [{'PASS' if ok else 'FAIL'}] additive "
          f"(+0x11, inside noise)")
    if hits3:
        print(f"         found    : {hits3[0].value[:60]}...")

    print("\n  Result:", "ALL PASS ✅" if ok_all else "FAILED ❌")
    return 0 if ok_all else 1


def show_help():
    print(f"""
{APP_ICON} {APP_NAME} v{APP_VERSION}
Advanced String Extraction & Malware Analysis Tool

Usage:
    python ITShield-Floss.py                          Launch GUI
    python ITShield-Floss.py <file>                   Analyze in CLI
    python ITShield-Floss.py <file> --export csv|json|txt|yara
    python ITShield-Floss.py <file> --find "ITS" --debug
    python ITShield-Floss.py --selftest

Decoding engines:
     Unicorn emulation   — dual-strategy: arg-driven blob refs
                             AND full function enumeration with
                             stack capture (ANY algorithm)
    Single-byte XOR        — whole-file, PER-KEY quotas, ranked
    Multi-byte XOR         — auto key recovery (2-8 byte keys)
    Additive / Rolling XOR — with printable-run gate
    Stack strings          — byte/word/dword/qword writes
    Manual Decoder (GUI)   — XOR hex, RC4, custom Python expression

Options:
    --min-length N        Minimum string length (default 4)
    --min-score N         Minimum confidence 0.0-1.0 (default 0.0)
    --find TEXT           Search results for TEXT (substring)
    --debug               Show per-phase statistics
    --no-unicode / --no-stack / --no-decoded / --no-suspicious
    --no-dotnet / --no-resources / --no-multixor
    --no-additive / --no-rolling / --no-emulation
    --export FORMAT       csv | json | txt | yara
    --save-session FILE / --session FILE
    --selftest            Run decoder self-test and exit

Optional dependencies:
    pip install numpy pefile capstone unicorn tkinterdnd2

Tips:
    Compile test C samples with -O0! With -O2 the compiler folds
    the XOR at compile time and the encoded array disappears.

Examples:
    python ITShield-Floss.py malware.exe
    python ITShield-Floss.py test.exe --find "decoded" --debug
""")

def main():
    args = sys.argv[1:]
    if '--help' in args or '-h' in args:
        show_help()
        sys.exit(0)
    if '--selftest' in args:
        sys.exit(run_selftest())

    load_plugins()

    filepath = export_format = session_file = None
    load_session_path = None
    find_text = None
    debug = False
    min_length, min_score = 4, 0.0
    options = AnalysisOptions()

    i = 0
    while i < len(args):
        a = args[i]
        if a == '--export':
            i += 1
            export_format = args[i].lower() if i < len(args) else None
        elif a == '--save-session':
            i += 1
            session_file = args[i] if i < len(args) else None
        elif a == '--session':
            i += 1
            load_session_path = args[i] if i < len(args) else None
        elif a == '--find':
            i += 1
            find_text = args[i] if i < len(args) else None
        elif a == '--debug':
            debug = True
        elif a == '--min-length':
            i += 1
            try:
                min_length = int(args[i])
            except (ValueError, IndexError):
                pass
        elif a == '--min-score':
            i += 1
            try:
                min_score = float(args[i])
            except (ValueError, IndexError):
                pass
        elif a == '--no-unicode':
            options.extract_unicode = False
        elif a == '--no-stack':
            options.extract_stack = False
        elif a == '--no-decoded':
            options.extract_decoded = False
        elif a == '--no-suspicious':
            options.extract_suspicious = False
        elif a == '--no-dotnet':
            options.scan_dotnet = False
        elif a == '--no-resources':
            options.scan_resources = False
        elif a == '--no-multixor':
            options.scan_multixor = False
        elif a == '--no-additive':
            options.scan_additive = False
        elif a == '--no-rolling':
            options.scan_rolling = False
        elif a == '--no-emulation':
            options.use_emulation = False
        elif not a.startswith('--'):
            filepath = a
        i += 1

    options.min_length = min_length
    options.min_score = min_score

    if load_session_path:
        if not os.path.exists(load_session_path):
            print(f"Error: session file not found: "
                  f"{load_session_path}")
            sys.exit(1)
        run_session(load_session_path, export_format)
        return

    if filepath is None:
        print(f"""
╔══════════════════════════════════════════════════════════╗
║     {APP_ICON}  {APP_NAME} v{APP_VERSION}  —  Light Edition              ║
║   Advanced String Extraction & Analysis Tool              ║
║     Dual-strategy emulation + per-key XOR quotas          ║
╚══════════════════════════════════════════════════════════╝
        """)
        _print_deps()
        try:
            MainWindow().run()
        except tk.TclError as e:
            print(f"Error: cannot start GUI: {e}")
            print("Try CLI mode: python ITShield-Floss.py <file>")
            sys.exit(1)
        return

    if not os.path.exists(filepath):
        print(f"Error: file not found: {filepath}")
        sys.exit(1)
    _print_deps()
    run_cli(filepath, options, export_format, session_file,
            debug, find_text)


if __name__ == "__main__":
    main()

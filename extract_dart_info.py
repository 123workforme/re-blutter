import io
import os
import re
import sys
import zipfile
import zlib
from struct import unpack

ELF_MAGIC = b'\x7fELF'
MACHO_MAGIC_64 = 0xFEEDFACF
MACHO_MAGIC_32 = 0xFEEDFACE
FAT_MAGIC = 0xCAFEBABE
FAT_MAGIC_64 = 0xCAFEBABF

CPU_TYPE_ARM64 = 0x0100000C
CPU_TYPE_X86_64 = 0x01000007

LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x02

FMT_ELF = 'elf'
FMT_MACHO = 'macho'


def detect_format(path):
    with open(path, 'rb') as f:
        head = f.read(4)
    if head[:4] == ELF_MAGIC:
        return FMT_ELF
    magic_le = unpack('<I', head)[0]
    magic_be = unpack('>I', head)[0]
    if magic_le in (MACHO_MAGIC_64, MACHO_MAGIC_32):
        return FMT_MACHO
    if magic_be in (FAT_MAGIC, FAT_MAGIC_64):
        return FMT_MACHO
    raise ValueError(f"Unknown binary format (magic {head.hex()}) in {path}")


class MachOSegment:
    __slots__ = ('vmaddr', 'vmsize', 'fileoff', 'filesize', 'sections')

    def __init__(self, vmaddr, vmsize, fileoff, filesize):
        self.vmaddr = vmaddr
        self.vmsize = vmsize
        self.fileoff = fileoff
        self.filesize = filesize
        self.sections = []


class MachO:
    def __init__(self, path=None, data=None, prefer_cpu=CPU_TYPE_ARM64):
        if data is None:
            with open(path, 'rb') as f:
                data = f.read()
        self.data = self._select_slice(data, prefer_cpu)

        magic = unpack('<I', self.data[:4])[0]
        if magic == MACHO_MAGIC_32:
            raise ValueError("Mach-O: only 64-bit is supported")
        if magic != MACHO_MAGIC_64:
            raise ValueError(f"Mach-O: unexpected magic {magic:#x} (need host-endian 64-bit)")

        (_, self.cputype, _, self.filetype,
         self.ncmds, self.sizeofcmds, _, _) = unpack('<IiiIIIII', self.data[:32])

        self.segments = []
        self.symoff = self.nsyms = self.stroff = self.strsize = 0
        self._parse_load_commands()

    @staticmethod
    def _select_slice(data, prefer_cpu):
        magic_be = unpack('>I', data[:4])[0]
        if magic_be not in (FAT_MAGIC, FAT_MAGIC_64):
            return data

        is64 = magic_be == FAT_MAGIC_64
        nfat = unpack('>I', data[4:8])[0]
        entry_size = 32 if is64 else 20
        chosen = None
        first = None
        for i in range(nfat):
            off = 8 + i * entry_size
            if is64:
                cputype, _, foff, fsize, _, _ = unpack('>iiQQII', data[off:off + entry_size])
            else:
                cputype, _, foff, fsize, _ = unpack('>iiIII', data[off:off + entry_size])
            slice_bytes = data[foff:foff + fsize]
            if first is None:
                first = slice_bytes
            if (cputype & 0xffffffff) == (prefer_cpu & 0xffffffff):
                chosen = slice_bytes
                break
        return chosen if chosen is not None else first

    def _parse_load_commands(self):
        off = 32
        for _ in range(self.ncmds):
            cmd, cmdsize = unpack('<II', self.data[off:off + 8])
            if cmd == LC_SEGMENT_64:
                (_, _, segname, vmaddr, vmsize, fileoff, filesize,
                 _, _, nsects, _) = unpack('<II16sQQQQiiII', self.data[off:off + 72])
                seg = MachOSegment(vmaddr, vmsize, fileoff, filesize)
                sec_off = off + 72
                for _s in range(nsects):
                    sectname, s_segname, s_addr, s_size, s_offset = unpack(
                        '<16s16sQQI', self.data[sec_off:sec_off + 52])
                    seg.sections.append((
                        s_segname.rstrip(b'\x00').decode('utf-8', 'replace'),
                        sectname.rstrip(b'\x00').decode('utf-8', 'replace'),
                        s_addr, s_size, s_offset))
                    sec_off += 80
                self.segments.append(seg)
            elif cmd == LC_SYMTAB:
                _, _, self.symoff, self.nsyms, self.stroff, self.strsize = unpack(
                    '<IIIIII', self.data[off:off + 24])
            off += cmdsize

    def va_to_fileoff(self, addr):
        for s in self.segments:
            if s.vmaddr <= addr < s.vmaddr + s.vmsize:
                return addr - s.vmaddr + s.fileoff
        return addr

    def find_symbol(self, name):
        target = name.encode() if isinstance(name, str) else name
        strtab = self.data[self.stroff:self.stroff + self.strsize]
        for i in range(self.nsyms):
            base = self.symoff + i * 16
            n_strx, _n_type, _n_sect, _n_desc, n_value = unpack(
                '<IBBHQ', self.data[base:base + 16])
            if n_strx == 0:
                continue
            end = strtab.find(b'\x00', n_strx)
            sym = strtab[n_strx:end]
            if sym == target:
                return self.va_to_fileoff(n_value)
        return None

    def const_data(self):
        blobs = []
        for s in self.segments:
            for segname, sectname, _addr, size, offset in s.sections:
                if sectname == '__const' or segname == '__DATA_CONST' or sectname == '__cstring':
                    blobs.append(self.data[offset:offset + size])
        return b'\x00'.join(blobs) if blobs else self.data

    @property
    def arch(self):
        cpu = self.cputype & 0xffffffff
        if cpu == (CPU_TYPE_ARM64 & 0xffffffff):
            return 'arm64'
        if cpu == (CPU_TYPE_X86_64 & 0xffffffff):
            return 'x64'
        raise ValueError(f"Unsupported Mach-O cputype: {cpu:#x}")


def _elf_snapshot_hash_flags(libapp_file):
    from elftools.elf.elffile import ELFFile
    with open(libapp_file, 'rb') as f:
        elf = ELFFile(f)
        dynsym = elf.get_section_by_name('.dynsym')
        sym = dynsym.get_symbol_by_name('_kDartVmSnapshotData')[0]
        assert sym['st_size'] > 128
        f.seek(sym['st_value'] + 20)
        snapshot_hash = f.read(32).decode()
        data = f.read(256)
        flags = data[:data.index(b'\0')].decode().strip().split(' ')
    return snapshot_hash, flags


def _macho_snapshot_hash_flags(libapp_file):
    macho = MachO(path=libapp_file)
    foff = macho.find_symbol('_kDartVmSnapshotData')
    if foff is None:
        raise ValueError("Mach-O: cannot find _kDartVmSnapshotData symbol")
    hash_off = foff + 20
    snapshot_hash = macho.data[hash_off:hash_off + 32].decode()
    rest = macho.data[hash_off + 32:hash_off + 32 + 256]
    flags = rest[:rest.index(b'\0')].decode().strip().split(' ')
    return snapshot_hash, flags


def extract_snapshot_hash_flags(libapp_file):
    if detect_format(libapp_file) == FMT_MACHO:
        return _macho_snapshot_hash_flags(libapp_file)
    return _elf_snapshot_hash_flags(libapp_file)


def _find_engine_ids_and_version(data):
    sha_hashes = re.findall(b'\x00([a-f\\d]{40})(?=\x00)', data)
    engine_ids = [h.decode() for h in sha_hashes]

    m = re.search(br'\x00([\d\w\.-]+) \((stable|beta|dev)\)', data)
    dart_version = m.group(1).decode() if m else None
    return engine_ids, dart_version


def _elf_libflutter_info(libflutter_file):
    from elftools.elf.elffile import ELFFile
    with open(libflutter_file, 'rb') as f:
        elf = ELFFile(f)
        if elf.header.e_machine == 'EM_AARCH64':
            arch = 'arm64'
        elif elf.header.e_machine == 'EM_IA_64':
            arch = 'x64'
        else:
            assert False, f"Unsupport architecture: {elf.header.e_machine}"

        section = elf.get_section_by_name('.rodata')
        data = section.data()

    engine_ids, dart_version = _find_engine_ids_and_version(data)
    if dart_version is None:
        assert len(engine_ids) == 2, f'found hashes {", ".join(engine_ids)}'
    return engine_ids, dart_version, arch, 'android'


def _macho_libflutter_info(libflutter_file):
    macho = MachO(path=libflutter_file)
    arch = macho.arch
    data = macho.const_data()
    engine_ids, dart_version = _find_engine_ids_and_version(data)
    if dart_version is None:
        engine_ids, dart_version = _find_engine_ids_and_version(macho.data)
        if dart_version is None:
            assert len(engine_ids) >= 1, "Mach-O: cannot find engine id or dart version in Flutter framework"
    return engine_ids, dart_version, arch, 'ios'


def extract_libflutter_info(libflutter_file):
    if detect_format(libflutter_file) == FMT_MACHO:
        return _macho_libflutter_info(libflutter_file)
    return _elf_libflutter_info(libflutter_file)


def get_dart_sdk_url_size(engine_ids):
    import requests
    for engine_id in engine_ids:
        url = f'https://storage.googleapis.com/flutter_infra_release/flutter/{engine_id}/dart-sdk-windows-x64.zip'
        resp = requests.head(url)
        if resp.status_code == 200:
            sdk_size = int(resp.headers['Content-Length'])
            return engine_id, url, sdk_size

    return None, None, None


def get_dart_commit(url):
    import requests
    commit_id = None
    dart_version = None
    fp = None
    with requests.get(url, headers={"Range": "bytes=0-4096"}, stream=True) as r:
        if r.status_code // 10 == 20:
            x = next(r.iter_content(chunk_size=4096))
            fp = io.BytesIO(x)

    if fp is not None:
        while fp.tell() < 4096 - 30 and (commit_id is None or dart_version is None):
            _, _, _, compMethod, _, _, _, compressSize, _, filenameLen, extraLen = unpack('<IHHHHHIIIHH', fp.read(30))
            filename = fp.read(filenameLen)
            if extraLen > 0:
                fp.seek(extraLen, io.SEEK_CUR)
            data = fp.read(compressSize)

            assert compMethod == zipfile.ZIP_DEFLATED, 'Unexpected compression method'
            if filename == b'dart-sdk/revision':
                commit_id = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()
            elif filename == b'dart-sdk/version':
                dart_version = zlib.decompress(data, wbits=-zlib.MAX_WBITS).decode().strip()

    return commit_id, dart_version


def extract_dart_info(libapp_file: str, libflutter_file: str):
    snapshot_hash, flags = extract_snapshot_hash_flags(libapp_file)

    engine_ids, dart_version, arch, os_name = extract_libflutter_info(libflutter_file)

    if dart_version is None:
        engine_id, sdk_url, sdk_size = get_dart_sdk_url_size(engine_ids)
        commit_id, dart_version = get_dart_commit(sdk_url)

    return dart_version, snapshot_hash, flags, arch, os_name


if __name__ == "__main__":
    libdir = sys.argv[1]
    libapp_file = os.path.join(libdir, 'libapp.so')
    libflutter_file = os.path.join(libdir, 'libflutter.so')
    if not os.path.isfile(libapp_file):
        libapp_file = os.path.join(libdir, 'App')
    if not os.path.isfile(libflutter_file):
        libflutter_file = os.path.join(libdir, 'Flutter')

    print(extract_dart_info(libapp_file, libflutter_file))

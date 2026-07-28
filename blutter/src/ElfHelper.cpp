#include "pch.h"
#include "ElfHelper.h"
PRAGMA_WARNING(push, 0)
#include <platform/elf.h>
#if defined(DART_TARGET_OS_MACOS)
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#endif
PRAGMA_WARNING(pop)
#include <algorithm>
#include <stdexcept>
#include <vector>
#include <string>
#if defined(_WIN32) || defined(WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/stat.h>
//#include <dlfcn.h>
#include <sys/mman.h>
#endif // #if defined(_WIN32) || defined(WIN32)

struct ElfIdent {
	uint8_t ei_magic[4];
	uint8_t ei_class;
	uint8_t ei_data;
	uint8_t ei_version;
	uint8_t ei_osabi;
	uint8_t ei_abiversion;
	uint8_t pad1[7];
};

using namespace dart::elf;

#ifdef _WIN32
static void* load_map_file(const char* path)
{
	HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("\nCannot find %s\n", path);
		return NULL;
	}

	// because Dart API requires only snapshot buffer addresses (no relative access across snapshot),
	//   so we can just mapping a whole file and find address of snapshots
	HANDLE hMapFile = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (hMapFile == INVALID_HANDLE_VALUE)
		return NULL;

	// need RW because dart initialization need writing data in BSS
	void* mem = MapViewOfFile(hMapFile, FILE_MAP_COPY, 0, 0, 0);
	CloseHandle(hMapFile);

	CloseHandle(hFile);
	return mem;
}
#else
static void* load_map_file(const char* path)
{
	// need RW because dart initialization need writing data in BSS
	int fd = open(path, O_RDONLY);
	struct stat st;

	fstat(fd, &st);
	void* mem = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

	close(fd);
	return mem;
}
#endif

LibAppInfo ElfHelper::findSnapshots(const uint8_t* elf)
{
	const auto* hdr = (const ElfHeader*)elf;
	if (hdr->section_table_entry_size != sizeof(SectionHeader))
		throw std::invalid_argument("ELF: Invalid section entry size");

	const auto* section = (SectionHeader*)(elf + hdr->section_table_offset);
	const auto sh_num = hdr->num_section_headers;

	// find .dynstr and .dynsym sections, so we can map the section names
	const char* dynstr = nullptr;
	const Symbol* dynsym = nullptr;
	const Symbol* dynsym_end = nullptr;
	for (uint16_t i = 0; i < sh_num; i++, section++) {
		if (section->type == SectionHeaderType::SHT_STRTAB && dynstr == nullptr) {
			// we want only .dynstr for .dynsym
			const char* strtab = (const char*)elf + section->file_offset;
			const char* last = strtab + section->file_size;
			const char* s_first = kVmSnapshotDataAsmSymbol;
			const char* s_last = s_first + strlen(kVmSnapshotDataAsmSymbol) + 1;
			//if (memmem(strtab, section->s_size, kVmSnapshotDataAsmSymbol, strlen(kVmSnapshotDataAsmSymbol))) {
			if (std::search(strtab, last, s_first, s_last) != last) {
				// found it
				dynstr = strtab;
			}
		}
		if (section->type == SectionHeaderType::SHT_DYNSYM) {
			if (section->entry_size != sizeof(Symbol))
				throw std::invalid_argument("ELF: Invalid DYNSYM entry size");
			dynsym = (Symbol*)(elf + section->file_offset);
			dynsym_end = (Symbol*)(elf + section->file_offset + section->file_size);
		}
		if (dynsym != nullptr && dynstr != nullptr)
			break;
	}

	// find the required symbol addresses
	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;
	for (; dynsym < dynsym_end; dynsym++) {
		if (dynsym->info == 0)
			continue;

		const char* name = dynstr + dynsym->name;
		// Note: sym_size is no needed for dart VM (its blob contains size)
		if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
			vm_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
			vm_snapshot_instructions = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
			isolate_snapshot_data = elf + dynsym->value;
		}
		else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
			isolate_snapshot_instructions = elf + dynsym->value;
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("ELF: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = elf,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
}

LibAppInfo ElfHelper::MapLibAppSo(const char* path)
{
	void* lib = load_map_file(path);
	uint8_t* base = (uint8_t*)(lib);
#if defined(DART_TARGET_OS_MACOS)
	auto header = (struct mach_header_64*)lib;
	switch (header->magic) {
	case MH_MAGIC:
	case MH_CIGAM:
		throw std::invalid_argument("Mach-O: Support only 64 bits");
	case MH_CIGAM_64:
		throw std::invalid_argument("Mach-O: Expected a host endian header");
	case MH_MAGIC_64:
		break;
	default:
		throw std::invalid_argument("Mach-O: Invalid magic header");
	}

	const uint8_t* vm_snapshot_data = nullptr;
	const uint8_t* vm_snapshot_instructions = nullptr;
	const uint8_t* isolate_snapshot_data = nullptr;
	const uint8_t* isolate_snapshot_instructions = nullptr;

	struct SegInfo { uint64_t vmaddr; uint64_t vmsize; uint64_t fileoff; };
	std::vector<SegInfo> segments;

	auto lc = (struct load_command*)(base + sizeof(struct mach_header_64));
	struct symtab_command* symtab_cmd = nullptr;

	for (uint32_t i = 0; i < header->ncmds; i++) {
		if (lc->cmd == LC_SEGMENT_64) {
			auto seg = (struct segment_command_64*)lc;
			segments.push_back({seg->vmaddr, seg->vmsize, seg->fileoff});
			auto sec = (struct section_64*)((uint8_t*)seg + sizeof(struct segment_command_64));
			for (uint32_t j = 0; j < seg->nsects; j++, sec++) {
				if (strcmp(sec->sectname, "__dart_app_snap") == 0 ||
				    strcmp(sec->sectname, "__dart_vm_snap") == 0) {
					auto snap_data = base + sec->offset;
					auto snap_name = std::string(sec->sectname);
					if (snap_name.find("vm") != std::string::npos) {
						vm_snapshot_data = snap_data;
					} else {
						isolate_snapshot_data = snap_data;
					}
				}
			}
		}
		else if (lc->cmd == LC_SYMTAB) {
			symtab_cmd = (struct symtab_command*)lc;
		}
		lc = (struct load_command*)((uint8_t*)lc + lc->cmdsize);
	}

	auto va_to_fileoff = [&](uint64_t addr) -> uint64_t {
		for (auto& s : segments) {
			if (addr >= s.vmaddr && addr < s.vmaddr + s.vmsize)
				return addr - s.vmaddr + s.fileoff;
		}
		return addr;
	};

	if (symtab_cmd) {
		auto syms = (struct nlist_64*)(base + symtab_cmd->symoff);
		auto strtab = (const char*)(base + symtab_cmd->stroff);
		for (uint32_t i = 0; i < symtab_cmd->nsyms; i++) {
			if (syms[i].n_un.n_strx == 0) continue;
			const char* name = strtab + syms[i].n_un.n_strx;
			uint64_t foff = va_to_fileoff(syms[i].n_value);
			if (strcmp(name, kVmSnapshotDataAsmSymbol) == 0) {
				vm_snapshot_data = base + foff;
			}
			else if (strcmp(name, kVmSnapshotInstructionsAsmSymbol) == 0) {
				vm_snapshot_instructions = base + foff;
			}
			else if (strcmp(name, kIsolateSnapshotDataAsmSymbol) == 0) {
				isolate_snapshot_data = base + foff;
			}
			else if (strcmp(name, kIsolateSnapshotInstructionsAsmSymbol) == 0) {
				isolate_snapshot_instructions = base + foff;
			}
		}
	}

	if (vm_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Data");
	if (vm_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart VM Snapshot Instructions");
	if (isolate_snapshot_data == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Data");
	if (isolate_snapshot_instructions == nullptr)
		throw std::invalid_argument("Mach-O: Cannot find Dart Isolate Snapshot Instructions");

	return LibAppInfo{
		.lib = base,
		.vm_snapshot_data = vm_snapshot_data,
		.vm_snapshot_instructions = vm_snapshot_instructions,
		.isolate_snapshot_data = isolate_snapshot_data,
		.isolate_snapshot_instructions = isolate_snapshot_instructions,
	};
#else
	const auto* hdr = (ElfHeader*)base;
	const auto* ident = (ElfIdent*)hdr->ident;
	if (memcmp(ident->ei_magic, "\x7f" "ELF", 4) != 0)
		throw std::invalid_argument("ELF: Invalid magic header");
	if (ident->ei_data != 1)
		throw std::invalid_argument("ELF: Support only little endian");
	if (ident->ei_class != ELFCLASS64) {
		throw std::invalid_argument("ELF: Support only 64 bits");
	}

	return findSnapshots(base);
#endif
}

#include "debugger.hpp"

#include <capstone/capstone.h>
#include <elf.h>
#include <fcntl.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <string_view>
#include <vector>

namespace {
std::vector<std::string> Split(std::string_view s, char delimiter);

/// @note We are only interested in the symbol table.
struct ElfSymTab {
  /// @brief Start of the mapped ELF binary segment.
  /// @note This is also the start of ELF header.
  void* maddr = MAP_FAILED;
  /// @brief Size of the mapped ELF binary segment.
  std::size_t msize = 0;
  /// @brief Start of the ELF header.
  /// @note This is the same as `maddr`.
  Elf64_Ehdr* ehdr = nullptr;
  /// @brief Start of the symbol table.
  Elf64_Sym* symtab = nullptr;
  /// @brief End of the symbol table.
  Elf64_Sym* symtab_end = nullptr;
  /// @brief Start of the string table.
  char* strtab = nullptr;

  ~ElfSymTab() {
    if (maddr != MAP_FAILED) {
      munmap(maddr, msize);
    }
  }

  static std::unique_ptr<ElfSymTab> From(const char* file);
};
}  // namespace

void Debugger::Run() {
  if (program_) {
    Load_();
  }
  char* line = nullptr;
  while ((line = readline("(sbg) "))) {
    if (*line /* not blank */) {
      add_history(line);
    }
    auto args = Split(line, ' ');
    auto command = args.at(0);
    if (command == "load") {
      auto program = args.at(1);
      program_ = program.c_str();
      Load_();
    } else {
      std::cout << "Unknown command: " << command << "\n";
    }
    std::free(line);
  }
  std::cout << "Quit\n";
}

void Debugger::Load_() {
  auto pid = fork();
  if (pid < 0) {
    std::perror("fork");
    return;
  }
  if (pid == 0 /* child */) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
      std::perror("ptrace");
      return;
    }
    execl(program_, program_, nullptr);
    // Noreturn.
    std::perror("execl");
    std::exit(1);
  } else {
    // Trapped at the first instruction.
    if (waitpid(pid, nullptr, 0) < 0) {
      std::perror("waitpid");
      return;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_EXITKILL) < 0) {
      std::perror("ptrace");
      return;
    }

    // Show some information about the program.
    // (1) The entry point address (the main function, not the _start).
    // (2) The first 5 instructions.
    // NOTE: Make sure the tracee is stopped before reading its memory.

    auto esymtab = ElfSymTab::From(program_);
    if (!esymtab) {
      return;
    }
    // Traverse the symbol table to find the entry point.
    std::uintptr_t entry = 0;
    for (auto sym = esymtab->symtab; sym < esymtab->symtab_end; ++sym) {
      if (std::strcmp(esymtab->strtab + sym->st_name, "main") == 0) {
        entry = sym->st_value;
        break;
      }
    }
    if (!entry) {
      std::cerr << "Cannot find the entry point.\n";
      return;
    }

    std::cout << "** program '" << program_ << "' loaded. entry point 0x"
              << std::hex << entry << ".\n";
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
      std::perror("cs_open");
      return;
    }
    constexpr auto kNumOfInsnToDisasm = std::size_t{5};
    constexpr auto kMaxInsnSize = std::size_t{15};
    std::uint8_t text[kMaxInsnSize * kNumOfInsnToDisasm] = {0};
    for (auto i = std::size_t{0}; i < sizeof(text); ++i) {
      text[i] = ptrace(PTRACE_PEEKTEXT, pid, entry + i, nullptr);
    }
    cs_insn* insn;
    auto count =
        cs_disasm(handle, text, sizeof(text), entry, kNumOfInsnToDisasm, &insn);
    if (count == 0) {
      std::cerr << "cs_disasm: " << cs_strerror(cs_errno(handle)) << "\n";
      return;
    }
    // TODO: If the disassembled instructions are less than 5, output `** the
    // address is out of the range of the text section.`
    auto max_len = std::size_t{0};
    for (auto i = std::size_t{0}; i < kNumOfInsnToDisasm; ++i) {
      max_len = std::max(max_len, static_cast<std::size_t>(insn[i].size));
    }
    auto len = std::size_t{0};
    for (auto i = std::size_t{0}; i < kNumOfInsnToDisasm; ++i) {
      std::cout << "\t" << std::hex << insn[i].address << ": ";
      for (auto j = std::size_t{0}; j < insn[i].size; ++j) {
        // XXX: Using insn[i].bytes[j] shows garbled output.
        std::cout << std::setfill('0') << std::setw(2) << std::hex
                  << static_cast<int>(text[len++]) << " ";
      }
      // A tab is usually 8 spaces wide. Every two bytes are separated by a
      // space. Thus, the longest instruction is (max_len + max_len / 2) spaces
      // wide. And the current instruction is (insn[i].size + insn[i].size / 2)
      // spaces wide. The required extra padding is the ceiling of ((max_len +
      // max_len / 2) - (insn[i].size + insn[i].size / 2)) / 8
      auto padding =
          ((max_len + max_len / 2 - insn[i].size - insn[i].size / 2) + 7) / 8;

      std::cout << std::string(padding + 1 /* at least one tab */, '\t')
                << insn[i].mnemonic << "\t" << insn[i].op_str << "\n";
    }
    cs_free(insn, count);
  }
}

namespace {
std::vector<std::string> Split(std::string_view s, char delimiter) {
  auto tokens = std::vector<std::string>{};
  auto token = std::string{};
  auto token_stream = std::istringstream{std::string{s}};
  while (std::getline(token_stream, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}

std::unique_ptr<ElfSymTab> ElfSymTab::From(const char* file) {
  // NOTE: The following code on reading ELF symbols is modified from
  // https://www.cs.cmu.edu/afs/cs.cmu.edu/academic/class/15213-f03/www/ftrace/elf.h
  // https://www.cs.cmu.edu/afs/cs.cmu.edu/academic/class/15213-f03/www/ftrace/elf.c

  // Do some consistency checks on the binary.
  auto fd = open(file, O_RDONLY);
  if (fd < 0) {
    std::perror("open");
    return nullptr;
  }
  struct stat sbuf;
  if (fstat(fd, &sbuf) < 0) {
    std::perror("fstat");
    return nullptr;
  }
  if (sbuf.st_size < static_cast<long>(sizeof(Elf64_Ehdr))) {
    std::cerr << "Invalid ELF file.\n";
    return nullptr;
  }

  // It looks OK, so map the ELF binary into our address space.
  auto esymtab = std::make_unique<ElfSymTab>();
  esymtab->maddr = mmap(nullptr, sbuf.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (esymtab->maddr == MAP_FAILED) {
    std::perror("mmap");
    return nullptr;
  }
  close(fd);

  // Make sure it's an ELF file.
  esymtab->ehdr = static_cast<Elf64_Ehdr*>(esymtab->maddr);
  if (std::strncmp(reinterpret_cast<const char*>(esymtab->ehdr->e_ident),
                   ELFMAG, SELFMAG) != 0) {
    std::cerr << "Invalid ELF file.\n";
    return nullptr;
  }

  // Now we can find the symbol table.
  auto shdr = reinterpret_cast<Elf64_Shdr*>(
      reinterpret_cast<std::uint8_t*>(esymtab->maddr) + esymtab->ehdr->e_shoff);
  for (auto i = std::size_t{0}; i < esymtab->ehdr->e_shnum; ++i) {
    if (shdr[i].sh_type == SHT_SYMTAB) {
      esymtab->symtab = reinterpret_cast<Elf64_Sym*>(
          reinterpret_cast<std::uint8_t*>(esymtab->maddr) + shdr[i].sh_offset);
      esymtab->symtab_end = reinterpret_cast<Elf64_Sym*>(
          reinterpret_cast<std::uint8_t*>(esymtab->symtab) + shdr[i].sh_size);
      esymtab->strtab = reinterpret_cast<char*>(
          reinterpret_cast<std::uint8_t*>(esymtab->maddr) +
          shdr[shdr[i].sh_link].sh_offset);
      break;
    }
  }
  if (!esymtab->symtab) {
    std::cerr << "No symbol table found.\n";
    return nullptr;
  }
  return esymtab;
}
}  // namespace

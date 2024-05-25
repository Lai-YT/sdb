#include "debugger.hpp"

#include <capstone/capstone.h>
#include <elf.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {
std::vector<std::string> Split(std::string_view s, char delimiter);
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
    } else if (command == "cont") {
      Continue_();
    } else if (command == "si") {
      Step_();
    } else if (command == "info") {
      auto subcommand = args.at(1);
      if (subcommand == "reg") {
        InfoRegs_();
      } else {
        std::cout << "Unknown subcommand: " << subcommand << "\n";
      }
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
    pid_ = pid;
    // Trapped at the first instruction.
    if (waitpid(pid_, nullptr, 0) < 0) {
      std::perror("waitpid");
      return;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid_, nullptr, PTRACE_O_EXITKILL) < 0) {
      std::perror("ptrace");
      return;
    }

    // Show some information about the program.
    // (1) The entry point address.
    // (2) The first 5 instructions.
    // NOTE: Make sure the tracee is stopped before reading its memory.

    auto file = std::ifstream{program_};
    if (!file) {
      std::perror("open");
      return;
    }
    auto header = Elf64_Ehdr{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    std::cout << "** program '" << program_ << "' loaded. entry point 0x"
              << std::hex << header.e_entry << ".\n";

    Disassemble_(header.e_entry, 5);
  }
}

void Debugger::Step_() {
  if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0) {
    std::perror("ptrace");
    return;
  }
  if (waitpid(pid_, nullptr, 0) < 0) {
    std::perror("waitpid");
    return;
  }
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return;
  }
  Disassemble_(regs.rip, 5);
}

void Debugger::Continue_() {
  if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
    std::perror("ptrace");
    return;
  }
  if (waitpid(pid_, nullptr, 0) < 0) {
    std::perror("waitpid");
    return;
  }
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return;
  }
  Disassemble_(regs.rip, 5);
}

void Debugger::InfoRegs_() {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return;
  }
// Output 3 registers per line.
#define COUT_INFO(reg) \
  std::cout << "$" << #reg << "\t0x" << std::setfill('0') << std::setw(16) \
            << std::hex << regs.reg
  // clang-format off
  COUT_INFO(rax) << "\t"; COUT_INFO(rbx) << "\t"; COUT_INFO(rcx) << "\n";
  COUT_INFO(rdx) << "\t"; COUT_INFO(rsi) << "\t"; COUT_INFO(rdi) << "\n";
  COUT_INFO(rbp) << "\t"; COUT_INFO(rsp) << "\t"; COUT_INFO(r8) << "\n";
  COUT_INFO(r9)  << "\t"; COUT_INFO(r10) << "\t"; COUT_INFO(r11) << "\n";
  COUT_INFO(r12) << "\t"; COUT_INFO(r13) << "\t"; COUT_INFO(r14) << "\n";
  COUT_INFO(r15) << "\t"; COUT_INFO(rip) << "\t"; COUT_INFO(eflags) << "\n";
  // clang-format on
#undef COUT_INFO
}

void Debugger::Disassemble_(std::uintptr_t addr, std::size_t insn_count) {
  csh handle;
  if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
    std::perror("cs_open");
    return;
  }
  constexpr auto kMaxInsnSize = std::size_t{15};
  auto text = std::vector<std::uint8_t>(kMaxInsnSize * insn_count);
  for (auto i = std::size_t{0}; i < sizeof(text); ++i) {
    text[i] = ptrace(PTRACE_PEEKTEXT, pid_, addr + i, nullptr);
  }
  cs_insn* insn;
  auto count =
      cs_disasm(handle, text.data(), text.size(), addr, insn_count, &insn);
  if (count == 0) {
    std::cerr << "cs_disasm: " << cs_strerror(cs_errno(handle)) << "\n";
    return;
  }
  // TODO: If the disassembled instructions are less than 5, output `** the
  // address is out of the range of the text section.`
  auto max_len = std::size_t{0};
  for (auto i = std::size_t{0}; i < insn_count; ++i) {
    max_len = std::max(max_len, static_cast<std::size_t>(insn[i].size));
  }
  auto len = std::size_t{0};
  for (auto i = std::size_t{0}; i < insn_count; ++i) {
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
}  // namespace

#include "debugger.hpp"

#include <capstone/capstone.h>
#include <elf.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <signal.h>
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
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {
std::vector<std::string> Split(std::string_view s, char delimiter);
}  // namespace

int Debugger::NextBreakpointId_() {
  return breakpoint_id_++;
}

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
    } else if (command == "break") {
      try {
        auto addr = std::stoul(args.at(1), nullptr, 16);
        Break_(addr);
      } catch (const std::invalid_argument& e) {
        std::cout << "Invalid address: " << args.at(1) << "\n";
      }
    } else if (command == "si") {
      Step_();
    } else if (command == "info") {
      auto subcommand = args.at(1);
      if (subcommand == "reg") {
        InfoRegs_();
      } else if (subcommand == "break") {
        InfoBreaks_();
      } else {
        std::cout << "Unknown subcommand: " << subcommand << "\n";
      }
    } else if (command == "delete") {
      auto command = args.at(1);
      try {
        auto id = std::stoi(command);
        DeleteBreak_(id);
      } catch (const std::invalid_argument& e) {
        std::cout << "Invalid id: " << command << "\n";
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
    if (Wait_() < 0) {
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
  auto status = StepOverBp_();
  if (status <= 0) {
    return;
  }
  // Not at a breakpoint.
  if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0) {
    std::perror("ptrace");
    return;
  }
  if (Wait_() < 0) {
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
  if (StepOverBp_() < 0) {
    return;
  }
  if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
    std::perror("ptrace");
    return;
  }
  if (Wait_() < 0) {
    return;
  }
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return;
  }
  Disassemble_(regs.rip, 5);
}

int Debugger::StepOverBp_() {
  auto rip = GetRip_();
  if (rip < 0) {
    return -1;
  }
  // The interrupt instruction (1-byte) is still a instruction, thus it's
  // executed with the PC incremented. We get the original address of the
  // breakpoint by subtracting 1.
  auto break_addr = static_cast<std::uintptr_t>(rip - 1);
  if (!addr_to_breakpoint_id_.count(break_addr)) {
    return 1 /* not at a breakpoint */;
  }
  auto bp_id = addr_to_breakpoint_id_.at(break_addr);
  if (auto bp_itr = breakpoints_.find(bp_id);
      bp_itr != breakpoints_.end() && !bp_itr->second.IsHit()) {
    std::cerr << "** stepping over a breakpoint at 0x" << std::hex << break_addr
              << ".\n";
    breakpoints_.at(bp_id).Delete();
    breakpoints_.erase(bp_id);
    if (SetRip_(break_addr)) {
      return -1;
    }
    ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr);
    if (Wait_() < 0) {
      return -1 /* error of the process has exited */;
    }
    // So that we get trapped next time.
    // Notice that the id is reused, so has no impact to the user.
    breakpoints_.emplace(bp_id, Breakpoint{pid_, break_addr});
    return 0 /* successfully stepped over a breakpoint */;
  } else if (bp_itr != breakpoints_.end() && bp_itr->second.IsHit()) {
    // Set it as not hit, so that it can be hit again.
    bp_itr->second.Unhit();
    // A hit breakpoint is not a breakpoint this time.
    return 1 /* not at a breakpoint */;
  }
  return 1 /* not at a breakpoint */;
}

void Debugger::Break_(std::uintptr_t addr) {
  std::cout << "** set a breakpoint at 0x" << std::hex << addr << ".\n";
  auto bp = Breakpoint{pid_, addr};
  auto bp_id = NextBreakpointId_();
  addr_to_breakpoint_id_.emplace(addr, bp_id);
  breakpoints_.emplace(bp_id, bp);
}

void Debugger::InfoRegs_() const {
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

void Debugger::InfoBreaks_() const {
  if (breakpoints_.empty()) {
    std::cout << "** no breakpoints.\n";
    return;
  }
  std::cout << "Num\tAddress\n";
  for (const auto& [id, bp] : breakpoints_) {
    std::cout << id << "\t0x" << std::hex << bp.addr() << "\n";
  }
}

void Debugger::DeleteBreak_(int id) {
  if (auto bp_itr = breakpoints_.find(id); bp_itr != breakpoints_.end()) {
    auto addr = bp_itr->second.addr();
    breakpoints_.erase(bp_itr);
    addr_to_breakpoint_id_.erase(addr);
    std::cout << "** deleted breakpoint " << id << ".\n";
  } else {
    std::cout << "** breakpoint " << id << " does not exist.\n";
  }
}

int Debugger::Wait_() {
  int status;
  if (waitpid(pid_, &status, 0) < 0) {
    std::perror("waitpid");
    return -1;
  }
  if (WIFEXITED(status)) {
    std::cout << "** the target program terminated.\n";
    return -1;
  }
  if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
    auto rip = GetRip_();
    if (rip < 0) {
      return -1;
    }
    // Since the interrupt instruction is executed, the breakpoint is the one
    // before the current PC.
    if (!addr_to_breakpoint_id_.count(rip - 1)) {
      // Likey to be trapped an orginal trap in the program.
      return 0;
    }
    auto bp_id = addr_to_breakpoint_id_.at(rip - 1);
    if (auto bp_itr = breakpoints_.find(bp_id);
        bp_itr != breakpoints_.end() && !bp_itr->second.IsHit()) {
      std::cout << "** hit a breakpoint at 0x" << std::hex << rip - 1 << ".\n";
      bp_itr->second.Hit();
    }
  }
  return 0;
}

std::intptr_t Debugger::GetRip_() const {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return -1;
  }
  return regs.rip;
}

int Debugger::SetRip_(std::uintptr_t rip) {
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return -1;
  }
  regs.rip = rip;
  if (ptrace(PTRACE_SETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return -1;
  }
  return 0;
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

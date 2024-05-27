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
#include <cstdio>
#include <cstdlib>
#include <cstring>
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
    Load_(program_);
    DisassembleFromRip_(5);
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
      Load_(program.c_str());
      DisassembleFromRip_(5);
    } else if (command == "cont") {
      if (CheckHasLoaded_() < 0) {
        continue;
      }
      if (Continue_() != Status::kSuccess) {
        continue;
      }
      DisassembleFromRip_(5);
    } else if (command == "break") {
      if (CheckHasLoaded_() < 0) {
        continue;
      }
      try {
        auto addr = std::stoul(args.at(1), nullptr, 16);
        Break_(addr);
      } catch (const std::invalid_argument& e) {
        std::cout << "Invalid address: " << args.at(1) << "\n";
      }
    } else if (command == "si") {
      if (CheckHasLoaded_() < 0) {
        continue;
      }
      if (Step_() != Status::kSuccess) {
        continue;
      }
      DisassembleFromRip_(5);
    } else if (command == "info") {
      if (CheckHasLoaded_() < 0) {
        continue;
      }
      auto subcommand = args.at(1);
      if (subcommand == "reg") {
        InfoRegs_();
      } else if (subcommand == "break") {
        InfoBreaks_();
      } else {
        std::cout << "Unknown subcommand: " << subcommand << "\n";
      }
    } else if (command == "delete") {
      if (CheckHasLoaded_() < 0) {
        continue;
      }
      auto command = args.at(1);
      try {
        auto id = std::stoi(command);
        DeleteBreak_(id);
      } catch (const std::invalid_argument& e) {
        std::cout << "Invalid id: " << command << "\n";
      }
    } else if (command == "syscall") {
      if (CheckHasLoaded_() < 0) {
        continue;
      }
      if (auto status = Syscall_(); status < 0) {
        continue;
      } else if (status == 0 /* syscall */) {
        // The syscall instruction is executed, thus we subtract 2 from the PC
        // to show the syscall instruction.
        auto rip = GetRip_();
        if (rip < 0) {
          continue;
        }
        Disassemble_(rip - 2, 5);
      } else {
        // On hitting a breakpoint, the PC is already adjusted.
        DisassembleFromRip_(5);
      }
    } else {
      std::cout << "Unknown command: " << command << "\n";
    }
    std::free(line);
  }
  std::cout << "Quit\n";
}

Debugger::Status Debugger::Load_(const char* program) {
  program_ = program;
  if (SetTextSectionEnd_() < 0) {
    return Status::kError;
  }
  auto pid = fork();
  if (pid < 0) {
    std::perror("fork");
    return Status::kError;
  }
  if (pid == 0 /* child */) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
      std::perror("ptrace");
      return Status::kError;
    }
    execl(program_, program_, nullptr);
    // Noreturn.
    std::perror("execl");
    return Status::kError;
  } else {
    pid_ = pid;
    // Trapped at the first instruction (entry point).
    if (auto status = Wait_(); status != Status::kSuccess) {
      return status;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid_, nullptr,
               PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD) < 0) {
      std::perror("ptrace");
      return Status::kError;
    }

    // Show some information about the program.
    // (1) The entry point address.
    // (2) The first 5 instructions.
    // NOTE: Make sure the tracee is stopped before reading its memory.

    auto entry_point = GetRip_();
    if (entry_point < 0) {
      return Status::kError;
    }
    std::cout << "** program '" << program_ << "' loaded. entry point 0x"
              << std::hex << entry_point << ".\n";
  }
  return Status::kSuccess;
}

/// @details When single stepping, we report a hit on a breakpoint before
/// actually reaching the interrupt instruction. This approach prevents a
/// scenario where the last step before the breakpoint shows no progress, as it
/// executes the interrupt instruction, which is not part of the actual program.
Debugger::Status Debugger::Step_() {
  // If the PC is at a breakpoint, it is already reported by the previous
  // command. Thus, we simply disable the breakpoint and single step.
  auto status = StepOverBp_();
  if (status < 0 /* error or the program has exited */) {
    return Status{status};
  }

  if (status != 0 /* not at a breakpoint */) {
    if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0) {
      std::perror("ptrace");
      return Status::kError;
    }
    if (auto status = Wait_(); status != Status::kSuccess) {
      return status;
    }
  }

  // If the next instruction is a breakpoint (current PC), we report a hit.
  auto rip = GetRip_();
  if (rip < 0) {
    return Status::kError;
  }
  if (addr_to_breakpoint_id_.count(rip)) {
    std::cout << "** hit a breakpoint at 0x" << std::hex << rip << ".\n";
  }

  return Status::kSuccess;
}

Debugger::Status Debugger::Continue_() {
  // If the PC is at a breakpoint, it is already reported by the previous
  // command. Thus, we simply step over the breakpoint.
  if (auto status = StepOverBp_();
      status < 0 /* error or the program has exited */) {
    return Status{status};
  }
  // Then the actual continue.
  if (ptrace(PTRACE_CONT, pid_, nullptr, nullptr) < 0) {
    std::perror("ptrace");
    return Status::kError;
  }
  if (auto status = Wait_(); status != Status::kSuccess) {
    return status;
  }

  // The continue may step on the breakpoint. If PC - 1 is a breakpoint, we know
  // it's hit.
  auto rip = GetRip_();
  if (rip < 0) {
    return Status::kError;
  }
  // We may also be stopped by other signals, or an interrupt of the program
  // itself, which are not reported as hitting a breakpoint.
  if (addr_to_breakpoint_id_.count(rip - 1)) {
    std::cout << "** hit a breakpoint at 0x" << std::hex << rip - 1 << ".\n";
    // And we adjust the PC to the original address, so that next time we can
    // execute it as not a breakpoint.
    if (SetRip_(rip - 1) < 0) {
      return Status::kError;
    }
  }
  return Status::kSuccess;
}

int Debugger::StepOverBp_() {
  auto ret = GetRip_();
  if (ret < 0) {
    return Status::kError;
  }
  auto rip = static_cast<std::uintptr_t>(ret);
  if (addr_to_breakpoint_id_.count(rip)) {
    auto bp_id = addr_to_breakpoint_id_.at(rip);
    breakpoints_.at(bp_id).Delete();
    breakpoints_.erase(bp_id);
    // Notice that the id is not erased, as we will reuse it. So that the user
    // is not aware of it.
    if (ptrace(PTRACE_SINGLESTEP, pid_, nullptr, nullptr) < 0) {
      std::perror("ptrace");
      return Status::kError;
    }
    if (auto status = Wait_(); status != Status::kSuccess) {
      return status /* error or the program has exited */;
    }
    breakpoints_.emplace(bp_id, Breakpoint{pid_, rip});
    return 0 /* stepped over a breakpoint */;
  }
  return 1 /* not at a breakpoint */;
}

void Debugger::Break_(std::uintptr_t addr) {
  std::cout << "** set a breakpoint at 0x" << std::hex << addr << ".\n";
  auto rip = GetRip_();
  if (rip < 0) {
    return;
  }
  CreateBreak_(addr);
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
    bp_itr->second.Delete();
    breakpoints_.erase(bp_itr);
    addr_to_breakpoint_id_.erase(addr);
    std::cout << "** deleted breakpoint " << id << ".\n";
  } else {
    std::cout << "** breakpoint " << id << " does not exist.\n";
  }
}

int Debugger::Syscall_() {
  // If the PC is at a breakpoint, it is already reported by the previous
  // command. Thus, we simply step over the breakpoint.
  if (auto status = StepOverBp_();
      status < 0 /* error or the program has exited */) {
    return status;
  }

  // Then the actual syscall.
  if (ptrace(PTRACE_SYSCALL, pid_, nullptr, nullptr) < 0) {
    std::perror("ptrace");
    return -1;
  }
  if (auto status = Wait_(); status != Status::kSuccess) {
    return status;
  }
  // The stop may be due to syscall or breakpoint.
  // If PC - 1 is a breakpoint, we know it's caused by the breakpoint.
  // Otherwise, it's caused by the syscall.
  auto rip = GetRip_();
  if (rip < 0) {
    return -1;
  }
  if (addr_to_breakpoint_id_.count(rip - 1)) {
    std::cout << "** hit a breakpoint at 0x" << std::hex << rip - 1 << ".\n";
    // And we adjust the PC to the original address, so that next time we can
    // execute it as not a breakpoint.
    if (SetRip_(rip - 1) < 0) {
      return -1;
    }
    return 1 /* stopped at a breakpoint */;
  }
  struct user_regs_struct regs;
  if (ptrace(PTRACE_GETREGS, pid_, nullptr, &regs) < 0) {
    std::perror("ptrace");
    return -1;
  }
  auto syscall_id = regs.orig_rax;
  // The syscall instruction is executed, thus we subtract 2 from the PC to
  // show the syscall instruction.
  if (is_entering_syscall_) {
    std::cout << "** enter a syscall(" << std::dec << syscall_id << ") at 0x"
              << std::hex << regs.rip - 2 << ".\n";
  } else {
    auto syscall_ret = regs.rax;
    std::cout << "** leave a syscall(" << std::dec << syscall_id
              << ") = " << syscall_ret << " at 0x" << std::hex << regs.rip - 2
              << ".\n";
  }
  is_entering_syscall_ = !is_entering_syscall_;
  return 0;
}

Debugger::Status Debugger::Wait_() {
  int status;
  if (waitpid(pid_, &status, 0) < 0) {
    std::perror("waitpid");
    return Status::kError;
  }
  if (WIFEXITED(status)) {
    std::cout << "** the target program terminated.\n";
    Unload_();
    return Status::kExit;
  }
  return Status::kSuccess;
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

void Debugger::Disassemble_(std::uintptr_t addr, std::size_t insn_count) const {
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

  auto insn_count_in_text_section = static_cast<std::size_t>(std::count_if(
      insn, insn + count,
      [this](auto&& i) { return i.address < text_section_end_; }));
  auto max_len = std::size_t{0};
  for (auto i = std::size_t{0}; i < insn_count_in_text_section; ++i) {
    max_len = std::max(max_len, static_cast<std::size_t>(insn[i].size));
  }
  auto len = std::size_t{0};
  for (auto i = std::size_t{0}; i < insn_count_in_text_section; ++i) {
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
  if (insn_count_in_text_section < insn_count) {
    std::cout << "** the address is out of the range of the text section.\n";
  }
  cs_free(insn, count);
  if (auto err = cs_close(&handle); err != CS_ERR_OK) {
    std::cerr << "cs_close: " << cs_strerror(err) << "\n";
  }
}

void Debugger::DisassembleFromRip_(std::size_t insn_count) const {
  auto rip = GetRip_();
  if (rip < 0) {
    return;
  }
  Disassemble_(rip, insn_count);
}

void Debugger::CreateBreak_(std::uintptr_t addr) {
  auto bp = Breakpoint{pid_, addr};
  auto bp_id = NextBreakpointId_();
  addr_to_breakpoint_id_.emplace(addr, bp_id);
  breakpoints_.emplace(bp_id, std::move(bp));
}

int Debugger::CheckHasLoaded_() const {
  if (program_) {
    return 0;
  }
  std::cout << "** please load a program first.\n";
  return -1;
}

int Debugger::SetTextSectionEnd_() {
  auto fd = open(program_, O_RDONLY);
  if (fd < 0) {
    std::perror("open");
    return -1;
  }
  struct stat st;
  if (fstat(fd, &st) < 0) {
    std::perror("fstat");
    close(fd);
    return -1;
  }
  if (st.st_size < static_cast<off_t>(sizeof(Elf64_Ehdr))) {
    std::cerr << "The file is too small to be an ELF file.\n";
    close(fd);
    return -1;
  }

  auto maddr = std::uintptr_t{0};
  if (auto ret = mmap(nullptr, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
      ret == MAP_FAILED) {
    std::perror("mmap");
    close(fd);
    return -1;
  } else {
    maddr = reinterpret_cast<std::uintptr_t>(ret);
  }

  if (std::strncmp(reinterpret_cast<char*>(maddr), ELFMAG, SELFMAG) != 0) {
    std::cerr << "The file is not an ELF file.\n";
    munmap(reinterpret_cast<void*>(maddr), st.st_size);
    close(fd);
    return -1;
  }

  auto ehdr = reinterpret_cast<Elf64_Ehdr*>(maddr);
  auto shdr = reinterpret_cast<Elf64_Shdr*>(maddr + ehdr->e_shoff);
  auto shstrtab =
      reinterpret_cast<char*>(maddr + shdr[ehdr->e_shstrndx].sh_offset);
  for (auto i = std::size_t{0}; i < ehdr->e_shnum; ++i) {
    if (std::string_view{&shstrtab[shdr[i].sh_name]} == ".text") {
      text_section_end_ = shdr[i].sh_addr + shdr[i].sh_size;
      munmap(reinterpret_cast<void*>(maddr), st.st_size);
      close(fd);
      return 0;
    }
  }
  munmap(reinterpret_cast<void*>(maddr), st.st_size);
  close(fd);
  return -1;
}

void Debugger::Unload_() {
  program_ = nullptr;
  pid_ = 0;
  text_section_end_ = 0;
  breakpoint_id_ = 0;
  is_entering_syscall_ = true;
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

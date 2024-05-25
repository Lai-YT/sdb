#include "breakpoint.hpp"

#include <sys/ptrace.h>

Breakpoint::Breakpoint(pid_t pid, std::uintptr_t addr)
    : pid_{pid}, addr_{addr} {
  Enable_();
}

void Breakpoint::Enable_() {
  auto data = ptrace(PTRACE_PEEKDATA, pid_, addr_, nullptr);
  saved_data_ = data & 0xff;  // save the lower byte
  std::uint64_t int3 = 0xcc;
  std::uint64_t data_with_int3 =
      ((data & ~0xff) | int3);  // set lower byte to 0xcc
  ptrace(PTRACE_POKEDATA, pid_, addr_, data_with_int3);
}

void Breakpoint::Delete() {
  // The data may be modified by other commands, so we need to read it again.
  auto data = ptrace(PTRACE_PEEKDATA, pid_, addr_, nullptr);
  auto restored_data = ((data & ~0xff) | saved_data_);
  ptrace(PTRACE_POKEDATA, pid_, addr_, restored_data);
}

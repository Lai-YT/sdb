#include "breakpoint.hpp"

#include <errno.h>
#include <sys/ptrace.h>

#include <stdexcept>

Breakpoint::Breakpoint(pid_t pid, std::uintptr_t addr)
    : pid_{pid}, addr_{addr} {
  if (Enable_() < 0) {
    throw std::runtime_error("Failed to enable breakpoint.");
  }
}

int Breakpoint::Enable_() {
  errno = 0;
  auto data = ptrace(PTRACE_PEEKDATA, pid_, addr_, nullptr);
  if (errno) {
    return -1;
  }
  saved_data_ = data & 0xff;  // save the lower byte
  std::uint64_t int3 = 0xcc;
  std::uint64_t data_with_int3 =
      ((data & ~0xff) | int3);  // set lower byte to 0xcc
  if (ptrace(PTRACE_POKEDATA, pid_, addr_, data_with_int3) < 0) {
    return -1;
  }
  return 0;
}

int Breakpoint::Delete() {
  // The data may be modified by other commands, so we need to read it again.
  errno = 0;
  auto data = ptrace(PTRACE_PEEKDATA, pid_, addr_, nullptr);
  if (errno) {
    return -1;
  }
  auto restored_data = ((data & ~0xff) | saved_data_);
  if (ptrace(PTRACE_POKEDATA, pid_, addr_, restored_data) < 0) {
    return -1;
  }
  return 0;
}

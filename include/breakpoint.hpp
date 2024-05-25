#ifndef BREAKPOINT_HPP
#define BREAKPOINT_HPP

#include <unistd.h>

#include <cstdint>

class Breakpoint {
 public:
  /// @brief Replace the data at the address with the breakpoint instruction
  /// (int3).
  void Enable();
  /// @brief Restore the original data.
  void Disable();

  bool IsEnabled() const {
    return enabled_;
  }

  std::intptr_t addr() const {
    return addr_;
  }

  Breakpoint(pid_t pid, std::uintptr_t addr) : pid_{pid}, addr_{addr} {}

 private:
  pid_t pid_;
  std::uintptr_t addr_;
  bool enabled_ = false;
  /// @brief The original data being replaced by the breakpoint instruction.
  std::uint8_t saved_data_ = 0;
};

#endif  // BREAKPOINT_HPP

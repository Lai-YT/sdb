#ifndef BREAKPOINT_HPP
#define BREAKPOINT_HPP

#include <unistd.h>

#include <cstdint>

class Breakpoint {
 public:
  /// @brief Removes the interrupt instruction by restoring the original data.
  /// @note Deleting a breakpoint twice may cause unexpected behavior.
  /// @return `0` on success, `-1` on failure.
  int Delete();

  std::uintptr_t addr() const {
    return addr_;
  }

  /// @note The breakpoint is immediately enabled.
  /// @throw `std::runtime_error` if failed to enable the breakpoint.
  Breakpoint(pid_t pid, std::uintptr_t addr);

 private:
  pid_t pid_;
  std::uintptr_t addr_;
  /// @brief The original data being replaced by the breakpoint instruction.
  std::uint8_t saved_data_ = 0;
  bool is_hit_ = false;

  /// @brief Replace the data at the address with the breakpoint instruction
  /// (int3).
  /// @return `0` on success, `-1` on failure.
  int Enable_();
};

#endif  // BREAKPOINT_HPP

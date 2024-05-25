#ifndef BREAKPOINT_HPP
#define BREAKPOINT_HPP

#include <unistd.h>

#include <cstdint>

class Breakpoint {
 public:
  /// @brief Removes the interrupt instruction by restoring the original data.
  /// @note Deleting a breakpoint twice may cause unexpected behavior.
  void Delete();

  /// @brief Check if the breakpoint is hit.
  bool IsHit() const {
    return is_hit_;
  }
  /// @brief Set the breakpoint as hit. This is to help avoiding from being
  /// trapped between two consecutive breakpoints.
  void Hit() {
    is_hit_ = true;
  }

  /// @brief Set the breakpoint as not hit, so that it can be hit again.
  void Unhit() {
    is_hit_ = false;
  }

  std::uintptr_t addr() const {
    return addr_;
  }

  /// @note The breakpoint is immediately enabled.
  Breakpoint(pid_t pid, std::uintptr_t addr);

 private:
  pid_t pid_;
  std::uintptr_t addr_;
  /// @brief The original data being replaced by the breakpoint instruction.
  std::uint8_t saved_data_ = 0;
  bool is_hit_ = false;

  /// @brief Replace the data at the address with the breakpoint instruction
  /// (int3).
  void Enable_();
};

#endif  // BREAKPOINT_HPP

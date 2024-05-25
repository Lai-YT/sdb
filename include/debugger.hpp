#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <unordered_map>

#include "breakpoint.hpp"

class Debugger {
 public:
  void Run();

  Debugger(const char* program) : program_{program} {}

 private:
  const char* program_;
  pid_t pid_{0};
  std::unordered_map<std::uintptr_t, Breakpoint> breakpoints_;

  /// @note The program is executed as being traced.
  void Load_();
  /// @brief Single step the program.
  void Step_();
  /// @brief Continue the program.
  void Continue_();
  /// @brief If the program is stopped at a breakpoint, Single step the program
  /// with the original instruction.
  /// @return `-1` on error, or if the process has exited.
  int StepOverBp_();
  /// @brief Set a breakpoint at the address.
  void Break_(std::uintptr_t addr);
  void InfoRegs_();

  //
  // Helper functions.
  //

  /// @return `-1` on error, or if the process has exited.
  int Wait_() const;
  /// @return The register value. `-1` on error.
  std::int64_t GetRip_() const;
  int SetRip_(std::uintptr_t rip);
  void Disassemble_(std::uintptr_t addr, std::size_t insn_count);
};

#endif  // DEBUGGER_HPP

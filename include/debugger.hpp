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
  /// @note Giving each breakpoint a unique id to support easy deletion.
  std::unordered_map<int, Breakpoint> breakpoints_;
  /// @note Do not access this directly; use `NextBreakpointId_()` instead.
  int breakpoint_id_{0};
  int NextBreakpointId_();
  /// @note Maps the address to the breakpoint id.
  /// @note Incremented for each "user-created" breakpoint.
  std::unordered_map<std::uintptr_t, int> addr_to_breakpoint_id_;

  /// @note The program is executed as being traced.
  void Load_();
  /// @brief Single step the program.
  void Step_();
  /// @brief Continue the program.
  void Continue_();
  /// @brief If the program is stopped at a breakpoint, Single step the program
  /// with the original instruction.
  /// @return `-1` on error, or if the process has exited; `1` if not at a
  /// breakpoint; `0` otherwise.
  int StepOverBp_();
  /// @brief Set a breakpoint at the address.
  void Break_(std::uintptr_t addr);
  void InfoRegs_() const;
  void InfoBreaks_() const;
  void DeleteBreak_(int id);

  //
  // Helper functions.
  //

  /// @return `-1` on error, or if the process has exited.
  int Wait_();
  /// @return The register value. `-1` on error.
  std::intptr_t GetRip_() const;
  int SetRip_(std::uintptr_t rip);
  void Disassemble_(std::uintptr_t addr, std::size_t insn_count);
};

#endif  // DEBUGGER_HPP

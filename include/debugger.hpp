#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <queue>
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
  /// @note `map` is used to traverse the breakpoints in order of their id.
  std::map<int, Breakpoint> breakpoints_;
  /// @note Do not access this directly; use `NextBreakpointId_()` instead.
  int breakpoint_id_{0};
  int NextBreakpointId_();
  /// @note Maps the address to the breakpoint id.
  /// @note Incremented for each "user-created" breakpoint.
  std::unordered_map<std::uintptr_t, int> addr_to_breakpoint_id_;
  /// @note the creation of these breakpoints are postponed because they are set
  /// on the current PC. They are created later to take effect next time they
  /// are hit.
  /// @note Using queue to allow possible duplicate breakpoints at a single PC.
  std::queue<std::uintptr_t> postponed_breakpoints_;

  //
  // Debugger commands.
  //

  /// @note The program is executed as being traced.
  void Load_(const char* program);
  /// @brief Single step the program.
  void Step_();
  /// @brief Continue the program.
  void Continue_();
  /// @brief Set a breakpoint at the address.
  void Break_(std::uintptr_t addr);
  void InfoRegs_() const;
  void InfoBreaks_() const;
  void DeleteBreak_(int id);

  //
  // Helper functions.
  //

  /// @brief If the program is stopped at a breakpoint, Single step the program
  /// with the original instruction.
  /// @return `-1` on error, or if the process has exited; `1` if not at a
  /// breakpoint; `0` otherwise.
  int StepOverBp_();
  /// @return `-1` on error, or if the process has exited.
  int Wait_();
  /// @return The register value. `-1` on error.
  std::intptr_t GetRip_() const;
  int SetRip_(std::uintptr_t rip);
  void Disassemble_(std::uintptr_t addr, std::size_t insn_count) const;
  void DisassembleFromRip_(std::size_t insn_count) const;
  void CreateBreak_(std::uintptr_t addr);
  /// @return `-1` if no program is loaded; `0` otherwise.
  int CheckHasLoaded_() const;
};

#endif  // DEBUGGER_HPP

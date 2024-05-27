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
  bool is_entering_syscall_{true};

  //
  // Debugger commands.
  //

  /// @brief An unified status code for functions to check and propagate.
  enum class Status {
    kSuccess = 0,
    kError = -1,
    /// @brief Usually an error from `ptrace`.
    kExit = -2,
  };

  /// @note The program is executed as being traced.
  Status Load_(const char* program);
  /// @brief Single step the program.
  Status Step_();
  /// @brief Continue the program.
  Status Continue_();
  /// @brief Set a breakpoint at the address.
  void Break_(std::uintptr_t addr);
  void InfoRegs_() const;
  void InfoBreaks_() const;
  void DeleteBreak_(int id);
  /// @brief Executes until (1) entering a syscall (2) leaving a syscall (3)
  /// hitting a breakpoint.
  Status Syscall_();

  //
  // Helper functions.
  //

  /// @brief If the program is stopped at a breakpoint, Single step the program
  /// with the original instruction.
  /// @return `-2` if the program has exited; `-1` on error; `1` if not at a
  /// breakpoint; `0` otherwise. (In addition to Status, it may return `1`.)
  int StepOverBp_();
  Status Wait_();
  /// @return The register value. `-1` on error.
  std::intptr_t GetRip_() const;
  /// @return `-1` on error.
  int SetRip_(std::uintptr_t rip);
  void Disassemble_(std::uintptr_t addr, std::size_t insn_count) const;
  void DisassembleFromRip_(std::size_t insn_count) const;
  void CreateBreak_(std::uintptr_t addr);
  /// @return `-1` if no program is loaded; `0` otherwise.
  int CheckHasLoaded_() const;
};

#endif  // DEBUGGER_HPP

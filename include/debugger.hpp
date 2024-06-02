#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <unordered_map>

#include "breakpoint.hpp"

class Debugger {
 public:
  void Run();

  Debugger(const char* program) : program_{program} {}

 private:
  const char* program_;
  /// @note This is to stop disassembling address outside the text section.
  std::uintptr_t text_section_end_{0};
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
  bool is_entering_syscall_{true};

  //
  // Debugger commands.
  //

  /// @brief An unified status code for functions to check and propagate.
  enum Status : int {
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
  /// @return `-2` if the program has exited; `-1` on error; `1` stopped at a
  /// breakpoint; `0` otherwise. (In addition to Status, it may return `1`.)
  /// @note Does not handled the case where the breakpoint is at a syscall.
  int Syscall_();
  /// @brief Patch the data at the address.
  /// @param len The length of the `data` in bytes; should be `1`, `2`, `4`, or
  /// `8`.
  /// @throw `std::invalid_argument` If `len` is not valid.
  Status Patch_(std::uintptr_t addr, std::uint64_t data, std::size_t len);

  //
  // Helper functions.
  //

  /// @brief If the PC is at a breakpoint, Single step the program with the
  /// original instruction.
  /// @return `-2` if the program has exited; `-1` on error; `1` if not at a
  /// breakpoint; `0` otherwise. (In addition to Status, it may return `1`.)
  int StepOverBp_();
  /// @brief Waits for the program to stop, and shows information according to
  /// the reason of stopping.
  /// @note The program is unloaded if it has exited.
  Status Wait_();
  /// @return The register value. `-1` on error.
  std::intptr_t GetRip_() const;
  /// @return `-1` on error.
  int SetRip_(std::uintptr_t rip);
  void Disassemble_(std::uintptr_t addr, std::size_t insn_count);
  void DisassembleFromRip_(std::size_t insn_count);
  void CreateBreak_(std::uintptr_t addr);
  /// @return `-1` if no program is loaded; `0` otherwise.
  int CheckHasLoaded_() const;
  /// @return `-1` on error; `0` otherwise.
  int SetTextSectionEnd_();
  /// @brief Resets the debugger.
  void Unload_();

  static void Usage_();
};

#endif  // DEBUGGER_HPP

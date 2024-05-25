#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP

#include <sys/types.h>

#include <cstddef>
#include <cstdint>

class Debugger {
 public:
  void Run();

  Debugger(const char* program) : program_{program} {}

 private:
  const char* program_;
  pid_t pid_{0};

  /// @note The program is executed as being traced.
  void Load_();
  /// @brief Single step the program.
  void Step_();

  void Disassemble_(std::uintptr_t addr, std::size_t insn_count);
};

#endif  // DEBUGGER_HPP

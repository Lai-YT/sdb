#ifndef DEBUGGER_HPP
#define DEBUGGER_HPP

#include <sys/types.h>

class Debugger {
 public:
  void Run();

  Debugger(const char* program) : program_{program} {}

 private:
  const char* program_;

  /// @note The program is executed as being traced.
  void Load_();
};

#endif  // DEBUGGER_HPP

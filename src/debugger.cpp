#include "debugger.hpp"

#include <elf.h>
#include <fcntl.h>
#include <readline/history.h>
#include <readline/readline.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string_view>
#include <vector>

namespace {
std::vector<std::string> Split(std::string_view s, char delimiter);
}

void Debugger::Run() {
  if (program_) {
    Load_();
  }
  char* line = nullptr;
  while ((line = readline("(sbg) "))) {
    if (*line /* not blank */) {
      add_history(line);
    }
    auto args = Split(line, ' ');
    auto command = args.at(0);
    if (command == "load") {
      auto program = args.at(1);
      program_ = program.c_str();
      Load_();
    } else {
      std::cout << "Unknown command: " << command << "\n";
    }
    std::free(line);
  }
  std::cout << "Quit\n";
}

void Debugger::Load_() {
  auto pid = fork();
  if (pid < 0) {
    std::perror("fork");
    return;
  }
  if (pid == 0 /* child */) {
    if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0) {
      std::perror("ptrace");
      return;
    }
    execl(program_, program_, nullptr);
    // Noreturn.
    std::perror("execl");
    std::exit(1);
  } else {
    auto file = std::ifstream{program_};
    if (!file) {
      std::perror("open");
      return;
    }
    auto header = Elf64_Ehdr{};
    file.read(reinterpret_cast<char*>(&header), sizeof(header));
    std::cout << "** program '" << program_ << "' loaded. entry point 0x"
              << std::hex << header.e_entry << ".\n";

    if (waitpid(pid, nullptr, 0) < 0) {
      std::perror("waitpid");
      return;
    }
    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr, PTRACE_O_EXITKILL) < 0) {
      std::perror("ptrace");
      return;
    }
  }
}

namespace {
std::vector<std::string> Split(std::string_view s, char delimiter) {
  auto tokens = std::vector<std::string>{};
  auto token = std::string{};
  auto token_stream = std::istringstream{std::string{s}};
  while (std::getline(token_stream, token, delimiter)) {
    tokens.push_back(token);
  }
  return tokens;
}
}  // namespace

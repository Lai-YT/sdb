#include <argp.h>

#include "debugger.hpp"

namespace {

struct Arguments {
  char* program;
};

error_t ParseOpt(int opt, char* arg, struct argp_state* state);

}  // namespace

extern "C" {  // For argp.
const char* argp_program_version = "sdb v1.0.3";
}

int main(int argc, char* argv[]) {
  const char* doc =
      "\nA simple x86-64 instruction-level debugger.\v"
      "Copyright (c) 2024 Lai-YT under the MIT License.";
  struct argp argp = {0, ParseOpt, "[PROGRAM]", doc, 0, 0, 0};
  auto args = Arguments{};
  argp_parse(&argp, argc, argv, ARGP_IN_ORDER, 0, &args);
  // Noreturn on error.

  auto dbg = Debugger{args.program};
  dbg.Run();

  return 0;
}

namespace {

error_t ParseOpt(int opt, char* arg, struct argp_state* state) {
  auto* arguments = static_cast<Arguments*>(state->input);
  switch (opt) {
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        arguments->program = arg;
      } else {
        argp_usage(state);
      }
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

}  // namespace

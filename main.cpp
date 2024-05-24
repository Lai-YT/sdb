#include <argp.h>
#include <unistd.h>

#include "debugger.hpp"

namespace {

struct Arguments {
  char* program;
};

error_t ParseOpt(int opt, char* arg, struct argp_state* state);

}  // namespace

int main(int argc, char* argv[]) {
  struct argp argp = {0, ParseOpt, "[PROGRAM]", 0, 0, 0, 0};
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

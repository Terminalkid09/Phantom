#pragma once

// ============================================================================
//  command_line.h — how a free-form shell argument survives the dispatcher
//  ──────────────────────────────────────────────────────────
//  The dispatcher splits a task into a verb and its argument. For most verbs
//  an argument is a token (`persist runkey`, `sleep 5000`), so `operator>>`
//  is enough. The OS-shell verbs (`shell` / `exec` / `run`) are different:
//  their argument is an entire command, and a legitimate one can contain
//  NEWLINES.
//
//  The measured failure: the Linux persistence builder ships a systemd unit
//  inside single quotes. That unit has real newlines between its lines. The
//  dispatcher used `std::getline`, which stops at the first newline, so the
//  target's `sh -c` received
//
//      ... printf '%s' '[Unit]
//
//  — an unterminated single quote. Every Linux persistence install failed
//  with `sh: 1: Syntax error: Unterminated quoted string`, the interpreter
//  saw no PERSISTENCE_OK marker, and auto-mode recorded `persistence = fail`
//  while the beacon's native `persist` verb had succeeded on the same host.
//
//  `argument_rest` returns everything after the first whitespace-delimited
//  token, preserving every byte of the remainder (newlines included) and
//  trimming only the separator whitespace before it.
//
//  Header-only and platform-free so the rule is covered by a compile-and-run
//  test (tests/test_beacon_command_line.cpp) rather than by source inspection.
// ============================================================================

#include <string>

namespace command_line {

//: Everything after the first token, with the leading separator removed.
//: Returns "" when the command has no argument. Never truncates at a newline.
inline std::string argument_rest(const std::string& command) {
    size_t i = 0;
    while (i < command.size()) {
        const char c = command[i];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') break;
        ++i;
    }
    while (i < command.size()) {
        const char c = command[i];
        if (c != ' ' && c != '\t' && c != '\r' && c != '\n') break;
        ++i;
    }
    return command.substr(i);
}

}  // namespace command_line

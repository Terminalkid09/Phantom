"""Simple cross-platform interactive selector using arrow keys.
Does not add external dependencies; uses msvcrt on Windows and termios/tty on POSIX.
Returns the selected option string or None if aborted.
"""
import sys
import os

def _getch():
    if os.name == 'nt':
        import msvcrt
        return msvcrt.getch()
    else:
        import tty, termios
        fd = sys.stdin.fileno()
        old = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            ch = sys.stdin.read(1)
            return ch.encode()
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old)


def select_option(prompt: str, options: list, default_index: int = 0) -> str | None:
    """Display options and let the user select using Up/Down arrows + Enter.

    Returns the selected option (string) or None if ESC pressed or non-interactive.
    """
    if not sys.stdin.isatty():
        return None

    idx = max(0, min(default_index, len(options)-1))

    try:
        # Print prompt
        sys.stdout.write(f"{prompt}\n")
        while True:
            # Render options
            for i, opt in enumerate(options):
                if i == idx:
                    # reverse video for selection
                    sys.stdout.write(f"\x1b[7m> {opt}\x1b[0m\n")
                else:
                    sys.stdout.write(f"  {opt}\n")
            sys.stdout.flush()

            ch = _getch()
            # Windows returns bytes, POSIX our _getch returns bytes
            if not ch:
                break
            # Handle escape sequences
            if ch in (b'\x1b', b'\x00', b'\xe0'):
                # Could be arrow keys
                if ch == b'\x1b':
                    # read next two
                    c2 = _getch()
                    c3 = _getch()
                    if c3 in (b'A', b'B'):
                        if c3 == b'A':  # up
                            idx = (idx - 1) % len(options)
                        elif c3 == b'B':  # down
                            idx = (idx + 1) % len(options)
                else:
                    # Windows: second call gives code
                    c2 = _getch()
                    if c2 in (b'H', b'K'):  # up
                        idx = (idx - 1) % len(options)
                    elif c2 in (b'P', b'M'):  # down
                        idx = (idx + 1) % len(options)
            elif ch in (b'\r', b'\n'):
                # Enter
                # Clear the rendered block before returning
                sys.stdout.write('\x1b[{}A'.format(len(options)))
                for _ in options:
                    sys.stdout.write('\x1b[2K\n')
                sys.stdout.write('\x1b[{}A'.format(len(options)))
                sys.stdout.flush()
                return options[idx]
            elif ch == b'\x03':
                # Ctrl-C
                raise KeyboardInterrupt
            elif ch == b'\x1b':
                # ESC: cancel
                return None
            else:
                # ignore other keys
                pass

            # Move cursor up to re-render in place
            sys.stdout.write('\x1b[{}A'.format(len(options)))
            sys.stdout.flush()
    except KeyboardInterrupt:
        return None
    return None
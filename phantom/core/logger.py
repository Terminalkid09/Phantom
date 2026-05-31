import logging
import os
from datetime import datetime

import logging
import os
from datetime import datetime
from typing import Optional

_logger: Optional[logging.Logger] = None

def _get_log_dir() -> str:
    """Return log directory, preferring data/logs relative to project root."""
    base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, "data", "logs")

def get_logger() -> logging.Logger:
    """Lazy-initialize the logger on first access."""
    global _logger
    if _logger is None:
        log_dir = _get_log_dir()
        os.makedirs(log_dir, exist_ok=True)
        log_filename = os.path.join(
            log_dir,
            f"phantom_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        )
        _logger = logging.getLogger("phantom")
        _logger.setLevel(logging.INFO)
        handler = logging.FileHandler(log_filename, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
        _logger.addHandler(handler)
    return _logger

# Backward compatibility proxy
class LoggerProxy:
    def __getattr__(self, name):
        return getattr(get_logger(), name)

logger = LoggerProxy()
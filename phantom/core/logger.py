import logging
import os
from datetime import datetime

os.makedirs("data/logs", exist_ok=True)
log_filename = f"data/logs/phantom_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(log_filename, encoding="utf-8"),
    ]
)

logger = logging.getLogger("phantom")
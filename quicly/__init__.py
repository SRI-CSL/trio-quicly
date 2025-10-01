#  Copyright ©  2025 SRI International.
#  This work is licensed under CC BY-NC-ND 4.0 license.
#  To view a copy of this license, visit https://creativecommons.org/licenses/by-nc-nd/4.0/

# quicly/__init__.py
import sys
if sys.version_info < (3, 11):
    raise RuntimeError("QUIC-LY requires Python 3.11 or newer")

# per https://docs.python-guide.org/writing/logging/#logging-in-a-library
import logging
logging.getLogger(__name__).addHandler(logging.NullHandler())
"""
methodologies/__init__.py — Triggers self-registration of all methodology modules.

Import order matters only in that generic must load before any OS-specific
module that references generic IDs in next_ids. All modules just call
MethodologyRegistry.get().register(), so load order is safe.

To add a new OS or category:
  1. Create wan_shi_tong/methodologies/<name>.py with _R.register(...) calls
  2. Add one line below:  from wan_shi_tong.methodologies import <name>  # noqa: F401
  No other files need changing.
"""

from wan_shi_tong.methodologies import generic   # noqa: F401
from wan_shi_tong.methodologies import linux     # noqa: F401
from wan_shi_tong.methodologies import windows   # noqa: F401
from wan_shi_tong.methodologies import macos     # noqa: F401
from wan_shi_tong.methodologies import android   # noqa: F401

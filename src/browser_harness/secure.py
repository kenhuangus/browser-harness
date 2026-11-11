"""Secure browser-harness entry point.

Forces telemetry OFF and prompt-injection security ON, then delegates
to browser_harness.run.main(). All environment overrides are ignored so
the secure posture is ALWAYS enforced regardless of caller settings.

Usage:
    browser-harness-secure <<'PY'
    print(page_info())
    PY
"""

from __future__ import annotations

import os
import sys

# ---------------------------------------------------------------------------
# 1. Telemetry is ALWAYS disabled
# ---------------------------------------------------------------------------
# Set all known telemetry-disable env vars to a falsy value so telemetry.py's
# _env_disabled() returns True regardless of any config file or user setting.
for _var in ("BH_TELEMETRY", "BROWSER_HARNESS_TELEMETRY", "ANONYMIZED_TELEMETRY"):
    os.environ[_var] = "0"

# Also write to the config file so is_enabled() stays False even if env is
# later cleared by a sub-process.
try:
    from .telemetry import _config_path, _save_config, _load_config

    _cfg = _load_config()
    _cfg["disabled"] = True
    _cfg["enabled"] = False
    _save_config(_cfg)
except Exception:
    # Config write failure must not block the harness; env vars above suffice.
    pass

# ---------------------------------------------------------------------------
# 2. Prompt-injection security is ALWAYS on (block mode, no override)
# ---------------------------------------------------------------------------
os.environ["BH_SECURITY_MODE"] = "block"
# Remove any override so guard_input() cannot be bypassed.
os.environ.pop("BH_SECURITY_OVERRIDE", None)

# ---------------------------------------------------------------------------
# 3. Delegate to the normal run.main()
# ---------------------------------------------------------------------------
from .run import main

if __name__ == "__main__":
    main()
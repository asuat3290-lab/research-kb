"""Max Research contracts plus the separately gated MR-1 control plane.

Importing this package does not create a database, run migrations, start a
lease, call MCP, load a model, or perform research.  The persistence and
admin APIs are explicit and operate only on a caller-selected control DB.
"""

from .contract import *  # noqa: F401,F403
from .admin import MaxAdminService  # noqa: F401
from .service import MaxCanaryService, MaxControlService, NativeLiveCanaryService, NativePreparationService, resolve_control_database  # noqa: F401
from .provider import *  # noqa: F401,F403
from .scheduler import *  # noqa: F401,F403
from .long_run import *  # noqa: F401,F403
from .long_run_executor import *  # noqa: F401,F403
from .live_canary import *  # noqa: F401,F403
from .production_bridge import *  # noqa: F401,F403
from .intent_preparer import *  # noqa: F401,F403
from .lifetime_separation import *  # noqa: F401,F403
from .preparation_handoff import *  # noqa: F401,F403
from .preparation_execution import *  # noqa: F401,F403
from .native_live import *  # noqa: F401,F403
from .convergence import *  # noqa: F401,F403
from .portability import *  # noqa: F401,F403
from .external_agent import *  # noqa: F401,F403

__all__ = [name for name in globals() if not name.startswith("_")]

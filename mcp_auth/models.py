from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class Principal:
    """Canonical principal shape used by middleware and MCP consumers.

    Fields:
      - id: unique identifier (sub/oid/username)
      - provider: provider name (local/google/aws/azure)
      - name: display name if available
      - email: email address if available
      - roles: optional roles/groups
      - raw: raw claims dict
    """

    id: str
    provider: str
    name: Optional[str] = None
    email: Optional[str] = None
    roles: Optional[List[str]] = None
    raw: Optional[Dict[str, Any]] = None

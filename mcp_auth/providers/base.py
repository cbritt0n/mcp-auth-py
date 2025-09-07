from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

@dataclass
class AuthResult:
    valid: bool
    principal: Optional[str] = None
    claims: Optional[Dict[str, Any]] = None
    raw: Optional[Dict[str, Any]] = None

class ProviderError(Exception):
    pass

class Provider(ABC):
    @abstractmethod
    def authenticate(self, request) -> AuthResult:
        """Authenticate an incoming request and return AuthResult.

        Raise ProviderError for configuration or network errors.
        """
        raise NotImplementedError()

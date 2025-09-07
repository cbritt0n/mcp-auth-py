from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from ..models import Principal


@dataclass
class AuthResult:
    valid: bool
    principal: Optional[Principal] = None
    claims: Optional[Dict[str, Any]] = None
    raw: Optional[Dict[str, Any]] = None


class ProviderError(Exception):
    """Provider-specific error with optional machine-readable code."""

    def __init__(self, message: str, code: Optional[str] = None):
        super().__init__(message)
        self.code = code


class Provider(ABC):
    @abstractmethod
    def authenticate(self, request) -> AuthResult:
        """Authenticate an incoming request and return AuthResult or raise ProviderError.

        Implementations may be synchronous or asynchronous (returning a coroutine). The
        middleware will await coroutine results.
        """
        raise NotImplementedError()

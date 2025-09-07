import os
import sys

# Ensure project root is on sys.path so tests can import the package under test
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Minimal BaseSettings shim for tests when 'pydantic-settings' is not installed.
try:
    import pydantic_settings  # type: ignore
except Exception:

    class BaseSettings:
        """Minimal shim: uses class attributes as defaults and allows overrides via constructor."""

        def __init__(self, **kwargs):
            for name, val in self.__class__.__dict__.items():
                if (
                    name.startswith("_")
                    or callable(val)
                    or isinstance(val, (staticmethod, classmethod))
                ):
                    continue
                setattr(self, name, val)
            for k, v in kwargs.items():
                setattr(self, k, v)

    # expose for tests/modules importing BaseSettings from pydantic_settings
    import types

    sys.modules.setdefault(
        "pydantic_settings", types.SimpleNamespace(BaseSettings=BaseSettings)
    )

# Scripts for mcp-auth-py
from .setup import main as setup_main
from .generate_token import main as generate_token_main
from .validate_install import main as validate_install_main

__all__ = ["setup_main", "generate_token_main", "validate_install_main"]

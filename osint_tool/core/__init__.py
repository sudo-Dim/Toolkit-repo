"""OSINT Tool - Core Package

Lazy-Importe (PEP 562), damit das Importieren von Hilfsmodulen wie
``osint_tool.core.http`` oder ``osint_tool.core.config`` nicht die Engine
(und damit die Module) eager lädt — das würde einen zirkulären Import
auslösen (engine -> modules -> core.http -> core/__init__ -> engine).
"""

from .config import AppConfig

__all__ = ["AppConfig", "OSINTEngine", "ScanResult", "ScanJob", "Reporter"]


def __getattr__(name):
    if name in ("OSINTEngine", "ScanResult", "ScanJob"):
        from . import engine
        return getattr(engine, name)
    if name == "Reporter":
        from .reporter import Reporter
        return Reporter
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

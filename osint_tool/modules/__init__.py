"""
OSINT Tool - Modul-Registry
Importiert und registriert alle verfügbaren OSINT-Module.
"""

from .username import UsernameModule
from .email_osint import EmailModule
from .phone import PhoneModule
from .domain import DomainModule
from .name_search import NameModule

# Alle verfügbaren Module
ALL_MODULES = [
    UsernameModule,
    EmailModule,
    PhoneModule,
    DomainModule,
    NameModule,
]

# Mapping: input_type -> Liste von Modulen die diesen Typ verarbeiten
INPUT_TYPE_MAP = {}
for mod_class in ALL_MODULES:
    instance = mod_class()
    for itype in instance.input_types:
        INPUT_TYPE_MAP.setdefault(itype, []).append(mod_class)

__all__ = [
    "ALL_MODULES",
    "INPUT_TYPE_MAP",
    "UsernameModule",
    "EmailModule",
    "PhoneModule",
    "DomainModule",
    "NameModule",
]

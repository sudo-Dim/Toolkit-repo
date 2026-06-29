"""
OSINT Tool - Basis-Modul
Abstrakte Basisklasse für alle OSINT-Module.
"""

import time
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime
from enum import Enum


class ResultSeverity(Enum):
    """Schweregrad eines Ergebnisses."""
    INFO = "info"
    FOUND = "found"
    WARNING = "warning"
    CRITICAL = "critical"
    NOT_FOUND = "not_found"


@dataclass
class OSINTResult:
    """Einzelnes Ergebnis einer OSINT-Abfrage."""
    source: str              # z.B. "GitHub", "HIBP", "DNS"
    module: str              # z.B. "username", "email", "domain"
    category: str            # z.B. "Social Media", "Security"
    severity: ResultSeverity
    title: str               # Kurzbeschreibung
    data: Dict[str, Any]     # Strukturierte Daten
    url: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "module": self.module,
            "category": self.category,
            "severity": self.severity.value,
            "title": self.title,
            "data": self.data,
            "url": self.url,
            "timestamp": self.timestamp,
        }


@dataclass
class ModuleReport:
    """Gesamtbericht eines Moduls."""
    module_name: str
    input_value: str
    input_type: str
    results: List[OSINTResult] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0

    @property
    def found_count(self) -> int:
        return sum(1 for r in self.results if r.severity == ResultSeverity.FOUND)

    @property
    def total_count(self) -> int:
        return len(self.results)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module_name,
            "input": self.input_value,
            "input_type": self.input_type,
            "summary": {
                "total_checks": self.total_count,
                "found": self.found_count,
                "errors": len(self.errors),
                "duration_seconds": round(self.duration_seconds, 2),
            },
            "results": [r.to_dict() for r in self.results],
            "errors": self.errors,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


class BaseModule(ABC):
    """
    Abstrakte Basisklasse für alle OSINT-Module.
    
    Jedes Modul muss implementieren:
        - name: Modulname
        - description: Beschreibung
        - input_types: Liste akzeptierter Eingabetypen
        - run(input_value): Hauptlogik
    """

    def __init__(self, config=None):
        self.config = config
        self.logger = logging.getLogger(f"osint.{self.name}")
        self._results: List[OSINTResult] = []
        self._errors: List[str] = []
        self._progress_callback = None

    @property
    @abstractmethod
    def name(self) -> str:
        """Eindeutiger Modulname."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Beschreibung des Moduls."""
        pass

    @property
    @abstractmethod
    def input_types(self) -> List[str]:
        """Akzeptierte Eingabetypen: 'username', 'email', 'phone', 'domain', 'ip', 'name'."""
        pass

    @abstractmethod
    def run(self, input_value: str, input_type: str) -> ModuleReport:
        """Führt die OSINT-Suche aus und gibt einen ModuleReport zurück."""
        pass

    def set_progress_callback(self, callback):
        """
        Setzt eine Callback-Funktion für Fortschrittsupdates.
        callback(module_name, current, total, message)
        Wird vom GUI genutzt.
        """
        self._progress_callback = callback

    def report_progress(self, current: int, total: int, message: str = ""):
        """Meldet Fortschritt an den Callback (falls gesetzt)."""
        if self._progress_callback:
            self._progress_callback(self.name, current, total, message)

    def add_result(self, result: OSINTResult):
        self._results.append(result)

    def add_error(self, error: str):
        self._errors.append(error)
        self.logger.error(error)

    def create_report(self, input_value: str, input_type: str,
                      start: float, end: float) -> ModuleReport:
        """Erstellt den abschließenden ModuleReport."""
        report = ModuleReport(
            module_name=self.name,
            input_value=input_value,
            input_type=input_type,
            results=list(self._results),
            errors=list(self._errors),
            start_time=datetime.fromtimestamp(start).isoformat(),
            end_time=datetime.fromtimestamp(end).isoformat(),
            duration_seconds=end - start,
        )
        # Reset für nächsten Lauf
        self._results = []
        self._errors = []
        return report

    def accepts_input(self, input_type: str) -> bool:
        """Prüft ob das Modul diesen Eingabetyp verarbeiten kann."""
        return input_type in self.input_types

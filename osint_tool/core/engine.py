"""
OSINT Tool - Engine
Zentrale Steuerung: Erkennt Eingabetypen, wählt Module,
orchestriert die Suche und sammelt Ergebnisse.
"""

import re
import time
import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional
from datetime import datetime

from .config import AppConfig
from ..modules import ALL_MODULES, INPUT_TYPE_MAP
from ..modules.base import BaseModule, ModuleReport


@dataclass
class ScanJob:
    """Ein einzelner Scan-Auftrag."""
    input_value: str
    input_type: str
    modules: List[str] = field(default_factory=list)  # Leere Liste = alle passenden
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    """Gesamtergebnis eines Scans."""
    job: ScanJob
    reports: List[ModuleReport] = field(default_factory=list)
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan": {
                "input": self.job.input_value,
                "type": self.job.input_type,
                "timestamp": self.job.timestamp,
                "duration_seconds": round(self.duration_seconds, 2),
            },
            "modules": [r.to_dict() for r in self.reports],
            "summary": {
                "total_modules": len(self.reports),
                "total_results": sum(r.total_count for r in self.reports),
                "total_found": sum(r.found_count for r in self.reports),
                "total_errors": sum(len(r.errors) for r in self.reports),
            },
        }


class OSINTEngine:
    """
    Haupt-Engine des OSINT-Tools.
    
    Nutzung:
        engine = OSINTEngine()
        result = engine.scan("john_doe", input_type="username")
        result = engine.auto_scan("test@example.com")  # Erkennt Typ automatisch
    """

    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.config.load_api_keys()
        self.logger = logging.getLogger("osint.engine")
        self._modules: Dict[str, BaseModule] = {}
        self._progress_callback: Optional[Callable] = None

        # Module initialisieren
        for mod_class in ALL_MODULES:
            instance = mod_class(config=self.config)
            self._modules[instance.name] = instance

    @property
    def available_modules(self) -> Dict[str, BaseModule]:
        return dict(self._modules)

    @property
    def supported_input_types(self) -> List[str]:
        return list(INPUT_TYPE_MAP.keys())

    def set_progress_callback(self, callback: Callable):
        """
        Setzt globalen Progress-Callback.
        callback(module_name, current, total, message)
        """
        self._progress_callback = callback
        for mod in self._modules.values():
            mod.set_progress_callback(callback)

    def detect_input_type(self, value: str) -> str:
        """
        Erkennt automatisch den Eingabetyp.
        
        Reihenfolge der Prüfung:
        1. E-Mail (enthält @, Punkt nach @)
        2. IP-Adresse (IPv4/IPv6)
        3. Domain (enthält Punkt, kein Leerzeichen)
        4. Telefonnummer (beginnt mit +, 0 oder reine Ziffern mit >6 Stellen)
        5. Username (kein Leerzeichen)
        6. Name (Fallback: enthält Leerzeichen)
        """
        value = value.strip()

        # Schutz vor pathologisch langen Eingaben (Regex-Backtracking/DoS)
        if len(value) > 100:
            return "username"

        # E-Mail
        if re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            return "email"

        # IPv4
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return "ip"

        # IPv6
        if ":" in value and re.match(r'^[0-9a-fA-F:]+$', value):
            return "ip"

        # Domain (hat Punkt, kein Leerzeichen, kein @)
        if "." in value and " " not in value and "@" not in value:
            # Entferne Protokoll für Check
            clean = re.sub(r'^https?://', '', value).split('/')[0]
            if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', clean):
                return "domain"

        # Telefonnummer
        digits_only = re.sub(r'[\s\-\(\)\/]', '', value)
        if re.match(r'^\+?\d{7,15}$', digits_only):
            return "phone"
        if value.startswith('+') or value.startswith('00'):
            if sum(c.isdigit() for c in value) >= 7:
                return "phone"

        # Name (enthält Leerzeichen)
        if " " in value:
            return "name"

        # Username (Fallback)
        return "username"

    def get_modules_for_type(self, input_type: str) -> List[BaseModule]:
        """Gibt alle Module zurück, die einen bestimmten Eingabetyp verarbeiten."""
        module_classes = INPUT_TYPE_MAP.get(input_type, [])
        return [self._modules[cls().name] for cls in module_classes
                if cls().name in self._modules]

    def scan(self, input_value: str, input_type: str,
             module_names: Optional[List[str]] = None) -> ScanResult:
        """
        Führt einen gezielten Scan durch.
        
        Args:
            input_value: Der zu suchende Wert
            input_type: Der Typ der Eingabe
            module_names: Optional - nur diese Module ausführen
        
        Returns:
            ScanResult mit allen Modulberichten
        """
        job = ScanJob(
            input_value=input_value,
            input_type=input_type,
            modules=module_names or [],
        )

        start = time.time()
        result = ScanResult(job=job, start_time=datetime.now().isoformat())

        # Module auswählen
        if module_names:
            modules = [self._modules[n] for n in module_names if n in self._modules]
        else:
            modules = self.get_modules_for_type(input_type)

        if not modules:
            self.logger.warning(f"Keine Module für Typ '{input_type}' gefunden")
            result.end_time = datetime.now().isoformat()
            return result

        self.logger.info(
            f"Starte Scan: '{input_value}' (Typ: {input_type}) "
            f"mit {len(modules)} Modul(en)"
        )

        # Module ausführen
        for module in modules:
            try:
                self.logger.info(f"Führe Modul '{module.name}' aus...")
                report = module.run(input_value, input_type)
                result.reports.append(report)
                self.logger.info(
                    f"Modul '{module.name}': {report.found_count}/{report.total_count} "
                    f"gefunden in {report.duration_seconds:.1f}s"
                )
            except Exception as e:
                self.logger.error(f"Modul '{module.name}' Fehler: {str(e)}")
                # Erstelle Error-Report
                error_report = ModuleReport(
                    module_name=module.name,
                    input_value=input_value,
                    input_type=input_type,
                    errors=[str(e)],
                )
                result.reports.append(error_report)

        end = time.time()
        result.end_time = datetime.now().isoformat()
        result.duration_seconds = end - start

        self.logger.info(
            f"Scan abgeschlossen in {result.duration_seconds:.1f}s - "
            f"{sum(r.found_count for r in result.reports)} Treffer"
        )

        return result

    def auto_scan(self, input_value: str,
                  module_names: Optional[List[str]] = None) -> ScanResult:
        """
        Erkennt den Eingabetyp automatisch und führt den Scan durch.
        """
        input_type = self.detect_input_type(input_value)
        self.logger.info(f"Auto-Erkennung: '{input_value}' -> Typ '{input_type}'")
        return self.scan(input_value, input_type, module_names)

    def multi_scan(self, inputs: List[dict]) -> List[ScanResult]:
        """
        Führt mehrere Scans nacheinander aus.
        
        Args:
            inputs: Liste von {"value": "...", "type": "..." (optional)}
        
        Returns:
            Liste von ScanResults
        """
        results = []
        for item in inputs:
            value = item.get("value", "")
            itype = item.get("type") or self.detect_input_type(value)
            modules = item.get("modules")
            result = self.scan(value, itype, modules)
            results.append(result)
        return results

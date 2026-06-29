"""
OSINT Tool - Username-Modul
Prüft ob ein Username auf verschiedenen Plattformen existiert.
Ähnlich wie Sherlock, Namechk, etc.
"""

import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.config import USERNAME_PLATFORMS


class UsernameModule(BaseModule):

    @property
    def name(self) -> str:
        return "username"

    @property
    def description(self) -> str:
        return "Prüft ob ein Username auf verschiedenen Plattformen existiert"

    @property
    def input_types(self) -> List[str]:
        return ["username"]

    def _check_platform(self, platform_name: str, platform_data: dict,
                        username: str) -> OSINTResult:
        """Prüft eine einzelne Plattform."""
        url = platform_data["url"].format(username)
        category = platform_data.get("category", "Other")

        try:
            headers = {"User-Agent": self.config.user_agent if self.config else ""}
            response = requests.get(
                url,
                headers=headers,
                timeout=self.config.request_timeout if self.config else 10,
                allow_redirects=True,
            )

            found = False
            check = platform_data.get("check_method", "status_code")

            if check == "status_code":
                found = response.status_code == platform_data.get("expected", 200)
            elif check == "content":
                match_text = platform_data.get("content_match", "")
                found = (
                    response.status_code == 200
                    and match_text in response.text
                )

            severity = ResultSeverity.FOUND if found else ResultSeverity.NOT_FOUND

            return OSINTResult(
                source=platform_name,
                module=self.name,
                category=category,
                severity=severity,
                title=f"{'Gefunden' if found else 'Nicht gefunden'} auf {platform_name}",
                data={
                    "exists": found,
                    "status_code": response.status_code,
                    "response_url": str(response.url),
                },
                url=url if found else None,
            )

        except requests.exceptions.Timeout:
            return OSINTResult(
                source=platform_name,
                module=self.name,
                category=category,
                severity=ResultSeverity.INFO,
                title=f"Timeout bei {platform_name}",
                data={"exists": None, "error": "Timeout"},
                url=url,
            )
        except requests.exceptions.RequestException as e:
            self.add_error(f"{platform_name}: {str(e)}")
            return OSINTResult(
                source=platform_name,
                module=self.name,
                category=category,
                severity=ResultSeverity.INFO,
                title=f"Fehler bei {platform_name}",
                data={"exists": None, "error": str(e)},
            )

    def run(self, input_value: str, input_type: str = "username") -> ModuleReport:
        start = time.time()
        username = input_value.strip().lstrip("@")
        platforms = USERNAME_PLATFORMS
        total = len(platforms)
        completed = 0

        self.report_progress(0, total, "Starte Username-Suche...")

        max_workers = self.config.max_concurrent_requests if self.config else 10

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    self._check_platform, name, data, username
                ): name
                for name, data in platforms.items()
            }

            for future in as_completed(futures):
                platform_name = futures[future]
                try:
                    result = future.result()
                    self.add_result(result)
                except Exception as e:
                    self.add_error(f"{platform_name}: {str(e)}")
                completed += 1
                self.report_progress(completed, total, f"Prüfe {platform_name}...")

        end = time.time()
        return self.create_report(username, input_type, start, end)

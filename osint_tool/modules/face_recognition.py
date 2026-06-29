"""
OSINT Tool - Gesichtserkennungs-/Bildsuche-Modul (GRUNDSTEIN)
============================================================

Dieses Modul legt das Fundament für eine PimEyes-ähnliche Gesichtssuche.
Es ist BEWUSST noch nicht vollständig ausgebaut — die schwere ML-Logik
(eigener Crawler + Embeddings + Vektor-Index) ist als klar dokumentierte
Schnittstelle vorbereitet, aber noch nicht implementiert.

Was JETZT schon funktioniert (ohne ML-Abhängigkeiten):
  • Eingabe = lokaler Bildpfad ODER Bild-URL
  • Generierung von Direktlinks zu Reverse-Face-/Reverse-Image-Suchmaschinen
    (Google Lens, Yandex, Bing, TinEye akzeptieren eine Bild-URL direkt;
     PimEyes, FaceCheck.ID, Search4Faces, Lenso.ai = Upload)
  • Optionale lokale Gesichts-Erkennung (Anzahl/Bounding-Boxes), FALLS
    optionale Pakete installiert sind (opencv / insightface / face_recognition)
  • Architektur-Roadmap + Capability-Report

ROADMAP (PimEyes-artige Eigenlösung — siehe FaceEngine unten):
  1. Detection   : Gesichter finden (RetinaFace / MTCNN / MediaPipe / YOLO-face)
  2. Alignment   : Gesicht normalisieren (5-Punkt-Landmarks)
  3. Embedding   : 512-d Vektor je Gesicht (ArcFace / InsightFace buffalo_l)
  4. Index       : Vektor-Datenbank über gecrawlte Web-Bilder (FAISS / hnswlib)
  5. Matching    : Cosine-Similarity + Schwellenwert -> Treffer mit Quelle
  6. Crawler     : sammelt & indexiert öffentlich zugängliche Bilder

⚠️  RECHTLICH/ETHISCH: Biometrische Gesichtssuche ist hochsensibel und in
    vielen Ländern (z.B. EU/DSGVO, BIPA) stark reguliert. Nur mit Einwilligung
    bzw. klarer Autorisierung einsetzen (z.B. eigene Bilder, autorisierte
    Ermittlungen, Sicherheitsforschung). Siehe LEGAL_NOTICE.
"""

import os
import time
from typing import List, Optional
from urllib.parse import quote

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.config import load_data

LEGAL_NOTICE = (
    "Biometrische Gesichtssuche ist hochsensibel und vielerorts gesetzlich "
    "reguliert (EU/DSGVO Art. 9, US-BIPA u.a.). Nur mit Einwilligung der "
    "abgebildeten Person oder klarer Autorisierung verwenden."
)

_IMAGE_EXTS = (".jpg", ".jpeg", ".png", ".webp", ".gif", ".bmp", ".tiff")

# Optionale ML-Pakete (für die zukünftige lokale Engine)
_OPTIONAL_LIBS = {
    "opencv": "cv2",
    "insightface": "insightface",
    "face_recognition": "face_recognition",
    "facenet-pytorch": "facenet_pytorch",
    "onnxruntime": "onnxruntime",
    "faiss": "faiss",
    "numpy": "numpy",
    "Pillow": "PIL",
}


def detect_capabilities() -> dict:
    """Meldet, welche optionalen ML-Pakete installiert sind."""
    import importlib.util
    caps = {}
    for label, mod in _OPTIONAL_LIBS.items():
        caps[label] = importlib.util.find_spec(mod) is not None
    caps["local_face_detection"] = caps.get("opencv") or caps.get("face_recognition") or caps.get("insightface")
    caps["local_embeddings"] = caps.get("insightface") or caps.get("face_recognition") or caps.get("facenet-pytorch")
    caps["vector_index"] = caps.get("faiss")
    return caps


class FaceEngine:
    """Grundgerüst für die zukünftige lokale Gesichts-Such-Engine.

    Die Methoden sind als Schnittstelle definiert und noch NICHT
    implementiert. Sie beschreiben den geplanten Aufbau, damit die
    Erweiterung sauber andocken kann.
    """

    EMBEDDING_DIM = 512  # ArcFace/InsightFace-Standard
    MATCH_THRESHOLD = 0.35  # Cosine-Distanz; < Schwelle => gleiche Person (kalibrieren!)

    def __init__(self, model: str = "buffalo_l", index_path: Optional[str] = None):
        self.model = model
        self.index_path = index_path

    # 1. Detection ----------------------------------------------------------
    def detect_faces(self, image_path: str) -> list:
        """TODO: Gesichter detektieren (bbox, landmarks, det_score).

        Geplant: insightface FaceAnalysis (RetinaFace) oder face_recognition
        (HOG/CNN). Rückgabe: Liste von Faces mit bbox + Landmarks.
        """
        raise NotImplementedError(
            "Lokale Gesichts-Detektion ist Teil der Roadmap (insightface/face_recognition).")

    # 2./3. Alignment + Embedding ------------------------------------------
    def compute_embeddings(self, image_path: str, faces=None) -> list:
        """TODO: 512-d ArcFace-Embedding je Gesicht berechnen."""
        raise NotImplementedError(
            "Embedding-Extraktion ist Teil der Roadmap (ArcFace / InsightFace buffalo_l).")

    # 4. Index --------------------------------------------------------------
    def build_index(self, image_dir: str) -> None:
        """TODO: Embeddings aller Bilder berechnen und in FAISS/hnswlib indexieren."""
        raise NotImplementedError(
            "Vektor-Index-Aufbau ist Teil der Roadmap (FAISS/hnswlib über gecrawlte Bilder).")

    # 5. Matching -----------------------------------------------------------
    def search_index(self, embedding, top_k: int = 20) -> list:
        """TODO: Nächste Nachbarn im Index suchen (Cosine), Treffer + Quelle zurückgeben."""
        raise NotImplementedError(
            "Index-Suche/Matching ist Teil der Roadmap (Cosine-Similarity + Threshold).")

    # 6. Crawler ------------------------------------------------------------
    def crawl_and_index(self, seeds: list) -> None:
        """TODO: Öffentliche Bilder crawlen, Gesichter extrahieren, indexieren."""
        raise NotImplementedError(
            "Crawler/Indexierung ist Teil der Roadmap.")


class FaceModule(BaseModule):

    @property
    def name(self) -> str:
        return "face"

    @property
    def description(self) -> str:
        return ("Gesichts-/Bildsuche (Grundstein): Reverse-Search-Engine-Links, "
                "optionale lokale Gesichtserkennung, PimEyes-artige Roadmap")

    @property
    def input_types(self) -> List[str]:
        return ["image"]

    # ── Bild-URL für URL-basierte Engines bestimmen ────────────
    @staticmethod
    def _is_url(value: str) -> bool:
        return value.lower().startswith(("http://", "https://"))

    def _engine_links(self, image_value: str, is_url: bool) -> List[dict]:
        engines = load_data("face_search_engines.json", "engines", [])
        out = []
        for e in engines:
            if e.get("accepts_url") and is_url:
                url = e["url"].replace("{imgurl}", quote(image_value, safe=""))
            else:
                # Upload-only oder lokale Datei -> Engine-Startseite + Hinweis
                url = e["url"].split("{imgurl}")[0] if "{imgurl}" in e["url"] else e["url"]
                if "{imgurl}" in e["url"]:
                    url = "https://" + e["url"].split("//", 1)[1].split("/")[0]
            out.append({"engine": e["name"], "category": e.get("category", ""),
                        "url": url, "accepts_url": e.get("accepts_url", False),
                        "notes": e.get("notes", "")})
        return out

    # ── Optionale lokale Gesichts-Detektion (falls Pakete da) ──
    def _local_detection(self, image_path: str) -> Optional[dict]:
        try:
            import cv2  # type: ignore
        except Exception:
            return None
        try:
            cascade_path = cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
            clf = cv2.CascadeClassifier(cascade_path)
            img = cv2.imread(image_path)
            if img is None:
                return {"error": "Bild konnte nicht gelesen werden"}
            gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
            faces = clf.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
            return {"engine": "OpenCV Haar-Cascade", "faces_detected": int(len(faces)),
                    "boxes": [[int(x), int(y), int(w), int(h)] for (x, y, w, h) in faces],
                    "image_size": [int(img.shape[1]), int(img.shape[0])]}
        except Exception as exc:
            return {"error": str(exc)}

    def run(self, input_value: str, input_type: str = "image") -> ModuleReport:
        start = time.time()
        value = input_value.strip()
        is_url = self._is_url(value)
        is_file = (not is_url) and os.path.exists(value)
        steps = 4
        step = 0

        def tick(msg):
            nonlocal step
            step += 1
            self.report_progress(step, steps, msg)

        # 0. Rechtlicher Hinweis (immer, sehr sichtbar)
        self.add_result(OSINTResult(
            source="Hinweis", module=self.name, category="Recht & Ethik",
            severity=ResultSeverity.WARNING, title="Nur mit Einwilligung/Autorisierung verwenden",
            data={"hinweis": LEGAL_NOTICE}))
        tick("Eingabe geprüft")

        # 1. Eingabe-Status
        valid_input = is_url or is_file
        self.add_result(OSINTResult(
            source="Bild-Eingabe", module=self.name, category="Input",
            severity=ResultSeverity.INFO if valid_input else ResultSeverity.WARNING,
            title=("Bild-URL erkannt" if is_url else
                   "Lokale Bilddatei erkannt" if is_file else
                   "Kein gültiges Bild (Pfad/URL prüfen)"),
            data={"value": value, "is_url": is_url, "is_file": is_file,
                  "hint": ("URL-basierte Engines (Google Lens/Yandex/Bing/TinEye) brauchen eine "
                           "öffentlich erreichbare Bild-URL. Bei lokalen Dateien dort manuell hochladen.")
                          if not is_url else None}))
        tick("Engines vorbereitet")

        # 2. Reverse-Search-Engine-Links
        for link in self._engine_links(value, is_url):
            direct = link["accepts_url"] and is_url
            self.add_result(OSINTResult(
                source=link["engine"], module=self.name,
                category=f"Reverse-Suche · {link['category']}".strip(" ·"),
                severity=ResultSeverity.FOUND if direct else ResultSeverity.INFO,
                title=(f"{link['engine']}: Direktlink (Bild-URL)" if direct
                       else f"{link['engine']}: manuell (Upload)"),
                data={"accepts_url": link["accepts_url"], "notes": link["notes"]},
                url=link["url"]))
        tick("Lokale Analyse")

        # 3. Optionale lokale Gesichts-Detektion + Capability-Report
        caps = detect_capabilities()
        if is_file:
            det = self._local_detection(value)
            if det and "faces_detected" in det:
                self.add_result(OSINTResult(
                    source="Lokale Gesichts-Detektion", module=self.name, category="Analyse",
                    severity=ResultSeverity.FOUND if det["faces_detected"] else ResultSeverity.NOT_FOUND,
                    title=f"{det['faces_detected']} Gesicht(er) erkannt (OpenCV)",
                    data=det))
            elif det and det.get("error"):
                self.add_result(OSINTResult(
                    source="Lokale Gesichts-Detektion", module=self.name, category="Analyse",
                    severity=ResultSeverity.INFO, title="Lokale Detektion fehlgeschlagen",
                    data=det))

        self.add_result(OSINTResult(
            source="Engine-Status", module=self.name, category="Roadmap",
            severity=ResultSeverity.INFO,
            title="Lokale Gesichtserkennung: Fundament gelegt (noch nicht aktiv)",
            data={
                "verfuegbare_pakete": {k: v for k, v in caps.items() if k in _OPTIONAL_LIBS},
                "faehigkeiten": {k: caps[k] for k in
                                 ("local_face_detection", "local_embeddings", "vector_index")},
                "roadmap": ["1. Detection (RetinaFace/MTCNN)", "2. Alignment",
                            "3. Embedding (ArcFace/InsightFace buffalo_l)",
                            "4. Vektor-Index (FAISS/hnswlib)", "5. Matching (Cosine + Threshold)",
                            "6. Crawler für Web-Bilder"],
                "aktivierung": ("Für lokale Detektion: pip install opencv-python. "
                                "Für Embeddings/Index (PimEyes-artig): pip install insightface onnxruntime faiss-cpu."),
            }))
        self.report_progress(steps, steps, "Gesichts-/Bildsuche abgeschlossen")
        return self.create_report(value, input_type, start, time.time())

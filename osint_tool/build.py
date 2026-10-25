"""Portable App bauen: python osint_tool/build.py (auf dem Zielbetriebssystem)."""

import argparse
import importlib.util
import json
import platform
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent
ROOT = PACKAGE.parent

# Entwicklungswerkzeuge und optionale Oberflächen gehören nicht zur Laufzeit.
# HTTP, DNS, Tcl/Tk und sämtliche phonenumbers-Metadaten bleiben vollständig.
EXCLUDED_MODULES = (
    "osint_tool.web", "osint_tool.main", "osint_tool.light", "osint_tool.start_web",
    "flask", "pytest", "unittest", "doctest", "test", "pdb", "pydoc", "pydoc_data",
    "setuptools", "_distutils_hack", "pkg_resources", "pip", "wheel", "PyInstaller",
    "cv2", "insightface", "face_recognition", "facenet_pytorch", "onnxruntime",
    "faiss", "numpy", "PIL", "torch",
)


def build_command(staging):
    name = "OSINTReconTool"
    command = [
        sys.executable, "-m", "PyInstaller", "--onefile",
        "--windowed", "--name", name,
        "--paths", str(ROOT), "--distpath", str(ROOT / "dist"),
        "--workpath", str(ROOT / "build" / "pyinstaller"), "--specpath", str(ROOT / "build"),
        "--add-data", f"{PACKAGE / 'data'}:osint_tool/data",
        "--add-data", f"{Path(staging) / 'config.json'}:osint_tool",
        # Die Standard-Hooks sammeln phonenumbers vollständig und alle dynamischen
        # DNS-Record-Typen. Ein pauschales Einsammeln von dns ist nicht nötig.
        "--noupx", "--clean", "--noconfirm",
    ]
    # Keine schweren, optionalen ML-Pakete in der portablen Standard-App.
    for module in EXCLUDED_MODULES:
        command.extend(["--exclude-module", module])
    command.append(str(PACKAGE / "start_desktop.py"))
    return command


def package_portable(executable):
    system = platform.system().lower()
    machine = platform.machine().lower()
    arch = "x64" if machine in ("amd64", "x86_64") else machine
    archive = executable.parent / f"{executable.stem}-{system}-{arch}.zip"
    example = json.dumps({"api_keys": {}, "site_auth": {}}, ensure_ascii=False, indent=2)
    instructions = (
        "OSINT Recon – portable App\n\n"
        f"1. ZIP in einen eigenen Ordner entpacken.\n2. {executable.name} starten.\n"
        "Python und ein Browser sind für die Desktop-App nicht erforderlich.\n"
        "Online-Datenquellen benötigen weiterhin eine Internetverbindung.\n\n"
        "Optional: config.local.example.json nach config.local.json kopieren und\n"
        "eigene API-Keys/site_auth eintragen. Die Datei liegt direkt neben der EXE.\n"
        "Keine Schlüssel in die EXE eingebaut. Konfiguration niemals öffentlich teilen.\n\n"
        "Desktop-Ergebnisse werden nur auf Wunsch exportiert. Standard-Exportordner:\n"
        "user-data/results neben der EXE; bei Schreibschutz im Benutzerprofil.\n"
        "Zum Entfernen App-Ordner und selbst gespeicherte Exporte löschen.\n"
    )
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as bundle:
        bundle.write(executable, executable.name)
        bundle.writestr("config.local.example.json", example)
        bundle.writestr("LIESMICH.txt", instructions)
        if executable.suffix.lower() == ".exe":
            bundle.writestr("START.bat", '@echo off\r\nstart "" "%~dp0OSINTReconTool.exe"\r\n')
    return archive


def audit_bundle(executable):
    """Prüft das fertige Paket, bevor es als portables ZIP ausgeliefert wird."""
    from importlib.metadata import version
    from PyInstaller.archive.readers import CArchiveReader

    archive = CArchiveReader(str(executable))
    modules = set(archive.open_embedded_archive("PYZ.pyz").toc)
    unexpected = sorted(name for name in modules
                        if any(name == excluded or name.startswith(excluded + ".")
                               for excluded in EXCLUDED_MODULES))
    if unexpected:
        raise RuntimeError(f"Nicht benötigte Module im Build: {unexpected}")

    preserved = {}
    for package in ("phonenumbers", "dns.rdtypes"):
        spec = importlib.util.find_spec(package)
        package_dir = Path(spec.origin).parent
        expected = set()
        for source in package_dir.rglob("*.py"):
            parts = list(source.relative_to(package_dir).with_suffix("").parts)
            if parts[-1] == "__init__":
                parts.pop()
            expected.add(".".join([package, *parts]))
        missing = sorted(expected - modules)
        if missing:
            raise RuntimeError(f"Fehlende Analyse-Metadaten/Module: {missing}")
        preserved[package] = len(expected)

    for required in ("requests", "urllib3", "charset_normalizer", "idna", "certifi", "dns.resolver"):
        if required not in modules:
            raise RuntimeError(f"Fehlende Laufzeit-Abhängigkeit: {required}")
    if not any(name.endswith("certifi/cacert.pem") for name in archive.toc):
        raise RuntimeError("TLS-Zertifikatsdaten fehlen im Build")
    report = {
        "executable_bytes": executable.stat().st_size,
        "python_modules": len(modules),
        "complete_metadata_modules": preserved,
        "runtime_dependencies": {name: version(name) for name in
            ("requests", "phonenumbers", "dnspython", "urllib3", "charset-normalizer", "idna", "certifi")},
        "excluded_development_modules": list(EXCLUDED_MODULES),
    }
    report_path = executable.parent / f"{executable.stem}-build.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def build():
    if importlib.util.find_spec("PyInstaller") is None:
        raise SystemExit("PyInstaller fehlt. Einmalig: python -m pip install 'pyinstaller>=6,<7'")
    (ROOT / "build").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="osint-build-") as staging:
        # config.json im Arbeitsbaum könnte echte Keys enthalten. Nie einbetten.
        (Path(staging) / "config.json").write_text(
            json.dumps({"api_keys": {}, "site_auth": {}}), encoding="utf-8")
        subprocess.run(build_command(staging), cwd=ROOT, check=True)
    name = "OSINTReconTool"
    executable = ROOT / "dist" / (name + (".exe" if sys.platform == "win32" else ""))
    audit_bundle(executable)
    archive = package_portable(executable)
    print(f"App: {executable}\nPortables Paket: {archive}")
    return executable


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    build()

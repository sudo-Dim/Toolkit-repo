"""Kompakte Tkinter-App mit nativer Ergebnisansicht und Datei-Export."""

import argparse
import json
import os
import subprocess
import sys
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urlsplit

from ..core.config import AppConfig
from ..core.engine import OSINTEngine
from ..core.inputs import clean_input
from ..core.paths import application_directory, desktop_data_directory
from ..core.reporter import Reporter
from .worker import ScanRunner

TYPES = {"Automatisch": None, "Username": "username", "E-Mail": "email",
         "Telefon": "phone", "Domain / IP": "domain", "Name": "name", "Bild": "image"}
LABELS = {"username": "Username", "email": "E-Mail", "phone": "Telefon",
          "domain": "Domain", "ip": "IP-Adresse", "name": "Name", "image": "Bild"}
SEVERITIES = {"found": "Treffer", "warning": "Warnung", "critical": "Kritisch",
              "info": "Info", "not_found": "Kein Treffer"}
FILTERS = {"Alle Ergebnisse": None, "Treffer": {"found"},
           "Warnungen": {"warning", "critical"}, "Info": {"info"},
           "Nicht gefunden": {"not_found"}}


def safe_link(value):
    if not isinstance(value, str) or any(ord(c) <= 32 for c in value):
        return False
    try:
        url = urlsplit(value)
        return (not url.username and not url.password and bool(url.hostname)
                and (url.scheme.lower() in ("http", "https")
                     or (url.scheme.lower() == "viber" and url.hostname == "chat")))
    except ValueError:
        return False


def result_links(result):
    links = []

    def visit(value):
        if safe_link(value) and value not in links:
            links.append(value)
        elif isinstance(value, dict):
            for key, child in value.items():
                if not str(key).startswith("_"):
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(result.get("url"))
    visit(result.get("data", {}))
    return links


class DesktopApp:
    def __init__(self, root, config=None, runner=None):
        self.root = root
        self.config = config or AppConfig()
        self.engine = OSINTEngine(self.config)
        self.runner = runner or ScanRunner()
        self.result = None
        self.rows = []
        self.visible_rows = {}
        self.selected_links = []
        self.poll_id = None
        self.detect_id = None
        self.closed = False

        root.title("OSINT Recon · Desktop")
        root.geometry("960x680")
        root.minsize(800, 580)
        root.configure(background="#f5f7fb")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._style()
        self._layout()
        self.input.trace_add("write", self._schedule_detection)
        root.bind("<Return>", lambda event: self.start_scan() if event.widget == self.entry else None)
        root.bind("<Escape>", lambda event: self.cancel_scan())
        self.entry.focus_set()

    def _style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        font = "Segoe UI" if sys.platform == "win32" else "DejaVu Sans"
        self.font = font
        style.configure(".", font=(font, 10), background="#f5f7fb", foreground="#1e293b")
        style.configure("TButton", padding=(12, 7))
        style.configure("Accent.TButton", background="#2563eb", foreground="white")
        style.map("Accent.TButton", background=[("disabled", "#cbd5e1"), ("active", "#1d4ed8")])
        style.configure("Title.TLabel", font=(font, 20, "bold"))
        style.configure("Muted.TLabel", foreground="#64748b")
        style.configure("Summary.TLabel", font=(font, 11, "bold"))
        style.configure("Treeview", rowheight=29, fieldbackground="white", background="white", borderwidth=0)
        style.configure("Treeview.Heading", font=(font, 9, "bold"), padding=(6, 8))
        style.map("Treeview", background=[("selected", "#dbeafe")], foreground=[("selected", "#1e3a8a")])
        style.configure("TEntry", padding=7)
        style.configure("TCombobox", padding=6)
        style.configure("Horizontal.TProgressbar", background="#2563eb", troughcolor="#e2e8f0", borderwidth=0)

    def _layout(self):
        main = ttk.Frame(self.root, padding=22)
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(5, weight=1)

        header = ttk.Frame(main)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 18))
        ttk.Label(header, text="OSINT Recon", style="Title.TLabel").pack(side="left")
        ttk.Label(header, text="DESKTOP", style="Muted.TLabel").pack(side="left", padx=12, pady=(8, 0))
        ttk.Button(header, text="App-Ordner", command=self.open_app_folder).pack(side="right")
        ttk.Label(main, text="Ein Ziel eingeben. Ergebnisse direkt in der App prüfen.",
                  style="Muted.TLabel").grid(row=1, column=0, sticky="w", pady=(0, 10))

        search = ttk.Frame(main)
        search.grid(row=2, column=0, sticky="ew")
        search.columnconfigure(0, weight=1)
        self.input = tk.StringVar()
        self.entry = ttk.Entry(search, textvariable=self.input)
        self.entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.type = tk.StringVar(value="Automatisch")
        self.type_box = ttk.Combobox(search, textvariable=self.type, values=list(TYPES), state="readonly", width=16)
        self.type_box.grid(row=0, column=1, padx=(0, 8))
        self.type_box.bind("<<ComboboxSelected>>", self._schedule_detection)
        self.start_button = ttk.Button(search, text="Analysieren", style="Accent.TButton", command=self.start_scan)
        self.start_button.grid(row=0, column=2)
        self.browse_button = ttk.Button(search, text="Bild wählen…", command=self.choose_image)
        self.browse_button.grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.detected = tk.StringVar(value="Username, E-Mail, Telefon, Domain, Name oder Bild")
        ttk.Label(search, textvariable=self.detected, style="Muted.TLabel").grid(
            row=1, column=1, columnspan=2, sticky="e", pady=(8, 0))

        progress_row = ttk.Frame(main)
        progress_row.grid(row=3, column=0, sticky="ew", pady=(16, 16))
        progress_row.columnconfigure(0, weight=1)
        self.status = tk.StringVar(value="Bereit für eine Analyse")
        ttk.Label(progress_row, textvariable=self.status, wraplength=720).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(progress_row, mode="determinate", maximum=100)
        self.progress.grid(row=1, column=0, sticky="ew", pady=(8, 0), padx=(0, 12))
        self.cancel_button = ttk.Button(progress_row, text="Abbrechen", state="disabled", command=self.cancel_scan)
        self.cancel_button.grid(row=0, column=1, rowspan=2)

        results_bar = ttk.Frame(main)
        results_bar.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        self.summary = tk.StringVar(value="Ergebnisse")
        ttk.Label(results_bar, textvariable=self.summary, style="Summary.TLabel").pack(side="left")
        self.filter = tk.StringVar(value="Alle Ergebnisse")
        filter_box = ttk.Combobox(results_bar, textvariable=self.filter, values=list(FILTERS), state="readonly", width=18)
        filter_box.pack(side="right")
        filter_box.bind("<<ComboboxSelected>>", lambda event: self.render_rows())

        panes = ttk.Panedwindow(main, orient="horizontal")
        panes.grid(row=5, column=0, sticky="nsew")
        left = ttk.Frame(panes)
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(left, columns=("status", "source", "title"), show="headings", selectmode="browse")
        for column, title, width in (("status", "Status", 95), ("source", "Quelle", 135), ("title", "Ergebnis", 260)):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=65)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scroll.set)
        for severity, color in (("found", "#047857"), ("warning", "#92400e"), ("critical", "#b91c1c"), ("not_found", "#64748b")):
            self.tree.tag_configure(severity, foreground=color)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)
        self.tree.bind("<Double-1>", lambda event: self.open_link())
        panes.add(left, weight=3)

        right = ttk.Frame(panes, padding=(12, 0, 0, 0))
        right.columnconfigure(0, weight=1)
        right.rowconfigure(1, weight=1)
        ttk.Label(right, text="DETAILS", style="Muted.TLabel").grid(row=0, column=0, sticky="w", pady=(0, 8))
        self.details = tk.Text(right, width=32, wrap="word", background="white", foreground="#334155",
                               font=(self.font, 10), relief="flat", padx=12, pady=12, state="disabled")
        self.details.grid(row=1, column=0, sticky="nsew")
        detail_scroll = ttk.Scrollbar(right, orient="vertical", command=self.details.yview)
        detail_scroll.grid(row=1, column=1, sticky="ns")
        self.details.configure(yscrollcommand=detail_scroll.set)
        self.link = tk.StringVar()
        self.link_box = ttk.Combobox(right, textvariable=self.link, state="disabled", width=25)
        self.link_box.grid(row=2, column=0, sticky="ew", pady=(10, 6))
        self.link_button = ttk.Button(right, text="Quelle öffnen ↗", state="disabled", command=self.open_link)
        self.link_button.grid(row=3, column=0, sticky="ew")
        panes.add(right, weight=2)
        self._detail_text("Hier erscheinen die Details zum ausgewählten Ergebnis.")

        footer = ttk.Frame(main)
        footer.grid(row=6, column=0, sticky="ew", pady=(16, 0))
        ttk.Label(footer, text="Ergebnisse bleiben bis zum Export im Arbeitsspeicher.", style="Muted.TLabel").pack(side="left")
        self.export_format = tk.StringVar(value="HTML")
        ttk.Combobox(footer, textvariable=self.export_format, values=["HTML", "JSON", "TXT"],
                     state="readonly", width=7).pack(side="left", padx=(16, 6))
        self.export_button = ttk.Button(footer, text="Speichern…", state="disabled", command=self.export)
        self.export_button.pack(side="right")

    def _schedule_detection(self, *args):
        if self.detect_id is not None:
            self.root.after_cancel(self.detect_id)
        self.detect_id = self.root.after(200, self.detect)

    def detect(self):
        self.detect_id = None
        try:
            value = clean_input(self.input.get())
            detected = TYPES[self.type.get()] or self.engine.detect_input_type(value)
            self.detected.set("Typ: " + LABELS.get(detected, detected))
        except ValueError:
            self.detected.set("Username, E-Mail, Telefon, Domain, Name oder Bild")

    def choose_image(self):
        filename = filedialog.askopenfilename(parent=self.root, title="Bild auswählen",
            filetypes=[("Bilder", "*.jpg *.jpeg *.png *.webp *.gif *.bmp *.tiff"), ("Alle Dateien", "*.*")])
        if filename:
            self.type.set("Bild")
            self.input.set(filename)

    def start_scan(self):
        if self.runner.active:
            return
        try:
            value = clean_input(self.input.get())
            input_type = TYPES[self.type.get()] or self.engine.detect_input_type(value)
            self.runner.start(self.config, value, input_type)
        except Exception as exc:
            self.status.set(f"Analyse nicht gestartet: {exc}")
            return
        self.result = None
        self.rows = []
        self.render_rows()
        self.summary.set("Analyse läuft…")
        self.status.set(f"{LABELS.get(input_type, input_type)} wird analysiert…")
        self.progress["value"] = 0
        self._busy(True)
        self.poll_id = self.root.after(80, self.poll)

    def _busy(self, busy):
        self.start_button.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if busy else "disabled")
        self.entry.configure(state="disabled" if busy else "normal")
        self.type_box.configure(state="disabled" if busy else "readonly")
        self.browse_button.configure(state="disabled" if busy else "normal")
        self.export_button.configure(state="normal" if self.result is not None and not busy else "disabled")

    def poll(self):
        self.poll_id = None
        for kind, payload in self.runner.poll():
            if kind == "progress":
                module, current, total, message = payload
                self.progress["value"] = max(0, min(100, 100 * current / total)) if total else 0
                self.status.set(message or module)
            elif kind == "result":
                self.show_result(payload)
            elif kind == "error":
                self.status.set(f"Analyse fehlgeschlagen: {payload}")
                self.summary.set("Keine vollständigen Ergebnisse")
        if self.runner.active:
            self.poll_id = self.root.after(80, self.poll)
        else:
            self._busy(False)

    def cancel_scan(self):
        if not self.runner.active:
            return
        self.runner.cancel()
        if self.poll_id is not None:
            self.root.after_cancel(self.poll_id)
            self.poll_id = None
        self._busy(False)
        self.status.set("Analyse abgebrochen")
        self.summary.set("Analyse abgebrochen")

    def show_result(self, result):
        self.result = result
        data = result.to_dict()
        summary = data["summary"]
        self.rows = []
        for report in data["modules"]:
            self.rows.extend(report["results"])
            self.rows.extend({"severity": "warning", "source": report["module"], "title": error,
                              "category": "Fehler", "data": {}, "url": None} for error in report["errors"])
        self.summary.set(f"{summary['total_results']} Ergebnisse · {summary['total_found']} Treffer · {summary['total_errors']} Fehler")
        self.status.set(f"Abgeschlossen in {result.duration_seconds:.1f} Sekunden")
        self.progress["value"] = 100
        self.render_rows()

    def render_rows(self):
        self.tree.delete(*self.tree.get_children())
        self.visible_rows.clear()
        allowed = FILTERS[self.filter.get()]
        for index, row in enumerate(self.rows):
            severity = row["severity"]
            if allowed is not None and severity not in allowed:
                continue
            iid = str(index)
            self.visible_rows[iid] = row
            self.tree.insert("", "end", iid=iid, values=(SEVERITIES.get(severity, severity), row["source"], row["title"]), tags=(severity,))
        self.selected_links = []
        self.link.set("")
        self.link_box.configure(values=(), state="disabled")
        self.link_button.configure(state="disabled")
        self._detail_text("Ein Ergebnis auswählen, um Details und Quellen zu sehen.")
        children = self.tree.get_children()
        if children:
            self.tree.selection_set(children[0])
            self.show_details()

    def _detail_text(self, text):
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")

    def show_details(self, event=None):
        selection = self.tree.selection()
        if not selection or selection[0] not in self.visible_rows:
            return
        row = self.visible_rows[selection[0]]
        data = {key: value for key, value in row.get("data", {}).items() if not key.startswith("_")}
        detail = f"{row['title']}\n\n{row['source']} · {row.get('category', '')}"
        if data:
            detail += "\n\n" + json.dumps(data, ensure_ascii=False, indent=2)
        self._detail_text(detail)
        self.selected_links = result_links(row)
        self.link_box.configure(values=self.selected_links, state="readonly" if self.selected_links else "disabled")
        self.link.set(self.selected_links[0] if self.selected_links else "")
        self.link_button.configure(state="normal" if self.selected_links else "disabled")

    def open_link(self):
        value = self.link.get()
        if value in self.selected_links and safe_link(value):
            webbrowser.open(value)

    def export(self):
        if self.result is None:
            return
        try:
            fmt = self.export_format.get().lower()
            reporter = Reporter(str(desktop_data_directory() / "results"))
            filename = filedialog.asksaveasfilename(parent=self.root, title="Ergebnisse speichern",
                initialdir=reporter.output_dir, initialfile=f"osint_report.{fmt}",
                defaultextension=f".{fmt}", filetypes=[(fmt.upper(), f"*.{fmt}")])
            if filename:
                getattr(reporter, f"export_{fmt}")(self.result, filename)
                self.status.set(f"Gespeichert: {filename}")
        except OSError as exc:
            messagebox.showerror("Export fehlgeschlagen", str(exc), parent=self.root)

    def open_app_folder(self):
        path = str(application_directory())
        try:
            if sys.platform == "win32":
                os.startfile(path)
            else:
                subprocess.Popen(["open" if sys.platform == "darwin" else "xdg-open", path])
        except OSError as exc:
            messagebox.showerror("Ordner nicht geöffnet", str(exc), parent=self.root)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.poll_id is not None:
            self.root.after_cancel(self.poll_id)
        if self.detect_id is not None:
            self.root.after_cancel(self.detect_id)
        self.runner.cancel()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="OSINT Recon Desktop")
    parser.add_argument("--smoke-test", metavar="REPORT", help=argparse.SUPPRESS)
    args = parser.parse_args()
    root = tk.Tk()
    app = DesktopApp(root)
    if args.smoke_test:
        # Offline-Prüfung für den tatsächlichen Build, inklusive Spawn und Tk.
        from .smoke import run_smoke_test
        run_smoke_test(app, Path(args.smoke_test))
    root.mainloop()

"""Scans in einem separaten Prozess: GUI bleibt bedienbar und Abbruch ist echt."""

import multiprocessing
import queue

from ..core.engine import OSINTEngine


def scan_worker(events, config, value, input_type):
    try:
        engine = OSINTEngine(config)
        engine.set_progress_callback(lambda module, current, total, message: events.put(
            ("progress", (module, current, total, message))))
        events.put(("result", engine.scan(value, input_type)))
    except Exception as exc:
        events.put(("error", str(exc)))


class ScanRunner:
    def __init__(self):
        self.context = multiprocessing.get_context("spawn")
        self.process = None
        self.events = None
        self.finished = False

    @property
    def active(self):
        return self.process is not None

    def start(self, config, value, input_type):
        if self.active:
            raise RuntimeError("Ein Scan läuft bereits")
        self.finished = False
        self.events = self.context.Queue()
        self.process = self.context.Process(
            target=scan_worker, args=(self.events, config, value, input_type), daemon=True)
        try:
            self.process.start()
        except Exception:
            self.process = None
            self.events.close()
            self.events = None
            raise

    def poll(self):
        if not self.active:
            return []
        messages = []
        while True:
            try:
                message = self.events.get_nowait()
                messages.append(message)
                if message[0] in ("result", "error"):
                    self.finished = True
            except queue.Empty:
                break
        if not self.process.is_alive():
            # Nach Prozessende ist der Queue-Feeder vollständig geleert.
            while True:
                try:
                    message = self.events.get_nowait()
                    messages.append(message)
                    self.finished |= message[0] in ("result", "error")
                except queue.Empty:
                    break
            if not self.finished:
                messages.append(("error", f"Scan-Prozess unerwartet beendet (Code {self.process.exitcode})"))
            self._release()
        return messages

    def cancel(self):
        if not self.active:
            return
        if self.process.is_alive():
            self.process.terminate()
            self.process.join(timeout=1)
            if self.process.is_alive():
                self.process.kill()
                self.process.join(timeout=1)
        self._release()

    def _release(self):
        self.process.join(timeout=0.2)
        self.process.close()
        self.events.close()
        self.process = None
        self.events = None

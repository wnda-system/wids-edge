import threading
import subprocess
import time

class ChannelHopper:
    def __init__(self, interface, channels, interval, logger):
        self.interface = interface
        self.channels = channels
        self.interval = interval
        self.logger = logger
        self.stop_event = threading.Event()

    def set_channel(self, ch):
        subprocess.run(
            ["iw", "dev", self.interface, "set", "channel", str(ch)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    def start(self):
        t = threading.Thread(target=self.run)
        t.daemon = True
        t.start()

    def run(self):
        while not self.stop_event.is_set():
            for ch in self.channels:
                if self.stop_event.is_set():
                    break
                self.set_channel(ch)
                time.sleep(self.interval)

    def stop(self):
        self.stop_event.set()

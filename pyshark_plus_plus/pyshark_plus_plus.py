import os
import subprocess
import threading
import time
from .statistics import parse_io_statistics


class TsharkWrapper:

    def __init__(
            self,
            file_path: str = None,
            interface: str = '1',
            capture_filter: str = None,
            tshark_path: str = "C:/Program Files/Wireshark/tshark.exe",
    ):

        # if file_path and not os.path.exists(file_path):
        #     raise Exception(f"Path {file_path} does not exist")

        self.file_path = file_path
        self.interface = interface
        self.capture_filter = capture_filter
        self.tshark_path = tshark_path

        self._event = threading.Event()
        self._process_capture = None

        self._thread: threading.Thread

    def start_thread(self):

        self._event.clear()
        self._thread = threading.Thread(target=self.start_capture)
        self._thread.start()
        time.sleep(0.1)

        if self._thread.is_alive():
            print("Sniffer thread is running")

        else:
            print(" -- Error running sniffer thread")

    def stop_thread(self):

        if not self._event.is_set():

            time.sleep(1)
            self._process_capture.terminate()
            self._process_capture.wait()
            self._event.set()

        else:

            raise Exception("Capture is not running or has already stopped")

    def __enter__(self):

        self.start_thread()
        time.sleep(0.1)
        return self

    def __exit__(self, *args):

        self.stop_thread()

    def list_interfaces(self):

        cmd = [self.tshark_path, '-D']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error listing interfaces: {result.stderr}")

        return result.stdout

    def start_capture(self, duration=None):

        cmd = [self.tshark_path, '-i', self.interface, "-p", "-q"]

        if self.file_path:
            cmd.extend(['-w', self.file_path])

        if self.capture_filter:
            cmd.extend(['-f', self.capture_filter])

        if duration:
            cmd.extend(['-a', f'duration:{duration}'])

        self._process_capture = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._process_capture.communicate()

        # if self._process_capture.returncode != 0:
        #     raise Exception(f"Error during capture: {self._process_capture.stderr}")

        return self._process_capture.returncode

    def read_pcap(self, pcap_file):

        cmd = [self.tshark_path, '-r', pcap_file]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error reading pcap file: {result.stderr}")

        return result.stdout

    def apply_filter(self, pcap_file, display_filter):

        cmd = [self.tshark_path, '-r', pcap_file, '-Y', display_filter]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error applying display filter: {result.stderr}")

        return result.stdout

    def get_statistics(self, file_path: str = None):

        file_path = file_path or self.file_path

        cmd = [self.tshark_path, '-r', file_path, '-q', '-z', 'io,stat,0']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print(result.stdout)

        # if result.returncode != 0:
        #     raise Exception(f"Error getting packet count: {result.stderr}")

        return parse_io_statistics(result.stdout)

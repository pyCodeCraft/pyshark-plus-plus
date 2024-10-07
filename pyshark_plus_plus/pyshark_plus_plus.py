"""
Tshark Wrapper Module

This module provides a `TsharkWrapper` class that acts as an interface to interact with `tshark`,
a command-line tool for capturing and analyzing network traffic. The module allows users to
easily manage network capture sessions, list network interfaces, apply filters to capture files,
and extract statistics from the captured data.

Key Features:
- Start and stop network captures using multiple interfaces (by number, name, or description).
- Read and filter `.pcap` files for network analysis.
- Retrieve network traffic statistics (via `tshark`).
- Context manager support for easy capture handling.

Dependencies:
- tshark (Wireshark command-line tool)
- Python built-in libraries: subprocess, threading, re, time

Type Aliases:
- `InterfaceNumberType`: Union of string, integer, list of strings, or list of integers for specifying interface numbers.
- `InterfaceNameType`: Union of string or list of strings for specifying interface names.
- `InterfaceDescriptionType`: Union of string or list of strings for specifying interface descriptions.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from typing import Dict, List, Union

from .statistics import parse_io_statistics

# Define type aliases for interface numbers, names, and descriptions
InterfaceNumberType = Union[str, int, List[str], List[int]]
InterfaceNameType = Union[str, List[str]]
InterfaceDescriptionType = Union[str, List[str]]


class TsharkWrapper:
    """
    A wrapper class for interacting with tshark, a command-line tool
    for capturing and analyzing network traffic.
    """

    def __init__(
            self,
            file_path: str = None,
            interface_number: InterfaceNumberType = None,
            interface_name: InterfaceNameType = None,
            interface_description: InterfaceDescriptionType = None,
            capture_filter: str = None,
            tshark_path: str = "C:/Program Files/Wireshark/tshark.exe",
    ):
        """
        Initialize the TsharkWrapper instance.

        :param file_path: The path to the file to capture traffic from. Defaults to None.
        :param interface_number: The interface number(s) to capture traffic from. Defaults to None.
        :param interface_name: The interface name(s) to capture traffic from. Defaults to None.
        :param interface_description: The interface description(s) to capture traffic from. Defaults to None.
        :param capture_filter: The capture filter to apply. Defaults to None.
        :param tshark_path: The path to the tshark executable. Defaults to "C:/Program Files/Wireshark/tshark.exe".
        """

        # if file_path and not os.path.exists(file_path):
        #     raise Exception(f"Path {file_path} does not exist")

        self.file_path = file_path
        self.capture_filter = capture_filter
        self.tshark_path = tshark_path

        self._event = threading.Event()
        self._process_capture = None

        self._thread = threading.Thread(target=self.start_capture)

        self.interface_number = self._get_interface_number(interface_number, interface_name, interface_description)

    def _get_interface_number(
            self,
            interface_number: InterfaceNumberType,
            interface_name: InterfaceNameType,
            interface_description: InterfaceDescriptionType,
    ) -> List[str]:
        """
        Get interface numbers based on the provided interface information.

        :param interface_number: The interface number(s) to capture traffic from.
        :param interface_name: The interface name(s) to capture traffic from.
        :param interface_description: The interface description(s) to capture traffic from.

        :returns interfaces: A list of interface numbers as strings.
        """

        interfaces = []

        if interface_number is not None:
            if isinstance(interface_number, list):
                interfaces.extend(str(i) for i in interface_number)
            else:
                interfaces.append(str(interface_number))

        if interface_name is not None:
            if isinstance(interface_name, list):
                interfaces.extend(self.get_interface_number_by_name(name) for name in interface_name)
            else:
                interfaces.append(self.get_interface_number_by_name(interface_name))

        if interface_description is not None:
            if isinstance(interface_description, list):
                interfaces.extend(self.get_interface_number_by_description(description) for description in interface_description)
            else:
                interfaces.append(self.get_interface_number_by_description(interface_description))

        return interfaces

    def start_thread(self):
        """
        Start the capture thread.
        """

        self._event.clear()
        self._thread.start()
        time.sleep(0.1)

        if self._thread.is_alive():
            print("Sniffer thread is running")

        else:
            print(" -- Error running sniffer thread")

    def stop_thread(self):
        """
        Stops the capture thread.
        """

        if not self._event.is_set():

            time.sleep(1)
            self._process_capture.terminate()
            self._process_capture.wait()
            self._event.set()

        else:

            raise Exception("Capture is not running or has already stopped")

    def __enter__(self):
        """
        Context manager protocol start.
        Automatically starts the capture thread when entering a 'with' block.
        """

        self.start_thread()
        time.sleep(0.1)
        return self

    def __exit__(self, *args):
        """
        Context manager protocol end.
        Automatically stops the capture thread when exiting a 'with' block.
        """

        self.stop_thread()

    def list_interfaces(self):
        """
        List available interfaces for capturing traffic.

        :return: A string representing the available interfaces listed by tshark.
        :raises Exception: If there is an error listing the interfaces.
        """

        cmd = [self.tshark_path, '-D']
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error listing interfaces: {result.stderr}")

        return result.stdout

    def get_interfaces_data(self) -> List[Dict[str, int | str]]:
        """
        Get detailed information about available interfaces.

        :return: A list of dictionaries containing interface number, name, and description.
        """

        stdout = self.list_interfaces()

        interfaces = []
        for line in stdout.splitlines():
            match = re.search(r'(\d+)\. (.*) \((.*)\)', line)
            if match:
                interface_number = match.group(1)
                interface_name = match.group(2)
                interface_description = match.group(3)
                interfaces.append(
                    {
                        "number": interface_number,
                        "name": interface_name,
                        "description": interface_description,
                    },
                )

        return interfaces

    def _get_interface_number_by_field(self, field_name: str, field_value: str = None) -> int:
        """
        Retrieve the interface number based on a given field (e.g., name or description).

        :param field_name: The field name to search for (e.g., "name" or "description").
        :param field_value: The value to match in the given field.
        :return: The matching interface number as an integer.
        :raises Exception: If no interface matches the given field value.
        """

        interfaces = self.get_interfaces_data()

        for interface in interfaces:
            if interface[field_name] == field_value:
                return interface["number"]

        raise Exception(f"Field {field_name} with value {field_value} not found")

    def get_interface_number_by_name(self, interface_name: str) -> int:
        """
        Get the interface number by its name.

        :param interface_name: The name of the interface.
        :return: The interface number as an integer.
        """

        return self._get_interface_number_by_field("name", interface_name)

    def get_interface_number_by_description(self, interface_description: str) -> int:
        """
        Get the interface number by its description.

        :param interface_description: The description of the interface.
        :return: The interface number as an integer.
        """

        return self._get_interface_number_by_field("description", interface_description)

    def start_capture(self, duration: int = None):
        """
        Start capturing traffic using tshark.

        :param duration: Optional. The duration to capture traffic in seconds. If None, it captures indefinitely.
        :return: The return code of the tshark process.
        :raises Exception: If an error occurs during capture.
        """

        cmd = [self.tshark_path, "-p", "-q"]

        # if self.interface == "any" and platform.system() == "Windows":
        #     stdout = self.list_interfaces()
        #     for i, line in enumerate(stdout.splitlines()):
        #         if "\\Device\\NPF_" in line:
        #             cmd.extend(["-i", str(i+1)])
        #
        # else:
        #     cmd.extend(["-i", str(self.interface)])

        cmd.extend(["-i"])
        cmd.extend(str(i) for i in self.interface_number)

        if self.file_path:
            cmd.extend(["-w", self.file_path])

        if self.capture_filter:
            cmd.extend(["-f", self.capture_filter])

        if duration:
            cmd.extend(["-a", f'duration:{duration}'])

        self._process_capture = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self._process_capture.communicate()

        # if self._process_capture.returncode != 0:
        #     raise Exception(f"Error during capture: {self._process_capture.stderr}")

        return self._process_capture.returncode

    def read_pcap(self, pcap_file: str):
        """
        Read and process a pcap file.

        :param pcap_file: The path to the pcap file.
        :return: The output of reading the pcap file.
        :raises Exception: If an error occurs while reading the pcap file.
        """

        cmd = [self.tshark_path, "-r", pcap_file]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error reading pcap file: {result.stderr}")

        return result.stdout

    def apply_filter(self, pcap_file: str, display_filter: str):
        """
        Apply a display filter to a pcap file.

        :param pcap_file: The path to the pcap file.
        :param display_filter: The display filter to apply.
        :return: The filtered output of the pcap file.
        :raises Exception: If an error occurs while applying the filter.
        """

        cmd = [self.tshark_path, "-r", pcap_file, "-Y", display_filter]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        if result.returncode != 0:
            raise Exception(f"Error applying display filter: {result.stderr}")

        return result.stdout

    def get_statistics(self, file_path: str = None):
        """
        Retrieve traffic statistics from a capture file.

        :param file_path: Optional. The path to the file. Defaults to the instance's file_path if not provided.
        :return: A dictionary containing parsed IO statistics.
        :raises Exception: If an error occurs while retrieving
        """

        file_path = file_path or self.file_path

        cmd = [self.tshark_path, "-r", file_path, "-q", "-z", "io,stat,0"]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        print(result.stdout)

        # if result.returncode != 0:
        #     raise Exception(f"Error getting packet count: {result.stderr}")

        return parse_io_statistics(result.stdout)

# Pyshark Plus Plus

`pyshark-plus-plus` is a Python library that provides a convenient interface for interacting with `tshark`, a command-line tool for capturing and analyzing network traffic. It enhances the capabilities of `tshark` by offering additional utilities, exception handling, and simplified methods for capturing network packets, listing interfaces, and analyzing `.pcap` files.

## Features

- **Capture Network Traffic**: Start and stop network packet captures with ease.
- **Interface Listing**: List available network interfaces by number, name, or description.
- **PCAP Processing**: Read, filter, and analyze `.pcap` files for network traffic data.
- **Statistics Extraction**: Retrieve detailed traffic statistics from captured files.
- **Context Manager Support**: Easily manage network capture sessions using Python's `with` statement.

## Installation

1. From pip:
    ```bash
    pip install pyshark-plus-plus
    ```

2. From gGitHub repository:
    ```bash
    git clone https://github.com/your-username/pyshark-plus-plus.git
    cd pyshark-plus-plus
    ```

3. Ensure `tshark` is installed on your system. You can download it from [Wireshark's website](https://www.wireshark.org/).

## Getting Started

### Basic Usage Example

```python
from pyshark_plus_plus import TsharkWrapper

# Start a network capture on a specific interface
with TsharkWrapper(interface_number=1) as sniffer:
    print("Capturing traffic...")
    sniffer.start_capture(duration=10)  # Capture traffic for 10 seconds
```

### Listing Available Interfaces

You can list the available interfaces using the following example:

```python
from pyshark_plus_plus import TsharkWrapper

sniffer = TsharkWrapper()
print(sniffer.list_interfaces())
```

For more examples, check out the `examples` directory.

## Project Structure

```bash
pyshark-plus-plus/
│
├── examples/
│   ├── __init__.py
│   ├── list_available_interfaces.py       # Example script for listing interfaces
│   └── sniff_from_localhost.py            # Example script for capturing packets from localhost
│
├── pyshark_plus_plus/
│   ├── __init__.py
│   ├── exceptions.py                      # Custom exceptions for the library
│   ├── pyshark_plus_plus.py               # Main wrapper class for interacting with tshark
│   └── statistics.py                      # Functions for processing capture statistics
│
├── tests/                                 # Unit tests for the library
│
├── venv/                                  # Virtual environment (optional)
│
├── LICENSE.txt                            # License information
├── CHANGELOG.md                           # Change history of the project
├── pyproject.toml                         # Configuration for building and packaging
├── README.md                              # Project documentation (this file)
└── tox.ini                                # Tox configuration for testing
```

## Testing

Unit tests are available in the `tests` directory.

## Contributing

We welcome contributions! Please follow these steps:

* Fork the repository.
* Create a new branch for your feature or bug fix.
* Write tests for your changes.
* Submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE.txt file for details.

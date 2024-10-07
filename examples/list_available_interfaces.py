import re

from pyshark_plus_plus import TsharkWrapper  # Replace with your actual module name


# Create an instance of the TsharkWrapper
wrapper = TsharkWrapper()

# List available interfaces
stdout = wrapper.list_interfaces()

print("Available Interfaces:")
print(stdout)

import re

interfaces = []
for line in stdout.splitlines():
    match = re.search(r'(\d+)\. (.*) \((.*)\)', line)
    if match:
        interface_number = match.group(1)
        interface_name = match.group(2)
        interface_description = match.group(3)
        interfaces.append((interface_number, interface_name, interface_description))
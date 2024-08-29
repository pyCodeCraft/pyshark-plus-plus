from pyshark_plus_plus import TsharkWrapper  # Replace with your actual module name


# Create an instance of the TsharkWrapper
wrapper = TsharkWrapper()

# List available interfaces
interfaces = wrapper.list_interfaces()

print("Available Interfaces:")
print(interfaces)

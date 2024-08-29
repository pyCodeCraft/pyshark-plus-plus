import time
import threading
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.client import ModbusTcpClient
from pymodbus.datastore import ModbusSequentialDataBlock
from pyshark_plus_plus import TsharkWrapper  # Replace with your actual module name

# Function to run a Modbus server
def run_modbus_server():
    # Initialize the datastore (with some test data)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0]*100),
        co=ModbusSequentialDataBlock(0, [1]*100),
        hr=ModbusSequentialDataBlock(0, [2]*100),
        ir=ModbusSequentialDataBlock(0, [3]*100)
    )
    context = ModbusServerContext(slaves=store, single=True)

    # Server identification
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'Pymodbus'
    identity.ProductCode = 'PM'
    identity.VendorUrl = 'http://github.com/riptideio/pymodbus/'
    identity.ProductName = 'Pymodbus Server'
    identity.ModelName = 'Pymodbus Server'
    identity.MajorMinorRevision = '1.0'

    # Start the server on localhost, port 5020
    print("Starting Modbus server on localhost:502...")
    StartTcpServer(context=context, identity=identity, address=("127.0.0.1", 502))

# Function to send Modbus requests to the server
def send_modbus_requests():
    client = ModbusTcpClient('127.0.0.1', port=502)

    if client.connect():
        print("Connected to Modbus server.")

        # Send some Modbus requests
        response = client.read_coils(0, 10)
        print(f"Read Coils Response: {response}")

        response = client.read_holding_registers(0, 10)
        print(f"Read Holding Registers Response: {response}")

        client.close()
    else:
        print("Failed to connect to Modbus server.")


def main():

    # Start Modbus server in a separate thread
    server_thread = threading.Thread(target=run_modbus_server)
    server_thread.daemon = True
    server_thread.start()

    # Allow some time for the server to start
    time.sleep(2)

    # Set up the TsharkWrapper with the appropriate interface and filter
    wrapper = TsharkWrapper(
        file_path="capture_localhost_modbus.pcap",
        interface="8",  # Assuming '1' corresponds to the localhost interface (use list_interfaces() to verify)
        # capture_filter="tcp port 502"  # Capture only Modbus TCP traffic
    )
    wrapper.list_interfaces()

    # Start capturing packets
    with wrapper as sniffer:
        print("Capturing packets on localhost interface...")

        # Send Modbus requests while capturing
        send_modbus_requests()

        # Capture for a few more seconds to ensure all packets are captured
        time.sleep(5)

    # After the capture ends, retrieve and print statistics
    stats = sniffer.get_statistics()
    print(f"Capture statistics: {stats}")

    # Read the captured packets from the pcap file
    packet_data = sniffer.read_pcap("capture_localhost_modbus.pcap")
    print(f"Captured Packet Data:\n{packet_data}")

if __name__ == "__main__":
    main()

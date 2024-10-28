import os
import time
from typing import Union

import serial
from serial.tools import list_ports
import argparse
import sys
from intelhex import IntelHex


class Flasher:
    def __init__(self, port='/dev/ttyUSB0', baud=115200):
        self.ser = serial.Serial(
            port=port,
            baudrate=baud,
            parity=serial.PARITY_EVEN,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )

    def start_connection(self, timeout=1):
        self.ser.write(bytes([0x7F]))
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                incoming = self.ser.read(1)
                if incoming == bytes([0x79]) or incoming == bytes([0x1F]):
                    return True
        return False

    def read_bytes(self, timeout=1):
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                return self.ser.read(self.ser.in_waiting)
        return -1

    def write_bytes(self, payload):
        self.ser.write(payload)

    def get_command(self, timeout=1):
        self.write_bytes(bytes([0x00, 0xFF]))
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                return self.ser.read(self.ser.in_waiting)[1:-1]
        return -1

    def get_id_command(self, timeout=1):
        self.write_bytes(bytes([0x02, 0xFD]))
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.ser.in_waiting > 0:
                return self.ser.read(self.ser.in_waiting)[1:-1]
        return -1

    def read_command(self, address: int, number_of_bytes: int) -> Union[bytearray, int]:
        """
        Implements a serial read command protocol.

        Args:
            address: The starting address to read from
            number_of_bytes: Number of bytes to read (1-256)
            ser: Initialized serial port object

        Returns:
            bytearray of received bytes if successful, -1 if failed
        """
        # Constants
        ACK = 0x79
        NACK = 0x1F

        # Step 1: Send command code and checksum
        self.ser.write(bytes([0x11, 0xEE]))

        # Wait for ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == NACK:
            return -1

        # Step 2: Send address (MSB first)
        # Convert address to 4 bytes
        address_bytes = [
            (address >> 24) & 0xFF,
            (address >> 16) & 0xFF,
            (address >> 8) & 0xFF,
            address & 0xFF
        ]

        # Send address bytes
        self.ser.write(bytes(address_bytes))

        # Calculate and send XOR of address bytes
        xor = 0
        for byte in address_bytes:
            xor ^= byte
        self.ser.write(bytes([xor]))

        # Wait for ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == NACK:
            return -1

        # Step 3: Send number of bytes to read (N-1)
        n_minus_1 = (number_of_bytes - 1) & 0xFF
        self.ser.write(bytes([n_minus_1]))

        # Send two's complement of N-1 as checksum
        # Two's complement = (inverse all bits) + 1
        checksum = ((~n_minus_1) & 0xFF)
        self.ser.write(bytes([checksum & 0xFF]))

        # Wait for final ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == NACK:
            return -1

        # Step 4: Read N+1 bytes
        received_data = self.ser.read(number_of_bytes)
        if len(received_data) != number_of_bytes:
            return -1

        return bytearray(received_data)

    def go_command(self, start_address: int):
        """
        Send Go command (Execute program starting at address) with starting address start_address.

        :param start_address: address to point PC to.
        :return: -1 if failed, 1 if succeded
        """

        # Send Command code and checksum:
        self.ser.write(bytes([0x21, 0xDE]))

        # Wait for ACK or NACK:
        response = self.ser.read(1)
        if not response or response[0] == 0x1F:
            return -1

        # Send start address (4 bytes, MSB first):
        address_bytes = [
            (start_address >> 24) & 0xFF,
            (start_address >> 16) & 0xFF,
            (start_address >> 8) & 0xFF,
            start_address & 0xFF
        ]
        self.ser.write(bytes(address_bytes))

        # Calculate and send XOR of address bytes
        xor = 0
        for byte in address_bytes:
            xor ^= byte
        self.ser.write(bytes([xor]))

        # Wait for ACK or NACK
        response = self.ser.read(1)
        if not response or response[0] == 0x1F:
            return -1

        return 1

    def write_command(self, start_address: int, number_of_bytes: int, payload: bytearray):
        """
        Args:
            start_address: The starting address to write to
            number_of_bytes: Number of bytes to write (1-256)
            payload (bytearray): Bytes to write

        Returns:
            1 if successful, -1 if failed
        """
        # Constants
        ACK = 0x79
        NACK = 0x1F

        if number_of_bytes > 256:
            return -1

        # Step 1: Send command code and checksum
        self.ser.write(bytes([0x31, 0xCE]))

        # Wait for ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == NACK:
            return -1

        # Step 2: Send address (MSB first)
        # Convert address to 4 bytes
        address_bytes = [
            (start_address >> 24) & 0xFF,
            (start_address >> 16) & 0xFF,
            (start_address >> 8) & 0xFF,
            start_address & 0xFF
        ]

        # Send address bytes
        self.ser.write(bytes(address_bytes))

        time.sleep(0.001)

        # Calculate and send XOR of address bytes
        xor = 0
        for byte in address_bytes:
            xor ^= byte
        self.ser.write(bytes([xor]))

        # Wait for ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == NACK:
            return -1

        # Step 3: Send number of bytes to write (N-1)
        # Begin to calculate checksum to send after N bytes
        n_minus_1 = (number_of_bytes - 1) & 0xFF
        checksum = 0 ^ n_minus_1
        self.ser.write(bytes([n_minus_1]))

        # Step 4: Send N data bytes:
        for byte in payload:
            self.ser.write(bytes([byte]))
            checksum ^= byte

        self.ser.write(bytes([checksum & 0xFF]))

        # Wait for final ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == NACK:
            return -1

        return 1

    def sector_erase_command(self, number_of_sectors: int, which_sectors: list):
        """
        Erase sectors of Flash Memory

        :param number_of_sectors: How many sectors to erase
        :param which_sectors: List of sectors to erase
        :return: 1 if successful, -1 if failed
        """

        # Send erase command code and checksum:
        self.ser.write(bytes([0x44, 0xBB]))

        # Wait for ACK/NACK
        response = self.ser.read(1)
        if not response or response[0] == 0x1F:
            return -1

        # Send sector erase code
        self.ser.write(bytes([0x20]))

        # Send number of sectors to be erased:
        self.ser.write(bytes([0x00, (number_of_sectors & 0xFF)]))

        # Create checksum array to be send at the end:
        checksum = bytearray([])

        # Send sectors numbers to be erased coded on 2 bytes (MSB first)
        for sector in which_sectors:
            self.ser.write(bytes([(sector >> 8) & 0xFF, sector & 0xFF]))
            xor = number_of_sectors ^ sector
            checksum.append((xor >> 8) & 0xFF)
            checksum.append(xor & 0xFF)

        # Wait for ACK/NACK:
        response = self.ser.read(1)
        if not response or response[0] == 0x1F:
            return -1
        return 1

    def flash_hex(self, filepath):
        # Load hex file
        print(f"Loading hex file: {filepath}")
        ih = IntelHex()
        ih.fromfile(fobj=filepath, format="hex")

        start_address = ih.minaddr()
        end_address = ih.maxaddr()
        print(f"Start address: {hex(start_address)}")
        print(f"End address: {hex(end_address)}")

        # First phase: Write all data
        print("Writing flash...")
        for address in range(start_address, end_address + 1, 128):
            bin_array = ih.tobinarray(start=address, size=128)
            result = self.write_command(address, 128, bin_array)
            if result == -1:
                print("Failed writing address: {}".format(hex(address)) + "Retrying...")
                result = self.write_command(start_address, 128, bin_array)
                if result == -1:
                    return -1
            print("flashing address: ", hex(address))

        # Give some time...
        time.sleep(0.05)

        # Second phase: Verify all data
        print("\nVerifying flash...")
        for address in range(start_address, end_address + 1, 128):
            bin_array = ih.tobinarray(start=address, size=128)
            read_result = self.read_command(address, 128)
            if read_result == -1:
                print("Failed reading address: {}".format(hex(address)) + " for verification!")
                return -1

            if bytes(bin_array) != read_result:
                print("Verification failed at address: {}".format(hex(address)))
                print("Expected:", ' '.join(f'{x:02x}' for x in bin_array))
                print("Read:", ' '.join(f'{x:02x}' for x in read_result))
                return -1
            print("verified address: ", hex(address))

        self.go_command(start_address)


# Common USB-UART bridge identifiers for known chips
known_chips = ["FTDI", "CH340", "CP210", "PL2303"]


def scan_serial_ports():
    ports = list_ports.comports()
    for port in ports:
        # Check if the port description matches known USB-UART bridges
        if any(chip in port.description for chip in known_chips):
            print(f"Found matching port: {port.device} - {port.description}")
            return port.device
    print("No matching USB-UART bridge found.")
    return None


def main():
    parser = argparse.ArgumentParser(description='Flash PY32 microcontroller via UART bootloader')
    parser.add_argument('-p', '--port',
                        default='/dev/ttyUSB0',
                        help='Serial port (default: /dev/ttyUSB0)')
    parser.add_argument('-b', '--baudrate',
                        type=int,
                        default=115200,
                        help='Baudrate (default: 115200)')
    parser.add_argument('-r', '--retries',
                        type=int,
                        default=3,
                        help='Number of times to try to establish connection with microcontroller (default: 3)')
    parser.add_argument('-f', '--file',
                        required=True,
                        help='Path to hex file')
    parser.add_argument('-s', '--scan',
                        action='store_true',
                        default=False,
                        help='Scan for serial ports')

    args = parser.parse_args()
    if args.scan:
        py_port = scan_serial_ports()
        if py_port is not None:
            py32 = Flasher(py_port, baud=args.baudrate)
            print(f"Opening serial port {py_port} with baud rate {args.baudrate}")
        else:
            print("Using default serial port with baud rate {}".format(args.baudrate))
            py32 = Flasher(port=args.port, baud=args.baudrate)
    retries = args.retries
    while True:
        if retries > 0:
            connected = py32.start_connection()
            if connected:
                print("Connection established with microcontroller")
                break
            else:
                time.sleep(0.1)
                print("Failed to establish connection... retrying")
                retries -= 1
        else:
            print("Failed to connect to microcontroller")
            return
        time.sleep(0.1)
    time.sleep(0.1)
    # get_response = py32.get_command()
    # print(" ".join(f"{byte:02x}" for byte in get_response))
    # read_uid = py32.read_command(0x1FFF_0E80, 20)
    # print(" ".join(f"{byte:02x}" for byte in read_uid))
    # py32.sector_erase_command(10, list(range(0, 11)))
    py32.flash_hex(os.path.realpath(args.file))



if __name__ == '__main__':
    main()
    sys.exit(0)
# PY32 Flasher
A Python-based UART bootloader tool for flashing PY32 microcontrollers. This tool provides a simple command-line 
interface to flash hex files onto PY32 microcontrollers using the UART bootloader protocol.
## Features
- Automatic serial port detection for common USB-UART bridges (FTDI, CH340, CP210, PL2303)
- Configurable baud rate and connection retry attempts 
- Hex file verification after flashing 
- Support for sector erasing and program execution 
- Progress monitoring during flashing and verification
## Prerequisites
- Python 3.x 
- PySerial 
- IntelHex 
Install the required packages using pip: 
```bash 

pip install pyserial intelhex 

```

## Usage
Basic usage: 
```bash

python py32_uploader.py -f firmware.hex 

```

### Command Line Options
- `-p, --port`: Specify serial port (default: /dev/ttyUSB0) 
- `-b, --baudrate`: Set baud rate (default: 115200) 
- `-r, --retries`: Number of connection retry attempts (default: 3) 
- `-f, --file`: Path to the hex file (required) 
- `-s, --scan`: Scan for available serial ports

### Examples:
Flash with custom port and baud rate: 
```bash 

python py32_uploader.py -p /dev/ttyUSB0 -b 115200 -f firmware.hex 

``` 
Auto-scan for serial port:
 
```bash 

python py32_uploader.py -s -f firmware.hex 

```

## Protocol Implementation
The tool implements the following bootloader commands: 
- Start connection (0x7F) 
- Get command (0x00) 
- Get ID command (0x02) 
- Read memory (0x11) 
- Go/Execute (0x21) 
- Write memory (0x31) 
- Sector erase (0x44)

## Limitations 
- Doesn't use the DTR and RTS lines for reset and boot mode. 

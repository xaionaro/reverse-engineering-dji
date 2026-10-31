# DJI DUML (DJI Unified Message Language) Comprehensive Reference

This document provides a detailed mapping of DJI DUML (v4) protocol as implemented in `djictl` and researched in the `o-gs/dji-firmware-tools` community.

## Protocol Structure (DUML v4)

Packets have an 11-byte header, payload, and 2-byte CRC16.

| Offset | Length | Name | Description |
|--------|--------|------|-------------|
| 0 | 1 | Magic | `0x55` |
| 1 | 1 | Length | Total packet length |
| 2 | 1 | Version/CRC | v4 uses `0x04` |
| 3 | 1 | CRC8 | Header checksum (Poly 0x31, Init 0xEE) |
| 4 | 1 | Source | Sender Component ID |
| 5 | 1 | Destination | Receiver Component ID |
| 6 | 2 | Sequence | Big Endian packet index |
| 8 | 1 | Flags | Bitfield (Request/Response, Encryption) |
| 9 | 1 | Cmd Set | Functional group |
| 10 | 1 | Cmd ID | Specific command |
| 11 | N | Payload | Data |
| 11+N | 2 | CRC16 | Full packet checksum (Poly 0x1021, Init 0x496C) |

## Component IDs (Addressing)

| ID | Name | Description |
|----|------|-------------|
| 0x01 | Camera | Primary imaging unit |
| 0x02 | App | Mobile app (MIMO, DJI Fly) |
| 0x03 | Gimbal | Stabilization and orientation |
| 0x04 | Flight Controller | Aircraft telemetry and control |
| 0x05 | WiFi (Air) | Air-side wireless module |
| 0x06 | Remote Controller | Physical RC-N1 or Smart Controller |
| 0x07 | WiFi (Ground) | GS wireless module |
| 0x08 | OFDM | Video transmission link |
| 0x09 | Battery | Smart battery BMS |
| 0x17 | Goggles | FPV Goggles V2 / Goggles 2 |

## Command Set & ID Mapping

### Set 0x00: General
- **0x01**: Get Version
- **0x0A**: Get Serial Number
- **0xDE**: FCC Support (Trigger $1W$ mode)

### Set 0x01: Special
- **0x0D**: Get Product ID
- **0x1E**: Get Firmware Version

### Set 0x02: Camera
- **0x01**: Take Photo
- **0x02**: Start/Stop Record
- **0x06**: Goggles Mode Toggle ($0=$ Normal, $1=$ USB/FPV)
- **0x08**: Osmo Broadcast Config (RTMP Livestream)
- **0x3C**: Video Subscribe
- **0x8E**: Start/Stop Streaming State Machine
- **0xE1**: Prepare to Livestream (Stage 1)

### Set 0x03: Flight Controller
- **0x01**: Get Flight Status
- **0x02**: Get/Set Parameters
- **0x29**: Joystick Command (Pitch/Roll/Yaw/Throttle)

### Set 0x06: Remote Controller
- **0x24**: Simulator Data (App -> RC)
  - Sticks: 4 x `uint16` (364–1684)
  - Buttons: `uint32`

### Set 0x07: Wi-Fi
- **0x07**: Get Camera AP SSID
- **0x0E**: Get Camera AP PSK
- **0x45**: Device Pairing (Set PIN / Get Status)
- **0xAC**: WiFi Scan Report

### Set 0x08: DM36X / Transcoder
- **0x78**: Configure Streaming (Set Bitrate/FPS/URL)

### Set 0x0D: Battery
- **0x01**: Battery Static Info
- **0x02**: Battery Dynamic Info (Voltage, Temp, Percentage)

## Implementation Coverage

The current Wireshark dissector (`dji-ble-message.c`) and `djictl` package implement:
1. **DUML framing**: Displays CRC8 and CRC16 fields.
2. **Addressing**: Identification of all major components.
3. **Payload Dissection**: Detailed bit-level views for RC sticks, livestreaming URLs, battery health, and pairing protocols.

# Examples

## `0x000280`

### Thoughts

I assume this is a signal that pairing started.

Not really sure though how to parse this:
01 04 80 00 01 000000000000000000000000000000000000000000000000000000 02 46 0000 01 0000000000000000000000000000000000000000 01 0000

It seems like in every message of this type the payload is the same.

### Samples

Frame 596: 85 bytes on wire (680 bits), 85 bytes captured (680 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 554904930102411000028001048000010000000000000000000000000000000000000000000000000000000246000001000000000000000000000000000000000000000001000017fc
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x49
    proto_ver: 0x04
    crc8_hdr: 0x93
    subsystem: 0x0102
    msg_id: 0x4110
    msg_type: pairing_started (0x000280)
    payload: 010480000100000000000000000000000000000000000000000000000000000002460000010000000000000000000000000000000000000000010000
    crc16_msg: 0xfc17

Frame 599: 85 bytes on wire (680 bits), 85 bytes captured (680 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 554904930102421000028001048000010000000000000000000000000000000000000000000000000000000246000001000000000000000000000000000000000000000001000099fa
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x49
    proto_ver: 0x04
    crc8_hdr: 0x93
    subsystem: 0x0102
    msg_id: 0x4210
    msg_type: pairing_started (0x000280)
    payload: 010480000100000000000000000000000000000000000000000000000000000002460000010000000000000000000000000000000000000000010000
    crc16_msg: 0xfa99

Frame 611: 85 bytes on wire (680 bits), 85 bytes captured (680 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 55490493010246100002800104800001000000000000000000000000000000000000000000000000000000024600000100000000000000000000000000000000000000000100007e0b
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x49
    proto_ver: 0x04
    crc8_hdr: 0x93
    subsystem: 0x0102
    msg_id: 0x4610
    msg_type: pairing_started (0x000280)
    payload: 010480000100000000000000000000000000000000000000000000000000000002460000010000000000000000000000000000000000000000010000
    crc16_msg: 0x0b7e

Frame 617: 85 bytes on wire (680 bits), 85 bytes captured (680 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 55490493010247100002800104800001000000000000000000000000000000000000000000000000000000024600000100000000000000000000000000000000000000000100000bf1
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x49
    proto_ver: 0x04
    crc8_hdr: 0x93
    subsystem: 0x0102
    msg_id: 0x4710
    msg_type: pairing_started (0x000280)
    payload: 010480000100000000000000000000000000000000000000000000000000000002460000010000000000000000000000000000000000000000010000
    crc16_msg: 0xf10b

Frame 790: 85 bytes on wire (680 bits), 85 bytes captured (680 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 5549049301027910000280010480000100000000000000000000000000000000000000000000000000000002460000010000000000000000000000000000000000000000010000287f
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x49
    proto_ver: 0x04
    crc8_hdr: 0x93
    subsystem: 0x0102
    msg_id: 0x7910
    msg_type: pairing_started (0x000280)
    payload: 010480000100000000000000000000000000000000000000000000000000000002460000010000000000000000000000000000000000000000010000
    crc16_msg: 0x7f28

## `0x0002dc`

### Thoughts

It seems the payload is constant:
* 00 12 01 0000 02 00000000000000000000000000000000

I don't know. Let's just call it 'unknown_2DC'
Judging from the message type, it is likely related to livestreaming.

### Samples

Frame 595: 47 bytes on wire (376 bits), 47 bytes captured (376 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 5523042e010240100002dc0012010000020000000000000000000000000000000019e7
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x23
    proto_ver: 0x04
    crc8_hdr: 0x2e
    subsystem: 0x0102
    msg_id: 0x4010
    msg_type: Unknown (0x0002dc)
    payload: 00120100000200000000000000000000000000000000
    crc16_msg: 0xe719

Frame 610: 47 bytes on wire (376 bits), 47 bytes captured (376 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 5523042e010245100002dc0012010000020000000000000000000000000000000060f4
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x23
    proto_ver: 0x04
    crc8_hdr: 0x2e
    subsystem: 0x0102
    msg_id: 0x4510
    msg_type: Unknown (0x0002dc)
    payload: 00120100000200000000000000000000000000000000
    crc16_msg: 0xf460

## `0x000405`

### Thoughts

If we compare payloads:
* e3060000ffff800000000001912e0500a92a0000cefcf4ffee27983c069650bfd330143fee1ed63c000000000100000000
* e3060000ffff80000000000179320500a92a0000cefcf4ffac1f983cef9550bff430143ff221d63c000000000100000000
* e3060000ffff800000000001dd320500a92a0000cefcf4ff182e983c209650bfae30143f2a1dd63c000000000100000000
* e3060000ffff800000000001a5330500a92a0000cefcf4ff3820983cf39550bfe930143f632cd63c000000000100000000
* e3060000ffff80000000000109340500a92a0000cefcf4ff1826983c189650bfbd30143f0d1ad63c000000000100000000
* e3060000feff8000000000010d440500a92a0000cefcf3ffb621983c6c9550bfad31143ffb22d63c000000000100000000
* e3060000feff800000000001bd930500a92a0000cefcf3ff1422983c6d9550bfab31143fcb21d63c000000000100000000
* e3060000feff800000000001edbd0500a92a0000cefcf4ff9b25983c619550bfbd31143f1020d63c000000000100000000

We see that there is a mask:
e3060000 fX ff800000000001 XX XX 0500a92a0000cefc fX ff XXXX 983c XX 9X 50bf XX 3X 143f XXXX d63c000000000100000000
                             ---                                      -      -----
                              |                                       |      another gradually increasing uint16?
                              |                                       this seems to alternate between 5 and 6
                              this seems to gradually grow: is it a timer, a piece of a frame ID or something like this?


I don't know. Let's just call it 'status_report?'

### Samples

Frame 552: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0x4c12
    msg_type: status_report? (0x000405)
    payload: e3060000ffff800000000001912e0500a92a0000cefcf4ffee27983c069650bfd330143fee1ed63c000000000100000000
    crc16_msg: 0xd16b


Frame 597: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b04021913000405e3060000ffff80000000000179320500a92a0000cefcf4ffac1f983cef9550bff430143ff221d63c00000000010000000014a9
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0x1913
    msg_type: Unknown (0x000405)
    payload: e3060000ffff80000000000179320500a92a0000cefcf4ffac1f983cef9550bff430143ff221d63c000000000100000000
    crc16_msg: 0xa914

Frame 600: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b04022d13000405e3060000ffff800000000001dd320500a92a0000cefcf4ff182e983c209650bfae30143f2a1dd63c0000000001000000007e92
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0x2d13
    msg_type: Unknown (0x000405)
    payload: e3060000ffff800000000001dd320500a92a0000cefcf4ff182e983c209650bfae30143f2a1dd63c000000000100000000
    crc16_msg: 0x927e

Frame 608: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
    [Source: 04:a8:5a:ce:07:63 (04:a8:5a:ce:07:63)]
    [Destination: Google_84:ac:0d (24:29:34:84:ac:0d)]
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b04025413000405e3060000ffff800000000001a5330500a92a0000cefcf4ff3820983cf39550bfe930143f632cd63c00000000010000000096eb
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0x5413
    msg_type: Unknown (0x000405)
    payload: e3060000ffff800000000001a5330500a92a0000cefcf4ff3820983cf39550bfe930143f632cd63c000000000100000000
    crc16_msg: 0xeb96

Frame 612: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b04026613000405e3060000ffff80000000000109340500a92a0000cefcf4ff1826983c189650bfbd30143f0d1ad63c000000000100000000321b
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0x6613
    msg_type: Unknown (0x000405)
    payload: e3060000ffff80000000000109340500a92a0000cefcf4ff1826983c189650bfbd30143f0d1ad63c000000000100000000
    crc16_msg: 0x1b32

Frame 791: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b0402b916000405e3060000feff8000000000010d440500a92a0000cefcf3ffb621983c6c9550bfad31143ffb22d63c0000000001000000000d12
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0xb916
    msg_type: Unknown (0x000405)
    payload: e3060000feff8000000000010d440500a92a0000cefcf3ffb621983c6c9550bfad31143ffb22d63c000000000100000000
    crc16_msg: 0x120d

Frame 1892: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b04022227000405e3060000feff800000000001bd930500a92a0000cefcf3ff1422983c6d9550bfab31143fcb21d63c00000000010000000006a0
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0x2227
    msg_type: Unknown (0x000405)
    payload: e3060000feff800000000001bd930500a92a0000cefcf3ff1422983c6d9550bfab31143fcb21d63c000000000100000000
    crc16_msg: 0xa006

Frame 2540: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553e044b0402d02f000405e3060000feff800000000001edbd0500a92a0000cefcf4ff9b25983c619550bfbd31143f1020d63c00000000010000000031be
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3e
    proto_ver: 0x04
    crc8_hdr: 0x4b
    subsystem: 0x0402
    msg_id: 0xd02f
    msg_type: Unknown (0x000405)
    payload: e3060000feff800000000001edbd0500a92a0000cefcf4ff9b25983c619550bfbd31143f1020d63c000000000100000000
    crc16_msg: 0xbe31

## `0x000d02`

### Thoughts

Examples of the payload:
* 00 8610 0000 ce01 00000000000000000000 36 0100 58 0000000000002004000000 01 01
* 00 1511 0000 0000 00000000000000000000 cc 0100 64 0000000000002004000000 00 01

This seems to be some kind of report of the livestreaming status. Let's call this 'streaming_status?'

### Samples

Frame 606: 59 bytes on wire (472 bits), 59 bytes captured (472 bits)
Bluetooth
    [Source: 04:a8:5a:ce:07:63 (04:a8:5a:ce:07:63)]
    [Destination: Google_84:ac:0d (24:29:34:84:ac:0d)]
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 552f046305024d01000d020086100000ce010000000000000000000036010058000000000000200400000001018df2
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x2f
    proto_ver: 0x04
    crc8_hdr: 0x63
    subsystem: 0x0502
    msg_id: 0x4d01
    msg_type: streaming_status (0x000d02)
    payload: 0086100000ce01000000000000000000003601005800000000000020040000000101
    crc16_msg: 0xf28d

Frame 5857: 59 bytes on wire (472 bits), 59 bytes captured (472 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x2f
    proto_ver: 0x04
    crc8_hdr: 0x63
    subsystem: 0x0502
    msg_id: 0x3e39
    msg_type: streaming_status (0x000d02)
    payload: 0015110000000000000000000000000000cc01006400000000000020040000000001
    crc16_msg: 0x06ce

## `0x000427`

### Thoughts

Is this just a "keep alive"?

Let's name it `keep_alive_427?`

### Samples

Frame 594: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551204c704020d1300042700000800006d69
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0402
    msg_id: 0x0d13
    msg_type: Unknown (0x000427)
    payload: 0000080000
    crc16_msg: 0x696d

Frame 598: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551204c70402211300042700000800006d1c
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0402
    msg_id: 0x2113
    msg_type: Unknown (0x000427)
    payload: 0000080000
    crc16_msg: 0x1c6d

Frame 601: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551204c70402331300042700000800007196
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0402
    msg_id: 0x3313
    msg_type: Unknown (0x000427)
    payload: 0000080000
    crc16_msg: 0x9671

Frame 609: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551204c704025a130004270000080000b12e
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0402
    msg_id: 0x5a13
    msg_type: Unknown (0x000427)
    payload: 0000080000
    crc16_msg: 0x2eb1

## `0x400081`

### Thoughts

If we look at the payload:
68673231320000000000000000000000000000000000000000000000000000000208000000000000020800000000000000000000000000000000000000000000

The first few bytes are in ASCII: hg212

I understand that "hg212" is just part number that means "DJI Osmo Pocket 3".

If we look at the rest of the payload:
0208000000000000020800000000000000000000000000000000000000000000

It seems like it is a series of two empty fields, assuming:
* 0x02 is some kind of type
* 0x08 is the length of the message? Or is this continuation of 0x02, since below we see some other messages start with, e.g., 0206 (while here we have 0208).
* 0x000000000000 is the empty message.

So let's name this message type "device_info".

### Samples

Frame 607: 89 bytes on wire (712 bits), 89 bytes captured (712 bits)
Bluetooth
    [Source: 04:a8:5a:ce:07:63 (04:a8:5a:ce:07:63)]
    [Destination: Google_84:ac:0d (24:29:34:84:ac:0d)]
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 554d04a84802220340008168673231320000000000000000000000000000000000000000000000000000000208000000000000020800000000000000000000000000000000000000000000dc0e
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x4d
    proto_ver: 0x04
    crc8_hdr: 0xa8
    subsystem: 0x4802
    msg_id: 0x2203
    msg_type: Unknown (0x400081)
    payload: 68673231320000000000000000000000000000000000000000000000000000000208000000000000020800000000000000000000000000000000000000000000
    crc16_msg: 0x0edc


## `0x000438`

### Thoughts

Unclear how to parse the payload:
0000 6464 00

I don't know. Let's just call it 'unknown_438'

### Samples

Frame 613: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551204c70402671300043800006464002678
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0402
    msg_id: 0x6713
    msg_type: Unknown (0x000438)
    payload: 0000646400
    crc16_msg: 0x7826

Frame 786: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551204c704029f1600043800006464007dee
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0402
    msg_id: 0x9f16
    msg_type: Unknown (0x000438)
    payload: 0000646400
    crc16_msg: 0xee7d

## `0x00041c`

### Thoughts

The payload is just `48`. I have no thoughts but: "why not 42?".

Let's call it 'unknown_41C'

### Samples

Frame 614: 26 bytes on wire (208 bits), 26 bytes captured (208 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 550e046604026b1300041c48e5e2
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0402
    msg_id: 0x6b13
    msg_type: Unknown (0x00041c)
    payload: 48
    crc16_msg: 0xe2e5

Frame 787: 26 bytes on wire (208 bits), 26 bytes captured (208 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 550e04660402a31600041c489ae2
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0402
    msg_id: 0xa316
    msg_type: Unknown (0x00041c)
    payload: 48
    crc16_msg: 0xe29a

## `0x0000f1`

### Thoughts

0000000000000000 is just 16 zero-bytes.

Maybe this is a keep-alive packet? The message type value is very low, so assuming this is a better candidate than 0x000427 (since "keep-alive" seems to be pretty fundamental and should be implemented very early in the process of the protocol development).

Let's name this message type `keep_alive_f1?`.

### Samples

Frame 615: 33 bytes on wire (264 bits), 33 bytes captured (264 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551504a9040273130000f100000000000000002057
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x15
    proto_ver: 0x04
    crc8_hdr: 0xa9
    subsystem: 0x0402
    msg_id: 0x7313
    msg_type: Unknown (0x0000f1)
    payload: 0000000000000000
    crc16_msg: 0x5720


## `0x000099`

### Thoughts

If we look at the payload:
* 02 06 0000 96 48 00000000 00 2e 00 0f 00 63616d5f6c617073655f706172616d 000000000000 15 00000000000000000000000000000000000000000000

Then:
* 63616d5f6c617073655f706172616d is just "cam_lapse_param" in ASCII. Is it https://developer.dji.com/iframe/mobile-sdk-doc/android/reference/dji/common/camera/CameraPhotoTimeLapseParam.html ?
* 0x0f seems to be the length of the "cam_lapse_param" string.
* 0x15 seems to be just the length of "(the length of the message after it) + 1"
* 0x48 is seen way to often in different places, but I still have no idea what it is.
* 0x2e seems to be "(the length of the message after it) + 1"; so we have structures inside structures here, it seems.

OK, let's take a look at the second payload:
* 02 06 0000 97 48 00000000 00 21 00 07 00 63616d5f666f76 000000000000 10 0000 30 000000 1b 0000 01 000000 c454 0000

Here we see:
* 63616d5f666f76 is just "cam_fov". I found that PDF https://www.codil.or.kr/filebank/original/RK/OTKCRK190241/OTKCRK190241.pdf mentions "cam_fov" in the context of "DJI", but I'm too lazy to dig into that direction.
* 0x07 is just the length of "cam_fov".
* Instead of 9648 we now have 9748. Is this the field ID? Does "9748" just correspond to "cam_fov"?

In any case, let's just name this message type `field_value`.

### Samples

Frame 1848: 84 bytes on wire (672 bits), 84 bytes captured (672 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 554804572802302000009902060000964800000000002e000f0063616d5f6c617073655f706172616d00000000000015000000000000000000000000000000000000000000002a20
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x48
    proto_ver: 0x04
    crc8_hdr: 0x57
    subsystem: 0x2802
    msg_id: 0x3020
    msg_type: Unknown (0x000099)
    payload: 02060000964800000000002e000f0063616d5f6c617073655f706172616d0000000000001500000000000000000000000000000000000000000000
    crc16_msg: 0x202a

Frame 1850: 71 bytes on wire (568 bits), 71 bytes captured (568 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553b04b42802312000009902060000974800000000002100070063616d5f666f76000000000000100000300000001b000001000000c4540000f4d6
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3b
    proto_ver: 0x04
    crc8_hdr: 0xb4
    subsystem: 0x2802
    msg_id: 0x3120
    msg_type: Unknown (0x000099)
    payload: 02060000974800000000002100070063616d5f666f76000000000000100000300000001b000001000000c4540000
    crc16_msg: 0xd6f4

Frame 1876: 71 bytes on wire (568 bits), 71 bytes captured (568 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 553b04b42802332000009902060000994800000000002100150063616d5f736d6172745f67696d62616c5f6d6f64650000000000000200010035e4
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x3b
    proto_ver: 0x04
    crc8_hdr: 0xb4
    subsystem: 0x2802
    msg_id: 0x3320
    msg_type: Unknown (0x000099)
    payload: 02060000994800000000002100150063616d5f736d6172745f67696d62616c5f6d6f646500000000000002000100
    crc16_msg: 0xe435


## `0x80ee03`

### Thoughts

If we look at the payload:
> 03 19 000000000000 20

I have no idea what it is. The total length is 18 bytes. Let's wait for more samples...

Also weird that `msg_id` is always zero-ed.

Let's call it `unknown_80EE03`

### Samples

Frame 5834: 34 bytes on wire (272 bits), 34 bytes captured (272 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x16
    proto_ver: 0x04
    crc8_hdr: 0xfc
    subsystem: 0x0802
    msg_id: 0x0000
    msg_type: Unknown (0x80ee03)
    payload: 031900000000000020
    crc16_msg: 0xf7a2

Frame 5880: 34 bytes on wire (272 bits), 34 bytes captured (272 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x16
    proto_ver: 0x04
    crc8_hdr: 0xfc
    subsystem: 0x0802
    msg_id: 0x0000
    msg_type: Unknown (0x80ee03)
    payload: 031900000000000020
    crc16_msg: 0xf7a2

## `0xc007ab`

### Thoughts

I have no idea what it is. Let's call it `unknown_C007AB`.
Judging from the message type, it is likely something related to WiFi. Maybe a confirmation of a successful connection?

### Samples

Frame 5853: 26 bytes on wire (208 bits), 26 bytes captured (208 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0702
    msg_id: 0x96bb
    msg_type: Unknown (0xc007ab)
    payload: 00
    crc16_msg: 0x403a

## `0x4007ac`

### Thoughts

If we look at the payload
* 01 11 0000 18 01 01 00 01 00 64736c6d6f64656d2e64782e63656e7465721d 01 01 000000 736c6f772e64736c6d6f64656d2e64782e63656e7465720f 01 01 01 0000 564d38313634393330 0f 01 01 01 0000 564d3737303438313411 01 01 02 0000 656972323330313239343211 01 01 02 01

It seems like it is just a list of WiFi access points visible by the device.

Let's call this: `wifi_scan_results`.

### Samples

Frame 5854: 256 bytes on wire (2048 bits), 256 bytes captured (2048 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0xf4
    proto_ver: 0x04
    crc8_hdr: 0x18
    subsystem: 0x0702
    msg_id: 0x0600
    msg_type: Unknown (0x4007ac)
    payload [truncated]: 0111000018010100010064736c6d6f64656d2e64782e63656e7465721d0101000000736c6f772e64736c6d6f64656d2e64782e63656e7465720f0101010000564d383136343933300f0101010000564d3737303438313411010102000065697232333031323934321101010201
    crc16_msg: 0xfd40

## `0x40028e`

### Thoughts

<no time to explain; see the samples>

### Samples

Frame 2270: 29 bytes on wire (232 bits), 29 bytes captured (232 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Write Command (0x52)
    Handle: 0x0030 (Unknown: Car Connectivity Consortium, LLC)
    Value: 551104920208ffab40028e00011c003bc8
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x11
    proto_ver: 0x04
    crc8_hdr: 0x92
    subsystem: 0x0208
    msg_id: 0xffab
    msg_type: start_stop_streaming (0x40028e)
    payload: 00011c00
    crc16_msg: 0xc83b

(when preparing to stream)

## `0x80028e`

### Thoughts

Seems like a response to `0x40028e` during preparing to stream (see above), since it happens shortly after and it duplicates the `00011c00` content.

Let's name this `start_stop_stream_result?`.

### Samples


Frame 2277: 40 bytes on wire (320 bits), 40 bytes captured (320 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
    Opcode: Handle Value Notification (0x1b)
    Handle: 0x002d (Unknown: FiRa Consortium)
    Value: 551c041b0802ffab80028e0000011c0009000900000000000020e729
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x1c
    proto_ver: 0x04
    crc8_hdr: 0x1b
    subsystem: 0x0802
    msg_id: 0xffab
    msg_type: Unknown (0x80028e)
    payload: 0000011c0009000900000000000020
    crc16_msg: 0x29e7

## `0xc0028e`

### Thoughts

I have no idea what to infer from `0xD6`. Let's just name this `unknown_C0028E`
Judging from the message type, it is likely related to livestreaming.

### Samples

Frame 8214: 26 bytes on wire (208 bits), 26 bytes captured (208 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0802
    msg_id: 0xa2bb
    msg_type: Unknown (0xc0028e)
    payload: d6
    crc16_msg: 0xf179

## `0x400032`

### Thoughts

Yeah, I have no idea what `3131000000` is. However, this seems to be a part of the pairing process.

Let's call it `pairing_stage2`.

### Samples

Frame 723: 30 bytes on wire (240 bits), 30 bytes captured (240 bits)
Bluetooth
    [Source: Google_84:ac:0d (24:29:34:84:ac:0d)]
    [Destination: 04:a8:5a:ce:07:63 (04:a8:5a:ce:07:63)]
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x12
    proto_ver: 0x04
    crc8_hdr: 0xc7
    subsystem: 0x0288
    msg_id: 0x74aa
    msg_type: Unknown (0x400032)
    payload: 3131000000
    crc16_msg: 0x6a42

## `0x400707`

### Thoughts

I have no idea what to infer from `0x20`. Let's call it `unknown_400707`.
Judging from message type, it is likely something related to pairing.

### Samples

Frame 743: 26 bytes on wire (208 bits), 26 bytes captured (208 bits)
Bluetooth
    [Source: Google_84:ac:0d (24:29:34:84:ac:0d)]
    [Destination: 04:a8:5a:ce:07:63 (04:a8:5a:ce:07:63)]
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0207
    msg_id: 0x76aa
    msg_type: Unknown (0x400707)
    payload: 20
    crc16_msg: 0x10dc


## `0x4007ab`

### Thoughts

No payload, do not know what it is. Calling `unknown_4007AB`.

### Samples

Bluetooth Attribute Protocol
    Opcode: Write Command (0x52)
        0... .... = Authentication Signature: False
        .1.. .... = Command: True
        ..01 0010 = Method: Write Request (0x12)
    Handle: 0x0030 (Unknown: Car Connectivity Consortium, LLC)
        [Service UUID: Unknown (0xfff0)]
        [UUID: Car Connectivity Consortium, LLC (0xfff5)]
    Value: 550d0433021bb0bb4007ab6633
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0d
    proto_ver: 0x04
    crc8_hdr: 0x33
    subsystem: 0x021b
    msg_id: 0xb0bb
    msg_type: Unknown (0x4007ab)
    payload: <MISSING>
    crc16_msg: 0x3366


## `0xc007ac`

### Thoughts

I have no idea how to interpret:
01 11 02 00 b5 d0 000000 75 2b

Let's call it `unknown_C007AC`. But judging from the message type, I guess it is something related to streaming configuration.

### Samples

Frame 10000: 36 bytes on wire (288 bits), 36 bytes captured (288 bits)
Bluetooth
Bluetooth HCI H4
Bluetooth HCI ACL Packet
Bluetooth L2CAP Protocol
Bluetooth Attribute Protocol
DJI MIMO BLE
    magic: 0x55
    msg_len: 0x18
    proto_ver: 0x04
    crc8_hdr: 0x20
    subsystem: 0x021b
    msg_id: 0x0000
    msg_type: Unknown (0xc007ac)
    payload: 01110200b5d0000000752b
    crc16_msg: 0xc280

## `0xC00746`

### Thoughts

This seems to be a part of the pairing process. IIRC, it happened when I've approved/confirmed the PIN during pairing. Let's call this `pairing_stage1`.

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0207
    msg_id: 0x0400
    msg_type: pair (0xc00746)
    payload: 00
    crc16_msg: 0x2835

## `0x400746`

### Thoughts

This happens right before DJI MIMO sent `0xC00746` (which seems to be a pairing command). So I assume this is a notification that the PIN was approved. Let's call this `pairing_pin_approved`

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0702
    msg_id: 0x0400
    msg_type: Unknown (0x400746)
    payload: 01
    crc16_msg: 0x7310


## `0xc00745`

### Thoughts

This was received soon after we set the pairing PIN. I haven't found a signal saying that pairing is required, so I assume this is a signal that it is actually required (and we notify about that only after sending the PIN, which is weird).

It seems like `payload` `0x0002` means pairing required, and `0x0001` means it is not required

Let's call it 'pairing_status'

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0f
    proto_ver: 0x04
    crc8_hdr: 0xa2
    subsystem: 0x0702
    msg_id: 0x72aa
    msg_type: Unknown (0xc00745)
    payload: 0002
    crc16_msg: 0x6900

(when pairing was required)


DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0f
    proto_ver: 0x04
    crc8_hdr: 0xa2
    subsystem: 0x0702
    msg_id: 0xfcab
    msg_type: pairing_required? (0xc00745)
    payload: 0001
    crc16_msg: 0x5f8c

(when pairing was not required)


## `0x400088`

### Thoughts

I received this soon after sending `0x4002e1`. Not sure what it is.

Let's call it "unknown_400088"

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0f
    proto_ver: 0x04
    crc8_hdr: 0xa2
    subsystem: 0x2802
    msg_id: 0x5520
    msg_type: Unknown (0x400088)
    payload: 1900
    crc16_msg: 0xc92c

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0f
    proto_ver: 0x04
    crc8_hdr: 0xa2
    subsystem: 0x2802
    msg_id: 0xc720
    msg_type: Unknown (0x400088)
    payload: 1900
    crc16_msg: 0xcd43

## `0xc002e1`

### Thoughts

The message type is very similar to `0x4002e1`, and this is the first unknown message that happened after `0x4002e1`, so let's call it `prepare_to_livestream_report`. Assuming `0x00` payload means "everything is OK".

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0802
    msg_id: 0xfeab
    msg_type: Unknown (0xc002e1)
    payload: 00
    crc16_msg: 0x618a

## `0x4007AB`

### Thoughts

The message type is very close to `0x4007AC`. So assuming this is a request to scan WiFi.

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0d
    proto_ver: 0x04
    crc8_hdr: 0x33
    subsystem: 0x021b
    msg_id: 0x00ac
    msg_type: unknown_4007AB (0x4007ab)
    payload: <MISSING>
    crc16_msg: 0xf962

## `0xC007AB`

Seems to be a response to `0x4007AC`. Assuming payload `0x00` means "OK".

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x0e
    proto_ver: 0x04
    crc8_hdr: 0x66
    subsystem: 0x0702
    msg_id: 0x00ac
    msg_type: unknown_C007AB (0xc007ab)
    payload: 00
    crc16_msg: 0x9b4e



## `0xC00747`

### Thoughts

It seems pretty obviously a response to `0x400747`, this this is a report of connecting to WiFi. Assuming payload `0x000000` means "everything is OK".

### Samples

DJI MIMO BLE
    magic: 0x55
    msg_len: 0x10
    proto_ver: 0x04
    crc8_hdr: 0x56
    subsystem: 0x0702
    msg_id: 0x198c
    msg_type: Unknown (0xc00747)
    payload: 000000
    crc16_msg: 0xb8f3

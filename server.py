#!/usr/bin/env python3

import socket
import sys


def handle_login_msg(msg, msi):
    print(msg.hex())
    protocol_version = msg[0]
    device_id = int.from_bytes(msg[1:9], 'little')
    device_type = msg[9]
    device_serial = int.from_bytes(msg[10:12], 'little')
    auth_key = int.from_bytes(msg[12:20], 'little')
    os_ver = int.from_bytes(msg[20:23], 'little')
    app_ver = int.from_bytes(msg[23:26], 'little')
    updater_ver = int.from_bytes(msg[26:29], 'little')

    print(hex(protocol_version))
    print(hex(device_id))
    print(hex(device_type))
    print(hex(device_serial))
    print(hex(auth_key))
    print(hex(os_ver))
    print(hex(app_ver))
    print(hex(updater_ver))

    return


# CRC-ITU CRC
def GetCrc16(data_array):
    crc16tab = (
        0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
        0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
        0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
        0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
        0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
        0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
        0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
        0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
        0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
        0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
        0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
        0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
        0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
        0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
        0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
        0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
        0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
        0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
        0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
        0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
        0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
        0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
        0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
        0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
        0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
        0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
        0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
        0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
        0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
        0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
        0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
        0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
    )
    fcs = int("FFFF", 16)
    i = 0
    while i < len(data_array):
        intNumber = data_array[i]
        crc16tabIndex = (fcs ^ intNumber) & int("FF", 16)
        fcs = (fcs >> 8) ^ crc16tab[crc16tabIndex]
        i = i + 1
    return fcs ^ 0xffff


def check_start_bit(packet):
    if (packet[0] != 0x5A):
        return False
    if (packet[1] != 0x5A):
        return False

    return


def get_crc(packet, ml):
    loc = 7 + ml
    bytes = packet[loc:loc + 2]
    crc = int.from_bytes(bytes, 'little')
    return crc


def calc_crc(packet, ml):
    crc = GetCrc16(packet[2:(7 + ml)])
    return crc


def check_stop_bit(packet, ml):
    loc = 7 + ml + 2
    if (packet[loc] != 0x0D):
        return False
    elif (packet[loc + 1] != 0x0A):
        return False

    return True


def get_ml(packet):
    return int(packet[2:3].hex(),16)


def get_mt(packet):
    return packet[6]


def get_msi(packet):
    packet[4:5]
    return


def get_msg(packet, ml):
    return packet[7:7 + ml]


def parse_packet(packet):
    print(packet.hex())

    cmd_req = 0x00
    cmd_ack_msg = 0x01
    login_msg = 0x02
    position_msg = 0x03
    status_msg = 0x04
    alarm_msg = 0x05

    if (False == check_start_bit(packet)):
        print("Error parsing: No Start bit found")
        return

    ml = get_ml(packet)
    print("ml %s" % ml)
    print("Calculated: %s" % (ml + 11))
    print("Received: %s" % len(packet))
    if (ml + 11 != len(packet)):
        print("Error parsing: Length not correct")
        print("ml %s" % ml)
        print("Calculated: %s" % (ml + 11))
        print("Received: %s" % len(packet))
        return

    if (False == check_stop_bit(packet, ml)):
        print("Error parsing: No Stop bit found")
        return

    if (get_crc(packet, ml) != calc_crc(packet, ml)):
        print("Error parsing: CRC fail")
        return

    mt = get_mt(packet)
    msi = get_msi(packet)
    msg = get_msg(packet, ml)

    if (mt == cmd_req):
        print("cmd_req received")
    elif (mt == cmd_ack_msg):
        print("cmd_ack_msg recevied")
    elif (mt == login_msg):
        handle_login_msg(msg, msi)
        print("login_msg received")
    elif (mt == position_msg):
        print("position_msg received")
    elif (mt == status_msg):
        print("status_msg recevied")
    elif (mt == alarm_msg):
        print("alarm_msg received")
    else:
        print("unknown message")
        return

def get_login_packet():
    protocol_version = 0xf0
    device_id = 0x0102030405060708
    device_type = 0x01  # MITAC-K245
    device_serial = 0x0102
    auth_key = 0x15f91a2854ad2abc
    os_ver = 0x1
    app_ver = 0x1
    updater_ver = 0x1

    payload = bytearray()

    payload.extend(protocol_version.to_bytes(1, 'little'))
    payload.extend(device_id.to_bytes(8, 'little'))
    payload.extend(device_type.to_bytes(1, 'little'))
    payload.extend(device_serial.to_bytes(2, 'little'))
    payload.extend(auth_key.to_bytes(8, 'little'))
    payload.extend(os_ver.to_bytes(3, 'little'))
    payload.extend(app_ver.to_bytes(3, 'little'))
    payload.extend(updater_ver.to_bytes(3, 'little'))

    return payload

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('localhost', 10000)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

while True:
    # Wait for a connection
    connection, client_address = sock.accept()
    connection.sendall(get_login_packet())

    try:

        # Receive the data in small chunks and retransmit it
        while True:
            data = connection.recv(1024)
            if data:
                parse_packet(data)
            else:
                break

    finally:
        # Clean up the connection
        connection.close()

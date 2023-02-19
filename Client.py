#!/usr/bin/env python3

import socket
import sys
import time
import array
import datetime
from .server import parse_packet

seq_id = 0


# CRC-ITU CRC
def GetCrc16(data_array):
    crc16tab = (
        0x0000,
        0x1189,
        0x2312,
        0x329B,
        0x4624,
        0x57AD,
        0x6536,
        0x74BF,
        0x8C48,
        0x9DC1,
        0xAF5A,
        0xBED3,
        0xCA6C,
        0xDBE5,
        0xE97E,
        0xF8F7,
        0x1081,
        0x0108,
        0x3393,
        0x221A,
        0x56A5,
        0x472C,
        0x75B7,
        0x643E,
        0x9CC9,
        0x8D40,
        0xBFDB,
        0xAE52,
        0xDAED,
        0xCB64,
        0xF9FF,
        0xE876,
        0x2102,
        0x308B,
        0x0210,
        0x1399,
        0x6726,
        0x76AF,
        0x4434,
        0x55BD,
        0xAD4A,
        0xBCC3,
        0x8E58,
        0x9FD1,
        0xEB6E,
        0xFAE7,
        0xC87C,
        0xD9F5,
        0x3183,
        0x200A,
        0x1291,
        0x0318,
        0x77A7,
        0x662E,
        0x54B5,
        0x453C,
        0xBDCB,
        0xAC42,
        0x9ED9,
        0x8F50,
        0xFBEF,
        0xEA66,
        0xD8FD,
        0xC974,
        0x4204,
        0x538D,
        0x6116,
        0x709F,
        0x0420,
        0x15A9,
        0x2732,
        0x36BB,
        0xCE4C,
        0xDFC5,
        0xED5E,
        0xFCD7,
        0x8868,
        0x99E1,
        0xAB7A,
        0xBAF3,
        0x5285,
        0x430C,
        0x7197,
        0x601E,
        0x14A1,
        0x0528,
        0x37B3,
        0x263A,
        0xDECD,
        0xCF44,
        0xFDDF,
        0xEC56,
        0x98E9,
        0x8960,
        0xBBFB,
        0xAA72,
        0x6306,
        0x728F,
        0x4014,
        0x519D,
        0x2522,
        0x34AB,
        0x0630,
        0x17B9,
        0xEF4E,
        0xFEC7,
        0xCC5C,
        0xDDD5,
        0xA96A,
        0xB8E3,
        0x8A78,
        0x9BF1,
        0x7387,
        0x620E,
        0x5095,
        0x411C,
        0x35A3,
        0x242A,
        0x16B1,
        0x0738,
        0xFFCF,
        0xEE46,
        0xDCDD,
        0xCD54,
        0xB9EB,
        0xA862,
        0x9AF9,
        0x8B70,
        0x8408,
        0x9581,
        0xA71A,
        0xB693,
        0xC22C,
        0xD3A5,
        0xE13E,
        0xF0B7,
        0x0840,
        0x19C9,
        0x2B52,
        0x3ADB,
        0x4E64,
        0x5FED,
        0x6D76,
        0x7CFF,
        0x9489,
        0x8500,
        0xB79B,
        0xA612,
        0xD2AD,
        0xC324,
        0xF1BF,
        0xE036,
        0x18C1,
        0x0948,
        0x3BD3,
        0x2A5A,
        0x5EE5,
        0x4F6C,
        0x7DF7,
        0x6C7E,
        0xA50A,
        0xB483,
        0x8618,
        0x9791,
        0xE32E,
        0xF2A7,
        0xC03C,
        0xD1B5,
        0x2942,
        0x38CB,
        0x0A50,
        0x1BD9,
        0x6F66,
        0x7EEF,
        0x4C74,
        0x5DFD,
        0xB58B,
        0xA402,
        0x9699,
        0x8710,
        0xF3AF,
        0xE226,
        0xD0BD,
        0xC134,
        0x39C3,
        0x284A,
        0x1AD1,
        0x0B58,
        0x7FE7,
        0x6E6E,
        0x5CF5,
        0x4D7C,
        0xC60C,
        0xD785,
        0xE51E,
        0xF497,
        0x8028,
        0x91A1,
        0xA33A,
        0xB2B3,
        0x4A44,
        0x5BCD,
        0x6956,
        0x78DF,
        0x0C60,
        0x1DE9,
        0x2F72,
        0x3EFB,
        0xD68D,
        0xC704,
        0xF59F,
        0xE416,
        0x90A9,
        0x8120,
        0xB3BB,
        0xA232,
        0x5AC5,
        0x4B4C,
        0x79D7,
        0x685E,
        0x1CE1,
        0x0D68,
        0x3FF3,
        0x2E7A,
        0xE70E,
        0xF687,
        0xC41C,
        0xD595,
        0xA12A,
        0xB0A3,
        0x8238,
        0x93B1,
        0x6B46,
        0x7ACF,
        0x4854,
        0x59DD,
        0x2D62,
        0x3CEB,
        0x0E70,
        0x1FF9,
        0xF78F,
        0xE606,
        0xD49D,
        0xC514,
        0xB1AB,
        0xA022,
        0x92B9,
        0x8330,
        0x7BC7,
        0x6A4E,
        0x58D5,
        0x495C,
        0x3DE3,
        0x2C6A,
        0x1EF1,
        0x0F78,
    )
    fcs = int("FFFF", 16)
    i = 0
    while i < len(data_array):
        intNumber = data_array[i]
        crc16tabIndex = (fcs ^ intNumber) & int("FF", 16)
        fcs = (fcs >> 8) ^ crc16tab[crc16tabIndex]
        i = i + 1
    return fcs ^ 0xFFFF


def get_login_packet():
    protocol_version = 0x01
    device_id = 0x3120F1CE55C08
    device_type = 0x01  # MITAC-K245
    device_serial = 0x0102
    auth_key = 0x15F91A2854AD2ABC
    os_ver = "1.2.3.4\x00"
    app_ver = "1.2.3.4\x00"
    updater_ver = "1.2.3.4\x00"
    # 0x312e322e332e3400 "1.2.3.4"

    payload = bytearray()

    payload.extend(protocol_version.to_bytes(1, "little"))
    payload.extend(device_id.to_bytes(8, "little"))
    payload.extend(device_type.to_bytes(1, "little"))
    payload.extend(device_serial.to_bytes(2, "little"))
    payload.extend(auth_key.to_bytes(8, "little"))
    # payload.extend(b'\x00')
    # payload.extend(os_ver.to_bytes(8,'big'))
    payload.extend(map(ord, os_ver))

    payload.extend(map(ord, app_ver))
    payload.extend(map(ord, updater_ver))
    print(payload)
    return payload


def get_location_packet():
    date = int(time.time())
    # print(date)

    no_gps_sat = 10

    lat_deg = 28
    lat_min = 28
    lat_sec = 52.3776

    long_deg = 77
    long_min = 1
    long_sec = 8.886

    # convert to decimal minutes and multiply by 30000
    latitude = int(((lat_deg * 60) + lat_min + (lat_sec / 60)) * 30000)
    longitude = int(((long_deg * 60) + long_min + (long_sec / 60)) * 30000)
    speed = 15
    course = 25
    altitude = 3000

    valid_bit = 0
    lat_direction_bit = 1
    long_direction_bit = 2
    ignition_bit = 3

    status = 0
    status = (
        status
        | 1 << valid_bit
        | 0 << lat_direction_bit
        | 0 << long_direction_bit
        | 1 << ignition_bit
    )

    HDOP = int(1.2 * 100)

    MCC = 404
    MNC = 96
    LAC = 20
    CELLID = 0x1E2F3C

    payload = bytearray()

    payload.extend(date.to_bytes(4, "little"))
    payload.extend(no_gps_sat.to_bytes(1, "little"))
    payload.extend(latitude.to_bytes(4, "little"))
    payload.extend(longitude.to_bytes(4, "little"))
    payload.extend(speed.to_bytes(1, "little"))
    payload.extend(course.to_bytes(2, "little"))
    payload.extend(altitude.to_bytes(2, "little"))
    payload.extend(HDOP.to_bytes(1, "little"))
    payload.extend(status.to_bytes(1, "little"))
    payload.extend(MCC.to_bytes(2, "little"))
    payload.extend(MNC.to_bytes(2, "little"))
    payload.extend(LAC.to_bytes(2, "little"))
    payload.extend(CELLID.to_bytes(3, "little"))

    return payload


def get_alarm_packet():
    alert_type = 0x1
    alert_sub_type = 0x0
    severity = 0x1
    date = int(time.time())
    no_gps_sats = 17

    lat_deg = 28
    lat_min = 28
    lat_sec = 52.3776

    long_deg = 77
    long_min = 1
    long_sec = 8.886

    valid_bit = 0
    lat_direction_bit = 1
    long_direction_bit = 2
    ignition_bit = 3

    # convert to decimal minutes and multiply by 30000
    latitude = int(((lat_deg * 60) + lat_min + (lat_sec / 60)) * 30000)
    longitude = int(((long_deg * 60) + long_min + (long_sec / 60)) * 30000)
    speed = 15
    course = 320
    altitude = 3000

    status = 0
    status = (
        status
        | 1 << valid_bit
        | 0 << lat_direction_bit
        | 0 << long_direction_bit
        | 1 << ignition_bit
    )

    payload = bytearray()

    payload.extend(alert_type.to_bytes(1, "little"))
    payload.extend(alert_sub_type.to_bytes(1, "little"))
    payload.extend(severity.to_bytes(1, "little"))
    payload.extend(date.to_bytes(4, "little"))
    payload.extend(no_gps_sats.to_bytes(1, "little"))
    payload.extend(latitude.to_bytes(4, "little"))
    payload.extend(longitude.to_bytes(4, "little"))
    payload.extend(speed.to_bytes(1, "little"))
    payload.extend(course.to_bytes(2, "little"))
    payload.extend(altitude.to_bytes(2, "little"))
    payload.extend(status.to_bytes(1, "little"))

    return payload


def get_status_packet():
    ignition_bit = 0
    sdcard_bit = 1
    sim_bit = 2

    curr_status = 0
    curr_status = curr_status | 1 << ignition_bit | 1 << sdcard_bit | 1 << sim_bit
    voltage = 1410  # 1410 mV, 14.1 V
    temp = 23
    rssi = -75
    sdcard_storage_size = 64 * 1024  # 64 GB
    sdcard_storage_used = 95  # 95 percent space used
    sdcard_cid = 94150414620534
    internal_storage_size = 1 * 1024  # 1 GB
    internal_storage_used = 80  # 80 percent space used
    sim_imsi = 310170845466094
    last_ignition_on_time = int(time.time()) - (60 * 60)  # Give one hour old time

    payload = bytearray()

    payload.extend(curr_status.to_bytes(1, "little"))
    payload.extend(voltage.to_bytes(2, "little"))
    payload.extend(temp.to_bytes(1, "little", signed=True))
    payload.extend(rssi.to_bytes(1, "little", signed=True))
    payload.extend(sdcard_storage_size.to_bytes(3, "little"))
    payload.extend(sdcard_storage_used.to_bytes(1, "little"))
    payload.extend(sdcard_cid.to_bytes(16, "little"))
    payload.extend(internal_storage_size.to_bytes(3, "little"))
    payload.extend(internal_storage_used.to_bytes(1, "little"))
    payload.extend(sim_imsi.to_bytes(8, "little"))
    payload.extend(last_ignition_on_time.to_bytes(8, "little"))

    return payload


def create_packet(payload_type, payload):
    packet = bytearray()

    # SB - Start bit
    packet.append(0x5A)
    packet.append(0x5A)

    # ML - Message Length
    length = len(payload)
    length_bytes = length.to_bytes(2, "little")
    packet.append(length_bytes[0])
    packet.append(length_bytes[1])

    global seq_id
    # MSI - Message Sequence ID
    seq_id_byes = seq_id.to_bytes(2, "little")
    packet.append(seq_id_byes[0])
    packet.append(seq_id_byes[1])
    seq_id = seq_id + 1

    # MT - Message Type
    payload_type_bytes = payload_type.to_bytes(2, "little")
    packet.append(payload_type_bytes[0])

    # MSG - Message body
    packet.extend(payload)

    # CRC - CRC check bits
    crc = GetCrc16(packet[2 : (7 + length)])  # CRC of ML+MSI+MT+MSG
    crc_bytes = crc.to_bytes(2, "little")
    packet.extend(crc_bytes)

    # STB - Stop bits (little endian)
    packet.append(0x0D)
    packet.append(0x0A)

    return packet


def get_cmd_ack_packet_payload(cmd_id):
    payload = bytearray()
    cmd_type = "0x01"
    cmd_req_id = cmd_id
    status = "0x00"
    payload_len = "0x00"

    payload.extend(cmd_type)
    payload.extend(cmd_req_id)
    payload.extend(status)
    payload.extend(payload_len)

    return payload


def cmd_req_msg_parser(msg):
    # to get the command_id
    cmd_req_msg_list = msg.split(",")
    cmd_req_id = cmd_req_msg_list[1]
    return cmd_req_id


def cmd_received_ack_packet(cmd_id):
    payload = get_cmd_ack_packet_payload(cmd_id)
    create_packet("0x01", payload)


# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Connect the socket to the port where the server is listening
server_address = ("cc59e31b75.loconav.com", 5223)
# print >>sys.stderr, 'connecting to %s port %s' % server_address
sock.connect(server_address)

try:

    # Send login packet
    payload = get_login_packet()
    message = create_packet(0x2, payload)  # 0x2 - login packet
    #    print( bytes(message).hex() )
    sock.sendall(message)

    # payload = get_location_packet()
    # message = create_packet(0x3, payload)  # 0x3 - location_msg
    # sock.sendall(message)

    # payload = get_alarm_packet()
    # message = create_packet(0x5, payload)  # 0x5 - alarm packet
    # # sock.sendall(message)

    # payload = get_status_packet()
    # message = create_packet(0x4, payload)  # 0x4 - status packet
    # sock.sendall(message)

    while True:
        data = sock.recv(1024)
        print(data, " recieved from server at", datetime.datetime.now())
        result_packet = parse_packet(data)
        if result_packet.get("mt") == "0x00":
            # get the command id to send ack to gp service.
            cmd_id = cmd_req_msg_parser(msg=result_packet.get("msg"))
            cmd_ack_msg = cmd_received_ack_packet(cmd_id)
            sock.sendall(cmd_ack_msg)


finally:
    # print >>sys.stderr, 'closing socket'
    sock.close()

#!/usr/bin/env python3

import socket
import sys
import time
import binascii


seq_id = 0

def handle_login_msg(msg, msi):
    print(msg.hex())
    protocol_version = msg[0]
    device_id = int.from_bytes(msg[1:9], 'little')
    device_type = msg[9]
    auth_key = int.from_bytes(msg[10:18], 'little')

    i = 0
    start = 18
    device_serial = ""

    for i in range(start, start + 30):  # taking 10 bytes as a aribtrary max length
        ch = int.from_bytes(msg[i:i + 1], 'little')
        # find the end of string
        if ch == 0:
            break
    device_serial = msg[start:i]

    start = i + 1
    os_ver = ""

    for i in range(start, start + 30):  # taking 10 bytes as a aribtrary max length
        ch = int.from_bytes(msg[i:i + 1], 'little')
        # find the end of string
        if ch == 0:
            break
    os_ver = msg[start:i]

    # print("Os version:")
    # print(os_ver.decode())

    start = i + 1
    app_ver = ""

    for i in range(start, start + 30):  # taking 10 bytes as a aribtrary max length
        ch = int.from_bytes(msg[i:i + 1], 'little')
        # find the end of string
        if ch == 0:
            break
    app_ver = msg[start:i]

    # print("App version:")
    # print(app_ver.decode())

    start = i + 1
    updater_ver = ""

    for i in range(start, start + 30):  # taking 10 bytes as a aribtrary max length
        ch = int.from_bytes(msg[i:i + 1], 'little')
        # find the end of string
        if ch == 0:
            break
    updater_ver = msg[start:i]

    # print("Updater version:")
    # print(updater_ver.decode())

    print("protocol_version - " + hex(protocol_version).__str__())
    print("device_id - " + device_id.__str__())
    print("device_type - " + hex(device_type).__str__())
    print("auth_key - " + auth_key.__str__())
    print("device_serial - " + device_serial.decode())
    print("os ver - " + os_ver.decode())
    print("app ver - " + app_ver.decode())
    print("updater ver - " + updater_ver.decode())

    print(hex(protocol_version))
    print(hex(device_id))
    print(hex(device_type))
    print(hex(auth_key))
    print("device_serial hex - " + hex(int.from_bytes(device_serial,'little')))
    print("os ver hex - " + hex(int.from_bytes(os_ver,'little')))
    print("app ver hex - " + hex(int.from_bytes(app_ver,'little')))
    print("updater ver - " + hex(int.from_bytes(updater_ver,'little')))

    return


def handle_location_mesg(msg, msi):
    print(msg.hex())

    date = int.from_bytes(msg[0:4], 'little')
    no_gps_sat = int.from_bytes(msg[4:5], 'little')
    latitude = int.from_bytes(msg[5:9], 'little')
    longitude = int.from_bytes(msg[9:13], 'little')
    speed = int.from_bytes(msg[13:14], 'little')
    course = int.from_bytes(msg[14:16], 'little')
    altitude = int.from_bytes(msg[16:18], 'little')
    hdop = int.from_bytes(msg[18:19], 'little')
    status = int.from_bytes(msg[19:20], 'little')
    mcc = int.from_bytes(msg[20:22], 'little')
    mnc = int.from_bytes(msg[22:24], 'little')
    lac = int.from_bytes(msg[24:26], 'little')
    cellid = int.from_bytes(msg[26:30], 'little')

    latVal = latitude / 30000
    lngVal = longitude / 30000



    print(hex(date))
    read_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(date))
    print("Date and Time received - " + read_time)
    print("No of GPS Sat - " + no_gps_sat.__str__())
    print(hex(latitude))
    print(hex(longitude))
    print("lat - " + latVal.__str__())
    print("lng - " + lngVal.__str__())
    print("speed - " + speed.__round__().__str__())
    print("Orientation - " + course.__str__())
    print("Alt - " + altitude.__str__())
    print("Hdop - " + (hdop/100).__str__())
    print("Status hex - " + hex(status))
    print("Status Binary - " + format(status,'b'))
    print("mcc - " + mcc.__str__())
    print("mnc - " + mnc.__str__())
    print("lac - " + lac.__str__())
    print("cellid - " + cellid.__str__())


def handle_status_msg(msg, msi):
    print(msg.hex())

    curr_status = int.from_bytes(msg[0:1], 'little')
    voltage = int.from_bytes(msg[1:3], 'little')
    temp = int.from_bytes(msg[3:4], 'little', signed=True)
    rssi = int.from_bytes(msg[4:5], 'little', signed=True)
    sdcard_storage_size = int.from_bytes(msg[5:8], 'little')
    sdcard_storage_used = int.from_bytes(msg[8:9], 'little')
    sdcard_cid = int.from_bytes(msg[9:25], 'little')
    internal_storage_size = int.from_bytes(msg[25:28], 'little')
    internal_storage_used = int.from_bytes(msg[28:29], 'little')
    sim_imsi = int.from_bytes(msg[29:37], 'little')
    last_ignition_on_time = int.from_bytes(msg[37:41], 'little')

    read_ignition_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_ignition_on_time))

    print("Current Status Binary - " + format(curr_status, 'b'))
    print("voltage - " + voltage.__str__())
    print("Temp - " + temp.__str__())
    print("rssi - " + rssi.__str__())
    print("sdcard_storage_size - " + sdcard_storage_size.__str__())
    print("sdcard_storage_used - " + sdcard_storage_used.__str__())
    print("sdcard_cid - " + sdcard_cid.__str__())
    print("internal_storage_size - " + internal_storage_size.__str__())
    print("internal_storage_used - " + internal_storage_used.__str__())
    print("sim_imsi - " + sim_imsi.__str__())
    print("last_ignition_on_time - " + read_ignition_time)

    print(hex(curr_status))
    print(voltage)
    print(temp)
    print(rssi)
    print(sdcard_storage_size)
    print(sdcard_storage_used)
    print(sdcard_cid)
    print(internal_storage_size)
    print(internal_storage_used)
    print(sim_imsi)
    print(last_ignition_on_time)


def handle_alarm_msg(msg, msi):
    print(msg.hex())

    alert_type = int.from_bytes(msg[0:1], 'little')
    alert_sub_type = int.from_bytes(msg[1:2], 'little')
    severity = int.from_bytes(msg[2:3], 'little')
    date = int.from_bytes(msg[3:7], 'little')
    no_gps_sats = int.from_bytes(msg[7:8], 'little')
    latitude = int.from_bytes(msg[8:12], 'little')
    longitude = int.from_bytes(msg[12:16], 'little')
    speed = int.from_bytes(msg[16:17], 'little')
    course = int.from_bytes(msg[17:19], 'little')
    altitude = int.from_bytes(msg[19:21], 'little')
    status = int.from_bytes(msg[21:22], 'little')

    latVal = latitude / 30000
    lngVal = longitude / 30000
    read_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(date))

    print("Date and Time received - " + read_time)
    print("No of GPS Sat - " + no_gps_sats.__str__())
    print(hex(latitude))
    print(hex(longitude))
    print("lat - " + latVal.__str__())
    print("lng - " + lngVal.__str__())
    print("speed - " + speed.__str__())
    print("Orientation - " + course.__str__())
    print("Alt - " + int(altitude).__str__())
    print("Status hex - " + hex(status))
    print("Status Binary - " + format(status, 'b'))

    print(alert_type)
    print(alert_sub_type)
    print(severity)
    print(date)
    print(no_gps_sats)
    print(latitude)
    print(longitude)
    print(speed)
    print(course)
    print(int(altitude))
    print(status)


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
    return int.from_bytes(packet[2:4], 'little')


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
        print("login_msg received")
        handle_login_msg(msg, msi)
    elif (mt == position_msg):
        print("position_msg received")
        handle_location_mesg(msg, msi)
    elif (mt == status_msg):
        print("status_msg recevied")
        handle_status_msg(msg, msi)
    elif (mt == alarm_msg):
        print("alarm_msg received")
        handle_alarm_msg(msg, msi)
    else:
        print("unknown message")
        return

def create_packet(payload_type, payload):
    packet = bytearray()

    # SB - Start bit
    packet.append(0x5A)
    packet.append(0x5A)

    # ML - Message Length
    length = len(payload)
    length_bytes = length.to_bytes(2, 'little')
    packet.append(length_bytes[0])
    packet.append(length_bytes[1])

    global seq_id
    # MSI - Message Sequence ID
    seq_id_byes = seq_id.to_bytes(2, 'little')
    packet.append(seq_id_byes[0])
    packet.append(seq_id_byes[1])
    #seq_id = seq_id + 1

    # MT - Message Type
    payload_type_bytes = payload_type.to_bytes(2, 'little')
    packet.append(payload_type_bytes[0])

    # MSG - Message body
    packet.extend(payload)

    # CRC - CRC check bits
    crc = GetCrc16(packet[2:(7 + length)])  # CRC of ML+MSI+MT+MSG
    crc_bytes = crc.to_bytes(2, 'little')
    packet.extend(crc_bytes)

    # STB - Stop bits (little endian)
    packet.append(0x0D)
    packet.append(0x0A)

    #print("packet sending - " + packet.hex())

    return packet


#parse_packet(bytearray.fromhex("5a5a2900fa1404070b002c15ba390002000000000000000000000000000000009a3b002da3a305fe866f01005a1972632e250d0a"))

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the port
server_address = ('192.168.0.133', 10500)
sock.bind(server_address)

# Listen for incoming connections
sock.listen(1)

# while True:
#     # Wait for a connection
#     connection, client_address = sock.accept()
#     while True:
#         user_input = input('Enter a ServerPacket: ')
#         body_Packet = input('Enter a BodyPacket: ')
#
#         # 👇️ Exit when user presses Enter with empty input
#         if user_input == '':
#             print('User pressed Enter')
#             break
#
#         #body = "0x00,0x753bb0da60dd11ed9b6a0242ac120002,0x00,0x02,0x636CCAB9,0xA\x00"
#
#         body = body_Packet
#         payload = bytearray()
#         payload.extend(map(ord, body))
#         serverPacket = create_packet(0x0, payload).hex()
#         print("Provided Packet -            " + user_input)
#         print("Calculated Server Packet -   " + serverPacket + "\nMatches Provided packet - " + serverPacket.__eq__(user_input).__str__())
#         connection.send(bytearray.fromhex(user_input))


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




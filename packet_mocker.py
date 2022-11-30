#!/usr/bin/env python3
import uuid

def create_vod():
	mtype = 0
	cmd_id = uuid.uuid4().hex
	cmd_req_id = int(cmd_id,16)
	cam_type = int(input("Cam no: "))
	video_config = int(input("Video config: "))
	start_time = int(input("Star time: "))
	duration = int(input("Duration: "))

	print("CmdId - " + cmd_id)
	print(hex(mtype), ",", hex(cmd_req_id), ",", hex(cam_type), ",", hex(video_config), ",", hex(start_time),",", hex(duration), sep="" )

def create_ls():
	mtype = 1
	cmd_id = uuid.uuid4().hex
	cmd_req_id = int(cmd_id, 16)
	cam_type = int(input("Cam no: "))
	video_config = int(input("Video config: "))
	duration = int(input("Duration: "))

	print("CmdId - " + cmd_id)
	print(hex(mtype), ",", hex(cmd_req_id), ",", hex(cam_type), ",", hex(video_config),",", hex(duration), sep="" )

def create_logupload():
	mtype = 4
	cmd_id = uuid.uuid4().hex
	cmd_req_id = int(cmd_id, 16)
	log_level = int(input("Log level: "))
	log_duration = int(input("Log duration: "))

	print("CmdId - " + cmd_id)
	print(hex(mtype), ",", hex(cmd_req_id), ",", hex(log_level), ",", hex(log_duration), sep="")


print("1. VOD Message")
print("2. Live Streaming Message")
print("3. Log upload")

choice = input("Insert your choice: ")

ch = int(choice)

if( ch == 1 ):
	print("VOD Message")
	create_vod()
if( ch == 2 ):
	print("Live Streaming")
	create_ls()
if( ch == 3 ):
	print("Log upload")
	create_logupload()

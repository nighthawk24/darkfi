#!/usr/bin/python
from gui import *
import os, time

def send(timest, nick, msg):
    arg_data = bytearray()
    serial.write_u64(arg_data, timest)
    arg_data += os.urandom(32)
    serial.encode_str(arg_data, nick)
    serial.encode_str(arg_data, msg)

    api.call_method("/window/view/chatty", "insert_line", arg_data)

for i in range(200):
    name = f"bob-{i}"
    send(1732944640000 + i*60000, "hhi12", f"hello {name}")
    #time.sleep(0.4)
    #input("> ")


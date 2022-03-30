#!/usr/bin/env python3

#
# Copyright (c) 2020 Raspberry Pi (Trading) Ltd.
#
# SPDX-License-Identifier: BSD-3-Clause
#

# sudo pip3 install pyusb

from itertools import count
import usb.core
import usb.util
import threading
import time

# find our device
dev = usb.core.find(idVendor=0x0000, idProduct=0x0002)

# was it found?
if dev is None:
    raise ValueError('Device not found')

# get an endpoint instance
cfg = dev.get_active_configuration()
intf = cfg[(0, 0)]

outep = usb.util.find_descriptor(
    intf,
    # match the first OUT endpoint
    custom_match= \
        lambda e: \
            usb.util.endpoint_direction(e.bEndpointAddress) == \
            usb.util.ENDPOINT_OUT)

inep = usb.util.find_descriptor(
    intf,
    # match the first IN endpoint
    custom_match= \
        lambda e: \
            usb.util.endpoint_direction(e.bEndpointAddress) == \
            usb.util.ENDPOINT_IN)

assert inep is not None
assert outep is not None

#test_string = "Hello World!"
#outep.write(test_string)
#from_device = inep.read(len(test_string))
#print("Device Says: {}".format(''.join([chr(x) for x in from_device])))

counter = 0;
packet_counter=0;
buffer_size=4096;
arr_out = []

def prepare_data():
    global counter, arr_out;
    arr_out = [];
    for i in range(0, buffer_size, 64):
        #integer as byte array * 15 will produce 64 bytes
        arr_out += counter.to_bytes(4, 'little') * 16
        counter+=1
  
prepare_data();

def continous_read():
    global packet_counter, inep, arr_out, outep,arr_out;
    while True:
        outep.write(arr_out)
        prepare_data()
        #read_str = ''.join([chr(x) for x in from_device])
        #for i in range(0,buffer_size,64):
        #    read_str = ''.join('{:02x}'.format(x) for x in from_device[i : i+4])
        #    print(read_str)
        packet_counter +=1;
        #if read_str == "lalala this is a tst ;=) I will just fill the buffer to a length":
        #    packet_counter +=1;
        #else:
        #    print("read string does not match excepted!")

x = threading.Thread(target=continous_read)
x.start()

while True:
    time.sleep(1)
    num_packets_sec = packet_counter;
    packet_counter = 0;
    print('bytes per sec: %s' % (num_packets_sec * buffer_size));
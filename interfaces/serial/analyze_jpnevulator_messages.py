#!/usr/bin/env python

"""
Analyze serial sniffing log files created with jpnevulator.

This tool is able to analyze log files created similar to this:

    stty -F /dev/ttyUSB1 9600
    stty -F /dev/ttyUSB2 9600
    stty -F /dev/ttyUSB1
    stty -F /dev/ttyUSB2
    jpnevulator --timing-print \\
        --tty /dev/ttyUSB1:SENDING \\
        --tty /dev/ttyUSB2:RECEIVING \\
        --read \\
        --timing-delta=80000 \\
        --ascii | tee huber-comm-log_XX_$(date -u +%Y-%m-%dT%H:%M:%S%z).txt

Their content looks like this:

    2015-08-10 14:39:50.025182: SENDING
    9E 66 1E 06 98 E0 98 80 66 18 1E 98 86 98 86 98 .f......f.......
    86 98 86 98 86 98 86 98 86 98 86 98 86 98 86 98 ................
    86 98 86 98 86 60 E6 78 E6 80                   .....`.x..
    2015-08-10 14:39:50.087181: RECEIVING
    5B 53 30 31 43 31 39 30 30 30 30 30 30 30 30 30 [S01C19000000000
    30 30 30 30 30 30 30 31 30 31 44 0D             0000000101D.

"""

import argparse
import pdb
from datetime import datetime as dt

def hex_formatter(raw, bytes_per_line=None):
    if bytes_per_line:
        def chunks(l, n):
            """Yield successive n-sized chunks from l."""
            for i in range(0, len(l), n):
                yield l[i:i+n]
        hex_bytes = list('{:02X}'.format(byte) for byte in raw)
        return '\n'.join(' '.join(el) for el in chunks(hex_bytes, bytes_per_line))
    else:
        return ' '.join('{:02X}'.format(byte) for byte in raw)

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('jpnevulator_log_file', help='')
    args = parser.parse_args()

    sending, receiving = 'SENDING', 'RECEIVING'
    bytes_per_line = 16
    pause_time = 1.

    hex_chars_per_line = bytes_per_line * 3 - 1
    num_incoming, num_outgoing = 0, 0
    packets = []
    current_direction = None
    current_dt = None
    current_buffer = b""
    with open(args.jpnevulator_log_file) as fp:
        for line in fp:
            line = line.strip()
            if not line: continue
            kind = None
            if len(line) >= 26 and line[2] != ' ':
                if current_buffer:
                    packets.append({
                      'direction': current_direction,
                      'dt':        current_dt,
                      'message':   current_buffer,
                    })
                    current_direction = None
                    current_dt = None
                    current_buffer = b""
                try:
                    current_dt = dt.strptime(line[0:26], '%Y-%m-%d %H:%M:%S.%f')
                except ValueError:
                    print("failing to analyze this line:")
                    continue
                direction = line[28:]
                if direction == sending:
                    current_direction = sending
                    num_outgoing += 1
                elif direction == receiving:
                    current_direction = receiving
                    num_incoming += 1
                else:
                    print("failing to analyze this line:")
                    print(line)
                continue
            if direction is None:
                print("discarding this line (no data direction detected so far):")
                print(line)
                continue
            hex_data = line[0:hex_chars_per_line]
            current_buffer += bytes(int(byte, 16) for byte in hex_data.split())

    print('Packets:')
    last_dt, diff_dt = None, None
    for packet in packets:
        if last_dt:
            diff_dt = (packet['dt'] - last_dt).total_seconds()
        if diff_dt and diff_dt > pause_time: print('-----------------')
        print("{dt} {diff_dt} {direction} {message}".format(diff_dt=diff_dt, **packet))
        last_dt = packet['dt']

    print('Number of incoming frames: {}'.format(num_incoming))
    print('Number of outgoing frames: {}'.format(num_outgoing))


if __name__ == '__main__':
    main()

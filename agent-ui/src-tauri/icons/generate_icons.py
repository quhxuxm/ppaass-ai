#!/usr/bin/env python3
import struct
import zlib
import os


def create_png(width, height, filename):
    def png_chunk(chunk_type, data):
        chunk_len = struct.pack(">I", len(data))
        chunk_crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
        return chunk_len + chunk_type + data + chunk_crc

    signature = b"\x89PNG\r\n\x1a\n"
    # Color type 6 = RGBA (with alpha channel)
    ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)
    ihdr = png_chunk(b"IHDR", ihdr_data)

    raw_data = b""
    for y in range(height):
        raw_data += b"\x00"  # filter byte
        for x in range(width):
            # RGBA: #3498db with full opacity
            raw_data += b"\x34\x98\xdb\xff"

    compressed = zlib.compress(raw_data)
    idat = png_chunk(b"IDAT", compressed)
    iend = png_chunk(b"IEND", b"")

    with open(filename, "wb") as f:
        f.write(signature + ihdr + idat + iend)
    print(f"Created {filename}")


os.chdir(os.path.dirname(os.path.abspath(__file__)))

create_png(32, 32, "32x32.png")
create_png(128, 128, "128x128.png")
create_png(256, 256, "128x128@2x.png")
create_png(512, 512, "icon.png")

import shutil

shutil.copy("32x32.png", "icon.icns")
shutil.copy("32x32.png", "icon.ico")
print("All icons created!")

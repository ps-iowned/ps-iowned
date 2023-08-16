# Changelog

2023-08-11
 - Added news & FAQ.

2023-05-25
 - Cybdyn upgrades website. Maybe new DRM up? Advice: don't upgrade new firmware until analyze of new DRM done.

2023-04-27
 - Added links to other repo.

2023-04-25:
 - Added encrypter.

2023-04-24:
 - Initial disclosure.

# PSIO is owned

The repository contains code and information about reverse engineering Cybdyn's PSIO. This work is not affiliated with Cybdyn, and is done for educational purposes only. It contains no copyrighted material. Work was done by two people, using clone of PSIO from Aliexpress, and PSIO firmware 2.6.28 from Cybdyn's website. Thanks to github copilot for help writing the document).

PSIO software is three parts:

 - PSX Menu: The main menu that is displayed when the PSX is powered on with PSIO connected.
 - MCU firmware: The firmware that runs on the PSIO's microcontroller.
 - FPGA firmware: The firmware that runs on the PSIO's FPGA.

PSX Menu has been hacked by other people, and is not covered here. Menu hack from other people lets you flash chinese PSIO clones. We go further than that, and reverse engineer the MCU firmware. It is possible to combine both hacks, and run modified firmware on the PSIO.

No official update for 2 years, and no response to emails. PSIO is dead. Time to hack it, and make it better with custom firmware.

## FAQ

Heard questions from community. Answers here. More questions? Create github discussion.

Q: Original PSIO Menu contains Sony code?  
A: Yes. Original PSIO menu made using original Sony tools & libraries. License impossible to obtain now, so, stolen code.

Q: Original PSIO ARM firmware contains non-Cybdyn code?  
A: Yes. Original PSIO ARM firmware made with [Keil](https://www.keil.com/demo/eval/arm.htm). License still possible to obtain, but unknown if Cybdyn has license.

Q: Original PSIO Menu contains DRM?  
A: Yes. Original PSIO Menu has very poor DRM. Original PSIO ARM firmware has no DRM. If custom Menu released, then no more DRM to protect current Original PSIO ARM firmware. Maybe next official update adds ARM firmware DRM, but still no official update.

Q: Custom Menu works on clones with Original PSIO ARM firmware?  
A: Yes. No DRM in custom Menu, then Original PSIO ARM firmware runs on clones. Can update clones to latest Original PSIO ARM firmware with custom Menu.

Q: Can Custom Menu have DRM?  
A: Yes, but stupid. DRM in Open Source easy to remove.

Q: Is ps-iowned Menu & ARM firmware coming?  
A: Yes. Limited time & money so slow work, but both coming. Menu first.

Q: Has ps-iowned received legal letter from Cybdyn?  
A: No. And useless. No copyright violation with ps-iowned. Only explain how things work, and create new Menu & ARM firmware from scratch.

Q: Does ps-iowned enable PSIO piracy?  
A: Yes, but side-effect. PSIO clones exist before ps-iowned, and adding DRM in Open Source impossible. This work not for clones, but for genuine Cybdyn customers with no updates for more than 2 years, and still lots of bugs on Original PSIO Menu and ARM firmware.

## News

2023-08-16: [Other custom Menu effort canceled](https://github.com/danhans42/lite_menu/blob/main/images/danhans_sorry.pdf).
Seen [mentions of PS-IOwned](https://www.retrorgb.com/alternative-psio-lite-menu-to-release-on-aug-13.html) Menu. Yes, work is in progress. Yes, we will release CFW, fully open source, and no copyright material.

2023-08-11: [Other custom Menu effort announced](https://github.com/danhans42/lite_menu/). Cybdyn sent legal letter. Community response positive for homebrew Menu, negative for Cybdyn:
 - https://twitter.com/WobblingP/status/1688927813351645185
 - https://twitter.com/REBehindtheMask/status/1688968562910629902
 - https://twitter.com/WobblingP/status/1688946248210857984
 - https://twitter.com/Voultar/status/1689706789049139201
 - https://www.youtube.com/watch?v=FsWnPP2hYDk&t=1800
 - https://www.reddit.com/r/psx/comments/15lkrpx/psio_open_source_replacement_menu/

## PSX Menu

PSX Menu is simple MIPS code that is loaded into PSX RAM and executed. It is not encrypted, but only obfuscated. It is stored in MENU.SYS on the PSIO's SD card. File is ISO9660 filesystem, so it can be extracted with 7zip Iso7z plugin, or mounted. When downloading new MENU.SYS from Cybdyn's website, it has watermark for identifying the download. Remove watermark with this code:

```python
import sys
import struct

with open(sys.argv[1], 'r+b') as f:
    f.seek(0x8A00)
    f.write(struct.pack('<III', 0, 0, 0))
```

After removing watermark, 2.6.28 MENU.SYS has hashes:

```
Name: MENU.SYS
Size: 87230976 bytes (83 MiB)
CRC32: B98DE06A
CRC64: 953CC48DA70F246F
SHA256: c8fccb18273751b3f78d3a66923906499a90e80e1e7b61f72eaf289d545d27bb
SHA1: c2856176110650e89c9851558631007202cb00ed
BLAKE2sp: ccdf0900ca171a3ced4052ef0ad13a9a672064f44211d955a3402e4632f6b0e6
```

Interesting files in MENU.SYS ISO are:

 - MAIN.EXE: the menu bootloader
 - PSIO.DAT: an archive containing more files

To read PSIO.DAT, use this code:

```python
import sys
import struct
import os

def unpack(inname, outdir):
    with open(inname, "rb") as inf:
        psio_dat = inf.read()

    assert psio_dat[0:3] == b"PCK"

    for x in range(0x800 // 24):
        off = 4 + x * 24
        chunk = psio_dat[off:off+24]
        filename, size, offset = struct.unpack("<16sII", chunk)
        filename = filename.rstrip(b"\x00").decode('ascii')
        offset *= 0x800
        if not filename:
            break

        print(filename)
        with open(os.path.join(outdir, filename), "wb") as outf:
            outf.write(psio_dat[offset:offset+size])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: %s <input PSIO.DAT> <output directory>" % sys.argv[0])
        sys.exit(1)
    unpack(sys.argv[1], sys.argv[2])
```

Files in PSIO.DAT are sometimes obfuscated. Remove obfuscation with this code:

```python
import sys
from collections import defaultdict

def psiodat_deobfuscate(inname, outname):
    with open(inname, "rb") as inf:
        data = inf.read()

    count = [defaultdict(int) for x in range(256)]
    for x, ch in enumerate(data):
        count[x % 256][ch] += 1

    key_bin = [0] * 256
    for x in range(256):
        a = sorted(count[x].items(), key=lambda it: -it[1])
        key_bin[x] = 256 - a[0][0]

    data = bytearray(data)
    for off in range(0, len(data), 0x100):
        chunk = data[off:off+0x100]
        for x in range(len(chunk)):
            chunk[x] = (chunk[x] + key_bin[x]) % 256
        data[off:off+0x100] = chunk

    with open(outname, "wb") as outf:
        outf.write(data)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: %s <input> <output>" % sys.argv[0])
        sys.exit(1)

    psiodat_deobfuscate(sys.argv[1], sys.argv[2])
```

Obfuscation maybe very bad encryption layer. ARM firmware is called `ARM.DAT` in PSIO.DAT. It is obfuscated and encrypted.

[Rewrite project](https://github.com/ps-iowned/loader).

## FPGA firmware and SPI flash

FPGA firmware is stored in SPI flash of the PSIO, not encrypted. SPI Flash has copy of ARM firmware in it, at offset 0x80000. ARM firmware is not obfuscated, but encrypted. Extract 128kB of SPI flash from offset 0x80000 and get the same ARM firmware as in PSIO.DAT after obfuscation. There is a copy at SPI flash offset 0xa0000.

[Rewrite project](https://github.com/ps-iowned/fpga-firmware).

## MCU firmware

MCU firmware is stored in the flash of the ATSAM3U1C. MCU is locked, so it can't be read out. MCU firmware is encrypted in PSIO.DAT and SPI flash, but it is possible to decrypt it. Encryption is very bad, and can be broken with simple code. Key and code was found with bug exploitation of the MCU firmware, but isn't necessary.

Encrypted firmware has simple header, then checksums of decrypted data, then encrypted data.

Use this code to decrypt MCU firmware files:

```python
import sys
import struct

def flip(b):
    return bytes([(~x & 0xFF) for x in b])

def decrypt_arm(inname, outname):
    # Encryption is technically based on aes. That is, it takes normal aes sbox,
    # shifts it around and uses in a simple custom substitution cipher.
    # It can probably be broken in a blackbox manner.

    # This is not the key used to encrypt the firmware. This is the public
    # AES sbox. The key is simply "SCPH"). Not clever at all.
    # https://en.wikipedia.org/wiki/Rijndael_S-box
    aes_sbox = bytes.fromhex("""
        63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
        CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
        B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
        04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
        09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84
        53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF
        D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8
        51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2
        CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73
        60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB
        E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79
        E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08
        BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A
        70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E
        E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF
        8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16
    """)
    # lolwtf
    shifted_sbox = aes_sbox[0x40:0xF0] + aes_sbox[:0x40] + aes_sbox[0xF0:]

    schedule = bytearray(256)
    for i in range(256):
        schedule[shifted_sbox[i]] = i

    with open(inname, "rb") as inf:
        data = inf.read()

    assert data[0:8] == b"SAM3U FW"
    assert data[0x10:0x14] == flip(data[0x14:0x18])
    num_blocks = struct.unpack("<I", data[0x10:0x14])[0]
    assert num_blocks <= 0xF5

    checksums = data[0x100:0x100+8*num_blocks]
    payload = data[0x10000:0x10000+256*num_blocks]

    # lol this is just "SCPH" in little endian
    key = b"HPCS"
    plaintext = b""
    for block in range(num_blocks):
        ciphertext = payload[block*0x100:(block+1)*0x100]
        chunk = []
        for j in range(64):
            for i in range(4):
                chunk.append((schedule[ciphertext[j*4+i]] - key[i]) & 0xFF)
            key = struct.pack("<I", (struct.unpack("<I", key)[0] + 0x1010101) & 0xFFFFFFFF)

        cipher_chk = sum(ciphertext)
        plain_chk = sum(chunk)

        assert checksums[block*8:block*8+2] == flip(checksums[block*8+2:block*8+4])
        assert checksums[block*8+4:block*8+6] == flip(checksums[block*8+6:block*8+8])
        assert struct.unpack("<H", checksums[block*8:block*8+2])[0] == plain_chk
        assert struct.unpack("<H", checksums[block*8+4:block*8+6])[0] == cipher_chk

        plaintext += bytes(chunk)

    with open(outname, "wb") as outf:
        outf.write(plaintext)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: %s <input> <output>" % sys.argv[0])
        sys.exit(1)

    decrypt_arm(sys.argv[1], sys.argv[2])
```

Firmware is written at offset 0x2000 in the flash of the ATSAM3U1C. First 0x2000 bytes of flash are bootloader, and rest is firmware. Bootloader has no copy in any other place, so it is not possible to recover it easily. Writing a custom bootloader is not necessary to run a custom firmware, because the bootloader is not locked, and it is possible to write a custom firmware that will be loaded by the original bootloader. But dumping the bootloader to reverse engineer it is only possible with bug exploit or custom firmware. Sharing the bootloader is not legal, so it is not included in this repository.

The bootloader is very simple. It checks SPI flash and sd card for firmware updates, and decrypts and writes it to flash address 0x2000. If no update present, it just boots the firmware at 0x2000. It is possible to write a custom bootloader that will load the firmware from USB, or UART, or from anywhere else. But it is not necessary.

UART is available easily on the ATSAM3U1C. It is only 3.3V, and not 5v safe so it is only safe to connect to a 3.3v USB to UART adapter to connect to a PC. The pinout is RX = R28, and TX = R29. Both resistors are pull ups. Keep them, and solder wires to them. The UART setting is 115200-8N-1. The firmware prints debug messages to UART, so it is possible to see what is going on.

Last sector of the flash contains serial number of the PSIO. It is the same serial number that is displayed in the menu. Take note of the serial number of your PSIO before hacking, to write it back later in flash.

Last sector of chinese PSIO clone looks like this:

```
0000ff00  30 35 30 37 31 35 30 30  31 37 38 39 00 00 00 00  |050715001789....|
0000ff10  20 00 30 30 30 30 30 30  30 30 30 30 00 00 00 00  | .0000000000....|
0000ff20  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

And zeroes until the end. This serial number is blacklisted in the Menu software. If you know your serial number, you can rewrite the last sector with it with a custom firmware and restore the original firmware after with a custom bootloader.

Encryption of firmware is reverse operation from decryption. This code creates valid encrypted firmwares:

```python
import sys
import struct

def flip(b):
    return bytes([(~x & 0xFF) for x in b])

# Encryption is reverse operation from decryption.
def encrypt_arm(inname, outname):
    aes_sbox = bytes.fromhex("""
        63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76
        CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0
        B7 FD 93 26 36 3F F7 CC 34 A5 E5 F1 71 D8 31 15
        04 C7 23 C3 18 96 05 9A 07 12 80 E2 EB 27 B2 75
        09 83 2C 1A 1B 6E 5A A0 52 3B D6 B3 29 E3 2F 84
        53 D1 00 ED 20 FC B1 5B 6A CB BE 39 4A 4C 58 CF
        D0 EF AA FB 43 4D 33 85 45 F9 02 7F 50 3C 9F A8
        51 A3 40 8F 92 9D 38 F5 BC B6 DA 21 10 FF F3 D2
        CD 0C 13 EC 5F 97 44 17 C4 A7 7E 3D 64 5D 19 73
        60 81 4F DC 22 2A 90 88 46 EE B8 14 DE 5E 0B DB
        E0 32 3A 0A 49 06 24 5C C2 D3 AC 62 91 95 E4 79
        E7 C8 37 6D 8D D5 4E A9 6C 56 F4 EA 65 7A AE 08
        BA 78 25 2E 1C A6 B4 C6 E8 DD 74 1F 4B BD 8B 8A
        70 3E B5 66 48 03 F6 0E 61 35 57 B9 86 C1 1D 9E
        E1 F8 98 11 69 D9 8E 94 9B 1E 87 E9 CE 55 28 DF
        8C A1 89 0D BF E6 42 68 41 99 2D 0F B0 54 BB 16
    """)
    shifted_sbox = aes_sbox[0x40:0xF0] + aes_sbox[:0x40] + aes_sbox[0xF0:]

    with open(inname, "rb") as inf:
        data = inf.read()
    last_block_len = (len(data) + 255) % 256
    data += b"\x00" * (256 - last_block_len)
    num_blocks = len(data) // 256
    assert num_blocks <= 0xF5

    checksums = []

    key = b"HPCS"
    ciphertext = b""
    for block in range(num_blocks):
        plaintext = data[block*0x100:(block+1)*0x100]
        chunk = []
        for j in range(64):
            for i in range(4):
                chunk.append(shifted_sbox[(plaintext[j*4+i] + key[i]) % 256])
            key = struct.pack("<I", (struct.unpack("<I", key)[0] + 0x1010101) & 0xFFFFFFFF)

        cipher_chk = sum(chunk)
        plain_chk = sum(plaintext)

        checksums += struct.pack("<H", plain_chk)
        checksums += flip(struct.pack("<H", plain_chk))
        checksums += struct.pack("<H", cipher_chk)
        checksums += flip(struct.pack("<H", cipher_chk))

        ciphertext += bytes(chunk)

    checksums = bytes(checksums)

    with open(outname, "wb") as outf:
        outf.write(b"SAM3U FW" + b"\x00" * 8)
        outf.write(struct.pack("<I", num_blocks))
        outf.write(flip(struct.pack("<I", num_blocks)))
        outf.write(b"\x00" * 8)
        outf.write(struct.pack("<I", sum(data)))
        outf.write(flip(struct.pack("<I", sum(data))))
        outf.write(struct.pack("<I", sum(ciphertext)))
        outf.write(flip(struct.pack("<I", sum(ciphertext))))
        outf.write(b"\x00" * (0x100 - 0x30))
        outf.write(checksums)
        outf.write(b"\x00" * (0x10000 - len(checksums) - 0x100))
        outf.write(ciphertext)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: %s <input> <output>" % sys.argv[0])
        sys.exit(1)

    encrypt_arm(sys.argv[1], sys.argv[2])
```

[Bootloader rewrite project](https://github.com/ps-iowned/mcu-bootloader).

[Firmware rewrite project](https://github.com/ps-iowned/mcu-firmware).

## Future work

PSIO is now completely open. Menu isn't very protected. And now firmware is decrypted. We can reverse engineer everything, and create CFW for PSIO. We will work on it next here, so stay tuned. People asked questions: yes, all is open source.

[Rewrite projects](https://github.com/ps-iowned?tab=repositories)

## Donations

Please help support this project by donating to the following addresses: [bc1ql9qlnfzpjdve9takajrvj7fnuy2fwd0zc0vr0m](bitcoin:bc1ql9qlnfzpjdve9takajrvj7fnuy2fwd0zc0vr0m?amount=0.0005)

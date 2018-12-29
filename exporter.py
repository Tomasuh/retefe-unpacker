#!/usr/bin/python

# Example hashes that the unpacker works on:
# 352b78b8ed38be7ada1d9f4d82352da5015a853bf3c3bdb8982e4977d98f981c
# 5c548447203104e9a26c355beaf2367a8fa4793a1b0d3668701ee9ba120b9a7b
# 1a3f25f4067e50aa113dfd9349fc4bdcf346d2e589ed6b4cebbc0a33e9eea50d

import yara
import sys
import struct
import pefile


def number_gen_rec(buffer_size, number):
    if number == 1:
        return buffer_size
    return 0xFFFFFFFF & buffer_size * \
        (0xFFFFFFFF & number_gen_rec(buffer_size, number - 1))


def number_gen(buffer_size, number, shifts, subtract_val):
    calculated_number = number_gen_rec(buffer_size, number)

    number = calculated_number << shifts  # * 8
    number = subtract_val - number

    return number & 0xffffffff


def pwd_calc(buffer_size, number, shifts, subtract_val):
    xor_arr = []

    seed = number_gen(buffer_size, number, shifts, subtract_val)

    while seed:
        xor_arr.append(seed & 0xff)
        seed = seed >> 8

    return xor_arr


def get_matches_for_rule(yara_matches, rulename):
    result = []
    for match in yara_matches:
        if match.rule == rulename:
            result = match.strings
            break

    if not result or len(result) != 1:
        print("Invalid number of matches for {}, aborting".format(rulename))
        print("Match: {}".format(result))
        sys.exit()

    return result


yara_rules = yara.compile(filepaths={"all_rules": "retefe.yara"})

result = yara_rules.match(sys.argv[1])

retefe_xor_seed = get_matches_for_rule(result, "retefe_xor_seed")

# Offset to seed for xor
offset = retefe_xor_seed[0][0]

xor_seed_2ndarg = get_matches_for_rule(result, "retefe_xor_seed_2ndarg")

# Offset to value that will be used to take xor^value
offset2 = xor_seed_2ndarg[0][0]

shift_and_subtract = get_matches_for_rule(result, "retefe_shift_and_sub_match")

# Offset to values that will be used in part of subtraction and shifts of xor^value
offset3 = shift_and_subtract[0][0]

retefe_encoded_buffer = get_matches_for_rule(result, "retefe_encoded_buffer")

offset4 = retefe_encoded_buffer[0][0]

with open(sys.argv[1], "rb") as f:
    f.seek(offset + 10)  # Offset starts at match, we want end of match
    seed_val = struct.unpack('<i', f.read(4))[0] - 1  # -1 because of indexing in code
    print("Found seed (and buffer size) value {}".format(hex(seed_val)))

    f.seek(offset2 + 14)  # Offset starts at match, we want end of match
    power_to_val = struct.unpack('<i', f.read(4))[0]
    print("Found power to value {}".format(hex(power_to_val)))

    f.seek(offset3 + 2)
    shift_val = int.from_bytes(f.read(1), byteorder='little')
    print("Found shift left value {}".format(hex(shift_val)))

    f.seek(offset3 + 4)
    subtract_val = int.from_bytes(f.read(4), byteorder='little')
    print("Found subtract value {}".format(hex(subtract_val)))

    f.seek(offset4 + 16)
    # (match length before instruction) + 7 (instruction length)
    buffer_place = struct.unpack('<i', f.read(4))[0] + 13 + 7

    print("Found buffer place arg {}".format(hex(buffer_place)))


def calculate_physical_address_encoded_buffer(next_instruction_raw_adr, relative_adr_buffer):
    pe = pefile.PE(sys.argv[1])

    text_va_base = None
    text_raw_base = None

    for section in pe.sections:
        if section.Name == ".text" or section.Name.startswith(b".text\x00"):
            text_va_base = section.VirtualAddress
            text_raw_base = section.PointerToRawData

    rva_next_instr = next_instruction_raw_adr - text_raw_base

    # Encoded buffer rva address :
    rva = rva_next_instr + text_va_base + relative_adr_buffer

    print("Calculated RVA for encoded buffer is {}".format(hex(rva)))

    buffer = pe.get_memory_mapped_image()[rva:rva + seed_val]

    n = 0
    result = ""
    for ch in buffer:
        result += chr((ch ^ xor_arr[n % 4]))
        n += 1

    with open(sys.argv[1] + ".extracted", "w") as f:
        f.write(result)

    print("Extracted file written to {}".format(sys.argv[1] + ".extracted"))


xor_arr = pwd_calc(seed_val, power_to_val, shift_val, subtract_val)

print("XOR array that will be used for decryption {}".format(xor_arr))

calculate_physical_address_encoded_buffer(offset4, buffer_place)


# Some logical reasoning left behind....
# Now also find buffer and calculate va to physical and dump it

# Raw address is 4ef60
# Data segment raw base is 4E600
# 4ef60 - 4E600 = 0x960, 2400, offset
# Data segment virtual is 50000
# Image base is 140000000
# So the encoded buffer should be in: 0x140000000 + 0x50000 + 0x960 = 0x140050960 = Correct!


# 0x4ad7c is value from lea
# Next instruction after lea is at 140005be4
# 5be4 + 0x4ad7c = 0x50960 = VA for encoded buffer

# So we need to know instruction address in order to calculate encoded buffer address
# raw address of matched instruction is offset4, 0x4fd0
# 0x4fd0 + 13(match length before instruction) + 7 (instruction length) = 0x4FE4 = Raw address Next instruction
# Raw base of .text is 0x400, so RVA is 0x4FE4 - 0x400 = 0x4BE4
# VA base of .text is 1000, and image base 140000000
# So next instruction should be at 0x140000000 + 0x1000 + 0x4BE4 = 0x140005BE4 = Correct!

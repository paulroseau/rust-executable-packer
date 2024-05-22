# Read the index of entry with section names
xxd -s 62 -l 2 -e hello 
# returns 0005

# Read the offset of the first section header entry
xxd -s 40 -l 8 hello
xxd -s 40 -l 8 -e hello # little endian
xxd -s 62 -l 2 -g 8 -e hello # grouping all bytes
# returns 000000002110

# check the value in decimal
echo $((0x2110))

# Every section data offset is stored in the section header at offset 0x18
# Reading the offset
xxd -s $((0x2110 + 0x40 * 5 + 0x18)) -l 8 -g 8 -e ./hello
# returns 0x20e3

# Reading the data
xxd -s  $((0x20e3)) ./hello | head -4
# 000020e3: 002e 7379 6d74 6162 002e 7374 7274 6162  ..symtab..strtab
# 000020f3: 002e 7368 7374 7274 6162 002e 7465 7874  ..shstrtab..text
# 00002103: 002e 6461 7461 0000 0000 0000 0000 0000  ..data..........
# 00002113: 0000 0000 0000 0000 0000 0000 0000 0000  ................

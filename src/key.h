#ifndef key_h
#define key_h

uint8_t key_part1[] = { 0x2e, 0x67, 0x6e, 0x75, 0x2e, 0x76 };

uint8_t key_part2[] = { 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e };

uint8_t key[12];

void build_key()
{
    memcpy(key, key_part1, sizeof(key_part1));
    memcpy(key + sizeof(key_part1),
           key_part2,
           sizeof(key_part2));
}


#endif

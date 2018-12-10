#include "AFDXFramePrase.h"
#include "afdx_structs.h"

#include <string.h>
#include <stdio.h>

void modifyIPFragment(void* p, int flag, u_short field) {
    ip4hdr* ip = (ip4hdr*)p;
    u_short value = ((flag&0x7)<<13) | (field&0x1FFF);
#if BYTE_ORDER == BIG_ENDIAN
    ip->ih_fragment =value;
#else
    ip->ih_fragment =  swapI16(value);
#endif
}

void parserIPFragment(void* p, int* flag, u_short* field) {
    ip4hdr* ip = (ip4hdr*)p;
#if BYTE_ORDER == BIG_ENDIAN
    u_short value = ip->ih_fragment;
#else
    u_short value = swapI16(ip->ih_fragment);
#endif
    *flag = (value >> 13) & 0x7;
    *field = value & 0x1FFF;
}

void modifyIPBroadcast(void* p, int flag, u_short field) {
    ip4hdr* ip = (ip4hdr*)p;
    u_short value = ((flag&0xF)<<12) | (field&0xFFF);
#if BYTE_ORDER == BIG_ENDIAN
    ip->ih_dst.baddr.const_field = value;
#else
    ip->ih_dst.baddr.const_field = swapI16(value);
#endif
}

void parserIPBroadcast(void* p, int* flag, u_short* field) {
    ip4hdr* ip = (ip4hdr*)p;
#if BYTE_ORDER == BIG_ENDIAN
    u_short value = ip->ih_dst.baddr.const_field;
#else
    u_short value = swapI16(ip->ih_dst.baddr.const_field);
#endif
    *flag = (value >> 12) & 0xF;
    *field = value & 0xFFFF;
}

u_long swapI32(u_long v)
{
    return ((v & 0x000000FF) << 24) |
           ((v & 0x0000FF00) << 8) |
           ((v & 0x00FF0000) >> 8) |
            ((v & 0xFF000000) >> 24);
}

u_short swapI16(u_short v)
{
    return ((v & 0x00FF) << 8) |
            ((v & 0xFF00) >> 8);
}

int parseSN(char* buffer, int buffersize)
{
    if (buffersize < sizeof(packet_header)+5) return -1;

    unsigned char* tmp = (unsigned char*)buffer;
    return tmp[buffersize-5];
}

unsigned int parseCRC(char *buffer, int buffersize)
{
    if (buffersize < sizeof(packet_header)+5) return -1;

    return *((unsigned int *)(buffer+buffersize-4));
}

void MACToString(void *buffer, char* value, int size)
{
    if (buffer == nullptr || size < 18) return;

    unsigned char* header = (unsigned char*)buffer;
    sprintf_s(value, 18, "%02x-%02x-%02x-%02x-%02x-%02x",
        header[0], header[1], header[2], header[3], header[4], header[5]);
}

void MACFromString(char *value, void *buffer)
{
    if (value == nullptr || buffer == nullptr) return;

    unsigned char* tmp = (unsigned char*)buffer;
    sscanf(value, "%02x-%02x-%02x-%02x-%02x-%02x",
           &tmp[0], &tmp[1], &tmp[2], &tmp[3], &tmp[4], &tmp[5]);
}

void IP4ToString(u_long value, char* buffer, int size)
{
    if (buffer == nullptr || size < 16) return;

    unsigned char* header = (unsigned char*)&value;
    sprintf_s(buffer, size, "%u.%u.%u.%u",
        header[3], header[2], header[1], header[0]);
}

u_long IP4FromString(char *value)
{
    if (value == nullptr) return 0;

    u_long res = 0;
    unsigned char* header = (unsigned char*)&res;
    sscanf(value, "%u.%u.%u.%u",
        &header[0], &header[1], &header[2], &header[3]);
    return swapI32(res);
}

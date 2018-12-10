/**
*  Hwa Create Corporation Ltd..
*  Yi.18, No8 Dongbeiwang West Road, Haidian District Beijing, 100094 P.R.China
*  (c) Copyright 2018, Hwa Create Corporation Ltd.
*  All rights reserved.                                                                        *
*  @file     AFDXFrameParser.h
*  @brief    AFDX packet and frame parse and combine.
*  @warning  For IP layer, if you want to handle frament, you need to call
*            modifyIPFragment or parserIPFragment function; If you want to
*            handle broadcast info, you need to call modifyIPBroadcast or
*            parserIPBroadcast function; For packet header time offset, you
*            need to call modifyPacketTime or parserPacketTime function.
*  @author   Weijun Shi
*  @date     2018/12/10
*  @version  1.0
*/
#ifndef __AFDX_FRAMEPRASE_H__
#define __AFDX_FRAMEPRASE_H__

#ifdef AFDX_FRAMEPARSE_EXPORTS
#define AFDX_FRAMEPARSE_EXPORT __declspec(dllexport)
#else
#define AFDX_FRAMEPARSE_EXPORT __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef	unsigned long u_long;
typedef	unsigned char u_char;
typedef	unsigned short u_short;

/**
 * @brief parseSN is used to parse sn number.
 * @return
 */
int AFDX_FRAMEPARSE_EXPORT parseSN(char* buffer, int buffersize);

/**
 * @brief parseCRC is used to parse CRC value of packet.
 * @return
 */
unsigned int AFDX_FRAMEPARSE_EXPORT parseCRC(char* buffer, int buffersize);

/**
 * @brief modifyPacketTime modify time with value.
 * @param data
 * @param value is time offset.
 */
void AFDX_FRAMEPARSE_EXPORT modifyPacketTime(void* data, u_long value);

/**
 * @brief parserPacketTime time offset, return by value
 * @param data
 * @param return value of time offset
 */
void AFDX_FRAMEPARSE_EXPORT parserPacketTime(void* data, u_long* value);

/**
 * @brief modifyIPFragment modify ip fragment flag and fragment offset.
 * @param ip point to ip layer
 * @param flag is fragment flag
 * @param offset is fragment start of
 */
void AFDX_FRAMEPARSE_EXPORT modifyIPFragment(void* ip, int flag, u_short offset);

/**
 * @brief parserIPFragment parse ip layer fragment, include flag and offset.
 * @param ip point to ip layer
 * @param flag is fragment flag, eg. DF or MF.
 * @param offset is fragment start of
 */
void AFDX_FRAMEPARSE_EXPORT parserIPFragment(void* ip, int* flag, u_short* offset);

/**
 * @brief modifyIPBroadcast modify ip broadcast info,
 *        include Class info and constraint field.
 * @param ip point to ip layer
 * @param flag is ip class, default 0xE
 * @param field is barocast constraint field, default 0x0E0
 */
void AFDX_FRAMEPARSE_EXPORT modifyIPBroadcast(void* ip, int flag, u_short field);

/**
 * @brief parserIPBroadcast parse broadcast info, Class info and constraint field.
 * @param ip point to ip layer
 * @param flag return Class value
 * @param field return brodcast constraint field info
 */
void AFDX_FRAMEPARSE_EXPORT parserIPBroadcast(void* ip, int* flag, u_short* field);

/**
 * @brief swapI32 swap 4 Bytes value v
 * @param v
 * @return swaped data
 */
u_long AFDX_FRAMEPARSE_EXPORT swapI32(u_long v);

/**
 * @brief swapI16 swap 2 Bytes value v
 * @param v
 * @return swaped data
 */
u_short AFDX_FRAMEPARSE_EXPORT swapI16(u_short v);

/**
 * @brief MACToString convert mac to string value, value's size at least 18 Bytes.
 * @param buffer is start of mac layer
 * @param value is string buffer, at least 18 Bytes
 */
void MACToString(void *buffer, char* value, int size);
void MACFromString(char *value, void *buffer);

/**
 * @brief IP4ToString convert ip4 to string
 * @param value ip4 long value
 * @param buffer to ip string
 * @param size of buffer
 */
void IP4ToString(u_long value, char* buffer, int size);
u_long IP4FromString(char *value);

#ifdef __cplusplus
}
#endif

#endif //__AFDX_FRAMEPRASE_H__

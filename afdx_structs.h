#ifndef AFDX_STRUCTS_H__
#define AFDX_STRUCTS_H__

#pragma pack(1)
#pragma pack(push)
#define BIG_ENDIAN 1

typedef	unsigned long u_long;
typedef	unsigned char u_char;
typedef	unsigned short u_short;
typedef	u_long tcp_seq;

/**
 * @brief The packet_header struct's size is 16 Bytes.
 */
struct packet_header {
    /**
      * 0x02:字节对齐错误; 0x04:CRC是否校验(0:false,1:true);
      * 0x10IP是否校检(0:false,1:true)
      */
    u_char flag;
    u_char res;
    u_short len;
    u_char net;
    u_char time[3];
    u_char ifg;
    u_char res1[7];
};

#define	MAC_NET_A 0x01
#define	MAC_NET_B 0x02

/**
 * @brief The machdr struct's size is 14 Bytes.
 */
struct machdr
{
    struct _d_mac {
        u_long field;
        u_short vl;
    } dmac;
    struct _s_mac {
        u_char field[3];        ///< default:0x030000
        u_short user_id;
#if BYTE_ORDER == BIG_ENDIAN
        u_char net: 3;          ///< net, MAC_NET_A, MAC_NET_B
        u_char field1: 5;
#else
        u_char field1: 5;
        u_char net: 3;          ///< net, MAC_NET_A, MAC_NET_B
#endif
    } smac;
    u_short eh_type;		    ///< ipv4:0x0800
};

#define	IP_DF_QUEUE 0   ///< dont fragment flag
#define	IP_DF_SAMPLE 1  ///< dont fragment flag
#define	IP_MF 2         ///< more fragments flag
#define	IP_ICMP 1         ///< more fragments flag
#define	IP_UDP 17         ///< more fragments flag

/**
 * @brief The ip4hdr struct's size is 20 Bytes.
 */
struct ip4hdr {
#if BYTE_ORDER == BIG_ENDIAN
    u_char	ih_ver:4,		///< version
            ih_ihl:4;       ///< header length
#else
    u_char	ih_ihl:4,		///< version
            ih_ver:4;       ///< header length
#endif
    u_char	ih_tos;			///< type of service
    u_short	ih_len;			///< total length
    u_short	ih_id;			///< identification
    u_short	ih_fragment;	///< fragment flag:3bit,DF,MF + offset:13bit
    u_char	ih_ttl;			///< time to live
    u_char	ih_protocol;	///< protocol
    u_short	ih_checksum;	///< checksum
    union {
        struct {
#if BYTE_ORDER == BIG_ENDIAN
            u_char type: 1;  ///< A:0
            u_char paddr: 7; ///< 0x0A
#else
            u_char paddr: 7; ///< 0x0A
            u_char type: 1;  ///< A:0
#endif
            u_short user_id;
#if BYTE_ORDER == BIG_ENDIAN
            u_char spare_field: 3; ///< default: 0
            u_char partition_id: 5;
#else
            u_char partition_id: 5;
            u_char spare_field: 3; ///< default: 0
#endif
        } iaddr;
        struct {
            u_short const_field; ///< class:4bit,0xE, field:12bit,0x0E0
            u_short vl;
        } baddr;

        struct { u_char s_b1,s_b2,s_b3,s_b4; } S_un_b;
        struct { u_short s_w1,s_w2; } S_un_w;
        u_long S_addr;
    } ih_src, ih_dst;	///< source and dest address
#define s_addr  ih_src.S_addr /* can be used for most tcp & ip code */
#define s_host  ih_src.S_un_b.s_b2    // host on imp
#define s_net   ih_src.S_un_b.s_b1    // network
#define s_imp   ih_src.S_un_w.s_w2    // imp
#define s_impno ih_src.S_un_b.s_b4    // imp #
#define s_lh    ih_src.S_un_b.s_b3    // logical host
};

#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PUSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20

/*
 * Udp protocol header. It's size is 8 Bytes.
 * Per RFC 768, September, 1981.
 */
struct udphdr {
    u_short	uh_sport;		///< source port
    u_short	uh_dport;		///< destination port
    short	uh_ulen;		///< udp length
    u_short	uh_sum;			///< udp checksum
};

/**
 * @brief The MIH struct's size is 8 Bytes.
 */
struct MIH {
    u_short sn;
    u_char src_timestamp[6];
};

/**
 * @brief The frame_header struct's size is 42 Bytes(no EDE).
 */
struct frame_header {
    machdr mac;
    ip4hdr ip;
    udphdr udp;

#if EDE_ENABLED == 1
    MIH mid;
#endif
};

#pragma pack(pop)
#endif

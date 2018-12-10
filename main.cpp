#include <QCoreApplication>
#include <QDebug>

#include "AFDXFramePrase.h"
#include "afdx_structs.h"

void testStructs() {
    packet_header packet;
    frame_header frame;
    machdr mac;
    ip4hdr ip;
    udphdr udp;
    MIH mih;
    auto ppacket = &packet;
    auto pframe = &frame;
    auto pmac = &mac;
    auto pip = &ip;
    auto pudp = &udp;
    auto pmih = &mih;
    qDebug() << "mac size:" << sizeof mac;
    qDebug() << "ip size:" << sizeof ip;
    qDebug() << "udp size:" << sizeof udp;
    qDebug() << "mih size:" << sizeof mih;
    qDebug() << "packet header size:" << sizeof packet;
    qDebug() << "frame header size:" << sizeof frame;

    u_long smacField = swapI32(0x123456);
    mac.dmac.field = swapI32(0x03000000);
    mac.dmac.vl = swapI16(0x1234);
    memcpy(&mac.smac.field, &smacField, sizeof mac.smac.field);
    mac.smac.user_id = 1;
    mac.smac.net = MAC_NET_B;
    mac.smac.field1 = 2;
    mac.eh_type = 0x0800;

    ip.ih_ver = 4;
    ip.ih_ihl = 5;
    ip.ih_tos = 0xFF;
    ip.ih_len = swapI16(0x64);
    ip.ih_id = swapI16(0x10);
    modifyIPFragment(pip, IP_MF, 0x0123);
    ip.ih_ttl = 1;
    ip.ih_protocol = IP_UDP;
    ip.ih_checksum = swapI16(0xFFFF);
    ip.ih_src.iaddr.type = 1;
    ip.ih_src.iaddr.paddr = 0xC;
    ip.ih_src.iaddr.user_id = swapI16(0x1234);
    ip.ih_src.iaddr.partition_id = 0xA;
    modifyIPBroadcast(pip, 0xE, 0x1234);
    ip.ih_src.baddr.vl = 0x4123;

    char buff[20];
    memset(buff, 1, 20);
    MACToString(&mac, buff, 18);
    qDebug() << buff;
    char *mm = "11-22-33-44-55-66";
    MACFromString(mm, &mac);

    u_long ipvalue = IP4FromString("192.168.0.1");
    qDebug() << ipvalue;
    IP4ToString(ipvalue+1, buff, 20);
    qDebug() << buff;
}

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

    testStructs();

    return a.exec();
}

#pragma once
#include <cstdio>
#include "radiotap.h"
#include "mac.h"
#pragma pack(push,1)

struct fcontrol{
    unsigned int protver : 2;
    unsigned int type : 2;
    unsigned int subtype : 4;
    unsigned int tods : 1;
    unsigned int fromds : 1;
    unsigned int moref : 1;
    unsigned int retry : 1;
    unsigned int power : 1;
    unsigned int mored : 1;
    unsigned int wep : 1;
    unsigned int rsvd : 1;
};

struct BeaconHdr{
    uint16_t fc_;
    uint16_t duration_; 
    Mac dmac_;
    Mac smac_;
    Mac bssid_;
    uint16_t sq_;
};

struct Beaconfixed{
    uint8_t timestamp[8];
    uint16_t interval;
    uint16_t capab;
};

struct Deauth{
    RadHdr radiotap_;
    uint32_t pad_;
    BeaconHdr beacon_;
    uint16_t manage_;
};


#pragma pack(pop)
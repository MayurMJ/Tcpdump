#include<pcap.h>
#include<iostream>
#include<string>
#include"PcapHelper.h"
int getDefaultDevice(parsedArgs *args) {
	char errbuf[PCAP_ERRBUF_SIZE];
	args->interface = string(pcap_lookupdev(errbuf));
	if (args->interface.size() == 0) {
		cerr << "Couldn't find default device: " << errbuf;
		return(2);
	}
	cout << "Device: " << args->interface;
	return(0);
}


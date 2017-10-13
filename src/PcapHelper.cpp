#include"PcapHelper.h"
using namespace std;

/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */


const struct sniff_tcp *tcp; /* The TCP header */
const struct udphdr *udp;  /*  The UDP header */
const struct icmphdr *icmp;

const u_char *payload; /* Packet payload */
u_int size_ip;
u_int size_packet;


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

string printASCIIHex(const u_char *ptr, int len, string &contPl) {
	stringstream stream;
	stringstream astream;
	stream << endl;
	char buf[5];		
	int i = 0;	
	for(i = 0; i < len;i++) {
		//cout << std::hex << ptr[i];
		sprintf(buf, "%02x ", ptr[i]);		
		stream << buf;
	}
	for(; i < 16; i++) stream << "   ";
	stream << "  ";
	for(i = 0; i < len; i++) {
		if(isprint(ptr[i])) {
			stream << ptr[i];
			astream << ptr[i];
		}
		else { 
			stream << ".";
			astream << ".";
		}
	}
	contPl += string (astream.str());
	std::string result(stream.str());
	return result;
}

string printPayload(const u_char *payload, int len, string &contPl) {
	string pl = "";
	if(len == 0) return pl;	
	int  buffer = len;
	const u_char *chptr = payload;	
	while((16 / buffer) == 0) {
		int lineLen = 16 % buffer;
		pl += printASCIIHex(chptr, lineLen, contPl);
		buffer -= lineLen;
		chptr += lineLen;
		if(buffer == 0) break;
	}
	pl += printASCIIHex(chptr, buffer, contPl);
	return pl;
}

void my_packet_handler(u_char *args, const struct pcap_pkthdr *packet_header, const u_char *packet) {
	string printData = "";
	stringstream stream;
	time_t t = packet_header->ts.tv_sec; //usec;
	time_t us = packet_header->ts.tv_usec;
	const char *format =  "%Y-%m-%d %H:%M:%S";
	struct tm lt;
        char res[32], buf[10];
	localtime_r(&t, &lt);
	strftime(res, sizeof(res), format, &lt);
	snprintf(buf, sizeof(buf), "%06ld", us);
	stream << string(res) << "."  << string(buf) << " ";         
	//cout << res << "." << buf << " ";
	ethernet = (struct sniff_ethernet*)(packet);
	char *src = ether_ntoa((const struct ether_addr *) ethernet->ether_shost);		
	stream << string(src);
	char *dest = ether_ntoa((const struct ether_addr *) ethernet->ether_dhost);	
	stream << " -> " << string(dest) << " type 0x";
	//printData += string(src) + " -> " + string(dest);	
	//printData += " type 0x";
	stream << std::hex << ntohs(ethernet->ether_type);
	stream << " len " << std::dec << packet_header->len;
	//cout << src << " -> " << dest;
	//cout << " type 0x" << std::hex << ntohs(ethernet->ether_type);
	//cout << " len " << packet_header->len;
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		//printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}
	/* print source and destination IP addresses */

	switch(ip->ip_p) {
		case IPPROTO_TCP:
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_packet = TH_OFF(tcp)*4;
			if (size_packet < 20) {
				//printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}
			stream << " " << inet_ntoa(ip->ip_src);
			stream << ":" << ntohs(tcp->th_dport);
			stream << " -> " << inet_ntoa(ip->ip_dst);
			stream << ":" << ntohs(tcp->th_sport);
			stream << " TCP";			
			break;
		case IPPROTO_UDP:
			udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);
			size_packet = sizeof(udp);
			
			stream << " " << inet_ntoa(ip->ip_src);
			stream << ":" << ntohs(udp->dest);
			stream << " -> " << inet_ntoa(ip->ip_dst);
			stream << ":" << ntohs(udp->source);
			stream << " UDP";
			break;
		case IPPROTO_ICMP:
			icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
			size_packet = sizeof(icmp);
			stream << " ICMP";			
			break;
		default:
			stream << " unknown";
			break;
	}
	std::string result(stream.str());	
	printData += result;
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_packet);
	size_t size_payload = ntohs(ip->ip_len) - (size_ip + size_packet);
	string pl = "";
	printData += printPayload(payload, size_payload, pl);
	if(strstr(pl.c_str(), (const char *)args))
		cout << printData << endl;
	return;
}

int openConnection(parsedArgs *args, int file) {
	const char *device;
	struct bpf_program fp;
	bpf_u_int32 net;
	if(file) {
		device = args->file.c_str(); 
	}
	else {
		device = args->interface.c_str();
	}
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	int timeout_limit = 1000; /* In milliseconds */
	if(file) {
		handle = pcap_open_offline(device, errbuf);
	}
	else {	
		handle = pcap_open_live(device, BUFSIZ, 1, timeout_limit, errbuf);
	}	
	if (handle == NULL) {
		cerr << "Could not open device" << device << " " << errbuf << endl;
		return 2;
	}
	if(args->exp.size() != 0) {
		const char *filter_exp = args->exp.c_str();
		if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 	cerr << "Couldn't parse filter " << filter_exp << pcap_geterr(handle) << endl;
		 	return(2);
	 	}
	 	if (pcap_setfilter(handle, &fp) == -1) {
		 	cerr << "Couldn't install filter" << filter_exp << pcap_geterr(handle) << endl;
		 	return(2);
	 	}
	}
    	pcap_loop(handle, 0, my_packet_handler, (u_char *) args->str.c_str());
	return 0;
}

#include<iostream>
#include<pcap.h>
#include<string.h>
#include<iostream>
#include<string>
#include"PcapHelper.h"

using namespace std;
void parseArgs(parsedArgs *args, char **argv, int n) {
	for(int i = 1; i < n; i++) {
		if(strcmp(argv[i], "-i") == 0 ) {		
			args->interface = string(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i], "-r") == 0 ) {
			args->file = string(argv[i+1]);
			i++;
		}
		else if(strcmp(argv[i], "-s") == 0 ) {
			args->str = string(argv[i+1]);
			i++;
		}
		else {
			if(argv[i] != NULL)			
			args->exp = string(argv[i]);
		}
	}
}

int main(int argc, char** argv) {
	parsedArgs *args = new parsedArgs();
	parseArgs(args, argv, argc);
	cout << args->exp;
	if(args->interface.size() == 0 && args->file.size() == 0) {
		getDefaultDevice(args);
		openConnection(args, 0);
	}
	else if(args->interface.size() == 0) {
		openConnection(args, 1);
	}
	else {
		openConnection(args, 0);
	}
}




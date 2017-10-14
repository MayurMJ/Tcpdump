#include<iostream>
#include<pcap.h>
#include<string.h>
#include<iostream>
#include<string>
#include <unistd.h>
#include"PcapHelper.h"

using namespace std;
void parseArgs(parsedArgs *args, char **argv, int n) {
	/*for(int i = 1; i < n; i++) {
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
			if(argv[i] != NULL) {			
				args->exp += " "; 
				args->exp += string(argv[i]);
			}
		}
	}*/
	int c, index;
	while ((c = getopt (n, argv, "i:r:s:")) != -1)
	switch (c)
	{
      		case 'i':
			args->interface = string(optarg);
			break;
		case 'r':
			args->file = string(optarg);
			break;
		case 's':
			args->str = string(optarg);
			break;
		default:
			exit(0);
	}
	for (index = optind; index < n; index++) {
		args->exp += " "; 
		args->exp += string(argv[index]);
	}
}

int main(int argc, char** argv) {
	parsedArgs *args = new parsedArgs();
	parseArgs(args, argv, argc);
	if(args->interface.size() == 0 && args->file.size() == 0) {
		getDefaultDevice(args);
		openConnection(args, 0);
	}
	if(args->interface.size() > 0 && args->file.size() > 0) {
		cout << "Please specify only one of the -i -r arguments" << endl;
	}	
	else if(args->interface.size() == 0) {
		openConnection(args, 1);
	}
	else {
		openConnection(args, 0);
	}
}

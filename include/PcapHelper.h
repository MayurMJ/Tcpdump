#ifndef PCAPHELPER_H
#define PCAPHELPER_H

#include <string>
using namespace std;
struct parsedArgs {
	string interface;
	string file;
	string str;
	string exp;
};


int getDefaultDevice(parsedArgs *args);
int openConnection(parsedArgs *args);
#endif

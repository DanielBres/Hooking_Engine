#include <string>
#include <ctype.h>
#include <windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <fstream>
#include <cstdlib>

using namespace std;
using std::string;

int getProcID(const string& p_name)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 structprocsnapshot = { 0 };

	structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

	if (snapshot == INVALID_HANDLE_VALUE)return 0;
	if (Process32First(snapshot, &structprocsnapshot) == FALSE)return 0;

	while (Process32Next(snapshot, &structprocsnapshot))
	{
		if (!strcmp(structprocsnapshot.szExeFile, p_name.c_str()))
		{
			CloseHandle(snapshot);
			cout << "[+]Process name is: " << p_name << "\n[+]Process ID: " << structprocsnapshot.th32ProcessID << endl;
			return structprocsnapshot.th32ProcessID;
		}
	}
	CloseHandle(snapshot);
	printf("[!]Unable to find Process ID");
	return 0;

}


int main(int argc, char ** argv) {

	string name;

	printf("Enter process name: ");
	cin >> name;

	getProcID(name);
}

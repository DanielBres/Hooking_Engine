#pragma once
#include <string>
#include <winternl.h>
//#include <ctype.h>
#include <windows.h>
//#include <Shlwapi.h>
#include <stdio.h>
#include <tlhelp32.h> 
#include <tchar.h> 
//#include <winnt.h>
#include <psapi.h>
//#include <tchar.h>
#include <iostream>
//#include <wdm.h>
#include <processthreadsapi.h>
//#include <fstream>
//#include <cstdlib>
using namespace std;


//void printError(TCHAR* msg);
//BOOL ListProcessModules(DWORD dwPID);
void GetTargetHandle();


void GetTargetHandle() {

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	
	bool res = CreateProcessA("C:\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pStartupInfo, pProcessInfo);
	
	if (res) {

		cout << "Created target process" << endl;
		GetLastError();
	}
	else {

		cout << "[-] Failed creating process: %s\n" << endl;
	}

	DWORD PID = pProcessInfo->dwProcessId;
	HANDLE PrimThreadHandle = pProcessInfo->hThread;


	BOOL exit_signal = TRUE;

	// Check if Ntdll.dll is loaded (process is suspended).
	while(exit_signal)
	{
		HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
		if (hNtdll == NULL) {
			std::cout << "...Not yet..........\n" << endl;
			//while (ResumeThread(PrimThreadHandle) > 0);
			//    Sleep(200);
			//SuspendThread(PrimThreadHandle);
			continue;
		}
		else {
			exit_signal = FALSE;
		}
	}
	std::cout << " [+] ntdll.dll is loaded, fun stuff can happen now !!!!\n" << endl;
	
	//ListProcessModules(PID);
}

/*
BOOL ListProcessModules(DWORD dwPID)
{
	HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
	MODULEENTRY32 me32;

	//  Take a snapshot of all modules in the specified process. 
	do {
		
		hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);

		if (hModuleSnap == INVALID_HANDLE_VALUE)
		{
			printError((TCHAR*)"CreateToolhelp32Snapshot (of modules)");
			continue;
		}
		
		Sleep(200);

		break;

	} while (TRUE);

	//  Set the size of the structure before using it. 
	me32.dwSize = sizeof(MODULEENTRY32);

	//  Retrieve information about the first module, 
	//  and exit if unsuccessful 
	if (!Module32First(hModuleSnap, &me32))
	{
		printError((TCHAR*)"Module32First");  // Show cause of failure 
		CloseHandle(hModuleSnap);     // Must clean up the snapshot object! 
		return(FALSE);
	}

	//  Now walk the module list of the process, 
	//  and display information about each module 
	do
	{
		_tprintf(TEXT("\n\n     MODULE NAME:     %s"), me32.szModule);
		_tprintf(TEXT("\n     executable     = %s"), me32.szExePath);
		_tprintf(TEXT("\n     process ID     = 0x%08X"), me32.th32ProcessID);
		_tprintf(TEXT("\n     ref count (g)  =     0x%04X"), me32.GlblcntUsage);
		_tprintf(TEXT("\n     ref count (p)  =     0x%04X"), me32.ProccntUsage);
		_tprintf(TEXT("\n     base address   = 0x%08X"), (DWORD)me32.modBaseAddr);
		_tprintf(TEXT("\n     base size      = %d"), me32.modBaseSize);

	} while (Module32Next(hModuleSnap, &me32));

	_tprintf(TEXT("\n"));

	//  Do not forget to clean up the snapshot object. 
	CloseHandle(hModuleSnap);
	return(TRUE);
}


void printError(TCHAR* msg)
{
	DWORD eNum;
	TCHAR sysMsg[256];
	TCHAR* p;

	eNum = GetLastError();
	FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, eNum,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		sysMsg, 256, NULL);

	// Trim the end of the line and terminate it with a null
	p = sysMsg;
	while ((*p > 31) || (*p == 9))
		++p;
	do { *p-- = 0; } while ((p >= sysMsg) &&
		((*p == '.') || (*p < 33)));

	// Display the message
	_tprintf(TEXT("\n  WARNING: %s failed with error %d (%s)"), msg, eNum, sysMsg);
}
*/

int main(int argc, char ** argv) {
	
	GetTargetHandle();
}

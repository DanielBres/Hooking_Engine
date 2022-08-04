#pragma once
#include <iostream>
#include <string>
#include <ctype.h>
#include <windows.h>
#include <Shlwapi.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <psapi.h>
#include <tchar.h>
#include <synchapi.h>
#include "Header.h"
using namespace std;

/*
int PrintModules(DWORD PID)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, PID);
	if (NULL == hProcess)
		return 1;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{
				std::cout << "[---] Module: " << szModName << hMods[i] << endl;
			}
		}
	}
	CloseHandle(hProcess);

	return 0;
}


int GetPid(const string& procName) {
	//
	// Function code taken from:  https://github.com/saeedirha/DLL-Injector/blob/master/DLL_Injector/Source.cpp
	//
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 structprocsnapshot = { 0 };

	structprocsnapshot.dwSize = sizeof(PROCESSENTRY32);

	if (snapshot == INVALID_HANDLE_VALUE)return 0;
	if (Process32First(snapshot, &structprocsnapshot) == FALSE)return 0;

	while (Process32Next(snapshot, &structprocsnapshot))
	{
		if (!strcmp(structprocsnapshot.szExeFile, procName.c_str()))
		{
			CloseHandle(snapshot);
			
			std::cout << "Process ID: " << structprocsnapshot.th32ProcessID << "." << endl;
			return structprocsnapshot.th32ProcessID;
		}
	}
	CloseHandle(snapshot);
	std::cout << "[!]Unable to find Process ID" << endl;
	return 0;
}
*/

// Make sure the DLL is x86 compiled !!!!!!!!
// The DLL will need to resume the thread
bool InjectDLL(const LPCSTR targetPath, const string &DLL_PATH) {
	
	int DLL_PATH_LEN = DLL_PATH.length() + 1;
	
	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();

	if (!AdjustPrivileges())
	{
		std::cout << "[!] Failed adjusting token privileges for injection...\n" << endl;
		system("pause");
	}
	std::cout << "[+] Successfuly adjusted token privileges for injection..." << endl;
	
	CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, pStartupInfo, pProcessInfo);
	HANDLE hProcess = pProcessInfo->hProcess;

	
	if(!hProcess){
		std::cout << "[!] Failed creating target process" << endl;
	}
	else {

		std::cout << "[+] Created target process.\n" << endl;
		
		int PID = pProcessInfo->dwProcessId;
		HANDLE MainThreadHandle = pProcessInfo->hThread;

		std::cout << "[+] Process loaded modules:\n\n" << endl;
		
		LPTHREAD_START_ROUTINE LoadLibAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"Kernel32"), "LoadLibraryA");
		if (!LoadLibAddr) {
			std::cout << "[!] Failed retrieving memory address of LoadLibraryA function" << endl;
			system("pause");
		}
		else {
			
			LPVOID allocation_buffer = VirtualAllocEx(hProcess, NULL, DLL_PATH_LEN, MEM_COMMIT, PAGE_READWRITE);
			if (!allocation_buffer) {
				std::cout << "[!] Failed allocating memory in target process" << endl;
				system("pause");
			}
			else {
				
				std::cout << "[+] Allocated memory in target process at offset: " << allocation_buffer << endl;
				if (!WriteProcessMemory(hProcess, allocation_buffer, DLL_PATH.c_str(), DLL_PATH_LEN, 0)) {
					std::cout << "[!] Failed writing DLL path to target process" << endl;
					system("pause");
				}
				else {
					
					// CreateRemoteThread(<Process Handle>, <lpThreadAttributes = NULL>, <dwStackSize = 0>, <lpStartAddress = LoadLibraryAddr>, <lpParameter = DLL_PATH for LoadLibrary>, <>
					HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, LoadLibAddr, (LPVOID)allocation_buffer, 0, NULL);
					DWORD dwWaitResult;
					
					dwWaitResult = WaitForSingleObject(hThread, INFINITE);
					
					if (!hThread) {
						std::cout << "[!] Failed creating remote thread in target process" << endl;
						system("pause");
					} else {
						std::cout << "[+] Successfully created remote thread in target process. Injected DLL path: \'" << DLL_PATH << "\' at offset (DLL path string!)" << allocation_buffer << " in process ID " << PID << "." << endl;
						ResumeThread(hMainThread);
						return true;
					}
					ResumeThread(hMainThread);
					return false;
				}
			}
		}
	}
}

int AdjustPrivileges()
{
	
	HANDLE Token;
	TOKEN_PRIVILEGES tp;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &Token))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.PrivilegeCount = 1;
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL);
		return 1;
	}
	return 0;
}


int main(int argc, char ** argv) {
	if (argc != 3) {
		std::cout << "\nUsage: DLL_inject.exe <Target process path> <DLL path>\n" << endl;
		std::cout << "Make sure to add \' \"<PATH>\" when providing path strings with spaces.\n" << endl;
		return false;
	}
	else {
		std::cout << "[+] Target Process Name: " << argv[1] << "\n" << endl;
		std::cout << "[+] DLL Path: " << argv[2] << "." << "\n" << endl;
		InjectDLL((LPCSTR)(argv[1]), argv[2]);
	}
		
	return EXIT_SUCCESS;
}

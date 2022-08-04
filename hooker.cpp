// hooker.cpp : Defines the exported functions for the DLL application.
//

/*
	Hooker DLL - Trace Malware API calls from within its process memory using inline hooking.

	Inspired by: 
	- https://github.com/MalwareTech/BasicHook
	- https://www.ired.team/offensive-security/code-injection-process-injection/how-to-hook-windows-api-using-c++
	- https://stackoverflow.com/questions/1969579/getting-a-handle-to-the-processs-main-thread
	
	Extended hook functions array and definitions in order to hook more functions.
	Current aim is to monitor API calls from a malware process (DLL injection) that relate to unpacking/decryption, execution, etc.
	
	**** This is a work in progress ***

*/
#define DLL_EXPORT

#include "stdafx.h"
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
#include "hooker.h"
#include <intrin.h>
#include <fstream>
#include <winsock2.h>
#include <winuser.h>
#include <wininet.h>
#include <processthreadsapi.h>

//#include "pch.h"
using namespace std;

/*
	Functionality:
	--------------
	- Get memory address of the hookedfunction function
	- Read the first 6 bytes of the MessageBoxA - will need these bytes for unhooking the function
	- Create a HookedMessageBox function that will be executed when the original MessageBoxA is called
	- Get memory address of the HookedMessageBox
	- Patch / redirect MessageBoxA to HookedMessageBox
	- Call MessageBoxA. Code gets redirected to HookedMessageBox
	- HookedMessageBox executes its code, prints the supplied arguments, unhooks the MessageBoxA and transfers the code control to the actual MessageBoxA
*/


/*
typedef struct
{
	const char *dll;
	const char *name;
	LPVOID proxy; 
	LPVOID original;

} HOOK_ARRAY;
*/

TdefOldHttpSendRequest OldGetHttpSendRequest;
TdefOldHttpSendRequestA OldHttpSendRequestA;
TdefOldGetCurrentProcessId OldGetCurrentProcessId;
TdefOldInternetOpenA OldInternetOpenA;
TdefOldConnect OldConnect;
TdefOldOpenProcess OldOpenProcess;
TdefOldOpenProcessA OldOpenProcessA;
TdefOldOpenProcessW OldOpenProcessW;
TdefOldVirtualProtect OldVirtualProtect;
TdefOldVirtualAlloc OldVirtualAlloc;
TdefOldVirtualAllocEx OldVirtualAllocEx;
TdefOldVirtualAllocExA OldVirtualAllocExA;
TdefOldVirtualAllocExW OldVirtualAllocExW;
TdefOldWriteProcessMemory OldWriteProcessMemory;
TdefOldResumeThread OldResumeThread;
TdefOldNtResumeThread OldNtResumeThread;
TdefOldSetThreadContext OldSetThreadContext;
TdefOldGetThreadContext OldGetThreadContext;
TdefOldCreateRemoteThread OldCreateRemoteThread;
TdefOldLoadLibraryA OldLoadLibraryA;
TdefOldLoadLibraryW OldLoadLibraryW;
TdefOldRtlDecompressBuffer OldRtlDecompressBuffer;
TdefOldCryptEncrypt OldCryptEncrypt;
TdefOldCryptDecrypt OldCryptDecrypt;
TdefOldCryptGenRandom OldCryptGenRandom;
TdefOldCryptCreateHash OldCryptCreateHash;
TdefOldCryptAcquireContext OldCryptAcquireContext;
TdefOldCryptAcquireCertificatePrivateKey OldCryptAcquireCertificatePrivateKey;
TdefOldCreateProcessA OldCreateProcessA;
TdefOldCreateProcessW OldCreateProcessW;
TdefOldCreateProcessInternalW OldCreateProcessInternalW;
//TdefOldNtCreateUserProcess OldNtCreateUserProcess;
TdefOldGetProcAddress OldGetProcAddress;
TdefOldGetModuleHandleA OldGetModuleHandleA;
//TdefOldFindResource OldFindResource;
TdefOldLoadResource OldLoadResource;
TdefOldFindResourceA OldFindResourceA;
TdefOldCreateThread OldCreateThread;
TdefOldExitProcess OldExitProcess;
TdefOldTerminateProcess OldTerminateProcess;
//TdefOldWriteFile OldWriteFile;
//TdefOldWriteFileW OldWriteFileA;
//TdefOldWriteFileW OldWriteFileW;

HOOK_ARRAY HookArray[] = 
{
	{"Wininet.dll", "HttpSendRequest", (LPVOID)&NewHttpSendRequest, (LPVOID)GetProcAddress(GetModuleHandleA("Wininet.dll"), "HttpSendRequest")},
	{"Wininet.dll", "HttpSendRequestA", (LPVOID)&NewHttpSendRequestA, (LPVOID)GetProcAddress(GetModuleHandleA("Wininet.dll"), "HttpSendRequestA")},
	{"kernel32.dll", "GetCurrentProcessId", (LPVOID)&NewGetCurrentProcessId, (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetCurrentProcessId")},
	{"Wininet.dll", "InternetOpenA", (LPVOID)&NewInternetOpenA, (LPVOID)GetProcAddress(GetModuleHandleA("Wininet.dll"), "InternetOpenA")},
	{"Ws2_32.dll", "connect", (LPVOID)&NewConnect, (LPVOID)GetProcAddress(GetModuleHandleA("Ws2_32.dll"), "connect")},
	{"kernel32.dll", "OpenProcess", (LPVOID)&NewOpenProcess, (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcess")},
	{"kernel32.dll", "OpenProcessA", (LPVOID)&NewOpenProcessA, (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcessA")},
	{"kernel32.dll", "OpenProcessW", (LPVOID)NewOpenProcessW, (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "OpenProcessW")},
	{"kernel32.dll", "VirtualProtect", (LPVOID)&NewVirtualProtect, (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "")},
	{"kernel32.dll", "VirtualAlloc", (LPVOID)&NewVirtualAlloc, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAlloc"))},
	{"kernel32.dll", "VirtualAllocEx", (LPVOID)&NewVirtualAllocEx, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocEx"))},
	{"kernel32.dll", "VirtualAllocExA", (LPVOID)&NewVirtualAllocExA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocExA"))},
	{"kernel32.dll", "VirtualAllocExW", (LPVOID)&NewVirtualAllocExW, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "VirtualAllocExW"))},
	{"kernel32.dll", "WriteProcessMemory", (LPVOID)&NewWriteProcessMemory, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteProcessMemory"))},
	{"kernel32.dll", "NtResumeThread", (LPVOID)&NewNtResumeThread, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "NtResumeThread"))},
	{"kernel32.dll", "ResumeThread", (LPVOID)&NewResumeThread, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "ResumeThread"))},
	{"kernel32.dll", "SetThreadContext", (LPVOID)&NewSetThreadContext, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "SetThreadContext"))},
	{"kernel32.dll", "GetThreadContext", (LPVOID)&NewGetThreadContext, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetThreadContext"))},
	{"kernel32.dll", "CreateRemotethread", (LPVOID)&NewCreateRemoteThread, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), ""))},
	{"kernel32.dll", "LoadLibraryA", (LPVOID)&NewLoadLibraryA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA"))},
	{"kernel32.dll", "LoadLibraryW", (LPVOID)&NewLoadLibraryW, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"))},
	{"kernel32.dll", "RtlDecompressBuffer", (LPVOID)&NewRtlDecompressBuffer, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "RtlDecompressBuffer"))},
	{"advapi32.dll", "CryptEncrypt", (LPVOID)&NewCryptEncrypt, (LPVOID)(GetProcAddress(GetModuleHandleA("advapi32.dll"), "CryptEncrypt"))},
	{"advapi32.dll", "CryptDecrypt", (LPVOID)&NewCryptDecrypt, (LPVOID)(GetProcAddress(GetModuleHandleA("advapi32.dll"), "CryptDecrypt"))},
	{"advapi32.dll", "CryptGenRandom", (LPVOID)&NewCryptGenRandom, (LPVOID)(GetProcAddress(GetModuleHandleA("advapi32.dll"), "CryptGenRandom"))},
	{"advapi32.dll", "CryptCreateHash", (LPVOID)&NewCryptCreateHash, (LPVOID)(GetProcAddress(GetModuleHandleA("advapi32.dll"), "CryptCreateHash"))},
	{"advapi32.dll", "CryptAcquireContext", (LPVOID)&NewCryptAcquireContext, (LPVOID)(GetProcAddress(GetModuleHandleA("advapi32.dll"), "CryptAcquireContext"))},
	{"advapi32.dll", "CryptAcquireCertificatePrivateKey", (LPVOID)&NewCryptAcquireCertificatePrivateKey, (LPVOID)(GetProcAddress(GetModuleHandleA("advapi32.dll"), "CryptAcquireCertificatePrivateKey"))},
	{"kernel32.dll", "CreateProcessA", (LPVOID)&NewCreateProcessA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA"))},
	{"kernel32.dll", "CreateProcessW", (LPVOID)&NewCreateProcessW, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW"))},
	{"kernel32.dll", "CreateProcessInternalW", (LPVOID)&NewCreateProcessInternalW, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessInternalW"))},
	{"kernel32.dll", "GetProcAddress", (LPVOID)&NewGetProcAddress, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"))},
	{"kernel32.dll", "GetModuleHandleA", (LPVOID)&NewGetModuleHandleA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA"))},
	//{"kernel32.dll", "FindResource", (LPVOID)&NewFindResource, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "FindResource"))},
	{"kernel32.dll", "LoadResource", (LPVOID)&NewLoadResource, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadResource"))},
	{"kernel32.dll", "FindResourceA", (LPVOID)&NewFindResourceA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "FindResourceA"))},
	//{"kernel32.dll", "LoadResourceA", (LPVOID)&NewLoadResourceA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadResourceA"))},
	{"kernel32.dll", "CreateThread", (LPVOID)&NewCreateThread, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateThread"))},
	{"kernel32.dll", "ExitProcess", (LPVOID)&NewExitProcess, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess"))},
	{"kernel32.dll", "TerminateProcess", (LPVOID)&NewTerminateProcess, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "TerminateProcess"))},
	//{"kernel32.dll", "WriteFile", (LPVOID)&NewWriteFile, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile"))},
	//{"kernel32.dll", "WriteFileA", (LPVOID)&NewWriteFileA, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFileA"))},
	//{"kernel32.dll", "WriteFileW", (LPVOID)&NewWriteFileW, (LPVOID)(GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFileW"))},
	//{"kernel32.dll", ""},
};


int HookAll()
{
	
	PrintModules();
	//ResumeMainThread(GetMainThread());
	SIZE_T bytesWritten = 0;
	SIZE_T bytesRead = 0;
	LPVOID OriginalAddress = NULL;
	char OriginalBytes[6] = {};
	int i, NumEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);
	char patch[6] = { 0 };

	for (i = 0; i < NumEntries; i++) {
		
		if (&HookArray[i].original == NULL) {
			continue;
			OriginalAddress = &HookArray[i].original;
		}
		
		// save the first 6 bytes of the original MessageBoxA function - will need for unhooking
		ReadProcessMemory(GetCurrentProcess(), OriginalAddress, OriginalBytes, 6, &bytesRead);

		// create a patch "push <address of new MessageBoxA); ret"
		memcpy_s(patch, 1, "\x68", 1);
		memcpy_s(patch + 1, 4, &OriginalAddress, 4);
		memcpy_s(patch + 5, 1, "\xC3", 1);
		
		// patch the MessageBoxA
		WriteProcessMemory(GetCurrentProcess(), (LPVOID)OriginalAddress /*first 6 bytes of original func*/, patch /*push\ret*/, sizeof(patch), &bytesWritten);

		// clear patch array for next hook 
		std::fill_n(patch, 6, 0); 
	}
	CreateLogFile();
	return 0;
}


int UnHookAll() 
{

	SIZE_T bytesWritten = 0;
	SIZE_T bytesRead = 0;
	LPVOID OriginalAddress = NULL;
	char OriginalBytes[6] = {};
	int i, NumEntries = sizeof(HookArray) / sizeof(HOOK_ARRAY);
	char patch[6] = { 0 };
	HANDLE hProcess = GetCurrentProcess();

	for (i = 0; i < NumEntries; i++) {

		
		// save the first 6 bytes of the original MessageBoxA function - will need for unhooking
		ReadProcessMemory(hProcess, OriginalAddress, OriginalBytes, 6, &bytesRead);

		OriginalAddress = &HookArray[i].original;
		
		// patch the MessageBoxA
		WriteProcessMemory(hProcess, (LPVOID)OriginalAddress /*first 6 bytes of original func*/, OriginalBytes, sizeof(OriginalBytes), &bytesWritten);

		// clear patch array for next hook 
		std::fill_n(patch, 6, 0); 
	}
	CloseHandle(hProcess);
	
	return 0;
}


void ResumeMainThread(HANDLE hThread)
{
	std::cout << "[+] Resuming main thread.\n" << endl;
	ResumeThread(hThread);
}


int PrintModules()
{
	int PID = GetCurrentProcessId();
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


// Code taken from https://www.codeproject.com/Questions/78801/How-to-get-the-main-thread-ID-of-a-process-known-b
#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif


// Function code taken from https://www.codeproject.com/Questions/78801/How-to-get-the-main-thread-ID-of-a-process-known-b
HANDLE GetMainThread()
{
	DWORD dwMainThreadID = 0;
	ULONGLONG ullMinCreateTime = MAXULONGLONG;

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	if (hThreadSnap != INVALID_HANDLE_VALUE) {
		THREADENTRY32 th32;
		th32.dwSize = sizeof(THREADENTRY32);
		BOOL bOK = TRUE;
		for (bOK = Thread32First(hThreadSnap, &th32); bOK; bOK = Thread32Next(hThreadSnap, &th32)) {

			HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, TRUE, th32.th32ThreadID);
			if (hThread) {
				FILETIME afTimes[4] = { 0 };
				if (GetThreadTimes(hThread,
					&afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
					ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime,
						afTimes[0].dwHighDateTime);
					if (ullTest && ullTest < ullMinCreateTime) {
						ullMinCreateTime = ullTest;
						dwMainThreadID = th32.th32ThreadID; // let it be main... :)
					}
				}
				return hThread;
			}

		}

	}
	return NULL;
}



int CreateLogFile()
{

	std::fstream file;

	file.open("API_calls.txt", ios::out);

	if (!file)
	{
		MessageBox(NULL, (LPCWSTR)L"Error in creating file!!!", (LPCWSTR)L"File Error", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2); 
		//cout << "Error in creating file!!!";
		return 0;
	}
	//file << "test" << endl;
	MessageBox(NULL, (LPCWSTR)L"Successfully created API_calls.txt !!!", (LPCWSTR)L"File Creation Success", MB_ICONWARNING | MB_CANCELTRYCONTINUE | MB_DEFBUTTON2);
	file.close();
	return 0;
}

/*
DWORD GetMainThreadId()
{
	LPVOID lpTid;

	_asm
	{
		mov eax, fs:[18h] // fs:[18h] is the Thread Environment Block (TEB).
		add eax, 36 //24h
		mov[lpTid], eax //Get
	}

	HANDLE hProcess = GetCurrentProcess();
	if (hProcess == NULL)
		return NULL;

	DWORD dwTid;
	if (ReadProcessMemory(hProcess, lpTid, &dwTid, sizeof(dwTid), NULL) == FALSE)
	{
		CloseHandle(hProcess);
		return NULL;
	}

	CloseHandle(hProcess);

	return dwTid;
}
*/


/*
Trampolines:
-----------------
- Defines the hook functions.
- Hook functions process received parameters from the original function calls and print them.
- Each API function has its own hook function.
- For example: OpenProcess --> OldProcess (original OpenProcess withoout hook), NewOpenProcess (execution is redirected to this function after hook patch is written to the
first 6 bytes of original function in memory. NewOpenProcess is called first and then calls OldOpenProcess to resume execution to original function in memory.
*/

BOOL WINAPI NewHttpSendRequest(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] HttpSendRequest called\n -- > Request headers: " << lpszHeaders << ", optional data: " << lpOptional << endl;
	outfile.close();
	return OldGetHttpSendRequest(hRequest, lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}


BOOL WINAPI NewHttpSendRequestA(HINTERNET hRequest, LPCTSTR lpszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength)
{
	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] HttpSendRequestA called\n -- > Request headers: " << lpszHeaders << ", optional data: " << lpOptional << endl;
	outfile.close();
	return OldHttpSendRequestA(hRequest,lpszHeaders, dwHeadersLength, lpOptional, dwOptionalLength);
}


DWORD WINAPI NewGetCurrentProcessId()
{
	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] GetCurrentProcessId called\n" << endl;
	outfile.close();
	return OldGetCurrentProcessId();
}

void WINAPI NewInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] InternetOpenA called --> user agent: " << lpszAgent << ", access type: " << dwAccessType << "\n" << endl;
	outfile.close();
	return OldInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

int WSAAPI NewConnect(SOCKET s, const sockaddr *name, int namelen)
{
	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] connect called --> socket address: " << name << "\n" << endl;
	outfile.close();
	return OldConnect(s, name, namelen);
}


HANDLE WINAPI NewOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] OpenProcess called --> Process ID " << dwProcessId << "was opened with disired access: " << dwDesiredAccess << endl;
	outfile.close();
	return OldOpenProcess((DWORD)dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI NewOpenProcessA(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] OpenProcess called --> Process ID " << dwProcessId << "was opened with disired access: " << dwDesiredAccess << endl;
	return OldOpenProcess((DWORD)dwDesiredAccess, bInheritHandle, dwProcessId);
}

HANDLE WINAPI NewOpenProcessW(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] OpenProcessW called --> Process ID " << dwProcessId << "was opened with disired access: " << dwDesiredAccess << endl;
	outfile.close();
	return OldOpenProcess((DWORD)dwDesiredAccess, bInheritHandle, dwProcessId);
}

int WINAPI NewVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect) {

	if (flNewProtect != PAGE_EXECUTE_READWRITE || flNewProtect != PAGE_EXECUTE || flNewProtect != PAGE_EXECUTE_READ || flNewProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualProtect((LPVOID)lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
	else {

		std::ofstream outfile;
		outfile.open("API_calls.txt", std::ios_base::app);
		outfile << "Memory permissions changed to " << flNewProtect << " on address " << lpAddress << ". The size of the region is " << dwSize << ".\n" << endl;
		outfile.close();
		return OldVirtualProtect((LPVOID)lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}
}

LPVOID WINAPI NewVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE && flProtect != PAGE_EXECUTE && flProtect != PAGE_EXECUTE_READ && flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	}
	else {

		std::ofstream outfile;
		outfile.open("API_calls.txt", std::ios_base::app);
		outfile << "Memory region was allocated at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		outfile.close();
		return OldVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
	}
}

LPVOID WINAPI NewVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE && flProtect != PAGE_EXECUTE && flProtect != PAGE_EXECUTE_READ && flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
	else
	{

		std::ofstream outfile;
		outfile.open("API_calls.txt", std::ios_base::app);
		outfile << "Process handle " << hProcess << "was used to allocate memory at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		outfile.close();
		return OldVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
}

LPVOID WINAPI NewVirtualAllocExA(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE || flProtect != PAGE_EXECUTE || flProtect != PAGE_EXECUTE_READ || flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAllocExA(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
	else
	{

		std::ofstream outfile;
		outfile.open("API_calls.txt", std::ios_base::app);
		outfile << "Process handle " << hProcess << "was used to allocate memory at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		outfile.close();
		return OldVirtualAllocExA(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
}

LPVOID WINAPI NewVirtualAllocExW(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {

	if (flProtect != PAGE_EXECUTE_READWRITE || flProtect != PAGE_EXECUTE || flProtect != PAGE_EXECUTE_READ || flProtect != PAGE_EXECUTE_WRITECOPY) {

		return OldVirtualAllocExW(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
	else
	{
		std::ofstream outfile;
		outfile.open("API_calls.txt", std::ios_base::app);
		outfile << "Process handle " << hProcess << "was used to allocate memory at " << lpAddress << "with permissions " << flProtect << ". The size of the region is " << dwSize << ".\n" << endl;
		outfile.close();
		return OldVirtualAllocExW(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}
}

int WINAPI NewWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T *lpNumberOfBytesWritten) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "Process handle " << hProcess << "was used to write " << lpNumberOfBytesWritten << " bytes in memory at " << lpBaseAddress << "." << endl;
	outfile.close();
	return OldWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

int WINAPI NewNtResumeThread(IN HANDLE ThreadHandle, OUT PULONG SuspendCount) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] NtResumeThread called --> Handle " << ThreadHandle << " was used to resume a thread.\n" << endl;
	outfile.close();
	return OldNtResumeThread(ThreadHandle, SuspendCount);
}

int WINAPI NewResumeThread(HANDLE hThread) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] ResumeThread called --> Handle " << hThread << " was used to resume a thread.\n" << endl;
	outfile.close();
	return OldResumeThread(hThread);
}

int WINAPI NewSetThreadContext(HANDLE hThread, const CONTEXT *lpContext) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] SetThreadContext called --> Handle " << hThread << " was used to set the thread context.\n" << endl;
	outfile << "[+] Thread entry point (saved in EAX register): " << lpContext << ".\n" << endl;
	outfile.close();
	return OldSetThreadContext(hThread, lpContext);
}

int WINAPI NewGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] GetThreadContext called --> Handle " << hThread << " was used to get the thread context.\n" << endl;
	outfile.close();
	return OldGetThreadContext(hThread, lpContext);
}

HANDLE WINAPI NewCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CreateRemoteThread called --> Process handle " << hProcess << " was used to create the remote thread context. New Thread entry point: " << lpStartAddress << ".\n" << endl;
	outfile.close();
	return OldCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

HMODULE WINAPI NewLoadLibraryA(LPCSTR lpLibFileName) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] LoadLibraryA called --> Loaded module: " << lpLibFileName << ".\n" << endl;
	outfile.close();
	return OldLoadLibraryA(lpLibFileName);
}

HMODULE WINAPI NewLoadLibraryW(LPCWSTR lpLibFileName) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] LoadLibraryA called --> Loaded module: " << lpLibFileName << ".\n" << endl;
	outfile.close();
	return OldLoadLibraryW(lpLibFileName);
}

NTSTATUS WINAPI NewRtlDecompressBuffer(USHORT CompressionFormat, PUCHAR UncompressedBuffer, ULONG  UncompressedBufferSize, PUCHAR CompressedBuffer, ULONG  CompressedBufferSize, PULONG FinalUncompressedSize) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] RtlDecompressBuffer called --> uncompressed buffer: " << UncompressedBuffer << ", buffer size: " << FinalUncompressedSize << "compression format: " << CompressionFormat << ".\n" << endl;
	outfile.close();
	return OldRtlDecompressBuffer(CompressionFormat, UncompressedBuffer, UncompressedBufferSize, CompressedBuffer, CompressedBufferSize, FinalUncompressedSize);
}

bool WINAPI NewCryptEncrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CryptEncrypt called --> encryption buffer: " << pbData << ", buffer length (bytes): " << pdwDataLen << ".\n" << endl;
	outfile.close();
	return OldCryptEncrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
}

bool WINAPI NewCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CryptDecrypt called --> decryption buffer: " << pbData << ", buffer length (bytes): " << pdwDataLen << ".\n" << endl;
	outfile.close();
	return OldCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
}

bool WINAPI NewCryptGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CryptGenRandom called --> data buffer: " << pbBuffer << ", buffer length: " << dwLen << "\n" << endl;
	outfile.close();
	return OldCryptGenRandom(hProv, dwLen, pbBuffer);
}

bool WINAPI NewCryptCreateHash(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY  hKey, DWORD dwFlags, HCRYPTHASH *phHash) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CryptCreateHash called --> Alg ID: " << Algid << ", key (if keyed-hash such as HMAC/MAC/CBC mode algorithm): " << hKey << "\n" << endl;
	outfile.close();
	return OldCryptCreateHash(hProv, Algid, hKey, dwFlags, phHash);
}

BOOL WINAPI NewCryptAcquireContext(HCRYPTPROV *phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CryptAcquireContext called --> key container name: " << szContainer << ",  CSP name: " << szProvider << ", provider Type: " << dwProvType << ", flags: " << dwFlags << "\n" << endl;
	outfile.close();
	return OldCryptAcquireContext(phProv, szContainer, szProvider, dwProvType, dwFlags);
}

BOOL WINAPI NewCryptAcquireCertificatePrivateKey(PCCERT_CONTEXT pCert, DWORD dwFlags, void *pvParameters, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE *phCryptProvOrNCryptKey, DWORD *pdwKeySpec, BOOL *pfCallerFreeProvOrNCryptKey) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CryptAcquireCertificatePrivateKey  called --> CERT_CONTEXT struct address: " << pCert << ", flags: " << dwFlags << "\n << endl";
	outfile.close();
	return OldCryptAcquireCertificatePrivateKey(pCert, dwFlags, pvParameters, phCryptProvOrNCryptKey, pdwKeySpec, pfCallerFreeProvOrNCryptKey);
}

HANDLE WINAPI NewCreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CreateProcessA called --> process name: " << lpApplicationName << ", commandline: " << lpCommandLine << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	outfile.close();
	return OldCreateProcessA(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

HANDLE WINAPI NewCreateProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CreateProcessw called --> process name: " << lpApplicationName << ", commandline: " << lpCommandLine << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	outfile.close();
	return OldCreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
}

DWORD WINAPI NewCreateProcessInternalW(DWORD unknown1, LPCTSTR lpApplicationName, LPTSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCTSTR lpCurrentDirectory, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation, DWORD unknown2) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CreateProcessw called --> process name: " << lpApplicationName << ", commandline: " << lpCommandLine << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	outfile.close();
	return OldCreateProcessInternalW(unknown1, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, unknown2);
}

LPVOID WINAPI NewGetProcAddress(HMODULE hModule, LPCSTR  lpProcName) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] GetProcAddress called --> Module: " << hModule << ", API function: " << lpProcName << "\n" << endl;
	outfile.close();
	return OldGetProcAddress(hModule, lpProcName);
}

HMODULE WINAPI NewGetModuleHandleA(LPCSTR lpModuleName) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile  << "[+] GetModuleHandleA called --> Mudole: " << lpModuleName << "\n" << endl;
	outfile.close();
	return OldGetModuleHandleA(lpModuleName);
}

HRSRC WINAPI NewFindResourceA(HMODULE hModule, LPCSTR lpName, LPCSTR lpType) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] FindResourceA called-- > Resource name: " << lpName << ", Owning PE file: " << hModule << "\n" << endl;
	outfile.close();
	return OldFindResourceA(hModule, lpName, lpType);
}

HGLOBAL WINAPI NewLoadResource(HMODULE hModule, HRSRC hResInfo) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] LoadResourceA called-- > Resource handle and information: " << hResInfo << ", Owning PE file: " << hModule << "\n" << endl;
	outfile.close();
	return OldLoadResource(hModule, hResInfo);
}

HANDLE WINAPI NewCreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE  lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] CreateThread called --> Thread start address: " << lpStartAddress << ", Creation flags: " << dwCreationFlags << "\n" << endl;
	outfile.close();
	return OldCreateThread(lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
}

LPVOID WINAPI NewExitProcess(UINT uExitCode) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] ExitProcess called --> exit code: " << uExitCode << "\n" << endl;
	outfile.close();
	return OldExitProcess(uExitCode);
}

int WINAPI NewTerminateProcess(HANDLE hProcess, UINT uExitCode) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] TerminateProcess called --> Process to terminate: " << hProcess << ", exit code: " << uExitCode << "\n" << endl;
	outfile.close();
	return OldTerminateProcess(hProcess, uExitCode);
}

/*
BOOL WINAPI NewWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] WriteFile called --> file handle: " << hFile << ", buffer: " << lpBuffer << "\n" << endl;
	outfile.close();
	return OldWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI NewWriteFileA(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] WriteFileA called --> file handle: " << hFile << ", buffer: " << lpBuffer << "\n" << endl;
	outfile.close();
	return OldWriteFileA(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

BOOL WINAPI NewWriteFileW(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {

	std::ofstream outfile;
	outfile.open("API_calls.txt", std::ios_base::app);
	outfile << "[+] WriteFileW called --> file handle: " << hFile << ", buffer: " << lpBuffer << "\n" << endl;
	outfile.close();
	return OldWriteFileW(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}
*/





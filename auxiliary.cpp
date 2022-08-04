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
//#include "pch.h"
using namespace std;



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


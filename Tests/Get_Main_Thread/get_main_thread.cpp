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
#include <intrin.h>
using namespace std;


HANDLE GetTargetHandle() {

	LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
	LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
	bool res = CreateProcessA("C:\\windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE, 0x00000004, NULL, NULL, pStartupInfo, pProcessInfo);

	if (res) {

		cout << "[+] Created target process" << endl;
	}
	else {

		cout << "[-] Failed creating process: %s\n" << endl;
	}
	return pProcessInfo->hProcess;
}


DWORD GetMainThreadId()
{
	LPVOID lpTid;

	_asm
	{
		mov eax, fs:[18h] // fs:[18h] is the Thread Environment Block (TEB).
		add eax, 36 // =24h.
		mov[lpTid], eax // Save primary thread ID in EAX.
	}

	HANDLE hProcess = GetTargetHandle();
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


int main(int argc, char ** argv)
{
	HANDLE hProcess = GetTargetHandle();
	int dwTid = GetMainThreadId();
	
	HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, dwTid);
	
	ResumeThread(hThread);

	return 0;
}

// dllmain.cpp : Defines the entry point for the DLL application.
#define DLL_EXPORT
#include "stdafx.h"
#include "hooker.h"

BOOL APIENTRY DllMain( HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		
		DisableThreadLibraryCalls(hModule);
		if (GetModuleHandleA("kernel32.dll") != NULL) 
		{
			
			HookAll();
			PrintModules();
			//UnHookAll();
		}
				
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		UnHookAll();
        break;
    }
    return TRUE;
}


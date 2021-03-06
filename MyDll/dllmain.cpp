// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <Windows.h>
#include <IMM.H>
#include <immdev.h>
#include <tchar.h>

#define EXTERN_DLL_EXPORT extern "C" __declspec(dllexport)


EXTERN_DLL_EXPORT LRESULT  foo( _In_ int code, _In_ WPARAM wParam, _In_ LPARAM lParam );


LRESULT  foo( _In_ int code, _In_ WPARAM wParam, _In_ LPARAM lParam )
{
	return CallNextHookEx( NULL, code, wParam, lParam );
}



BOOL APIENTRY DllMain( HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	/* Open file*/
	switch ( ul_reason_for_call )
	{
		case DLL_PROCESS_ATTACH:
			MessageBox( NULL, L"Dll injected.", L"", 0 );
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			MessageBox( NULL, L"Dll detached.", L"", 0 );
			break;

	}


	return TRUE;
}


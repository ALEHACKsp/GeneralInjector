#include "stdafx.h"

#include <TlHelp32.h>
#include <strsafe.h>
#include "Helper.h"

static BOOL SetPrivilege(
     HANDLE hToken,          // token handle
     LPCTSTR Privilege,      // Privilege to enable/disable
     BOOL bEnablePrivilege   // TRUE to enable.  FALSE to disable
)
{
     TOKEN_PRIVILEGES tp;
     LUID luid;
     TOKEN_PRIVILEGES tpPrevious;
     DWORD cbPrevious = sizeof( TOKEN_PRIVILEGES );

     if ( !LookupPrivilegeValue( NULL, Privilege, &luid ) ) return FALSE;

     // 
     // first pass.  get current privilege setting
     // 
     tp.PrivilegeCount = 1;
     tp.Privileges[0].Luid = luid;
     tp.Privileges[0].Attributes = 0;

     AdjustTokenPrivileges(
          hToken,
          FALSE,
          &tp,
          sizeof( TOKEN_PRIVILEGES ),
          &tpPrevious,
          &cbPrevious
     );

     if ( GetLastError() != ERROR_SUCCESS ) return FALSE;

     // 
     // second pass.  set privilege based on previous setting
     // 
     tpPrevious.PrivilegeCount = 1;
     tpPrevious.Privileges[0].Luid = luid;

     if ( bEnablePrivilege ) {
          tpPrevious.Privileges[0].Attributes |= ( SE_PRIVILEGE_ENABLED );
     }
     else {
          tpPrevious.Privileges[0].Attributes ^= ( SE_PRIVILEGE_ENABLED &
               tpPrevious.Privileges[0].Attributes );
     }

     AdjustTokenPrivileges(
          hToken,
          FALSE,
          &tpPrevious,
          cbPrevious,
          NULL,
          NULL
     );

     if ( GetLastError() != ERROR_SUCCESS ) return FALSE;

     return TRUE;
}


static BOOLEAN EnableDebugPrivilege()
{
     HANDLE hToken = NULL;
     TOKEN_PRIVILEGES tokenPriv;
     LUID luidDebug;
     if ( OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken ) != FALSE )
     {
          if ( LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luidDebug ))
          {
               tokenPriv.PrivilegeCount = 1;
               tokenPriv.Privileges[0].Luid = luidDebug;
               tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
               AdjustTokenPrivileges( hToken, FALSE, &tokenPriv, 0, NULL, NULL );
          }
     }
     CloseHandle( hToken );
     return TRUE;
}


BOOLEAN Helper::IsProcessWow64( DWORD Pid , PBOOL IsWow64)
{

     EnableDebugPrivilege();
     HANDLE hProcess = OpenProcess( PROCESS_QUERY_INFORMATION, FALSE, Pid );
     if ( hProcess &&
          IsWow64Process( hProcess, IsWow64 ) )
     {
          return TRUE;
     }

     return FALSE;
}

BOOLEAN Helper::GetProcessFullpath( DWORD Pid ,LPTSTR ImagePath)
{
     if ( Pid == 0 )	return FALSE;	// Skip Idle process

     HANDLE hModuleSnap;
     MODULEENTRY32  me32 = { 0 };
     me32.dwSize = sizeof( me32 );

     EnableDebugPrivilege();
     hModuleSnap = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, Pid );
     if ( hModuleSnap != INVALID_HANDLE_VALUE )
     {
          if ( Module32First( hModuleSnap, &me32 ) )
          {
               _tcscpy_s( ImagePath, MAX_PATH, me32.szExePath );
               CloseHandle( hModuleSnap );
               return TRUE;
               
          }
          CloseHandle( hModuleSnap );
     }
     return FALSE;
}

#ifndef _AMD64_
BOOLEAN Helper::IsWow64Emulator()
{
     // IsWow64Process()
     // For 32 bit process in x86 : return false
     // For 32 bit process in x64 : return true
     BOOL isWow64;
     if ( IsProcessWow64( GetCurrentProcessId(), &isWow64 ) )
          return isWow64;
     return FALSE;
}
#endif
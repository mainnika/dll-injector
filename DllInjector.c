/*
 *  DllInjector.c
 *  
 *  Copyright (C) 2008  Ahmed Obied
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation; either version 2
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 *  Usage: DllInjector.exe [DLL path] [Target Process ID]
 */

#include <windows.h>
#include <stdio.h>

BOOL Inject(LPSTR dllPath, DWORD pID)
{
	HANDLE hProcess, hThread;
	LPVOID mRegion;
	BOOL status;
	FARPROC loadLibrary;
	
	printf("[-] Target Process ID: %d\n", pID);
	printf("[-] DLL Path: %s\n\n", dllPath);
	printf("[-] Opening the target process ... ");

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
	if (hProcess == NULL) {
		printf("[OpenProcess failure]\n");
		return FALSE;
	}

	printf("[success]\n");
	printf("[-] Allocating memory in the target process ... ");

	mRegion = VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE); 
	if (mRegion == NULL) {
		printf("[VirtualAllocEx failure]\n");
		return FALSE;
	}

	printf("[success]\n");
	printf("[-] Writing to the allocated memory in the target process ... ");

	status = WriteProcessMemory(hProcess, mRegion, (LPCVOID)dllPath, strlen(dllPath), NULL);
	if (!status) {
		printf("[WriteProcessMemory failure]\n");
		return FALSE;
	}

	printf("[success]\n");
	printf("[-] Creating a remote thread in the target process ... ");

	loadLibrary = GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibrary, mRegion, 0, NULL);
	if (hThread == NULL) {
		printf("[CreateRemoteThread failure]\n");
		return FALSE;
	}

	printf("[success]\n");

	WaitForSingleObject(hThread, INFINITE);
	VirtualFreeEx(hProcess, mRegion, strlen(dllPath), MEM_RELEASE);
	CloseHandle(hThread);	
	CloseHandle(hProcess);

	return TRUE;
}

int main(int argc, char **argv)
{
	if (argc != 3) {
		printf("Usage: ./%s [DLL path] [Target Process ID]\n", argv[0]);
		exit(1);
	}

	printf("\n");
	printf("[****************** DLLInjector ******************]\n");
	printf("By Ahmed Obied\n\n");

	if (Inject(argv[1], atoi(argv[2])))
		printf("\n[-] Injecting \"%s\" into %s succeeded\n", argv[1], argv[2]);
	else
		printf("\n[-] Injecting \"%s\" into %s failed\n", argv[1], argv[2]);

	printf("[*************************************************]\n");

	return 0;
}
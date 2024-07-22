#include <windows.h>
#include <iostream>
#include "Encrypt.hpp"
#include "Protection/lazy.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <string>
#include <windows.h>



using namespace std;
void IfDebugActiveProcess(const char*);
typedef NTSTATUS(__stdcall* _NtSetInformationThread)(_In_ HANDLE, _In_ THREAD_INFORMATION_CLASS, _In_ PVOID, _In_ ULONG);




void HwidBan() {


	char buffer[MAX_PATH];
	GetTempPathA(MAX_PATH, buffer); // Obtener el directorio temporal de Windows

	string tempDir = buffer;
	string fileName = Encrypt("wctKO02.tmp").decrypt(); // Nombre del archivo a crear

	string filePath = tempDir + "\\" + fileName; // Ruta completa del archivo

	ofstream outputFile(filePath); // Crear el archivo en el directorio temporal

	if (outputFile.is_open()) {
		outputFile << Encrypt("Este es un archivo de ejemplo en el directorio temporal del usuario.").decrypt() << endl;
		outputFile.close();
		cout << Encrypt("Archivo creado correctamente en: ").decrypt() << filePath << endl;
	}
	else {
		cout << Encrypt("Error al crear el archivo en el directorio temporal.").decrypt() << endl;
	}
}
const int MAX_PATH_LENGTH = MAX_PATH;

// Función para verificar si el archivo de ban existe en el directorio temporal
bool checkhwidban() {
	char buffer[MAX_PATH_LENGTH];
	GetTempPathA(MAX_PATH_LENGTH, buffer); // Obtener el directorio temporal de Windows

	string tempDir = buffer;
	string fileName = Encrypt("wctKO02.tmp").decrypt(); // Nombre del archivo a buscar

	string filePath = tempDir + "\\" + fileName; // Ruta completa del archivo

	// Verificar si el archivo existe
	DWORD dwAttrib = GetFileAttributesA(filePath.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}


void IfDebugString()
{
	SetLastError(0);
	OutputDebugStringA(Encrypt("Anti Debug"));
	if (GetLastError() != 0)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

void IfIsDebuggerPresent()
{
	BOOL found = false;
	found = IsDebuggerPresent();
	if (found)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

void IfCheckRemoteDebuggerPresent()
{
	HANDLE process = INVALID_HANDLE_VALUE;
	BOOL found = false;
	process = GetCurrentProcess();
	CheckRemoteDebuggerPresent(process, &found);
	if (found)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

void IfCheckWindowClassName()
{
	BOOL found = false;
	HANDLE window = NULL;
	const wchar_t* x64dbg = Encrypt(L"Qt5QWindowIcon");
	const wchar_t* processhacker1 = Encrypt(L"ProcessHacker");
	const wchar_t* processhacker2 = Encrypt(L"MainWindowClassName");
	const wchar_t* ida = Encrypt(L"Qt5153QTQWindowIcon");
	const wchar_t* cheatengine = Encrypt(L"Window");
	const wchar_t* filegrab = Encrypt(L"WindowsForms10.Window.8.app.0.378734a");
	window = FindWindow(x64dbg, NULL);
	if (window)
	{
		found = true;
	}
	window = FindWindow(processhacker1, NULL);
	if (window)
	{
		found = true;
	}
	window = FindWindow(processhacker2, NULL);
	if (window)
	{
		found = true;
	}
	window = FindWindow(ida, NULL);
	if (window)
	{
		found = true;
	}
	window = FindWindow(cheatengine, NULL);
	if (window)
	{
		found = true;
	}
	window = FindWindow(filegrab, NULL);
	if (window)
	{
		found = true;
	}
	if (found)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

void IfDebugActiveProcess(const char* cpid)
{
	BOOL found = false;
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(si);
	TCHAR szPath[MAX_PATH];
	DWORD exitCode = 0;
	CreateMutex(NULL, false, Encrypt(L"Anti Debug"));
	if (GetLastError() != ERROR_SUCCESS)
	{
		if (DebugActiveProcess((DWORD)atoi(cpid)))
		{
			return;
		}
		else
		{
			HwidBan();
			LI_FN(exit)(555);
		}
	}
	DWORD pid = GetCurrentProcessId();
	GetModuleFileName(NULL, szPath, MAX_PATH);
	char cmdline[MAX_PATH + 1 + sizeof(int)];
	snprintf(cmdline, sizeof(cmdline), Encrypt("%ws %d"), szPath, pid);
	BOOL success = CreateProcessA(
	NULL,
	cmdline,
	NULL,
	NULL,
	false,
	0,
	NULL,
	NULL,
	&si,
	&pi);
	WaitForSingleObject(pi.hProcess, INFINITE);
	GetExitCodeProcess(pi.hProcess, &exitCode);
	if (exitCode == 555)
	{
		found = true;
	}
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	if (found)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

DWORD WINAPI Dummy(LPVOID lpParam)
{
	while (true)
	{
		Sleep(0);
	}
}

void IfResumeDummy()
{
	HANDLE dummy = CreateThread(NULL, NULL, Dummy, NULL, NULL, NULL);
	while (true)
	{
		if (ResumeThread(dummy) >= 1)
		{
			HwidBan();
			LI_FN(exit)(0);
			for (long long int i = 0; ++i; (&i)[i] = i);
			*((char*)NULL) = 0;
		}
		Sleep(1);
	}
}

void IfCloseHandleException()
{
	HANDLE Invalid = (HANDLE)0xBEEF;
	DWORD found = false;
	__try
	{
		CloseHandle(Invalid);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		found = true;
	}
	if (found)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

void IfHardwareDebugRegisters()
{
	BOOL found = false;
	CONTEXT ctx = { 0 };
	HANDLE hThread = GetCurrentThread();

	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	if (GetThreadContext(hThread, &ctx))
	{
		if ((ctx.Dr0 != 0x00) || (ctx.Dr1 != 0x00) || (ctx.Dr2 != 0x00) || (ctx.Dr3 != 0x00) || (ctx.Dr6 != 0x00) || (ctx.Dr7 != 0x00))
		{
			found = true;
		}
	}
	if (found)
	{
		HwidBan();
		LI_FN(exit)(0);
	}
}

void IfNtSetInformationThread()
{
	THREAD_INFORMATION_CLASS ThreadHideFromDebugger = (THREAD_INFORMATION_CLASS)0x11;
	HMODULE hNtdll = LoadLibraryW(Encrypt(L"ntdll.dll"));
	if (hNtdll == INVALID_HANDLE_VALUE || hNtdll == NULL)
	{
		return;
	}
	_NtSetInformationThread NtSetInformationThread = NULL;
	NtSetInformationThread = (_NtSetInformationThread)GetProcAddress(hNtdll, Encrypt("NtSetInformationThread"));
	if (NtSetInformationThread == NULL)
	{
		return;
	}
	NtSetInformationThread(GetCurrentThread(), ThreadHideFromDebugger, 0, 0);
}

void IfDebugBreak()
{
	__try
	{
		DebugBreak();
	}
	__except (GetExceptionCode() == EXCEPTION_BREAKPOINT ?
		EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH)


	{
	}
}

void Thread()
{
	while (true)
	{
		IfDebugString();
		IfIsDebuggerPresent();
		IfCheckRemoteDebuggerPresent();
		IfCheckWindowClassName();
		IfCloseHandleException();
		IfHardwareDebugRegisters();
		IfNtSetInformationThread();
		IfDebugBreak();
	}
}
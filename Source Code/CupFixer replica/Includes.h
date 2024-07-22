#pragma once


#include <iostream>
#include <windows.h>
#include <vcruntime.h>
#include <tlhelp32.h>
#include <uxtheme.h>
#include <dwmapi.h>
#include <winternl.h>
#include <thread>

#include <vector>
#include <array>
#include <WinInet.h>
#include <urlmon.h>


#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "Winmm.lib")
#pragma comment(lib, "Wininet.lib")

#define GLFW_EXPOSE_NATIVE_WIN32


//#include "Comm.h"


using namespace std;



std::string tm_to_readable_time(tm ctx) {
	char buffer[80];

	strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

	return std::string(buffer);
}

static std::time_t string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}



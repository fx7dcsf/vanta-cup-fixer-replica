#include <iostream>
#include <Windows.h>
#include <chrono>
#include <thread>
#include <cstdlib>
#include <ctime>
#include "resource-.h"
#include "auth.hpp"
#include <string>
#include "utils.hpp"
#include "skStr.h"
#include "Protection.hpp"
#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <thread>
#include <chrono>
#include <iostream>
#include <string>
#include <Windows.h>
#include <WinINet.h>
#include <fstream>
#include <iostream>
#include <sys/stat.h>
#include <wchar.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include <cstdlib>
#include <ctime>
#include <vector>
#include <string>
#include <Windows.h>
#include <iostream>
#include <filesystem>
#include <cstdlib>
#include <iostream>
#include <vector> // Added this line to include the vector header
#include <filesystem>
#include <iostream>
#include <windows.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "Wininet.lib") // Link with WinINet library
#include <string> // Include string header for std::wstring
#include <Wininet.h> // Include WinINet header for Internet functions
#include <iostream>
#include <thread>
#include <chrono>
#include <Windows.h>
#include <iostream>
#include <string>
#include <cstdlib> // For system()


#pragma comment(lib, "wininet.lib")
using namespace std;
namespace fs = std::filesystem;




bool DownloadFile(const std::wstring& url, const std::wstring& filePath) {
	HINTERNET hInternet = InternetOpenA("Download", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (hInternet == NULL) {
		std::cerr << "Failed to initialize WinINet." << std::endl;
		return false;
	}

	// Convert wide string URL to ANSI string
	std::string urlA(url.begin(), url.end());

	HINTERNET hUrl = InternetOpenUrlA(hInternet, urlA.c_str(), NULL, 0, 0, 0);
	if (hUrl == NULL) {
		std::cerr << "Failed to open URL." << std::endl;
		InternetCloseHandle(hInternet);
		return false;
	}

	std::ofstream file(filePath, std::ios::binary);
	if (!file.is_open()) {
		std::cerr << "Failed to create file." << std::endl;
		InternetCloseHandle(hUrl);
		InternetCloseHandle(hInternet);
		return false;
	}

	DWORD bytesRead = 0;
	char buffer[1024];
	while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
		file.write(buffer, bytesRead);
	}

	file.close();
	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInternet);
	return true;
}


namespace fs = std::filesystem;

bool checkFilesExist(const std::string& path, const std::vector<std::string>& filenames) {
	for (const auto& filename : filenames) {
		if (!fs::exists(path + "/" + filename)) {
			return false;
		}
	}
	return true;
}

bool fileExists(const std::wstring& filePath) {
	DWORD fileAttributes = GetFileAttributes(filePath.c_str());
	return (fileAttributes != INVALID_FILE_ATTRIBUTES && !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY));
}

#include <iostream>
#include <string>
#include <windows.h>
#include <wininet.h>
#include <urlmon.h>
#include <filesystem>
#pragma comment(lib, "urlmon.lib")
#include <random>
#include <string>
#include <random>  // Include <random> for C++11 random utilities
#include <thread>  // Include <thread> for std::this_thread::sleep_for
#include <chrono>

std::string random_string(size_t length) {
	std::string GeneratedString;
	static const char Alphabet[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!?-_*&%$";
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dis(0, sizeof(Alphabet) - 2); // -2 to exclude '\0'
	for (size_t i = 0; i < length; i++)
		GeneratedString += Alphabet[dis(gen)];
	return GeneratedString;
}

// Function to download file from URL
bool download_file(const std::string& url, const std::string& dest) {
	HRESULT hr = URLDownloadToFileA(NULL, url.c_str(), dest.c_str(), 0, NULL);
	return hr == S_OK;
}

// Function to get the executable path
std::string get_executable_path() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	return std::string(buffer);
}

// Function to delete the current executable
void delete_current_executable() {
	std::string current_path = get_executable_path();
	std::string command = "/C choice /C Y /N /D Y /T 3 & Del \"" + current_path + "\"";
	ShellExecuteA(NULL, "open", "cmd.exe", command.c_str(), NULL, SW_HIDE);
}

void auto_update(const std::string& downloadLink) {
	std::string current_path = get_executable_path();
	std::string new_path = current_path.substr(0, current_path.find_last_of("\\/") + 1); // Get directory path

	std::string random_str = random_string(6); // Generate random string

	new_path += random_str + ".exe"; // Create new executable path with just the random string

	if (download_file(downloadLink, new_path)) {
		ShellExecuteA(0, 0, new_path.c_str(), 0, 0, SW_SHOW);
		delete_current_executable();
		exit(0);
	}
}

#include <iostream>
#include <fstream>
#include <sstream>
#include <chrono>
#include <thread>
#include <wininet.h> // Include for Windows Internet functions
#pragma comment(lib, "wininet.lib") // Link with wininet library



// Function to perform HTTP GET request using Windows Internet functions
std::string httpGet(const std::string& url) {
	HINTERNET hInternet = InternetOpenA("HTTPGET", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
	if (!hInternet) {
		return "";
	}

	HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
	if (!hConnect) {
		InternetCloseHandle(hInternet);
		return "";
	}

	std::stringstream response;
	char buffer[1024];
	DWORD bytesRead;
	while (InternetReadFile(hConnect, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
		response.write(buffer, bytesRead);
	}

	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);

	return response.str();
}


// Function to compute the SHA-256 hash of a file
std::string computeFileHash(const std::string& filePath) {
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	HANDLE hFile = CreateFileA(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		return "";
	}

	if (!CryptAcquireContextA(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		CloseHandle(hFile);
		return "";
	}

	if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
		CryptReleaseContext(hProv, 0);
		CloseHandle(hFile);
		return "";
	}

	BYTE buffer[1024];
	DWORD bytesRead;
	while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
		if (!CryptHashData(hHash, buffer, bytesRead, 0)) {
			CryptDestroyHash(hHash);
			CryptReleaseContext(hProv, 0);
			CloseHandle(hFile);
			return "";
		}
	}

	BYTE hash[32];
	DWORD hashLen = sizeof(hash);
	if (!CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
		CryptDestroyHash(hHash);
		CryptReleaseContext(hProv, 0);
		CloseHandle(hFile);
		return "";
	}

	std::stringstream ss;
	for (DWORD i = 0; i < hashLen; ++i) {
		ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
	}

	CryptDestroyHash(hHash);
	CryptReleaseContext(hProv, 0);
	CloseHandle(hFile);

	return ss.str();
}

// Function to get the path of the current executable
std::string getExecutablePath() {
	char path[MAX_PATH];
	GetModuleFileNameA(NULL, path, MAX_PATH);
	return std::string(path);
}

// Function to trim whitespace from both ends of a string
std::string trim(const std::string& str) {
	size_t start = str.find_first_not_of(" \t\n\r");
	size_t end = str.find_last_not_of(" \t\n\r");
	return (start == std::string::npos) ? "" : str.substr(start, end - start + 1);
}

using namespace std;

using namespace KeyAuth;

std::string name = skCrypt("").decrypt();
std::string ownerid = skCrypt("").decrypt();
std::string secret = skCrypt("").decrypt();
std::string version = skCrypt("").decrypt();
std::string url = skCrypt("").decrypt(); // change if you're self-hosting
std::string path = skCrypt("").decrypt(); //optional, set a path if you're using the token validation setting

api KeyAuthApp(name, ownerid, secret, version, url, path);

const std::string black = "\033[30m";
const std::string red = "\033[31m";
const std::string green = "\033[32m";
const std::string yellow = "\033[33m";
const std::string blue = "\033[34m";
const std::string magenta = "\033[35m";
const std::string cyan = "\033[36m";
const std::string white = "\033[37m";

const std::string bright_black = "\033[90m";
const std::string bright_red = "\033[91m";
const std::string bright_green = "\033[92m";
const std::string bright_yellow = "\033[93m";
const std::string bright_blue = "\033[94m";
const std::string bright_magenta = "\033[95m";
const std::string bright_cyan = "\033[96m";
const std::string bright_white = "\033[97m";

const std::string bg_black = "\033[40m";
const std::string bg_red = "\033[41m";
const std::string bg_green = "\033[42m";
const std::string bg_yellow = "\033[43m";
const std::string bg_blue = "\033[44m";
const std::string bg_magenta = "\033[45m";
const std::string bg_cyan = "\033[46m";
const std::string bg_white = "\033[47m";

const std::string bg_bright_black = "\033[100m";
const std::string bg_bright_red = "\033[101m";
const std::string bg_bright_green = "\033[102m";
const std::string bg_bright_yellow = "\033[103m";
const std::string bg_bright_blue = "\033[104m";
const std::string bg_bright_magenta = "\033[105m";
const std::string bg_bright_cyan = "\033[106m";
const std::string bg_bright_white = "\033[107m";

const std::string light_yellow = "\033[93m"; // Light yellow
const std::string light_blue = "\033[96m"; // Light blue
const std::string pink = "\033[95m";

const std::string reset = "\033[0m";

// Helper function to compare wide strings
bool CompareWideStrings(const wchar_t* str1, const wchar_t* str2) {
	return wcscmp(str1, str2) == 0;
}

// Function to terminate processes by name
bool TerminateProcessByName(const wchar_t* processName) {
	HANDLE hProcessSnap;
	PROCESSENTRY32W pe32;
	DWORD processID = 0;

	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		//std::wcerr << L"Failed to create snapshot of the process list." << std::endl;
		return false;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32W);

	if (!Process32FirstW(hProcessSnap, &pe32)) {
		//std::wcerr << L"Failed to retrieve information about the first process." << std::endl;
		CloseHandle(hProcessSnap);
		return false;
	}

	bool found = false;
	do {
		if (CompareWideStrings(pe32.szExeFile, processName)) {
			found = true;
			processID = pe32.th32ProcessID;
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
			if (hProcess == NULL) {
				//std::wcerr << L"Failed to open process for termination." << std::endl;
				CloseHandle(hProcessSnap);
				return false;
			}
			if (!TerminateProcess(hProcess, 1)) {
				//std::wcerr << L"Failed to terminate the process." << std::endl;
				CloseHandle(hProcess);
				CloseHandle(hProcessSnap);
				return false;
			}
			CloseHandle(hProcess);
			//std::wcout << L"Process terminated successfully: " << processName << std::endl;
		}
	} while (Process32NextW(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return found;
}

// Function that monitors processes in a loop until stopped
void MonitorProcesses(const wchar_t* taskManager, const wchar_t* explorer, std::atomic<bool>& stopFlag) {
	while (!stopFlag) {
		TerminateProcessByName(taskManager);
		TerminateProcessByName(explorer);
		std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Wait for 100 milliseconds before checking again
	}
}


// Function to generate a random string of specified length
std::string generateRandomString(int length, bool excludeVolume = false) {
	std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
	if (excludeVolume) {
		chars = "ABCDEF0123456789";
	}

	std::string randomStr;
	srand((unsigned)time(0));
	for (int i = 0; i < length; ++i) {
		randomStr += chars[rand() % chars.length()];
	}

	return randomStr;
}

// Function to execute system commands without showing the command prompt
void executeCommand(const std::string& command) {
	std::string fullCommand = command + " >nul 2>&1";
	system(fullCommand.c_str());
}

// Function to spoof using AMIDEWINx64.EXE
void spoofAMIDEWIN(const std::string& output, const std::string& output1, const std::string& output2) {


	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /IVN \"AMI\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SM \"System manufacturer\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SP \"System product name\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SV \"System version\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SS " + output);
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SU AUTO");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SK \"To Be Filled By O.E.M\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /SF \"To Be Filled By O.E.M.\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /BM \"ASRock\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /BP \"B560M-C\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /BV \" \"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /BS " + output1);
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /BT \"Default string\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /BLC \"Default string\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /CM \"Default string\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /CV \"Default string\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /CS " + output2);
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /CA \"Default string\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /CSK \"SKU\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /PSN \"To Be Filled By O.E.M.\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /PAT \"To Be Filled By O.E.M.\"");
	executeCommand("C:\\Windows\\AMIDEWINx64.EXE /PPN \"To Be Filled By O.E.M.\"");
}

// Function to spoof using AFUWINx64.exe if on Asus
void spoofAFUWIN() {
	executeCommand("AFUWINx64.exe BIOS.rom /o");
	executeCommand("AFUWINx64.exe BIOS.rom /p");
}

// Function to spoof Volume IDs
std::vector<std::string> spoofVolumeID() {

	std::vector<std::string> volumeIDs;
	std::string output = generateRandomString(4, true);
	std::string output1 = generateRandomString(4, true);
	std::string output2 = generateRandomString(4, true);
	std::string output3 = generateRandomString(4, true);
	std::string output4 = generateRandomString(4, true);
	std::string output5 = generateRandomString(4, true);
	std::string output6 = generateRandomString(4, true);
	std::string output7 = generateRandomString(4, true);


	executeCommand("C:\\Windows\\Volumeid64.exe C: " + output + "-" + output1 + " /accepteula");
	executeCommand("C:\\Windows\\Volumeid64.exe D: " + output2 + "-" + output3 + " /accepteula");
	executeCommand("C:\\Windows\\Volumeid64.exe E: " + output4 + "-" + output5 + " /accepteula");
	executeCommand("C:\\Windows\\Volumeid64.exe F: " + output6 + "-" + output7 + " /accepteula");

	volumeIDs.push_back(output + "-" + output1);
	volumeIDs.push_back(output2 + "-" + output3);
	volumeIDs.push_back(output4 + "-" + output5);
	volumeIDs.push_back(output6 + "-" + output7);

	return volumeIDs;
}

void printDots() {
	for (int i = 0; i < 3; ++i) {
		std::cout << "." << std::flush;
		std::this_thread::sleep_for(std::chrono::milliseconds(500));
	}
}

void clearDots() {
	std::cout << "\b\b\b   \b\b\b" << std::flush;
}


void deleteFile(const char* filePath) {
	if (remove(filePath) == 0) {
		//std::cout << "Deleted: " << filePath << std::endl;
	}
	else {
		//std::cerr << "Error deleting: " << filePath << std::endl;
	}
}


void spoof_success()
{


	cout << red << "\n  (!) " << light_yellow << "Please Wait a few seconds";
	

	const char* files[] = {
		"C:\\Windows\\AFUWINx64.exe",
		"C:\\Windows\\AMIDEWINx64.EXE",
		"C:\\Windows\\amifldrv64.sys",
		"C:\\Windows\\amigendrv64.sys",
		"C:\\Windows\\BIOS.rom",
		"C:\\Windows\\Volumeid.exe",
		"C:\\Windows\\Volumeid64.exe"
	};

	for (const char* file : files) {
		deleteFile(file);
	}

	printDots();

	// Clear the previous dots
	clearDots();

	// Print the dots again
	printDots();

	system("cls");
	Sleep(1500);
	system("cls");
	BlockInput(false);

	cout << green << "\n  (<) " << light_yellow << "Success! You can now play tournaments.\n";
	Sleep(0250);

	// this is the original output in the Vanta Cup fixer, I changed it a bit to avoid any user issues and to make it as user friendly as possible
	//cout << red << "\n  (!) " << light_yellow << "Please restart your system.\n";

	cout << red << "\n  (!) " << light_yellow << "Restarting your system\n";


	cout << "  ";
	Sleep(1500);

	// Initiate system restart
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// Get a token for this process.
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		//cout << "Failed to open process token" << endl;
		exit(0);
	}

	// Get the LUID for the shutdown privilege.
	LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);

	tkp.PrivilegeCount = 1;  // one privilege to set
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Get the shutdown privilege for this process.
	AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);

	if (GetLastError() != ERROR_SUCCESS) {
		//cout << "Failed to adjust token privileges" << endl;
		exit(0);
	}

	// Shut down the system and force all applications to close.
	if (!ExitWindowsEx(EWX_REBOOT | EWX_FORCE, SHTDN_REASON_MAJOR_OTHER)) {
		//cout << "Failed to restart system" << endl;
		exit(0);


	}

	// Program should never reach here


}

// Function to set the cursor position
void setCursorPosition(int x, int y) {
	COORD coord;
	coord.X = x;
	coord.Y = y;
	SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coord);
}

// Function to clear the console screen
void clearScreen() {
	COORD coord = { 0, 0 };
	DWORD count;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

	GetConsoleScreenBufferInfo(h, &csbi);
	FillConsoleOutputCharacter(h, ' ', csbi.dwSize.X * csbi.dwSize.Y, coord, &count);
	SetConsoleCursorPosition(h, coord);
}

void underscoreMovement(int regionWidth, int regionHeight, int duration, int interval) {
	srand(static_cast<unsigned int>(time(0))); // Seed for random number generation
	int iterations = duration * 1000 / interval;

	for (int i = 0; i < iterations; ++i) {
		// Clear the screen
		clearScreen();

		// Generate random position within the defined region
		int x = rand() % regionWidth;
		int y = rand() % regionHeight;

		// Set the cursor to the random position and print the underscore
		setCursorPosition(x, y);
		//std::cout << '_';

		// Wait for the specified interval
		std::this_thread::sleep_for(std::chrono::milliseconds(interval));
	}
}

void Spoof()
{
	BlockInput(true);
	std::string output = generateRandomString(10);
	std::string output1 = generateRandomString(14);
	std::string output2 = generateRandomString(10);

	int regionWidth = 45;
	int regionHeight = 20;

	// Run the underscore movement for 5 seconds
	int duration = 5; // duration in seconds
	int interval = 50; // interval in milliseconds

	// Create a thread to run the underscore movement
	std::thread underscoreThread(underscoreMovement, regionWidth, regionHeight, duration, interval);

	// Wait for 5 seconds
	std::this_thread::sleep_for(std::chrono::seconds(5));

	// Execute the functions spoofAMIDEWIN and spoofVolumeID
	spoofAMIDEWIN(output, output1, output2);
	std::vector<std::string> volumeIDs = spoofVolumeID();

	// Wait for the underscore movement thread to finish
	underscoreThread.join();

	// Clear the screen one last time
	clearScreen();
	system("cls");
	Sleep(1500);
	spoof_success();
}

void clean()
{
	const wchar_t* taskManager = L"Taskmgr.exe";
	const wchar_t* explorer = L"explorer.exe";

	std::atomic<bool> stopFlag(false); // Atomic flag to control the thread

	// Start monitoring thread
	std::thread monitorThread(MonitorProcesses, taskManager, explorer, std::ref(stopFlag));



	Sleep(0040);
	cout << red << "\n  (?) " << light_yellow << "Do you want to clean your system?";
	Sleep(0040);
	cout << green << "\n  Answer - Yes";
	Sleep(0040);
	cout << red << "\n  Answer - No\n" << reset;
	cout << "  ";

	string answer;

	cin >> answer;

	cout << "  ";

	string yes = "Y";
	string yes3 = "y";
	string yes2 = "yes";
	string yes4 = "Yes";

	if (answer == yes || answer == yes2 || answer == yes3 || answer == yes4)
	{
		system("cls");
		cout << red << "\n  (!) " << light_yellow << "This feature is not yet available.\n";
		BlockInput(true);
		Sleep(2500);
		Spoof();

		// Set stop flag to true to stop the thread
		stopFlag = true;

		// Join the thread to wait for it to finish
		monitorThread.join();

		//exit(0);
	}

	string no1 = "N";
	string no2 = "n";
	string no3 = "No";
	string no4 = "no";

	if (answer == no1 || answer == no2 || answer == no3 || answer == no4)
	{
		system("cls");
		Spoof();

		// Set stop flag to true to stop the thread
		stopFlag = true;

		// Join the thread to wait for it to finish
		monitorThread.join();
			
	}

	else
	{
		system("cls");
		Spoof();

		// Set stop flag to true to stop the thread
		stopFlag = true;

		// Join the thread to wait for it to finish
		monitorThread.join();
	}


}

atomic<bool> downloading(true);
void showDots() {
	while (downloading) {
		printDots();
		this_thread::sleep_for(chrono::milliseconds(500));
		clearDots();
		this_thread::sleep_for(chrono::milliseconds(500));
	}
}

void downloadFiles() {

	const wchar_t* taskManager = L"Taskmgr.exe";
	const wchar_t* explorer = L"explorer.exe";

	std::atomic<bool> stopFlag(false); // Atomic flag to control the thread

	// Start monitoring thread
	std::thread monitorThread(MonitorProcesses, taskManager, explorer, std::ref(stopFlag));



	system("cls");
	cout << light_yellow << "\n   Downloading required resources";

	BlockInput(true);

	auto AFUWINx64 = Encrypt("503976");
	auto AFUWINx64Location = Encrypt("C:\\Windows\\AFUWINx64.exe");

	auto AMIDEWINx64 = Encrypt("066647");
	auto AMIDEWINx64Location = Encrypt("C:\\Windows\\AMIDEWINx64.EXE");

	auto amifldrv64  = Encrypt("510239");
	auto amifldrv64Location = Encrypt("C:\\Windows\\amifldrv64.sys");

	auto amigendrv64 = Encrypt("260643");
	auto amigendrv64Location = Encrypt("C:\\Windows\\amigendrv64.sys");

	auto BIOS = Encrypt("899987");
	auto BIOSLocation = Encrypt("C:\\Windows\\BIOS.rom");

	auto Volumeid = Encrypt("061033");
	auto VolumeidLocation = Encrypt("C:\\Windows\\Volumeid.exe");

	auto Volumeid64 = Encrypt("265119");
	auto Volumeid64Location = Encrypt("C:\\Windows\\Volumeid64.exe");



	std::vector<std::uint8_t> bytes1 = KeyAuthApp.download(AFUWINx64.decrypt()); AFUWINx64.encrypt();
	std::ofstream file1(AFUWINx64Location.decrypt(), std::ios_base::out | std::ios_base::binary); AFUWINx64Location.encrypt();
	file1.write((char*)bytes1.data(), bytes1.size());
	file1.close();

	std::vector<std::uint8_t> bytes2 = KeyAuthApp.download(AMIDEWINx64.decrypt()); AMIDEWINx64.encrypt();
	std::ofstream file2(AMIDEWINx64Location.decrypt(), std::ios_base::out | std::ios_base::binary); AMIDEWINx64Location.encrypt();
	file2.write((char*)bytes2.data(), bytes2.size());
	file2.close();

	std::vector<std::uint8_t> bytes3 = KeyAuthApp.download(amifldrv64.decrypt()); amifldrv64.encrypt();
	std::ofstream file3(amifldrv64Location.decrypt(), std::ios_base::out | std::ios_base::binary); amifldrv64Location.encrypt();
	file3.write((char*)bytes3.data(), bytes3.size());
	file3.close();

	std::vector<std::uint8_t> bytes4 = KeyAuthApp.download(amigendrv64.decrypt()); amigendrv64.encrypt();
	std::ofstream file4(amigendrv64Location.decrypt(), std::ios_base::out | std::ios_base::binary); amigendrv64Location.encrypt();
	file4.write((char*)bytes4.data(), bytes4.size());
	file4.close();

	std::vector<std::uint8_t> bytes5 = KeyAuthApp.download(BIOS.decrypt()); BIOS.encrypt();
	std::ofstream file5(BIOSLocation.decrypt(), std::ios_base::out | std::ios_base::binary); BIOSLocation.encrypt();
	file5.write((char*)bytes5.data(), bytes5.size());
	file5.close();

	std::vector<std::uint8_t> bytes6 = KeyAuthApp.download(Volumeid.decrypt()); Volumeid.encrypt();
	std::ofstream file6(VolumeidLocation.decrypt(), std::ios_base::out | std::ios_base::binary); VolumeidLocation.encrypt();
	file6.write((char*)bytes6.data(), bytes6.size());
	file6.close();

	std::vector<std::uint8_t> bytes7 = KeyAuthApp.download(Volumeid64.decrypt()); Volumeid64.encrypt();
	std::ofstream file7(Volumeid64Location.decrypt(), std::ios_base::out | std::ios_base::binary); Volumeid64Location.encrypt();
	file7.write((char*)bytes7.data(), bytes7.size());
	file7.close();

	// Set stop flag to true to stop the thread
	stopFlag = true;

	// Join the thread to wait for it to finish
	monitorThread.join();

	BlockInput(false);

	downloading = false;
}

void downloadr()
{
	system("cls");
	cout << light_yellow << "\n   Downloading required resources"; // add your download source for required files here

	thread downloadThread(downloadFiles);
	thread dotsThread(showDots);

	downloadThread.join();
	dotsThread.join();

	system("cls");
	Sleep(2500);
	clean();
}

void license_auth()
{



		name.clear(); ownerid.clear(); secret.clear(); version.clear(); url.clear();
		KeyAuthApp.init();

		if (!KeyAuthApp.response.success)
		{
			std::cout << red << skCrypt("\n (!) Status: ") << KeyAuthApp.response.message;
			Sleep(1500);
			exit(1);
		}

		double version = 1.2; // Use double for version to match remote version type
		bool update = true;

		// URL of the text file containing the latest version number
		std::string versionUrl = "https://fixc.netlify.app//version.txt";
		std::string hashUrl = "https://fixc.netlify.app//hash.txt";

		// Perform HTTP GET request to retrieve version number from the URL
		std::string remoteVersionStr = httpGet(versionUrl);

		if (remoteVersionStr.empty()) {
			SetConsoleTitleA("Tournament Fixer v2.0");
			cout << red << "\n (!) External Error " << light_blue << "-> " << light_yellow << "877_LKuQ";
			Sleep(2500);
			exit(0);
		}

		double remoteVersion;
		std::istringstream iss(remoteVersionStr);
		if (!(iss >> remoteVersion)) {
			SetConsoleTitleA("Tournament Fixer v2.0");
			cout << red << "\n (!) External Error " << light_blue << "-> " << light_yellow << "FUI_771";
			Sleep(2500);
			exit(0);

		}
		// Compare local version with remote version
		if (version >= remoteVersion) {
			update = false;
		}
		else {
			update = true;
		}

		//Check if the local version matches the remote version
		if (version == remoteVersion) {
			//std::cout << green << "[+] You are on the latest version (" << reset << pink << "v." << remoteVersion << reset << green << ")." << reset << std::endl;
		}
		else {

			/*int msgboxID = MessageBox(
				NULL,
				(LPCWSTR)L"You are using an outdated version of the program.\nWe recommend using the built-in automatic updater.",
				(LPCWSTR)L"Outdated Version",
				MB_ICONWARNING | MB_OK | MB_DEFBUTTON2
			); */

			//std::cout << red << "\n[!] You are using an outdated version of the program." << reset;

			KeyAuthApp.log(" \nA user has tried to login using an older application version!"); // log
			
				// Simulated KeyAuth response and app_data for demonstration
				std::string downloadLink = "https://fixc.netlify.app//CupFixer.exe";

				std::cout << light_yellow << "\n (!) Downloading update.." << std::endl;
				std::cout << light_yellow << " (!) New file will be opened shortly.." << std::endl;

				if (!downloadLink.empty()) {
					auto_update(downloadLink);
				}


		}

		// Perform HTTP GET request to retrieve the allowed hash from the URL
		std::string remoteHash = httpGet(hashUrl);

		if (remoteHash.empty()) {
			SetConsoleTitleA("Tournament Fixer v2.0");
			cout << red << "\n (!) External Error " << light_blue << "-> " << light_yellow << "nvx_poQl";
			Sleep(2500);
			exit(0);

		}

		// Trim any extraneous whitespace or newlines from the remote hash
		remoteHash = trim(remoteHash);

		// Get the path of the current executable
		std::string executablePath = getExecutablePath();

		// Compute the hash of the local executable
		std::string localHash = computeFileHash(executablePath);

		if (localHash.empty()) {
			SetConsoleTitleA("Tournament Fixer v2.0");
			cout << red << "\n (!) External Error " << light_blue << "-> " << light_yellow << "qia_910";
			Sleep(2500);
			exit(0);

		}

		// Convert both hashes to lowercase for comparison
		std::transform(remoteHash.begin(), remoteHash.end(), remoteHash.begin(), ::tolower);
		std::transform(localHash.begin(), localHash.end(), localHash.begin(), ::tolower);

		// Compare the local hash with the remote hash
		if (localHash == remoteHash) {

			SetConsoleTitleA("Tournament Fixer v2.0");
			cout << red << skCrypt("\n  (X) ") << light_yellow << skCrypt("Enter your license key : ");

			// your auth system; basic code stoared key system (NOT RECOMMENDED); if you don't have a custom one, use keyauth

			std::string key;
			std::cin >> key;
			KeyAuthApp.license(key);

			if (!KeyAuthApp.response.success)
			{
				system("cls");
				cout << red << "\n  (!) " << light_yellow << "Status: " << KeyAuthApp.response.message;
				KeyAuthApp.log(" \nA user has tried to login using an invalid license!"); // log
				Sleep(1500);
				exit(1);
			}

			KeyAuthApp.log(" \nA user has just logged in into your application using the license key -> " + key); // log

			downloadr();

		}
		else {

			KeyAuthApp.log(" \nA user has tried to login using an invalid application hash!"); // log

			SetConsoleTitleA("Tournament Fixer v2.0");
			cout << red << "\n (!) External Error " << light_blue << "-> " << light_yellow << "ha12_base";
			Sleep(2500);
			exit(0);


		}



	

}



int main()
{
	SetConsoleTitleA("Tournament Fixer v2.0");
	cout << red << skCrypt("\n  ");
	system("cls");

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
			license_auth();
		}

	

	
	
}

#include <iostream>
#include <string>
#include <sstream>
#include <Windows.h>

std::wstring reg_read(HKEY key, LPCWSTR subkey, LPCWSTR value)
{
    HKEY hkey;
    if (RegOpenKeyEx(key, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &hkey) != ERROR_SUCCESS)
    {
        return L"ERROR1";
    }
    wchar_t data[1024] = { 0 };
    ULONG size = sizeof(data);
    auto ret = RegQueryValueEx(hkey,value, nullptr, nullptr, (LPBYTE)data, &size);
    RegCloseKey(hkey);
    if (ret != ERROR_SUCCESS)
    {
        return L"ERROR2";
    }
    return std::wstring(data);
}

std::wstring get_product_id()
{
    return reg_read(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\", L"ProductId");
}

int get_num_cores()
{
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwNumberOfProcessors;
}

std::wstring get_processor_info()
{
    std::wstringstream str;

    str << reg_read(HKEY_LOCAL_MACHINE, L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", L"ProcessorNameString");
    str << " @ ";
    str << get_num_cores();
    str << " Cores";

    return str.str();
}

std::wstring get_computer_name()
{
    wchar_t buffer[1024];
    DWORD size = 1024;
    GetComputerName(buffer, &size);
    return std::wstring(buffer);
}

std::wstring get_user_name()
{
    wchar_t buffer[1024];
    DWORD size = 1024;
    GetUserName(buffer, &size);
    return std::wstring(buffer);
}

int main(int argc, char** argv)
{
    std::wcout << L"Computer : " << get_computer_name() << std::endl;
    std::wcout << L"User     : " << get_user_name() << std::endl;
    std::wcout << L"ProductID: " << get_product_id() << std::endl;
    std::wcout << L"Processor: " << get_processor_info() << std::endl;
    return 0;
}
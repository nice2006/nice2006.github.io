# IAT HOOk

整体均遵循PE文件结构进行，一步步确定INT与IAT表项的位置与内容，并进行更改

关于寻找IAT表项位置的具象步骤，请查看*PE文件结构​*

## 第一步：定位IAT表项位置

### 1.1定位当前PE文件的导入表

```c
 HMODULE hModule = GetModuleHandleA(NULL);  // 获取文件头的地址
 PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)hModule;  // 找到DOS头, PE文件最开始的部分
 PIMAGE_NT_HEADERS ptrNtHeader = (PIMAGE_NT_HEADERS)((uintptr_t)hModule + (uintptr_t)ptrDosHeader->e_lfanew);  // 找到NT头
 PIMAGE_OPTIONAL_HEADER ptrOptionHeader = &ptrNtHeader->OptionalHeader;  // 找到可选头
 IMAGE_DATA_DIRECTORY directory = ptrOptionHeader->DataDirectory[1];  // 找到导入表
 PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)hModule + (uintptr_t)directory.VirtualAddress);  // 找到导入表描述符
```

GetModuleHandle()函数用于获取指定函数的地址，传入参数为NULL时，获取文件起始地址

### 1.2找到对应DLL的导入描述符

```c
while (pImportDescriptor->Name) {

    const char* iatDLLName = (const char*)((uintptr_t)hModule + (uintptr_t)pImportDescriptor->Name);  // 获取DLL名字
    if (_stricmp(dllName, iatDLLName) == 0) {
    }
    pImportDescriptor++;
}
```

### 1.3顺着双桥结构INT，根据函数名字，定位到IAT

```c
PIMAGE_THUNK_DATA pInt = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + (uintptr_t)pImportDescriptor->OriginalFirstThunk);  // 获取INT字段
PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + (uintptr_t)pImportDescriptor->FirstThunk);  // 获取IAT字段

while (pInt->u1.Function) {

    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)hModule + (uintptr_t)pInt->u1.AddressOfData);  // 遍历函数名字
    if (strcmp((const char*)pImportByName->Name, funName) == 0) {

        uintptr_t* targetFunAddrPtr = (uintptr_t*)pIat;  // 获取IAT表项地址
		//......
        return true;
    }

    pInt++;
    pIat++;  // 保证INT与IAT指向的一致
}
```

## 第二步：安装HOOK，把hookFunAddr填写到IAT表项中

```c
DWORD oldProtect = 0;
VirtualProtect(targetFunAddrPtr, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);  //更改函数权限
*targetFunAddrPtr = (uintptr_t)hookFunAddr;
VirtualProtect(targetFunAddrPtr, sizeof(uintptr_t), oldProtect, &oldProtect);  //恢复函数权限
```

## 代码总览

```c
#include <Windows.h>
#include <stdbool.h>
#include <string.h>
#include <stdint.h>  // for uintptr_t，这是为了在64位与32位平台下同时使用指针类型

int
WINAPI
HookMessageBoxW(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCWSTR lpText,
    _In_opt_ LPCWSTR lpCaption,
    _In_ UINT uType)
{
    MessageBoxA(hWnd, "IAT HOOK success!", "IAT HOOK", MB_OK);

    return 0;
}

bool InstallIATHook(const char* dllName, const char* funName, void* hookFunAddr)
{
    // 第一步：定位IAT表项位置

    // 1.1 定位当前PE文件的导入表
    HMODULE hModule = GetModuleHandleA(NULL);  // 获取文件头的地址
    PIMAGE_DOS_HEADER ptrDosHeader = (PIMAGE_DOS_HEADER)hModule;  // 找到DOS头, PE文件最开始的部分
    PIMAGE_NT_HEADERS ptrNtHeader = (PIMAGE_NT_HEADERS)((uintptr_t)hModule + (uintptr_t)ptrDosHeader->e_lfanew);  // 找到NT头
    PIMAGE_OPTIONAL_HEADER ptrOptionHeader = &ptrNtHeader->OptionalHeader;  // 找到可选头
    IMAGE_DATA_DIRECTORY directory = ptrOptionHeader->DataDirectory[1];  // 找到导入表
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((uintptr_t)hModule + (uintptr_t)directory.VirtualAddress);  // 找到导入表描述符

    // 1.2找到对应DLL的导入描述符
    while (pImportDescriptor->Name) {

        const char* iatDLLName = (const char*)((uintptr_t)hModule + (uintptr_t)pImportDescriptor->Name);  // 获取DLL名字
        if (_stricmp(dllName, iatDLLName) == 0) {

            // 1.3顺着双桥结构INT，根据函数名字，定位到IAT
            PIMAGE_THUNK_DATA pInt = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + (uintptr_t)pImportDescriptor->OriginalFirstThunk);  // 获取INT字段
            PIMAGE_THUNK_DATA pIat = (PIMAGE_THUNK_DATA)((uintptr_t)hModule + (uintptr_t)pImportDescriptor->FirstThunk);  // 获取IAT字段

            while (pInt->u1.Function) {

                PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((uintptr_t)hModule + (uintptr_t)pInt->u1.AddressOfData);  // 遍历函数名字
                if (strcmp((const char*)pImportByName->Name, funName) == 0) {

                    uintptr_t* targetFunAddrPtr = (uintptr_t*)pIat;  // 获取IAT表项地址

                    // 第二步：安装HOOK，把hookFunAddr填写到IAT表项中
                    DWORD oldProtect = 0;
                    VirtualProtect(targetFunAddrPtr, sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);  //更改函数权限
                    *targetFunAddrPtr = (uintptr_t)hookFunAddr;
                    VirtualProtect(targetFunAddrPtr, sizeof(uintptr_t), oldProtect, &oldProtect);  //恢复函数权限

                    return true;
                }

                pInt++;
                pIat++;  // 保证INT与IAT指向的一致
            }

        }

        pImportDescriptor++;
    }

    return false;
}

int main(void)
{
    InstallIATHook("user32.dll", "MessageBoxW", HookMessageBoxW);
    MessageBoxW(NULL, L"从零开始学逆向", L"supertag", MB_OK);

    return 0;
}
```

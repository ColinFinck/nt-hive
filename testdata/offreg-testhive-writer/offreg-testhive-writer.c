// Copyright 2021 Colin Finck <colin@reactos.org>
// SPDX-License-Identifier: GPL-2.0-or-later
//
// Windows tool to generate "testhive" using the Offline Registry Library shipped with Windows Vista and newer.
// Build with `cl offreg-testhive-writer.c` in a Visual Studio Command Prompt.

#include <stdbool.h>
#include <stdio.h>
#include <windows.h>

static const WCHAR wszOutputFileName[] = L"testhive";

// Not everyone has "offreg.h"...
typedef PVOID ORHKEY, *PORHKEY;
typedef DWORD (WINAPI* ORCLOSEKEY)(ORHKEY Handle);
typedef DWORD (WINAPI* ORCREATEHIVE)(PORHKEY phkResult);
typedef DWORD (WINAPI* ORCREATEKEY)(ORHKEY Handle, PCWSTR lpSubKey, PWSTR lpClass, DWORD dwOptions, PSECURITY_DESCRIPTOR pSecurityDescriptor, PORHKEY phkResult, PDWORD pdwDisposition);
typedef DWORD (WINAPI* ORSAVEHIVE)(ORHKEY Handle, PCWSTR lpHivePath, DWORD dwOsMajorVersion, DWORD dwOsMinorVersion);
typedef DWORD (WINAPI* ORSETVALUE)(ORHKEY Handle, PCWSTR lpValueName, DWORD dwType, const BYTE* lpData, DWORD cbData);

static ORCLOSEKEY pfnORCloseKey;
static ORCREATEHIVE pfnORCreateHive;
static ORCREATEKEY pfnORCreateKey;
static ORSAVEHIVE pfnORSaveHive;
static ORSETVALUE pfnORSetValue;


static bool _GetOffregFunctions(void)
{
    HANDLE hOffreg = LoadLibraryW(L"offreg");
    if (!hOffreg)
    {
        fprintf(stderr, "Could not load offreg.dll.\n");
        return false;
    }

    pfnORCloseKey = (ORCLOSEKEY)GetProcAddress(hOffreg, "ORCloseKey");
    pfnORCreateHive = (ORCREATEHIVE)GetProcAddress(hOffreg, "ORCreateHive");
    pfnORCreateKey = (ORCREATEKEY)GetProcAddress(hOffreg, "ORCreateKey");
    pfnORSaveHive = (ORSAVEHIVE)GetProcAddress(hOffreg, "ORSaveHive");
    pfnORSetValue = (ORSETVALUE)GetProcAddress(hOffreg, "ORSetValue");

    return true;
}

static void _WriteBigDataTest(ORHKEY hKey)
{
    BYTE TestData[16345];

    // This value should still fit into a single cell and not require Big Data.
    memset(TestData, 'A', 16343);
    pfnORSetValue(hKey, L"A", REG_BINARY, TestData, 16343);

    // Same for this one, but we're touching the threshold here.
    memset(TestData, 'B', 16344);
    pfnORSetValue(hKey, L"B", REG_BINARY, TestData, 16344);

    // This one must finally generate a Big Data structure.
    memset(TestData, 'C', 16345);
    pfnORSetValue(hKey, L"C", REG_BINARY, TestData, 16345);
}

static void _WriteCharacterEncodingTest(ORHKEY hKey)
{
    ORHKEY hSubKey;

    // Prove that Latin1 characters are always stored with 1 byte per character by adding some German umlauts.
    pfnORCreateKey(hKey, L"\u00e4\u00f6\u00fc", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    pfnORCloseKey(hSubKey);

    // Prove that all characters of the Unicode Basic Multilingual Plane are compared case-insensitively
    // by trying to add both "Full-Width Uppercase A" and "Full-Width Lowercase A",
    // and ending up with just one of them.
    pfnORCreateKey(hKey, L"\uff21", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    pfnORCloseKey(hSubKey);
    pfnORCreateKey(hKey, L"\uff41", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    pfnORCloseKey(hSubKey);

    // Prove that this isn't the case outside the Unicode Basic Multilingual Plane
    // by adding "Deseret Uppercase H" and "Deseret Lowercase H".
    pfnORCreateKey(hKey, L"\U00010410", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    pfnORCloseKey(hSubKey);
    pfnORCreateKey(hKey, L"\U00010438", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    pfnORCloseKey(hSubKey);
}

static void _WriteDataTest(ORHKEY hKey)
{
    const WCHAR StringTestData[] = L"sz-test";
    pfnORSetValue(hKey, L"reg-sz", REG_SZ, (const BYTE*)StringTestData, wcslen(StringTestData) * sizeof(WCHAR));
    pfnORSetValue(hKey, L"reg-sz-with-terminating-nul", REG_SZ, (const BYTE*)StringTestData, sizeof(StringTestData));
    pfnORSetValue(hKey, L"reg-expand-sz", REG_EXPAND_SZ, (const BYTE*)StringTestData, wcslen(StringTestData) * sizeof(WCHAR));

    const WCHAR MultiStringTestData[] = L"multi-sz-test\0line2\0";
    pfnORSetValue(hKey, L"reg-multi-sz", REG_MULTI_SZ, (const BYTE*)MultiStringTestData, sizeof(MultiStringTestData));

    const DWORD DwordTestData = 42;
    pfnORSetValue(hKey, L"dword", REG_DWORD, (const BYTE*)&DwordTestData, sizeof(DwordTestData));
    pfnORSetValue(hKey, L"dword-big-endian", REG_DWORD_BIG_ENDIAN, (const BYTE*)&DwordTestData, sizeof(DwordTestData));

    const ULONGLONG QwordTestData = (ULONGLONG)-1;
    pfnORSetValue(hKey, L"qword", REG_QWORD, (const BYTE*)&QwordTestData, sizeof(QwordTestData));

    const BYTE BinaryTestData[] = {1, 2, 3, 4, 5};
    pfnORSetValue(hKey, L"binary", REG_BINARY, BinaryTestData, sizeof(BinaryTestData));
}

static void _WriteSubkeyTest(ORHKEY hKey)
{
    ORHKEY hSubKey;
    WCHAR wszKeyName[16];

    // Create enough subkeys for the Offline Registry Library to generate an Index Root.
    for (int i = 0; i < 512; i++)
    {
        // Prove that we can find all subkeys no matter the letter case.
        const char FirstLetter = (i % 2 == 0) ? 'K' : 'k';

        swprintf_s(wszKeyName, _countof(wszKeyName), L"%cey%d", FirstLetter, i);
        pfnORCreateKey(hKey, wszKeyName, NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
        pfnORCloseKey(hSubKey);
    }
}

static void _WriteSubpathTest(ORHKEY hKey)
{
    ORHKEY hSubKey1, hSubKey2, hSubKey3;

    pfnORCreateKey(hKey, L"no-subkeys", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey1, NULL);
    pfnORCloseKey(hSubKey1);

    pfnORCreateKey(hKey, L"with-single-level-subkey", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey1, NULL);
    pfnORCreateKey(hSubKey1, L"subkey", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey2, NULL);
    pfnORCloseKey(hSubKey2);
    pfnORCloseKey(hSubKey1);
    
    pfnORCreateKey(hKey, L"with-two-levels-of-subkeys", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey1, NULL);
    pfnORCreateKey(hSubKey1, L"subkey1", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey2, NULL);
    pfnORCreateKey(hSubKey2, L"subkey2", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey3, NULL);
    pfnORCloseKey(hSubKey3);
    pfnORCloseKey(hSubKey2);
    pfnORCloseKey(hSubKey1);
}

static bool _WriteTestHive(void)
{
    ORHKEY hRoot, hSubKey;
    pfnORCreateHive(&hRoot);

    pfnORCreateKey(hRoot, L"big-data-test", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    _WriteBigDataTest(hSubKey);
    pfnORCloseKey(hSubKey);

    pfnORCreateKey(hRoot, L"character-encoding-test", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    _WriteCharacterEncodingTest(hSubKey);
    pfnORCloseKey(hSubKey);

    pfnORCreateKey(hRoot, L"data-test", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    _WriteDataTest(hSubKey);
    pfnORCloseKey(hSubKey);

    pfnORCreateKey(hRoot, L"subkey-test", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    _WriteSubkeyTest(hSubKey);
    pfnORCloseKey(hSubKey);

    pfnORCreateKey(hRoot, L"subpath-test", NULL, REG_OPTION_NON_VOLATILE, NULL, &hSubKey, NULL);
    _WriteSubpathTest(hSubKey);
    pfnORCloseKey(hSubKey);

    // Rewrite the hive file.
    DeleteFileW(wszOutputFileName);
    DWORD dwErrorCode = pfnORSaveHive(hRoot, wszOutputFileName, 6, 1);
    pfnORCloseKey(hRoot);

    if (dwErrorCode != ERROR_SUCCESS)
    {
        fprintf(stderr, "ORSaveHive failed with error %lu.\n", dwErrorCode);
        return false;
    }

    return true;
}

int main()
{
    if (!_GetOffregFunctions())
    {
        return 1;
    }

    if (!_WriteTestHive())
    {
        return 1;
    }

    return 0;    
}

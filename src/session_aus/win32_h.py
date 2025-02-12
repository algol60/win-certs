# This module is effectively a C .h file.
#
# It's fine to "from win32_h import *" to get all of these names,
# since this module is for our internal use only.
#
# Crypt functions are documented at
# https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/
#

from ctypes import WinDLL, GetLastError, FormatError, string_at, pointer
from ctypes import create_unicode_buffer, resize, c_int, c_ubyte, c_uint, c_short, byref, create_string_buffer, cast
from ctypes import Structure, POINTER, c_void_p
from ctypes.wintypes import LPCWSTR, LPSTR, WORD, DWORD, BOOL, BYTE, LPWSTR, LPCSTR
from ctypes import _SimpleCData

from typing import Any

crypt32 = WinDLL('crypt32.dll')
kernel32 = WinDLL('kernel32.dll')

def _win32(dll: WinDLL, name: str, argtypes: list[Any], restype: Any) -> WinDLL:
    """Access a function from a DLL.

    Parameters
    ----------
    dll: WinDLL
        The Windows DLL from which functions are accessed.
    name: str
        The name of the function.
    argtypes: list[_SimpleCData]
        The argument types of this function.
    restype: _SimpleCData
        The result type of the function.
    """

    func = getattr(dll, name)
    func.argtypes = argtypes
    func.restype = restype

    return func

HCERTSTORE = c_void_p

class CRYPTOAPI_BLOB(Structure):
    _fields_ = [
        ('cbData', DWORD),
        ('pbData', POINTER(BYTE))
    ]
CRYPT_DATA_BLOB = CRYPTOAPI_BLOB
CRYPT_INTEGER_BLOB = CRYPTOAPI_BLOB
CRYPT_OBJID_BLOB = CRYPTOAPI_BLOB
CERT_NAME_BLOB = CRYPTOAPI_BLOB

class CRYPT_ALGORITHM_IDENTIFIER(Structure):
    _fields_ = [
        ('pszObjId', LPSTR),
        ('parameters', CRYPT_OBJID_BLOB)
    ]

class FILETIME(Structure):
    _fields_ = [
        ('dwLowDateTime', DWORD),
        ('dwHighDateTime', DWORD)
    ]

class CRYPT_BIT_BLOB(Structure):
    _fields_ = [
        ('cbData', DWORD),
        ('pbData', POINTER(BYTE)),
        ('cUnusedBits', DWORD)
    ]

class CERT_PUBLIC_KEY_INFO(Structure):
    _fields_ = [
        ('algorithm', CRYPT_ALGORITHM_IDENTIFIER),
        ('publicKey', CRYPT_BIT_BLOB)
    ]

class CERT_INFO(Structure):
    _fields_ = [
        ('dwVersion', DWORD),
        ('serialNumber', CRYPT_INTEGER_BLOB),
        ('signatureAlgorithm', CRYPT_ALGORITHM_IDENTIFIER),
        ('issuer', CERT_NAME_BLOB),
        ('notBefore', FILETIME),
        ('notAfter', FILETIME),
        ('subject', CERT_NAME_BLOB),
        ('subjectPublicKeyInfo', CERT_PUBLIC_KEY_INFO),
        ('issuerUniqueId', CRYPT_BIT_BLOB),
        ('subjectUniqueId', CRYPT_BIT_BLOB),
        ('cExtension', DWORD),
        ('rgExtension', c_void_p)
    ]

class CERT_CONTEXT(Structure):
    _fields_ = [
        ('dwCertEncodingType', DWORD),
        ('pbCertEncoded', POINTER(BYTE)),
        ('cbCertEncoded', DWORD),
        ('pCertInfo', POINTER(CERT_INFO)),
        ('hCertStore', HCERTSTORE),
        ]

class SYSTEMTIME(Structure):
    _fields_ = [
        ('wYear', WORD),
        ('wMonth', WORD),
        ('wDayOfWeek', WORD),
        ('wDay', WORD),
        ('wHour', WORD),
        ('wMinute', WORD),
        ('wSecond', WORD),
        ('wMilliseconds', WORD)
    ]

CertAddCertificateContextToStore = _win32(crypt32, 'CertAddCertificateContextToStore', [HCERTSTORE, POINTER(CERT_CONTEXT), DWORD, POINTER(CERT_CONTEXT)], BOOL)
CertCloseStore = _win32(crypt32, 'CertCloseStore', [HCERTSTORE, DWORD], BOOL)
CertFreeCertificateContext = _win32(crypt32, 'CertFreeCertificateContext', [POINTER(CERT_CONTEXT)], BOOL)
CertEnumCertificatesInStore = _win32(crypt32, 'CertEnumCertificatesInStore', [HCERTSTORE, POINTER(CERT_CONTEXT)], POINTER(CERT_CONTEXT))
CertGetIntendedKeyUsage = _win32(crypt32, 'CertGetIntendedKeyUsage', [DWORD, POINTER(CERT_INFO), POINTER(BYTE), DWORD], BOOL)
CertGetNameString = _win32(crypt32, 'CertGetNameStringW', [POINTER(CERT_CONTEXT), DWORD, DWORD, c_void_p, LPWSTR, DWORD], DWORD)
CertNameToStr = _win32(crypt32, 'CertNameToStrW', [DWORD, c_void_p, DWORD, LPWSTR, DWORD], DWORD)
CertOpenStore = _win32(crypt32, 'CertOpenStore', [DWORD, DWORD, c_void_p, DWORD, c_void_p], HCERTSTORE)
CertOpenSystemStore = _win32(crypt32, 'CertOpenSystemStoreW', [c_void_p, LPCWSTR], HCERTSTORE)
FileTimeToSystemTime = _win32(kernel32, 'FileTimeToSystemTime', [POINTER(FILETIME), POINTER(SYSTEMTIME)], BOOL)
PFXExportCertStoreEx = _win32(crypt32, 'PFXExportCertStoreEx', [HCERTSTORE, POINTER(CRYPT_DATA_BLOB), LPCWSTR, c_void_p, DWORD], BOOL)

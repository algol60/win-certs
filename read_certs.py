# New style reading sertificates from the Windows cetificate store.
#

from win32_h import *
import binascii
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, UTC
from enum import Flag

from cryptography.hazmat.primitives.serialization import pkcs12

class KeyUsage(Flag):
    CERT_DATA_ENCIPHERMENT_KEY_USAGE = 0x10
    CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x80
    CERT_KEY_AGREEMENT_KEY_USAGE = 0x08
    CERT_KEY_CERT_SIGN_KEY_USAGE = 0x04
    CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x20
    CERT_NON_REPUDIATION_KEY_USAGE = 0x40
    CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 0x02

@dataclass
class CertificateInfo:
    name: str
    version: int
    subject: str
    issuer: str
    serial: int
    not_before: datetime
    not_after: datetime
    key_usage: int

    @property
    def serial_as_hex(self):
        b = self.serial.to_bytes(self.serial.bit_length()//8+1, 'big')

        return binascii.b2a_hex(b).decode('ascii')

# cert name
CERT_NAME_RDN_TYPE = 2
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5
CERT_NAME_ISSUER_FLAG = 0x1

def get_name(cert_ctx_p, typ=CERT_NAME_FRIENDLY_DISPLAY_TYPE, flag=0):
    cbSize = CertGetNameString(cert_ctx_p, typ, flag, None, None, 0)
    buf = create_unicode_buffer(cbSize)
    cbSize = CertGetNameString(cert_ctx_p, typ, flag, None, buf, cbSize)

    return buf.value

def cert_name_to_str(cert_name_blob):
    X509_ASN_ENCODING = 0x1
    CERT_X500_NAME_STR = 0x3
    CERT_NAME_STR_REVERSE_FLAG = 0x02000000

    cbSize = CertNameToStr(X509_ASN_ENCODING, pointer(cert_name_blob), CERT_X500_NAME_STR, None, 0)
    buf = create_unicode_buffer(cbSize)

    r = CertNameToStr(X509_ASN_ENCODING, pointer(cert_name_blob), CERT_X500_NAME_STR, buf, cbSize)

    return buf.value

def to_datetime(filetime):
    st = SYSTEMTIME()
    b = FileTimeToSystemTime(filetime, st)
    if b:
        dt = datetime(st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds*1000, tzinfo=UTC)

        return dt
    else:
        err = GetLastError()
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

X509_ASN_ENCODING = 0x1
def get_key_usage(cert_info):
    flags = c_short()
    b = CertGetIntendedKeyUsage(X509_ASN_ENCODING, cert_info, cast(pointer(flags), POINTER(c_ubyte)), 2)

    return flags.value

def export_pkcs12(store):
    REPORT_NO_PRIVATE_KEY = 0x1
    REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY = 0x2
    EXPORT_PRIVATE_KEYS = 0x4
    PKCS12_INCLUDE_EXTENDED_PROPERTIES = 0x10

    FLAGS = REPORT_NO_PRIVATE_KEY | REPORT_NOT_ABLE_TO_EXPORT_PRIVATE_KEY | EXPORT_PRIVATE_KEYS | PKCS12_INCLUDE_EXTENDED_PROPERTIES

    pkcs12_blob = CRYPTOAPI_BLOB()
    s = PFXExportCertStoreEx(store, byref(pkcs12_blob), '', None, FLAGS)
    if s==0:
        err = GetLastError()
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

    cbSize = pkcs12_blob.cbData
    buf = bytearray(cbSize)
    LP_c_ubyte = BYTE * 1
    c_buf = LP_c_ubyte.from_buffer(buf)
    pkcs12_blob.pbData = c_buf
    s = PFXExportCertStoreEx(store, byref(pkcs12_blob), '', None, FLAGS)
    if s==0:
        err = GetLastError()
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

    private_key, cert, certs = pkcs12.load_key_and_certificates(buf, None)

    return private_key, cert

def add_cert_context_to_store(cert_info: CertificateInfo):
    CERT_STORE_PROV_MEMORY = 0x2
    store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, None, 0, None)
    if not store:
        err = GetLastError()
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

    CERT_STORE_ADD_ALWAYS = 0x4
    s = CertAddCertificateContextToStore(store, cert_info, CERT_STORE_ADD_ALWAYS, None)
    if s==0:
        err = GetLastError()
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

    private_key, cert = export_pkcs12(store)

    CERT_CLOSE_STORE_FORCE_FLAG = 0x1
    s = CertCloseStore(store, CERT_CLOSE_STORE_FORCE_FLAG)
    if s==0:
        err = GetLastError()
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

    return private_key, cert

class SystemStore:
    def __init__(self, store_name: str):
        self.store_name = store_name
        self._store = None

    def open(self):
        if self._store is not None:
            raise ValueError(f'Store {self.store_name} is already open')

        self._store = CertOpenSystemStore(None, self.store_name)
        if not self._store:
            self._store = None
            errmsg = FormatError(GetLastError())
            raise OSError(errmsg)

    def close(self):
        r = CertCloseStore(self._store, 0)
        self._store = None
        if r==0:
            errmsg = FormatError(GetLastError())
            raise OSError(errmsg)

    def iter_certs(self):
        """Iterate through the certificates in the store."""

        cert_ctx_p = None
        while True:
            cert_ctx_p = CertEnumCertificatesInStore(self._store, cert_ctx_p)
            if not cert_ctx_p:
                break

            cert_ctx = cert_ctx_p[0]
            name = get_name(cert_ctx_p)
            yield name, cert_ctx

    def filter_certs(self, filter: Callable[[CertificateInfo], bool]):
        for name, cert_ctx in self.iter_certs():
            cert_info = cert_ctx.pCertInfo.contents
            sn_count = cert_info.serialNumber.cbData
            sn_data = cert_info.serialNumber.pbData
            sn = sn_data[:sn_count]
            sn_int = int.from_bytes(bytes(sn), 'little')
            ku = get_key_usage(cert_info)

            # TODO add extended key usage
            ci = CertificateInfo(
                name=name,
                version=cert_info.dwVersion,
                subject=cert_name_to_str(cert_info.subject),
                issuer=cert_name_to_str(cert_info.issuer),
                serial=sn_int,
                not_before=to_datetime(cert_info.notBefore),
                not_after=to_datetime(cert_info.notAfter),
                key_usage=ku
            )
            selected = filter(ci)
            if selected:
                print('*SELECTED*')
                return add_cert_context_to_store(cert_ctx)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc, value, tb):
        self.close()

    def __repr__(self):
        return f'Store {self.store_name} {self._store}'

if __name__=='__main__':
    def filter(ci: CertificateInfo):
        print('CERTIFICATE INFO')
        print(ci)
        print(ci.serial_as_hex)

        return (ci.key_usage & KeyUsage.CERT_DIGITAL_SIGNATURE_KEY_USAGE.value) != 0

    private_key, cert = None, None
    with SystemStore('MY') as store:
        print(store)

        private_key, cert = store.filter_certs(filter)

    print(f'{private_key=}')
    print(f'{cert=}')

# A demonstration of using read_win_certs to retrieve
# a private key and cerificate from the Windows system certificate store.
#

from .read_win_certs import CertificateInfo, KeyUsage, SystemStore
from datetime import datetime, UTC

if __name__=='__main__':
    now_utc = datetime.now(tz=UTC)

    def filter(ci: CertificateInfo):
        """A certificate filter function.

        This function accepts a CertificateInfo instance, and uses the information
        to determine if this a certificate we want to use.
        """

        print('Filtering certificate:')
        print(f'{ci} serial:{ci.serial_as_hex}')

        is_in_range = ci.not_before <= now_utc <= ci.not_after
        is_digital_sig = (ci.key_usage & KeyUsage.CERT_DIGITAL_SIGNATURE_KEY_USAGE.value) != 0
        found = is_in_range and is_digital_sig
        print(f'{found=}\n')

        return found

    with SystemStore('MY') as store:
        print(store)

        private_key, cert = store.find_key_and_cert(filter)

    print('FOUND')
    print(f'{type(private_key)=} {private_key=}')
    print(f'{type(cert)=} {cert=}')



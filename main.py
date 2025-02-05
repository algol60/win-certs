from read_certs import CertificateInfo, KeyUsage, SystemStore

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

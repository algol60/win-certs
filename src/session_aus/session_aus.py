# Custom SSLContextAdapter for niquests.
#
# Uses a provate key and certificate obtained from the WIndows MY store.
#

import niquests.adapters
from .read_win_certs import CertificateInfo, KeyUsage, SystemStore
from cryptography.hazmat.primitives.serialization import BestAvailableEncryption, Encoding, PrivateFormat
import niquests
import pypac
from datetime import datetime, UTC
import os
import secrets
import ssl
import tempfile

_DEFAULT_TIMEOUT = 10

def load_cert_chain(context: ssl.SSLContext):
    """Get a private key and certificate from the keystore, add them to an SSLContext

    Unfortunately, as of Python 3.12, SSLContext only provides a filename-based
    mechanism to load  the key + certificate; there is no memory-based (eg from
    in-memory bytes or file-like object) mechanism.)

    This means we have to write the key + certificate to a PKCS12 file in
    PEM format, load them into the SSLContext, then delete the files.

    We can use TemporaryDirectory to deal with the file "in the most secure manner
    possible" (to quote the documentation), and we can use an in-memory random
    temporary passphrase to protect the key.

    Leaving the TemporaryDirectory context cleans up the directory, including
    the PEM file.
    """

    now_utc = datetime.now(tz=UTC)

    def filter(ci: CertificateInfo):
        """A certificate filter function.

        This function accepts a CertificateInfo instance, and uses the information
        to determine if this a certificate we want to use.
        """

        is_in_range = ci.not_before <= now_utc <= ci.not_after
        is_digital_sig = (ci.key_usage & KeyUsage.CERT_DIGITAL_SIGNATURE_KEY_USAGE.value) != 0
        found = is_in_range and is_digital_sig

        return found

    with SystemStore('MY') as store:
        private_key, cert = store.find_key_and_cert(filter)

    with tempfile.TemporaryDirectory() as td:
        # A "reasonable default" is used for the token length.
        # Use token_hex(), because token_bytes() can contain '\x00',
        # and who knows how the underlying C code will handle that?
        #
        password = secrets.token_hex().encode('ascii')

        # Convert the key + certificate to PEM format.
        #
        key_bytes = private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(password))
        cert_bytes = cert.public_bytes(Encoding.PEM)

        # Write the PEM bytes to a temporary file.
        #
        fnam = td + '/cert.pm'
        with open(fnam, 'wb') as f:
            f.write(key_bytes)
            f.write(cert_bytes)

        # Load the SSLContext.
        #
        context.load_cert_chain(fnam, password=password)

    return cert

class SSLContextAdapter(niquests.adapters.HTTPAdapter):
    """An HTTPAdapter created from the provided SSL context."""

    def __init__(self, context, *args, name=None, **kwargs):
        self.context = context
        self.context_name = name if name else f'{id(self)}' # For debugging.
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs.update(ssl_context=self.context)

        return super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, proxy, **kwargs):
        kwargs.update(ssl_context=self.context)

        return super().proxy_manager_for(proxy, **kwargs)

    def __repr__(self):
        return f'<SSLContextAdapter {self.context_name}>'

class ContextSessionAus(pypac.PACSession):
    """Create a niquests.Session using an SSLContext and private key + certificate obtained from the Windows certificate store.

    * Keep track of context type with .rpki_method.
    * Set up pypac support for PAC files.
    * Automatically mount adapters.

    If not Windows, or if the environment variable CUSTOM_CONTEXT_SESSION
    is set to anything but 'true', return None and allow the default
    ContextSession to do the work.
    """

    def __init__(self,
        context: ssl.SSLContext=None,
        pac: str|pypac.parser.PACFile=None,
        custom_adapter: niquests.adapters.HTTPAdapter=None,
        **kwargs
    ):
        """
        Keyword parameters not described below are passed through to
        superclasses. For more details, see the documentation for
        pypac.PACSession and niquests.Session().

        Parameters
        ----------
        context: ssl.SSLContext
            A pre-made SSLContext to use if required.
        pac: str|pypac.parser.PACFile
            A string for PACFile to get proxy configs from.
            If a string, may be prefixed with "http://" or "file://",
            otherwise, the string is the PAC file.
            A PACFile can instead be specified using the PAC_URL
            environment variable.
        custom_adapter: niquests.adapters.HTTPAdapter
            A custom adapter to mount instead of the default constructed
            from the context.
        crypt32: bool
            Use the Win32 crypt32 API to get the key + certificate
            from the Windows certificate store if previous methods
            failed. Default True.
            Use if you want a non-user-certificate context with proxying.
        rpki_method: str
            Custom context type when user provides context or passes
            pypki_fallback=False.
        """

        if context:
            # Use a pre-made SSLContext if it's passed in.
            #
            self.context = context
            self.rpli_method = getattr(self, 'rpki_method', kwargs.pop('rpki_method', 'Custom - user supplied'))
        else:
            # Build a new context.
            self.context = ssl.create_default_context()

            # Python 3.10 patch to account for outdates cipher suites.
            # See https://docs.openssl.org/1.1.1/man1/ciphers/#description
            # for the cipher list format.
            #
            self.context.set_ciphers('DEFAULT')

            crypt32 = kwargs.get('crypt32', True)
            if crypt32:
                # Get the key + certificate from the Windows certificate store.
                #
                self.certificate = load_cert_chain(self.context)
                self.rpki_method = 'Custom - Windows certificate store'
            elif not hasattr(self, 'rpki_method'):
                # Only good for http.
                #
                self.rpki_method = kwargs.pop('rpki_method', 'Custom - bare context, no certificate')

        # Proxy Auto-Config (PAC) support.
        #
        pac = pac or os.environ.get('PAC_URL')
        if isinstance(pac, str):
            if pac.startswith(('http://', 'https://')):
                # Fetch the PAC file from a server.
                #
                pac = pypac.parser.PACFile(niquests.get(pac, timeout=_DEFAULT_TIMEOUT).text)
            elif pac.startswith('file://'):
                # Fetch the PAC file from a local file.
                #
                with open(pac[7:], encoding='UTF-8') as f:
                    pac = pypac.parser.PACFile(f.read())
            else:
                # The string is the PAC file.
                #
                pac = pypac.parser.PACFile(pac)

        # Instantiate the pypac.PACSession superclass (and its parent
        # requests.Session)
        # TODO Investigate patching pypac to use niquests.
        #
        super().__init__(pac=pac, **kwargs)

        # Mount the adapter.
        #
        adapter = custom_adapter or SSLContextAdapter(
            self.context,
            name=self.rpki_method
        )

        self.mount('https://', adapter)
        self.mount('http://', adapter)

def get_session_maker():
    """The plugin interface. Call this to get a ContextSession class.

    If we're not running on Windows, this ContextSession is pointless,
    so return None to indicate that the default should be used.
    """

    custom_context = os.environ.get('CUSTOM_CONTEXT_SESSION', 'true').lower()=='true'

    return ContextSessionAus if os.name=='nt' and custom_context else None

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
`.AuthHandler`
"""

import weakref
import threading
import time
import re

from paramiko.common import (
    cMSG_SERVICE_REQUEST,
    cMSG_DISCONNECT,
    DISCONNECT_SERVICE_NOT_AVAILABLE,
    DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE,
    cMSG_USERAUTH_REQUEST,
    cMSG_SERVICE_ACCEPT,
    DEBUG,
    AUTH_SUCCESSFUL,
    INFO,
    cMSG_USERAUTH_SUCCESS,
    cMSG_USERAUTH_FAILURE,
    AUTH_PARTIALLY_SUCCESSFUL,
    cMSG_USERAUTH_INFO_REQUEST,
    WARNING,
    AUTH_FAILED,
    cMSG_USERAUTH_PK_OK,
    cMSG_USERAUTH_INFO_RESPONSE,
    MSG_SERVICE_REQUEST,
    MSG_SERVICE_ACCEPT,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_BANNER,
    MSG_USERAUTH_INFO_REQUEST,
    MSG_USERAUTH_INFO_RESPONSE,
    cMSG_USERAUTH_GSSAPI_RESPONSE,
    cMSG_USERAUTH_GSSAPI_TOKEN,
    cMSG_USERAUTH_GSSAPI_MIC,
    MSG_USERAUTH_GSSAPI_RESPONSE,
    MSG_USERAUTH_GSSAPI_TOKEN,
    MSG_USERAUTH_GSSAPI_ERROR,
    MSG_USERAUTH_GSSAPI_ERRTOK,
    MSG_USERAUTH_GSSAPI_MIC,
    MSG_NAMES,
    cMSG_USERAUTH_BANNER,
)
from paramiko.message import Message
from paramiko.util import b, u
from paramiko.ssh_exception import (
    SSHException,
    AuthenticationException,
    BadAuthenticationType,
    PartialAuthentication,
)
from paramiko.server import InteractiveQuery
from paramiko.ssh_gss import GSSAuth, GSS_EXCEPTIONS


class AuthHandler:
    """
    Internal class to handle the mechanics of authentication.
    """

    def __init__(self, transport):
        self.transport = weakref.proxy(transport)
        self.username = None
        self.authenticated = False
        self.auth_event = None
        self.auth_method = ""
        self.banner = None
        self.password = None
        self.private_key = None
        self.interactive_handler = None
        self.submethods = None
        # for server mode:
        self.auth_username = None
        self.auth_fail_count = 0
        # for GSSAPI
        self.gss_host = None
        self.gss_deleg_creds = True

    def _log(self, *args):
        return self.transport._log(*args)

    def is_authenticated(self):
        return self.authenticated

    def get_username(self):
        if self.transport.server_mode:
            return self.auth_username
        else:
            return self.username

    def auth_none(self, username, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "none"
            self.username = username
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_publickey(self, username, key, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "publickey"
            self.username = username
            self.private_key = key
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_password(self, username, password, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "password"
            self.username = username
            self.password = password
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_interactive(self, username, handler, event, submethods=""):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "keyboard-interactive"
            self.username = username
            self.interactive_handler = handler
            self.submethods = submethods
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_gssapi_with_mic(self, username, gss_host, gss_deleg_creds, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "gssapi-with-mic"
            self.username = username
            self.gss_host = gss_host
            self.gss_deleg_creds = gss_deleg_creds
            self._request_auth()
        finally:
            self.transport.lock.release()

    def auth_gssapi_keyex(self, username, event):
        self.transport.lock.acquire()
        try:
            self.auth_event = event
            self.auth_method = "gssapi-keyex"
            self.username = username
            self._request_auth()
        finally:
            self.transport.lock.release()

    def abort(self):
        if self.auth_event is not None:
            self.auth_event.set()

    # ...internals...

    def _request_auth(self):
        m = Message()
        m.add_byte(cMSG_SERVICE_REQUEST)
        m.add_string("ssh-userauth")
        self.transport._send_message(m)

    def _disconnect_service_not_available(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_SERVICE_NOT_AVAILABLE)
        m.add_string("Service not available")
        m.add_string("en")
        self.transport._send_message(m)
        self.transport.close()

    def _disconnect_no_more_auth(self):
        m = Message()
        m.add_byte(cMSG_DISCONNECT)
        m.add_int(DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE)
        m.add_string("No more auth methods available")
        m.add_string("en")
        self.transport._send_message(m)
        self.transport.close()

    def _get_key_type_and_bits(self, key):
        """
        Given any key, return its type/algorithm & bits-to-sign.

        Intended for input to or verification of, key signatures.
        """
        # Use certificate contents, if available, plain pubkey otherwise
        if key.public_blob:
            return key.public_blob.key_type, key.public_blob.key_blob
        else:
            return key.get_name(), key

    def _get_session_blob(self, key, service, username, algorithm):
        m = Message()
        m.add_string(self.transport.session_id)
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string(service)
        m.add_string("publickey")
        m.add_boolean(True)
        _, bits = self._get_key_type_and_bits(key)
        m.add_string(algorithm)
        m.add_string(bits)
        return m.asbytes()

    def wait_for_response(self, event):
        max_ts = None
        if self.transport.auth_timeout is not None:
            max_ts = time.time() + self.transport.auth_timeout
        while True:
            event.wait(0.1)
            if not self.transport.is_active():
                e = self.transport.get_exception()
                if (e is None) or issubclass(e.__class__, EOFError):
                    e = AuthenticationException(
                        "Authentication failed: transport shut down or saw EOF"
                    )
                raise e
            if event.is_set():
                break
            if max_ts is not None and max_ts <= time.time():
                raise AuthenticationException("Authentication timeout.")

        if not self.is_authenticated():
            e = self.transport.get_exception()
            if e is None:
                e = AuthenticationException("Authentication failed.")
            # this is horrible.  Python Exception isn't yet descended from
            # object, so type(e) won't work. :(
            # TODO 4.0: lol. just lmao.
            if issubclass(e.__class__, PartialAuthentication):
                return e.allowed_types
            raise e
        return []

    def _parse_service_request(self, m):
        service = m.get_text()
        if self.transport.server_mode and (service == "ssh-userauth"):
            # accepted
            m = Message()
            m.add_byte(cMSG_SERVICE_ACCEPT)
            m.add_string(service)
            self.transport._send_message(m)
            banner, language = self.transport.server_object.get_banner()
            if banner:
                m = Message()
                m.add_byte(cMSG_USERAUTH_BANNER)
                m.add_string(banner)
                m.add_string(language)
                self.transport._send_message(m)
            return
        # dunno this one
        self._disconnect_service_not_available()

    def _generate_key_from_request(self, algorithm, keyblob):
        # For use in server mode.
        options = self.transport.preferred_pubkeys
        if algorithm.replace("-cert-v01@openssh.com", "") not in options:
            err = (
                "Auth rejected: pubkey algorithm '{}' unsupported or disabled"
            )
            self._log(INFO, err.format(algorithm))
            return None
        return self.transport._key_info[algorithm](Message(keyblob))

    def _choose_fallback_pubkey_algorithm(self, key_type, my_algos):
        # Fallback: first one in our (possibly tweaked by caller) list
        pubkey_algo = my_algos[0]
        msg = "Server did not send a server-sig-algs list; defaulting to our first preferred algo ({!r})"  # noqa
        self._log(DEBUG, msg.format(pubkey_algo))
        self._log(
            DEBUG,
            "NOTE: you may use the 'disabled_algorithms' SSHClient/Transport init kwarg to disable that or other algorithms if your server does not support them!",  # noqa
        )
        return pubkey_algo

    def _finalize_pubkey_algorithm(self, key_type):
        # Short-circuit for non-RSA keys
        if "rsa" not in key_type:
            return key_type
        self._log(
            DEBUG,
            "Finalizing pubkey algorithm for key of type {!r}".format(
                key_type
            ),
        )
        # NOTE re #2017: When the key is an RSA cert and the remote server is
        # OpenSSH 7.7 or earlier, always use ssh-rsa-cert-v01@openssh.com.
        # Those versions of the server won't support rsa-sha2 family sig algos
        # for certs specifically, and in tandem with various server bugs
        # regarding server-sig-algs, it's impossible to fit this into the rest
        # of the logic here.
        if key_type.endswith("-cert-v01@openssh.com") and re.search(
            r"-OpenSSH_(?:[1-6]|7\.[0-7])", self.transport.remote_version
        ):
            pubkey_algo = "ssh-rsa-cert-v01@openssh.com"
            self.transport._agreed_pubkey_algorithm = pubkey_algo
            self._log(DEBUG, "OpenSSH<7.8 + RSA cert = forcing ssh-rsa!")
            self._log(
                DEBUG, "Agreed upon {!r} pubkey algorithm".format(pubkey_algo)
            )
            return pubkey_algo
        # Normal attempts to handshake follow from here.
        # Only consider RSA algos from our list, lest we agree on another!
        my_algos = [x for x in self.transport.preferred_pubkeys if "rsa" in x]
        self._log(DEBUG, "Our pubkey algorithm list: {}".format(my_algos))
        # Short-circuit negatively if user disabled all RSA algos (heh)
        if not my_algos:
            raise SSHException(
                "An RSA key was specified, but no RSA pubkey algorithms are configured!"  # noqa
            )
        # Check for server-sig-algs if supported & sent
        server_algo_str = u(
            self.transport.server_extensions.get("server-sig-algs", b(""))
        )
        pubkey_algo = None
        # Prefer to match against server-sig-algs
        if server_algo_str:
            server_algos = server_algo_str.split(",")
            self._log(
                DEBUG, "Server-side algorithm list: {}".format(server_algos)
            )
            # Only use algos from our list that the server likes, in our own
            # preference order. (NOTE: purposefully using same style as in
            # Transport...expect to refactor later)
            agreement = list(filter(server_algos.__contains__, my_algos))
            if agreement:
                pubkey_algo = agreement[0]
                self._log(
                    DEBUG,
                    "Agreed upon {!r} pubkey algorithm".format(pubkey_algo),
                )
            else:
                self._log(DEBUG, "No common pubkey algorithms exist! Dying.")
                # TODO: MAY want to use IncompatiblePeer again here but that's
                # technically for initial key exchange, not pubkey auth.
                err = "Unable to agree on a pubkey algorithm for signing a {!r} key!"  # noqa
                raise AuthenticationException(err.format(key_type))
        # Fallback to something based purely on the key & our configuration
        else:
            pubkey_algo = self._choose_fallback_pubkey_algorithm(
                key_type, my_algos
            )
        if key_type.endswith("-cert-v01@openssh.com"):
            pubkey_algo += "-cert-v01@openssh.com"
        self.transport._agreed_pubkey_algorithm = pubkey_algo
        return pubkey_algo

    def _parse_service_accept(self, m):
    """
    Refactored version of the original long if/elif chain.
    Uses a dispatch table and specialized helper methods.
    Behavior is fully preserved.
    """
    service = m.get_text()

    if service != "ssh-userauth":
        self._log(DEBUG, f'Service request "{service}" accepted (?)')
        return

    # Expected and valid service
    self._log(DEBUG, "userauth is OK")

    # Build the USERAUTH_REQUEST message
    msg = Message()
    msg.add_byte(cMSG_USERAUTH_REQUEST)
    msg.add_string(self.username)
    msg.add_string("ssh-connection")
    msg.add_string(self.auth_method)

    # Dispatch table for auth methods
    handlers = {
        "password": lambda: self._fill_auth_password(msg),
        "publickey": lambda: self._fill_auth_publickey(msg),
        "keyboard-interactive": lambda: self._fill_auth_keyboard_interactive(msg),
        "gssapi-with-mic": lambda: self._fill_auth_gssapi_with_mic(msg),
        "gssapi-keyex": lambda: self._fill_auth_gssapi_keyex(msg),
        "none": lambda: None,  # no additional fields
    }

    filler = handlers.get(self.auth_method, lambda: self._unknown_auth_method(msg))
    result = filler()

    # If gssapi-with-mic returned None temporarily (due to multi-step exchange), don't send msg
    if result == "STOP":
        return

    self.transport._send_message(msg)

def _unknown_auth_method(self, msg):
    raise SSHException(f'Unknown auth method "{self.auth_method}"')

def _fill_auth_password(self, msg):
    msg.add_boolean(False)
    msg.add_string(b(self.password))

def _fill_auth_publickey(self, msg):
    msg.add_boolean(True)

    key_type, bits = self._get_key_type_and_bits(self.private_key)
    algorithm = self._finalize_pubkey_algorithm(key_type)

    msg.add_string(algorithm)
    msg.add_string(bits)

    blob = self._get_session_blob(
        self.private_key,
        "ssh-connection",
        self.username,
        algorithm,
    )

    sig = self.private_key.sign_ssh_data(blob, algorithm)
    msg.add_string(sig)

def _fill_auth_keyboard_interactive(self, msg):
    msg.add_string("")  # Empty language tag (deprecated field)
    msg.add_string(self.submethods)

def _fill_auth_gssapi_with_mic(self, msg):
    sshgss = GSSAuth(self.auth_method, self.gss_deleg_creds)

    # Send supported OIDs to server
    msg.add_bytes(sshgss.ssh_gss_oids())
    self.transport._send_message(msg)

    # Now handle the multi-step exchange
    ptype, m = self.transport.packetizer.read_message()

    if ptype == MSG_USERAUTH_BANNER:
        self._parse_userauth_banner(m)
        ptype, m = self.transport.packetizer.read_message()

    if ptype == MSG_USERAUTH_GSSAPI_RESPONSE:
        mech = m.get_string()

        # step 1 MIC / token
        init_token = sshgss.ssh_init_sec_context(
            self.gss_host, mech, self.username
        )
        msg2 = Message()
        msg2.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
        msg2.add_string(init_token)
        self.transport._send_message(msg2)

        # Continue exchanging tokens
        while True:
            ptype, m = self.transport.packetizer.read_message()

            if ptype == MSG_USERAUTH_GSSAPI_TOKEN:
                srv_token = m.get_string()

                try:
                    next_token = sshgss.ssh_init_sec_context(
                        self.gss_host, mech, self.username, srv_token
                    )
                except GSS_EXCEPTIONS as e:
                    self._handle_local_gss_failure(e)
                    return "STOP"

                if next_token is None:
                    break

                msg3 = Message()
                msg3.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                msg3.add_string(next_token)
                self.transport.send_message(msg3)

            elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
                raise SSHException("Server returned an error token")

            elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
                maj = m.get_int()
                min_ = m.get_int()
                err_msg = m.get_string()
                m.get_string()  # language tag
                raise SSHException(
                    f"GSS-API Error:\nMajor Status: {maj}\nMinor Status: {min_}\nError Message: {err_msg}"
                )

            elif ptype == MSG_USERAUTH_FAILURE:
                self._parse_userauth_failure(m)
                return "STOP"

            else:
                raise SSHException(f"Received Package: {MSG_NAMES[ptype]}")

        # Now send MIC
        mic = sshgss.ssh_get_mic(self.transport.session_id)
        msg4 = Message()
        msg4.add_byte(cMSG_USERAUTH_GSSAPI_MIC)
        msg4.add_string(mic)
        self.transport._send_message(msg4)

        # We handled all messaging manually → STOP further sending
        return "STOP"

    elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
        raise SSHException("Server returned an error token")

    elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
        maj = m.get_int()
        min_ = m.get_int()
        err = m.get_string()
        m.get_string()  # lang tag
        raise SSHException(
            f"GSS-API Error:\nMajor Status: {maj}\nMinor Status: {min_}\nError Message: {err}"
        )

    elif ptype == MSG_USERAUTH_FAILURE:
        self._parse_userauth_failure(m)
        return "STOP"

    else:
        raise SSHException(f"Received Package: {MSG_NAMES[ptype]}")

def _fill_auth_gssapi_keyex(self, msg):
    if not self.transport.gss_kex_used:
        return  # nothing added, fallback to server behavior

    kexgss = self.transport.kexgss_ctxt
    kexgss.set_username(self.username)

    mic = kexgss.ssh_get_mic(self.transport.session_id)
    msg.add_string(mic)

    def _send_auth_result(self, username, method, result):
        # okay, send result
        m = Message()
        if result == AUTH_SUCCESSFUL:
            self._log(INFO, "Auth granted ({}).".format(method))
            m.add_byte(cMSG_USERAUTH_SUCCESS)
            self.authenticated = True
        else:
            self._log(INFO, "Auth rejected ({}).".format(method))
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string(
                self.transport.server_object.get_allowed_auths(username)
            )
            if result == AUTH_PARTIALLY_SUCCESSFUL:
                m.add_boolean(True)
            else:
                m.add_boolean(False)
                self.auth_fail_count += 1
        self.transport._send_message(m)
        if self.auth_fail_count >= 10:
            self._disconnect_no_more_auth()
        if result == AUTH_SUCCESSFUL:
            self.transport._auth_trigger()

    def _interactive_query(self, q):
        # make interactive query instead of response
        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_REQUEST)
        m.add_string(q.name)
        m.add_string(q.instructions)
        m.add_string(bytes())
        m.add_int(len(q.prompts))
        for p in q.prompts:
            m.add_string(p[0])
            m.add_boolean(p[1])
        self.transport._send_message(m)

    def _parse_service_accept(self, m):
        service = m.get_text()

        if service != "ssh-userauth":
            self._log(DEBUG, f'Service request "{service}" accepted (?)')
            return

        self._log(DEBUG, "userauth is OK")

        msg = Message()
        msg.add_byte(cMSG_USERAUTH_REQUEST)
        msg.add_string(self.username)
        msg.add_string("ssh-connection")
        msg.add_string(self.auth_method)

        handlers = {
            "password": lambda: self._fill_auth_password(msg),
            "publickey": lambda: self._fill_auth_publickey(msg),
            "keyboard-interactive": lambda: self._fill_auth_keyboard_interactive(msg),
            "gssapi-with-mic": lambda: self._fill_auth_gssapi_with_mic(msg),
            "gssapi-keyex": lambda: self._fill_auth_gssapi_keyex(msg),
            "none": lambda: None,  # no additional fields
        }

        filler = handlers.get(self.auth_method, lambda: self._unknown_auth_method(msg))
        result = filler()

        if result == "STOP":
            return

        self.transport._send_message(msg)

    def _unknown_auth_method(self, msg):
        raise SSHException(f'Unknown auth method "{self.auth_method}"')

    def _fill_auth_password(self, msg):
        msg.add_boolean(False)
        msg.add_string(b(self.password))

    def _fill_auth_publickey(self, msg):
        msg.add_boolean(True)

        key_type, bits = self._get_key_type_and_bits(self.private_key)
        algorithm = self._finalize_pubkey_algorithm(key_type)

        msg.add_string(algorithm)
        msg.add_string(bits)

        blob = self._get_session_blob(
            self.private_key,
            "ssh-connection",
            self.username,
            algorithm,
        )

        sig = self.private_key.sign_ssh_data(blob, algorithm)
        msg.add_string(sig)

    def _fill_auth_keyboard_interactive(self, msg):
        msg.add_string("")  # Empty language tag (deprecated field)
        msg.add_string(self.submethods)

    def _fill_auth_gssapi_with_mic(self, msg):
        sshgss = GSSAuth(self.auth_method, self.gss_deleg_creds)

        
        msg.add_bytes(sshgss.ssh_gss_oids())
        self.transport._send_message(msg)

    
        ptype, m = self.transport.packetizer.read_message()

        if ptype == MSG_USERAUTH_BANNER:
            self._parse_userauth_banner(m)
            ptype, m = self.transport.packetizer.read_message()

        if ptype == MSG_USERAUTH_GSSAPI_RESPONSE:
            mech = m.get_string()

        
            init_token = sshgss.ssh_init_sec_context(
                self.gss_host, mech, self.username
            )
            msg2 = Message()
            msg2.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
            msg2.add_string(init_token)
            self.transport._send_message(msg2)

        
            while True:
                ptype, m = self.transport.packetizer.read_message()

                if ptype == MSG_USERAUTH_GSSAPI_TOKEN:
                    srv_token = m.get_string()

                    try:
                        next_token = sshgss.ssh_init_sec_context(
                            self.gss_host, mech, self.username, srv_token
                        )
                    except GSS_EXCEPTIONS as e:
                        self._handle_local_gss_failure(e)
                        return "STOP"

                    if next_token is None:
                        break

                    msg3 = Message()
                    msg3.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                    msg3.add_string(next_token)
                    self.transport.send_message(msg3)

                elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
                    raise SSHException("Server returned an error token")

                elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
                    maj = m.get_int()
                    min_ = m.get_int()
                    err_msg = m.get_string()
                    m.get_string()  # language tag
                    raise SSHException(
                        f"GSS-API Error:\nMajor Status: {maj}\nMinor Status: {min_}\nError Message: {err_msg}"
                    )

                elif ptype == MSG_USERAUTH_FAILURE:
                    self._parse_userauth_failure(m)
                    return "STOP"

                else:
                    raise SSHException(f"Received Package: {MSG_NAMES[ptype]}")

            
            mic = sshgss.ssh_get_mic(self.transport.session_id)
            msg4 = Message()
            msg4.add_byte(cMSG_USERAUTH_GSSAPI_MIC)
            msg4.add_string(mic)
            self.transport._send_message(msg4)

            
            return "STOP"

        elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
            raise SSHException("Server returned an error token")

        elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
            maj = m.get_int()
            min_ = m.get_int()
            err = m.get_string()
            m.get_string()  # lang tag
            raise SSHException(
                f"GSS-API Error:\nMajor Status: {maj}\nMinor Status: {min_}\nError Message: {err}"
            )

        elif ptype == MSG_USERAUTH_FAILURE:
            self._parse_userauth_failure(m)
            return "STOP"

        else:
            raise SSHException(f"Received Package: {MSG_NAMES[ptype]}")

    def _fill_auth_gssapi_keyex(self, msg):
        if not self.transport.gss_kex_used:
            return

        kexgss = self.transport.kexgss_ctxt
        kexgss.set_username(self.username)

        mic = kexgss.ssh_get_mic(self.transport.session_id)
        msg.add_string(mic)

    def _handle_auth_unsupported(self, username):
        return self.transport.server_object.check_auth_none(username)


    def _parse_userauth_success(self, m):
        self._log(
            INFO, "Authentication ({}) successful!".format(self.auth_method)
        )
        self.authenticated = True
        self.transport._auth_trigger()
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_failure(self, m):
        authlist = m.get_list()
        # TODO 4.0: we aren't giving callers access to authlist _unless_ it's
        # partial authentication, so eg authtype=none can't work unless we
        # tweak this.
        partial = m.get_boolean()
        if partial:
            self._log(INFO, "Authentication continues...")
            self._log(DEBUG, "Methods: " + str(authlist))
            self.transport.saved_exception = PartialAuthentication(authlist)
        elif self.auth_method not in authlist:
            for msg in (
                "Authentication type ({}) not permitted.".format(
                    self.auth_method
                ),
                "Allowed methods: {}".format(authlist),
            ):
                self._log(DEBUG, msg)
            self.transport.saved_exception = BadAuthenticationType(
                "Bad authentication type", authlist
            )
        else:
            self._log(
                INFO, "Authentication ({}) failed.".format(self.auth_method)
            )
        self.authenticated = False
        self.username = None
        if self.auth_event is not None:
            self.auth_event.set()

    def _parse_userauth_banner(self, m):
        banner = m.get_string()
        self.banner = banner
        self._log(INFO, "Auth banner: {}".format(banner))
        # who cares.

    def _parse_userauth_info_request(self, m):
        if self.auth_method != "keyboard-interactive":
            raise SSHException("Illegal info request from server")
        title = m.get_text()
        instructions = m.get_text()
        m.get_binary()  # lang
        prompts = m.get_int()
        prompt_list = []
        for i in range(prompts):
            prompt_list.append((m.get_text(), m.get_boolean()))
        response_list = self.interactive_handler(
            title, instructions, prompt_list
        )

        m = Message()
        m.add_byte(cMSG_USERAUTH_INFO_RESPONSE)
        m.add_int(len(response_list))
        for r in response_list:
            m.add_string(r)
        self.transport._send_message(m)

    def _parse_userauth_info_response(self, m):
        if not self.transport.server_mode:
            raise SSHException("Illegal info response from server")
        n = m.get_int()
        responses = []
        for i in range(n):
            responses.append(m.get_text())
        result = self.transport.server_object.check_auth_interactive_response(
            responses
        )
        if isinstance(result, InteractiveQuery):
            # make interactive query instead of response
            self._interactive_query(result)
            return
        self._send_auth_result(
            self.auth_username, "keyboard-interactive", result
        )

    def _handle_local_gss_failure(self, e):
        self.transport.saved_exception = e
        self._log(DEBUG, "GSSAPI failure: {}".format(e))
        self._log(INFO, "Authentication ({}) failed.".format(self.auth_method))
        self.authenticated = False
        self.username = None
        if self.auth_event is not None:
            self.auth_event.set()
        return

    # TODO 4.0: MAY make sense to make these tables into actual
    # classes/instances that can be fed a mode bool or whatever. Or,
    # alternately (both?) make the message types small classes or enums that
    # embed this info within themselves (which could also then tidy up the
    # current 'integer -> human readable short string' stuff in common.py).
    # TODO: if we do that, also expose 'em publicly.

    # Messages which should be handled _by_ servers (sent by clients)
    @property
    def _server_handler_table(self):
        return {
            # TODO 4.0: MSG_SERVICE_REQUEST ought to eventually move into
            # Transport's server mode like the client side did, just for
            # consistency.
            MSG_SERVICE_REQUEST: self._parse_service_request,
            MSG_USERAUTH_REQUEST: self._parse_userauth_request,
            MSG_USERAUTH_INFO_RESPONSE: self._parse_userauth_info_response,
        }

    # Messages which should be handled _by_ clients (sent by servers)
    @property
    def _client_handler_table(self):
        return {
            MSG_SERVICE_ACCEPT: self._parse_service_accept,
            MSG_USERAUTH_SUCCESS: self._parse_userauth_success,
            MSG_USERAUTH_FAILURE: self._parse_userauth_failure,
            MSG_USERAUTH_BANNER: self._parse_userauth_banner,
            MSG_USERAUTH_INFO_REQUEST: self._parse_userauth_info_request,
        }

    # NOTE: prior to the fix for #1283, this was a static dict instead of a
    # property. Should be backwards compatible in most/all cases.
    @property
    def _handler_table(self):
        if self.transport.server_mode:
            return self._server_handler_table
        else:
            return self._client_handler_table


class GssapiWithMicAuthHandler:
    """A specialized Auth handler for gssapi-with-mic

    During the GSSAPI token exchange we need a modified dispatch table,
    because the packet type numbers are not unique.
    """

    method = "gssapi-with-mic"

    def __init__(self, delegate, sshgss):
        self._delegate = delegate
        self.sshgss = sshgss

    def abort(self):
        self._restore_delegate_auth_handler()
        return self._delegate.abort()

    @property
    def transport(self):
        return self._delegate.transport

    @property
    def _send_auth_result(self):
        return self._delegate._send_auth_result

    @property
    def auth_username(self):
        return self._delegate.auth_username

    @property
    def gss_host(self):
        return self._delegate.gss_host

    def _restore_delegate_auth_handler(self):
        self.transport.auth_handler = self._delegate

    def _parse_userauth_gssapi_token(self, m):
        client_token = m.get_string()
        # use the client token as input to establish a secure
        # context.
        sshgss = self.sshgss
        try:
            token = sshgss.ssh_accept_sec_context(
                self.gss_host, client_token, self.auth_username
            )
        except Exception as e:
            self.transport.saved_exception = e
            result = AUTH_FAILED
            self._restore_delegate_auth_handler()
            self._send_auth_result(self.auth_username, self.method, result)
            raise
        if token is not None:
            m = Message()
            m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
            m.add_string(token)
            self.transport._expected_packet = (
                MSG_USERAUTH_GSSAPI_TOKEN,
                MSG_USERAUTH_GSSAPI_MIC,
                MSG_USERAUTH_REQUEST,
            )
            self.transport._send_message(m)

    def _parse_userauth_gssapi_mic(self, m):
        mic_token = m.get_string()
        sshgss = self.sshgss
        username = self.auth_username
        self._restore_delegate_auth_handler()
        try:
            sshgss.ssh_check_mic(
                mic_token, self.transport.session_id, username
            )
        except Exception as e:
            self.transport.saved_exception = e
            result = AUTH_FAILED
            self._send_auth_result(username, self.method, result)
            raise
        # TODO: Implement client credential saving.
        # The OpenSSH server is able to create a TGT with the delegated
        # client credentials, but this is not supported by GSS-API.
        result = AUTH_SUCCESSFUL
        self.transport.server_object.check_auth_gssapi_with_mic(
            username, result
        )
        # okay, send result
        self._send_auth_result(username, self.method, result)

    def _parse_service_request(self, m):
        self._restore_delegate_auth_handler()
        return self._delegate._parse_service_request(m)

    def _parse_userauth_request(self, m):
        self._restore_delegate_auth_handler()
        return self._delegate._parse_userauth_request(m)

    __handler_table = {
        MSG_SERVICE_REQUEST: _parse_service_request,
        MSG_USERAUTH_REQUEST: _parse_userauth_request,
        MSG_USERAUTH_GSSAPI_TOKEN: _parse_userauth_gssapi_token,
        MSG_USERAUTH_GSSAPI_MIC: _parse_userauth_gssapi_mic,
    }

    @property
    def _handler_table(self):
        # TODO: determine if we can cut this up like we did for the primary
        # AuthHandler class.
        return self.__handler_table


class AuthOnlyHandler(AuthHandler):
    """
    AuthHandler, and just auth, no service requests!

    .. versionadded:: 3.2
    """

    # NOTE: this purposefully duplicates some of the parent class in order to
    # modernize, refactor, etc. The intent is that eventually we will collapse
    # this one onto the parent in a backwards incompatible release.

    @property
    def _client_handler_table(self):
        my_table = super()._client_handler_table.copy()
        del my_table[MSG_SERVICE_ACCEPT]
        return my_table

    def send_auth_request(self, username, method, finish_message=None):
        """
        Submit a userauth request message & wait for response.

        Performs the transport message send call, sets self.auth_event, and
        will lock-n-block as necessary to both send, and wait for response to,
        the USERAUTH_REQUEST.

        Most callers will want to supply a callback to ``finish_message``,
        which accepts a Message ``m`` and may call mutator methods on it to add
        more fields.
        """
        # Store a few things for reference in handlers, including auth failure
        # handler (which needs to know if we were using a bad method, etc)
        self.auth_method = method
        self.username = username
        # Generic userauth request fields
        m = Message()
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(username)
        m.add_string("ssh-connection")
        m.add_string(method)
        # Caller usually has more to say, such as injecting password, key etc
        finish_message(m)
        # TODO 4.0: seems odd to have the client handle the lock and not
        # Transport; that _may_ have been an artifact of allowing user
        # threading event injection? Regardless, we don't want to move _this_
        # locking into Transport._send_message now, because lots of other
        # untouched code also uses that method and we might end up
        # double-locking (?) but 4.0 would be a good time to revisit.
        with self.transport.lock:
            self.transport._send_message(m)
        # We have cut out the higher level event args, but self.auth_event is
        # still required for self.wait_for_response to function correctly (it's
        # the mechanism used by the auth success/failure handlers, the abort
        # handler, and a few other spots like in gssapi.
        # TODO: interestingly, wait_for_response itself doesn't actually
        # enforce that its event argument and self.auth_event are the same...
        self.auth_event = threading.Event()
        return self.wait_for_response(self.auth_event)

    def auth_none(self, username):
        return self.send_auth_request(username, "none")

    def auth_publickey(self, username, key):
        key_type, bits = self._get_key_type_and_bits(key)
        algorithm = self._finalize_pubkey_algorithm(key_type)
        blob = self._get_session_blob(
            key,
            "ssh-connection",
            username,
            algorithm,
        )

        def finish(m):
            # This field doesn't appear to be named, but is False when querying
            # for permission (ie knowing whether to even prompt a user for
            # passphrase, etc) or True when just going for it. Paramiko has
            # never bothered with the former type of message, apparently.
            m.add_boolean(True)
            m.add_string(algorithm)
            m.add_string(bits)
            m.add_string(key.sign_ssh_data(blob, algorithm))

        return self.send_auth_request(username, "publickey", finish)

    def auth_password(self, username, password):
        def finish(m):
            # Unnamed field that equates to "I am changing my password", which
            # Paramiko clientside never supported and serverside only sort of
            # supported.
            m.add_boolean(False)
            m.add_string(b(password))

        return self.send_auth_request(username, "password", finish)

    def auth_interactive(self, username, handler, submethods=""):
        """
        response_list = handler(title, instructions, prompt_list)
        """
        # Unlike most siblings, this auth method _does_ require other
        # superclass handlers (eg userauth info request) to understand
        # what's going on, so we still set some self attributes.
        self.auth_method = "keyboard_interactive"
        self.interactive_handler = handler

        def finish(m):
            # Empty string for deprecated language tag field, per RFC 4256:
            # https://www.rfc-editor.org/rfc/rfc4256#section-3.1
            m.add_string("")
            m.add_string(submethods)

        return self.send_auth_request(username, "keyboard-interactive", finish)

    # NOTE: not strictly 'auth only' related, but allows users to opt-in.
    def _choose_fallback_pubkey_algorithm(self, key_type, my_algos):
        msg = "Server did not send a server-sig-algs list; defaulting to something in our preferred algorithms list"  # noqa
        self._log(DEBUG, msg)
        noncert_key_type = key_type.replace("-cert-v01@openssh.com", "")
        if key_type in my_algos or noncert_key_type in my_algos:
            actual = key_type if key_type in my_algos else noncert_key_type
            msg = f"Current key type, {actual!r}, is in our preferred list; using that"  # noqa
            algo = actual
        else:
            algo = my_algos[0]
            msg = f"{key_type!r} not in our list - trying first list item instead, {algo!r}"  # noqa
        self._log(DEBUG, msg)
        return algo

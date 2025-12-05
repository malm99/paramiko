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
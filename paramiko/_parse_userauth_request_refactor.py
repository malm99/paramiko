def _parse_userauth_request(self, m):

    if not self.transport.server_mode:
        self._send_default_failure()
        return

    if self.authenticated:
        return

    username = m.get_text()
    service = m.get_text()
    method = m.get_text()

    self._log(
        DEBUG,
        f"Auth request (type={method}) service={service}, username={username}"
    )

    if service != "ssh-connection":
        self._disconnect_service_not_available()
        return

    if (self.auth_username is not None) and (
        self.auth_username != username
    ):
        self._log(
            WARNING,
            "Auth rejected because the client attempted to change username mid-flight"
        )
        self._disconnect_no_more_auth()
        return

    self.auth_username = username

    gss_allowed = self.transport.server_object.enable_auth_gssapi()

    # Dispatch tabel
    handlers = {
        "none": lambda: self._handle_auth_none(username),
        "password": lambda: self._handle_auth_password(username, m),
        "publickey": lambda: self._handle_auth_publickey(username, m),
        "keyboard-interactive": lambda: self._handle_auth_keyboard_interactive(username, m),
        "gssapi-with-mic": (
            lambda: self._handle_auth_gssapi_with_mic(username, m)
            if gss_allowed else self._handle_auth_unsupported(username)
        ),
        "gssapi-keyex": (
            lambda: self._handle_auth_gssapi_keyex(username, m)
            if gss_allowed else self._handle_auth_unsupported(username)
        ),
    }

    handler = handlers.get(method, lambda: self._handle_auth_none(username))
    result = handler()

    # Some handlers return None because they already sent a message
    if result is not None:
        self._send_auth_result(username, method, result)


""" def _handle_auth_none(self, username):
    return self.transport.server_object.check_auth_none(username)

def _handle_auth_password(self, username, m):
    changereq = m.get_boolean()
    password = m.get_binary()

    try:
        password = password.decode("UTF-8")
    except UnicodeError:
        pass  # raw bytes allowed

    if changereq:
        self._log(DEBUG, "Password change request (rejected)")
        newpassword = m.get_binary()
        try:
            newpassword = newpassword.decode("UTF-8", "replace")
        except UnicodeError:
            pass
        return AUTH_FAILED

    return self.transport.server_object.check_auth_password(
        username, password
    )

def _handle_auth_publickey(self, username, m):
    sig_attached = m.get_boolean()
    algorithm = m.get_text()
    keyblob = m.get_binary()

    try:
        key = self._generate_key_from_request(algorithm, keyblob)
    except SSHException as e:
        self._log(INFO, f"Auth rejected: public key: {str(e)}")
        key = None
    except Exception as e:
        self._log(
            INFO,
            f"Auth rejected: unsupported or mangled public key ({e.__class__.__name__}: {e})"
        )
        key = None

    if key is None:
        self._disconnect_no_more_auth()
        return None  # stops flow

    result = self.transport.server_object.check_auth_publickey(
        username, key
    )

    if result != AUTH_FAILED:
        if not sig_attached:
            m2 = Message()
            m2.add_byte(cMSG_USERAUTH_PK_OK)
            m2.add_string(algorithm)
            m2.add_string(keyblob)
            self.transport._send_message(m2)
            return None

        sig = Message(m.get_binary())
        blob = self._get_session_blob(
            key, "ssh-connection", username, algorithm
        )
        if not key.verify_ssh_sig(blob, sig):
            self._log(INFO, "Auth rejected: invalid signature")
            result = AUTH_FAILED

    return result

def _handle_auth_keyboard_interactive(self, username, m):
    submethods = m.get_string()
    result = self.transport.server_object.check_auth_interactive(
        username, submethods
    )

    if isinstance(result, InteractiveQuery):
        self._interactive_query(result)
        return None

    return result


def _handle_auth_gssapi_with_mic(self, username, m):
    sshgss = GSSAuth("gssapi-with-mic")

    mechs = m.get_int()
    if mechs > 1:
        self._log(INFO, "Disconnect: More than one GSS-API mechanism received")
        self._disconnect_no_more_auth()
        return None

    desired_mech = m.get_string()
    if not sshgss.ssh_check_mech(desired_mech):
        self._log(INFO, "Disconnect: Invalid GSS-API mechanism received")
        self._disconnect_no_more_auth()
        return None

    supported = sshgss.ssh_gss_oids("server")

    m2 = Message()
    m2.add_byte(cMSG_USERAUTH_GSSAPI_RESPONSE)
    m2.add_bytes(supported)

    self.transport.auth_handler = GssapiWithMicAuthHandler(self, sshgss)
    self.transport._expected_packet = (
        MSG_USERAUTH_GSSAPI_TOKEN,
        MSG_USERAUTH_GSSAPI_MIC,
        MSG_USERAUTH_REQUEST,
        MSG_SERVICE_REQUEST,
    )

    self.transport._send_message(m2)
    return None

def _handle_auth_gssapi_keyex(self, username, m):
    mic_token = m.get_string()
    sshgss = self.transport.kexgss_ctxt

    if sshgss is None:
        return AUTH_FAILED

    try:
        sshgss.ssh_check_mic(
            mic_token, self.transport.session_id, self.auth_username
        )
    except Exception:
        return AUTH_FAILED

    result = AUTH_SUCCESSFUL
    self.transport.server_object.check_auth_gssapi_keyex(username, result)
    return result

def _handle_auth_unsupported(self, username):
    return self.transport.server_object.check_auth_none(username)

def _send_default_failure(self):
    m = Message()
    m.add_byte(cMSG_USERAUTH_FAILURE)
    m.add_string("none")
    m.add_boolean(False)
    self.transport._send_message(m)

 """
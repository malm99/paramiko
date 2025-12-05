def _parse_userauth_request(self, m):
        if not self.transport.server_mode:
            # er, uh... what?
            m = Message()
            m.add_byte(cMSG_USERAUTH_FAILURE)
            m.add_string("none")
            m.add_boolean(False)
            self.transport._send_message(m)
            return
        if self.authenticated:
            # ignore
            return
        username = m.get_text()
        service = m.get_text()
        method = m.get_text()
        self._log(
            DEBUG,
            "Auth request (type={}) service={}, username={}".format(
                method, service, username
            ),
        )
        if service != "ssh-connection":
            self._disconnect_service_not_available()
            return
        if (self.auth_username is not None) and (
            self.auth_username != username
        ):
            self._log(
                WARNING,
                "Auth rejected because the client attempted to change username in mid-flight",  # noqa
            )
            self._disconnect_no_more_auth()
            return
        self.auth_username = username
        # check if GSS-API authentication is enabled
        gss_auth = self.transport.server_object.enable_auth_gssapi()

        if method == "none":
            result = self.transport.server_object.check_auth_none(username)
        elif method == "password":
            changereq = m.get_boolean()
            password = m.get_binary()
            try:
                password = password.decode("UTF-8")
            except UnicodeError:
                # some clients/servers expect non-utf-8 passwords!
                # in this case, just return the raw byte string.
                pass
            if changereq:
                # always treated as failure, since we don't support changing
                # passwords, but collect the list of valid auth types from
                # the callback anyway
                self._log(DEBUG, "Auth request to change passwords (rejected)")
                newpassword = m.get_binary()
                try:
                    newpassword = newpassword.decode("UTF-8", "replace")
                except UnicodeError:
                    pass
                result = AUTH_FAILED
            else:
                result = self.transport.server_object.check_auth_password(
                    username, password
                )
        elif method == "publickey":
            sig_attached = m.get_boolean()
            # NOTE: server never wants to guess a client's algo, they're
            # telling us directly. No need for _finalize_pubkey_algorithm
            # anywhere in this flow.
            algorithm = m.get_text()
            keyblob = m.get_binary()
            try:
                key = self._generate_key_from_request(algorithm, keyblob)
            except SSHException as e:
                self._log(INFO, "Auth rejected: public key: {}".format(str(e)))
                key = None
            except Exception as e:
                msg = "Auth rejected: unsupported or mangled public key ({}: {})"  # noqa
                self._log(INFO, msg.format(e.__class__.__name__, e))
                key = None
            if key is None:
                self._disconnect_no_more_auth()
                return
            # first check if this key is okay... if not, we can skip the verify
            result = self.transport.server_object.check_auth_publickey(
                username, key
            )
            if result != AUTH_FAILED:
                # key is okay, verify it
                if not sig_attached:
                    # client wants to know if this key is acceptable, before it
                    # signs anything...  send special "ok" message
                    m = Message()
                    m.add_byte(cMSG_USERAUTH_PK_OK)
                    m.add_string(algorithm)
                    m.add_string(keyblob)
                    self.transport._send_message(m)
                    return
                sig = Message(m.get_binary())
                blob = self._get_session_blob(
                    key, service, username, algorithm
                )
                if not key.verify_ssh_sig(blob, sig):
                    self._log(INFO, "Auth rejected: invalid signature")
                    result = AUTH_FAILED
        elif method == "keyboard-interactive":
            submethods = m.get_string()
            result = self.transport.server_object.check_auth_interactive(
                username, submethods
            )
            if isinstance(result, InteractiveQuery):
                # make interactive query instead of response
                self._interactive_query(result)
                return
        elif method == "gssapi-with-mic" and gss_auth:
            sshgss = GSSAuth(method)
            # Read the number of OID mechanisms supported by the client.
            # OpenSSH sends just one OID. It's the Kerveros V5 OID and that's
            # the only OID we support.
            mechs = m.get_int()
            # We can't accept more than one OID, so if the SSH client sends
            # more than one, disconnect.
            if mechs > 1:
                self._log(
                    INFO,
                    "Disconnect: Received more than one GSS-API OID mechanism",
                )
                self._disconnect_no_more_auth()
            desired_mech = m.get_string()
            mech_ok = sshgss.ssh_check_mech(desired_mech)
            # if we don't support the mechanism, disconnect.
            if not mech_ok:
                self._log(
                    INFO,
                    "Disconnect: Received an invalid GSS-API OID mechanism",
                )
                self._disconnect_no_more_auth()
            # send the Kerberos V5 GSSAPI OID to the client
            supported_mech = sshgss.ssh_gss_oids("server")
            # RFC 4462 says we are not required to implement GSS-API error
            # messages. See section 3.8 in http://www.ietf.org/rfc/rfc4462.txt
            m = Message()
            m.add_byte(cMSG_USERAUTH_GSSAPI_RESPONSE)
            m.add_bytes(supported_mech)
            self.transport.auth_handler = GssapiWithMicAuthHandler(
                self, sshgss
            )
            self.transport._expected_packet = (
                MSG_USERAUTH_GSSAPI_TOKEN,
                MSG_USERAUTH_REQUEST,
                MSG_SERVICE_REQUEST,
            )
            self.transport._send_message(m)
            return
        elif method == "gssapi-keyex" and gss_auth:
            mic_token = m.get_string()
            sshgss = self.transport.kexgss_ctxt
            if sshgss is None:
                # If there is no valid context, we reject the authentication
                result = AUTH_FAILED
                self._send_auth_result(username, method, result)
            try:
                sshgss.ssh_check_mic(
                    mic_token, self.transport.session_id, self.auth_username
                )
            except Exception:
                result = AUTH_FAILED
                self._send_auth_result(username, method, result)
                raise
            result = AUTH_SUCCESSFUL
            self.transport.server_object.check_auth_gssapi_keyex(
                username, result
            )
        else:
            result = self.transport.server_object.check_auth_none(username)
        # okay, send result
        self._send_auth_result(username, method, result)
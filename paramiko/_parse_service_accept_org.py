def _parse_service_accept(self, m):
    service = m.get_text()
    if service == "ssh-userauth":
        self._log(DEBUG, "userauth is OK")
        m = Message()
        m.add_byte(cMSG_USERAUTH_REQUEST)
        m.add_string(self.username)
        m.add_string("ssh-connection")
        m.add_string(self.auth_method)
        if self.auth_method == "password":
            m.add_boolean(False)
            password = b(self.password)
            m.add_string(password)
        elif self.auth_method == "publickey":
            m.add_boolean(True)
            key_type, bits = self._get_key_type_and_bits(self.private_key)
            algorithm = self._finalize_pubkey_algorithm(key_type)
            m.add_string(algorithm)
            m.add_string(bits)
            blob = self._get_session_blob(
                self.private_key,
                "ssh-connection",
                self.username,
                algorithm,
            )
            sig = self.private_key.sign_ssh_data(blob, algorithm)
            m.add_string(sig)
        elif self.auth_method == "keyboard-interactive":
            m.add_string("")
            m.add_string(self.submethods)
        elif self.auth_method == "gssapi-with-mic":
            sshgss = GSSAuth(self.auth_method, self.gss_deleg_creds)
            m.add_bytes(sshgss.ssh_gss_oids())
            # send the supported GSSAPI OIDs to the server
            self.transport._send_message(m)
            ptype, m = self.transport.packetizer.read_message()
            if ptype == MSG_USERAUTH_BANNER:
                self._parse_userauth_banner(m)
                ptype, m = self.transport.packetizer.read_message()
            if ptype == MSG_USERAUTH_GSSAPI_RESPONSE:
                # Read the mechanism selected by the server. We send just
                # the Kerberos V5 OID, so the server can only respond with
                # this OID.
                mech = m.get_string()
                m = Message()
                m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                try:
                    m.add_string(
                        sshgss.ssh_init_sec_context(
                            self.gss_host, mech, self.username
                        )
                    )
                except GSS_EXCEPTIONS as e:
                    return self._handle_local_gss_failure(e)
                self.transport._send_message(m)
                while True:
                    ptype, m = self.transport.packetizer.read_message()
                    if ptype == MSG_USERAUTH_GSSAPI_TOKEN:
                        srv_token = m.get_string()
                        try:
                            next_token = sshgss.ssh_init_sec_context(
                                self.gss_host,
                                mech,
                                self.username,
                                srv_token,
                            )
                        except GSS_EXCEPTIONS as e:
                            return self._handle_local_gss_failure(e)
                        # After this step the GSSAPI should not return any
                        # token. If it does, we keep sending the token to
                        # the server until no more token is returned.
                        if next_token is None:
                            break
                        else:
                            m = Message()
                            m.add_byte(cMSG_USERAUTH_GSSAPI_TOKEN)
                            m.add_string(next_token)
                            self.transport.send_message(m)
                else:
                    raise SSHException(
                        "Received Package: {}".format(MSG_NAMES[ptype])
                    )
                m = Message()
                m.add_byte(cMSG_USERAUTH_GSSAPI_MIC)
                # send the MIC to the server
                m.add_string(sshgss.ssh_get_mic(self.transport.session_id))
            elif ptype == MSG_USERAUTH_GSSAPI_ERRTOK:
                # RFC 4462 says we are not required to implement GSS-API
                # error messages.
                # See RFC 4462 Section 3.8 in
                # http://www.ietf.org/rfc/rfc4462.txt
                raise SSHException("Server returned an error token")
            elif ptype == MSG_USERAUTH_GSSAPI_ERROR:
                maj_status = m.get_int()
                min_status = m.get_int()
                err_msg = m.get_string()
                m.get_string()  # Lang tag - discarded
                raise SSHException(
                    """GSS-API Error:
Major Status: {}
Minor Status: {}
Error Message: {}
""".format(
                        maj_status, min_status, err_msg
                    )
                )
            elif ptype == MSG_USERAUTH_FAILURE:
                self._parse_userauth_failure(m)
                return
            else:
                raise SSHException(
                    "Received Package: {}".format(MSG_NAMES[ptype])
                )
        elif (
            self.auth_method == "gssapi-keyex"
            and self.transport.gss_kex_used
        ):
            kexgss = self.transport.kexgss_ctxt
            kexgss.set_username(self.username)
            mic_token = kexgss.ssh_get_mic(self.transport.session_id)
            m.add_string(mic_token)
        elif self.auth_method == "none":
            pass
        else:
            raise SSHException(
                'Unknown auth method "{}"'.format(self.auth_method)
            )
        self.transport._send_message(m)
    else:
        self._log(
            DEBUG, 'Service request "{}" accepted (?)'.format(service)
        )
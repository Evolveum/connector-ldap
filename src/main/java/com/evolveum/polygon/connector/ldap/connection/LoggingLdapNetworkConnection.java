/*
 * Copyright (c) 2026 Evolveum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.evolveum.polygon.connector.ldap.connection;

import com.evolveum.polygon.connector.ldap.ConnectionLog;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.mina.core.session.IoSession;

/**
 * Observes the existing MINA callbacks, without issuing requests or changing connection handling.
 * The LDAP API does not expose its current IoSession. Retain the last callback session for diagnostics,
 * including after disconnect; do not use this reference to decide whether the connection is usable.
 */
public class LoggingLdapNetworkConnection extends LdapNetworkConnection {
    private final ConnectionLog connectionLog;
    private volatile IoSession diagnosticSession;

    public LoggingLdapNetworkConnection(LdapConnectionConfig config, ConnectionLog connectionLog) {
        super(config);
        this.connectionLog = connectionLog;
    }

    public IoSession getDiagnosticSession() {
        return diagnosticSession;
    }

    @Override
    public void sessionCreated(IoSession session) throws Exception {
        diagnosticSession = session;
        super.sessionCreated(session);
        connectionLog.debugState(this, session, "transport-created");
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        try {
            super.sessionClosed(session);
        } finally {
            connectionLog.debugState(this, session, "transport-closed");
        }
    }

    @Override
    public void inputClosed(IoSession session) throws Exception {
        connectionLog.debugState(this, session, "transport-input-closed");
        super.inputClosed(session);
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        connectionLog.debugFailure(this, session, "transport-exception", cause);
        super.exceptionCaught(session, cause);
    }

    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        super.messageSent(session, message);
        connectionLog.logProtocol(this, session, "sent", message);
    }

    @Override
    public void messageReceived(IoSession session, Object message) throws Exception {
        try {
            super.messageReceived(session, message);
        } finally {
            connectionLog.logProtocol(this, session, "received", message);
        }
    }
}

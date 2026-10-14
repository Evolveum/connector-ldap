/*
 * Copyright (c) 2021 Evolveum
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
package com.evolveum.polygon.connector.ldap;

import com.evolveum.polygon.connector.ldap.connection.LoggingLdapNetworkConnection;
import com.evolveum.polygon.connector.ldap.connection.ServerDefinition;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Message;
import org.apache.directory.api.ldap.model.message.MessageTypeEnum;
import org.apache.directory.api.ldap.model.message.ResultResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.mina.core.session.IoSession;
import org.identityconnectors.common.logging.Log;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Terse connection log.
 */
public class ConnectionLog {
    private static final Log LOG = Log.getLog(ConnectionLog.class);
    private static final Pattern AD_CODE = Pattern.compile("(?i)\\b([0-9a-f]{8}):\\s*LdapErr:");
    private static final Pattern AD_DSID = Pattern.compile("(?i)\\bDSID-([0-9a-f]{8})\\b");

    // Names describe midPoint's mapping: ConnId INFO -> DEBUG, OK -> TRACE.
    // Both enablement and output belong to the configured ConnId logging provider.
    public boolean isDebug() {
        return LOG.isInfo();
    }

    public boolean isTrace() {
        return LOG.isOk();
    }

    /** Local observations only: clientAuthenticated is not a query of the server's authorization state. */
    public void debugState(LdapNetworkConnection connection, String event) {
        if (!isDebug()) { return; }
        IoSession session = connection instanceof LoggingLdapNetworkConnection
                ? ((LoggingLdapNetworkConnection) connection).getDiagnosticSession() : null;
        debugState(connection, session, event);
    }

    public void debugState(LdapNetworkConnection connection, IoSession session, String event) {
        if (!isDebug()) { return; }
        try {
            StringBuilder message = new StringBuilder("CONN ").append(getConnectionDesc(connection))
                    .append(" DEBUG event=").append(event);
            if (connection != null) {
                message.append(" clientConnected=").append(connection.isConnected())
                        .append(" clientAuthenticated=").append(connection.isAuthenticated());
            }
            if (session == null) {
                message.append(" ioSession=unavailable");
            } else {
                // MINA session ID is JVM-local. Addresses include the source port, for packet/DC-log correlation.
                // Keep the explicit callback session: the connection may already refer to a replacement session.
                message.append(" ioSession=").append(session.getId())
                        .append(" local=").append(session.getLocalAddress())
                        .append(" remote=").append(session.getRemoteAddress())
                        .append(" sessionConnected=").append(session.isConnected())
                        .append(" closing=").append(session.isClosing())
                        .append(" secured=").append(session.isSecured())
                        .append(" sessionCreatedAtMillis=").append(session.getCreationTime())
                        .append(" sessionAgeMillis=").append(System.currentTimeMillis() - session.getCreationTime())
                        .append(" lastReadAtMillis=").append(session.getLastReadTime())
                        .append(" lastWriteAtMillis=").append(session.getLastWriteTime());
            }
            debug(message.toString());
        } catch (RuntimeException e) {
            // Diagnostic collection must not break a connection operation or a MINA callback.
            debug("CONN DEBUG state unavailable (error=" + e.getClass().getSimpleName() + ")");
        }
    }

    /**
     * Keep bind exchanges and failed responses at DEBUG with a state snapshot. Routine protocol metadata is
     * compact and TRACE-only: correlate it with lifecycle snapshots using connectionObject and ioSession.
     * Never render an LDAP message: credentials, filters, entries and controls may contain secrets.
     */
    public void logProtocol(LdapNetworkConnection connection, IoSession session, String direction, Object value) {
        if (!isDebug() || !(value instanceof Message) || value instanceof SearchResultEntry) { return; }
        try {
            Message message = (Message) value;
            boolean bind = message.getType() == MessageTypeEnum.BIND_REQUEST
                    || message.getType() == MessageTypeEnum.BIND_RESPONSE;
            LdapResult result = message instanceof ResultResponse ? ((ResultResponse) message).getLdapResult() : null;
            boolean failure = message instanceof ResultResponse && isFailure(result);
            if (!bind && !failure && !isTrace()) { return; }

            String event = "ldap-" + direction + " messageId=" + message.getMessageId() + " type=" + message.getType();
            if (message instanceof ResultResponse) {
                event += result != null ? " resultCode=" + result.getResultCode() + diagnosticCodes(result.getDiagnosticMessage())
                        : " resultCode=unavailable";
            }
            if (bind || failure) {
                debugState(connection, session, event);
            } else {
                // No repeated socket addresses, authentication flags or timestamps for each healthy operation.
                trace("CONN " + getConnectionDesc(connection)
                        + " ioSession=" + (session != null ? session.getId() : "unavailable") + " TRACE event=" + event);
            }
        } catch (RuntimeException e) {
            debug("CONN DEBUG protocol metadata unavailable (error=" + e.getClass().getSimpleName() + ")");
        }
    }

    private boolean isFailure(LdapResult result) {
        if (result == null) { return true; }
        ResultCodeEnum code = result.getResultCode();
        // A false comparison and a SASL challenge are normal LDAP responses, not failures.
        return code != ResultCodeEnum.SUCCESS && code != ResultCodeEnum.COMPARE_TRUE
                && code != ResultCodeEnum.COMPARE_FALSE && code != ResultCodeEnum.SASL_BIND_IN_PROGRESS;
    }

    public void debugFailure(LdapNetworkConnection connection, IoSession session, String event, Throwable failure) {
        if (!isDebug()) { return; }
        debugState(connection, session, event + " error=" + failure.getClass().getSimpleName()
                + diagnosticCodes(failure.getMessage()));
    }

    /** Log only recognized numeric AD diagnostics, never the free-form message or exception stack. */
    private String diagnosticCodes(String diagnostic) {
        if (diagnostic == null) { return ""; }
        Matcher code = AD_CODE.matcher(diagnostic);
        Matcher dsid = AD_DSID.matcher(diagnostic);
        return (code.find() ? " adCode=" + code.group(1) : "")
                + (dsid.find() ? " dsid=" + dsid.group(1) : "");
    }

    protected void debug(String message) {
        LOG.info("{0}", message);
    }

    protected void trace(String message) {
        LOG.ok("{0}", message);
    }

    public boolean isSuccess() {
        return LOG.isInfo();
    }

    public boolean isWarn() {
        return LOG.isWarning();
    }

    public boolean isError() {
        return LOG.isError();
    }

    public void success(ServerDefinition serverDef, String operation, Object params) {
        if (!isSuccess()) { return; }
        if (params == null) {
            LOG.info("CONN {0} {1} success ", getConnectionDesc(serverDef), operation);
        } else {
            LOG.info("CONN {0} {1} success ({2})", getConnectionDesc(serverDef), operation, params);
        }
    }

    public void success(LdapNetworkConnection connection, String operation, Object params) {
        if (!isSuccess()) { return; }
        LOG.info("CONN {0} {1} success ({2})", getConnectionDesc(connection), operation, params);
    }

    public void success(ServerDefinition serverDef, String operation) {
        if (!isSuccess()) { return; }
        LOG.info("CONN {0} {1} success ", getConnectionDesc(serverDef), operation);
    }

    public void success(LdapNetworkConnection connection, String operation) {
        if (!isSuccess()) { return; }
        LOG.info("CONN {0} {1} success ", getConnectionDesc(connection), operation);
    }

    public void error(ServerDefinition serverDef, String operation, Exception exception) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2}", getConnectionDesc(serverDef), operation, exception.getMessage());
    }

    public void error(LdapNetworkConnection connection, String operation, Exception exception) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2}", getConnectionDesc(connection), operation, exception.getMessage());
    }

    public void error(ServerDefinition serverDef, String operation, Exception exception, Object params) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} ({3})", getConnectionDesc(serverDef), operation, exception.getMessage(), params);
    }

    public void error(LdapNetworkConnection connection, String operation, Exception exception, Object params) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} ({3})", getConnectionDesc(connection), operation, exception.getMessage(), params);
    }

    public void error(ServerDefinition serverDef, String operation, LdapResult ldapResult, Object params) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} ({3}) ({4})", getConnectionDesc(serverDef), operation, ldapResult.getDiagnosticMessage(), ldapResult.getResultCode(), params);
    }

    public void error(LdapNetworkConnection connection, String operation, LdapResult ldapResult, Object params) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} ({3}) ({4})", getConnectionDesc(connection), operation, ldapResult.getDiagnosticMessage(), ldapResult.getResultCode(), params);
    }

    public void error(ServerDefinition serverDef, String operation, String message, Object params) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} ({3})", getConnectionDesc(serverDef), operation, message, params);
    }

    public void error(LdapNetworkConnection connection, String operation, String message, Object params) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} ({3})", getConnectionDesc(connection), operation, message, params);
    }

    public void errorTagged(ServerDefinition serverDef, String operation, Exception exception, String tag) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} [{3}]", getConnectionDesc(serverDef), operation, exception.getMessage(), tag);
    }

    public void errorTagged(ServerDefinition serverDef, String operation, Exception exception, String tag, Object params) {
        if (!isError()) { return; }
        if (params == null) {
            LOG.info("CONN {0} {1} error: {2} [{3}]", getConnectionDesc(serverDef), operation, exception.getMessage(), tag);
        } else {
            LOG.info("CONN {0} {1} error: {2} [{3}] ({4})", getConnectionDesc(serverDef), operation, exception.getMessage(), tag, params);
        }
    }

    public void errorTagged(LdapNetworkConnection connection, String operation, Exception exception, String tag) {
        if (!isError()) { return; }
        LOG.info("CONN {0} {1} error: {2} [{3}]", getConnectionDesc(connection), operation, exception.getMessage(), tag);
    }


    public void searchSuccess(LdapNetworkConnection connection, SearchRequest searchReq, Integer numEntries, String tag) {
        if (!isSuccess()) { return; }
        LOG.info("CONN {0} search success ({1} {2} {3}{4}): {5} entries returned", getConnectionDesc(connection),
                searchReq.getBase(), searchReq.getScope(), searchReq.getFilter(),
                tag == null ? "" : " " + tag,
                numEntries == null ? "?" : numEntries);
    }

    public void searchWarning(LdapNetworkConnection connection, SearchRequest searchReq, Integer numEntries, String tag, String message) {
        if (!isWarn()) { return; }
        LOG.warn("CONN {0} search warning: {1} ({2} {3} {4}{5}): {6} entries returned", getConnectionDesc(connection),
                message,
                searchReq.getBase(), searchReq.getScope(), searchReq.getFilter(), tag == null ? "" : " " + tag,
                numEntries == null ? "?" : numEntries);
    }

    public void searchReferral(LdapNetworkConnection connection, SearchRequest searchReq, String referralInfo) {
        if (!isSuccess()) { return; }
        LOG.info("CONN {0} search referral: {1} ({2} {3} {4})", getConnectionDesc(connection),
                referralInfo,
                searchReq.getBase(), searchReq.getScope(), searchReq.getFilter());
    }

    public void searchError(LdapNetworkConnection connection, Exception exception, SearchRequest searchReq, Integer numEntries, String tag) {
        if (!isError()) { return; }
        LOG.info("CONN {0} search error: {2} ({3} {4} {5}{6}): {6} entries returned", getConnectionDesc(connection), exception.getMessage(),
                searchReq.getBase(), searchReq.getScope(), searchReq.getFilter(), tag == null ? "" : " " + tag,
                numEntries == null ? "?" : numEntries);
    }

    public void failedCheckAlive(LdapNetworkConnection connection, String reason) {
        LOG.info("CONN {0} checkAlive failed ({1})", getConnectionDesc(connection), reason);
    }

    /** Returns the old connection description before closing it, for correlation with the outcome. */
    public String reconnectStarted(LdapNetworkConnection connection, Exception reason) {
        String description = getConnectionDesc(connection);
        LOG.warn("CONN {0} reconnect start (reason={1})", description,
                reason != null ? reason.getClass().getSimpleName() : "unknown");
        if (isDebug()) {
            debugState(connection, "reconnect-before-close"
                    + (reason != null ? " error=" + reason.getClass().getSimpleName() + diagnosticCodes(reason.getMessage()) : ""));
        }
        return description;
    }

    /** A successful reconnect includes a successful bind, not necessarily a successful retried operation. */
    public void reconnectSucceeded(String oldConnection, LdapNetworkConnection newConnection, long durationMillis) {
        LOG.info("CONN {0} reconnect success (newConnection={1})", oldConnection, getConnectionDesc(newConnection));
        if (isDebug()) {
            debugState(newConnection, "reconnect-success oldConnection=" + oldConnection + " durationMillis=" + durationMillis);
        }
    }

    public void reconnectFailed(String oldConnection, Exception failure, long durationMillis) {
        LOG.warn("CONN {0} reconnect failed (error={1})", oldConnection, failure.getClass().getSimpleName());
        if (isDebug()) {
            debug("CONN " + oldConnection + " DEBUG event=reconnect-failed durationMillis=" + durationMillis
                    + " error=" + failure.getClass().getSimpleName() + diagnosticCodes(failure.getMessage()));
        }
    }

    private String getConnectionDesc(ServerDefinition serverDef) {
        if (serverDef == null) {
            return "-";
        }
        if (serverDef.getConnection() == null) {
            // Something better?
            return "-";
        }
        return getConnectionDesc(serverDef.getConnection());
    }

    private String getConnectionDesc(LdapNetworkConnection connection) {
        if (connection == null) {
            return "-";
        }
        // JVM-local connection object identity, not an AD account UID or server-side session ID.
        // This remains available after close and correlates connect/bind/close/reconnect records.
        return LdapUtil.formatConnectionInfo(connection)
                + " [connectionObject=" + Integer.toHexString(System.identityHashCode(connection)) + "]";
    }

    public void schemaSuccess(LdapNetworkConnection connection, int numberOfObjectClasses, int numberOfSchemaErrors) {
        if (!isSuccess()) { return; }
        LOG.info("CONN {0} schema success ({1} objectclasses, {2} errors)", getConnectionDesc(connection), numberOfObjectClasses, numberOfSchemaErrors);
    }

    public void schemaError(LdapNetworkConnection connection, Exception e) {
        if (!isError()) { return; }
        LOG.info("CONN {0} schema error: {1}", getConnectionDesc(connection), e.getMessage());
    }
}

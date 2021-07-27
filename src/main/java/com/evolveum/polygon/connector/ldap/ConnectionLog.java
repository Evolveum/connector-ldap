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

import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;

/**
 * Terse connection log.
 */
public class ConnectionLog {
    private static final Log LOG = Log.getLog(ConnectionLog.class);

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

    private String getConnectionDesc(ServerDefinition serverDef) {
        if (serverDef == null) {
            return "-";
        }
        if (serverDef.getConnection() == null) {
            // Something better?
            return "-";
        }
        return LdapUtil.formatConnectionInfo(serverDef.getConnection());
    }

    private String getConnectionDesc(LdapNetworkConnection connection) {
        if (connection == null) {
            return "-";
        }
        return LdapUtil.formatConnectionInfo(connection);
    }

}

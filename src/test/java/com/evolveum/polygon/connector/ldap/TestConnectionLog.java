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
package com.evolveum.polygon.connector.ldap;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import com.evolveum.polygon.connector.ldap.connection.LoggingLdapNetworkConnection;
import com.evolveum.polygon.connector.ldap.connection.ServerConnectionPool;
import com.evolveum.polygon.connector.ldap.connection.ServerDefinition;
import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.message.BindRequestImpl;
import org.apache.directory.api.ldap.model.message.CompareResponseImpl;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDoneImpl;
import org.apache.directory.api.ldap.model.message.SearchResultEntryImpl;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestConnectionLog {
    private static final String BASE_DN = "dc=example,dc=com";
    private static final String BIND_DN = "cn=Directory Manager";
    private static final String PASSWORD = "not-for-debug-output";
    private static final String DIAGNOSTIC = "000004DC: LdapErr: DSID-0C090D5A, comment: " + PASSWORD;

    @DataProvider
    public Object[][] reconnectOutcomes() {
        return new Object[][] { { false }, { true } };
    }

    @Test(dataProvider = "reconnectOutcomes")
    public void testReconnectDiagnostics(boolean rejectRebind) throws Exception {
        AtomicBoolean rejectBind = new AtomicBoolean();
        AtomicInteger binds = new AtomicInteger();
        AtomicInteger searches = new AtomicInteger();
        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig(BASE_DN);
        serverConfig.addAdditionalBindCredentials(BIND_DN, PASSWORD);
        serverConfig.addInMemoryOperationInterceptor(new InMemoryOperationInterceptor() {
            @Override
            public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
                binds.incrementAndGet();
                if (rejectBind.get()) {
                    throw new LDAPException(ResultCode.INVALID_CREDENTIALS, PASSWORD);
                }
            }

            @Override
            public void processSearchRequest(InMemoryInterceptedSearchRequest request) {
                searches.incrementAndGet();
            }
        });
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(serverConfig);
        RecordingLog log = new RecordingLog();
        log.traceEnabled = true;
        ServerConnectionPool<LdapConfiguration> pool = null;
        try {
            server.startListening();
            server.add("dn: " + BASE_DN, "objectClass: domain", "dc: example");
            LdapConfiguration configuration = new LdapConfiguration();
            configuration.setHost("127.0.0.1");
            configuration.setPort(server.getListenPort());
            configuration.setBaseContext(BASE_DN);
            configuration.setBindDn(BIND_DN);
            configuration.setBindPassword(new GuardedString(PASSWORD.toCharArray()));
            configuration.recompute();
            ServerDefinition definition = ServerDefinition.createDefaultDefinition(configuration);
            pool = new ServerConnectionPool<>(configuration, new ErrorHandler(), log);
            pool.addServerDefinition(definition);

            LdapNetworkConnection oldConnection = pool.connectServer(definition);
            long oldSession = ((LoggingLdapNetworkConnection) oldConnection).getDiagnosticSession().getId();
            log.await("type=BIND_RESPONSE", "resultCode=SUCCESS", "ioSession=" + oldSession + " ");
            rejectBind.set(rejectRebind);
            ReconnectException reason = new ReconnectException(DIAGNOSTIC);
            if (rejectRebind) {
                try {
                    pool.reconnect(oldConnection, reason);
                    Assert.fail("Rebind should have failed");
                } catch (ConnectionFailedException expected) {
                    log.await("type=BIND_RESPONSE", "resultCode=INVALID_CREDENTIALS");
                    log.await("event=reconnect-failed", "durationMillis=", "error=ConnectionFailedException");
                }
            } else {
                LdapNetworkConnection replacement = pool.reconnect(oldConnection, reason);
                long newSession = ((LoggingLdapNetworkConnection) replacement).getDiagnosticSession().getId();
                Assert.assertNotEquals(oldSession, newSession);
                log.await("event=reconnect-success", "ioSession=" + newSession + " ",
                        "clientAuthenticated=true", "oldConnection=", "durationMillis=");
                try (EntryCursor cursor = replacement.search(BASE_DN, "(objectClass=*)", SearchScope.OBJECT, "dc")) {
                    Assert.assertTrue(cursor.next());
                    Assert.assertFalse(cursor.next());
                }
                log.await("TRACE event=ldap-received", "type=SEARCH_RESULT_DONE", "resultCode=SUCCESS",
                        "ioSession=" + newSession + " ");
            }
            log.await("event=reconnect-before-close", "ioSession=" + oldSession + " ",
                    "clientConnected=true", "adCode=000004DC", "dsid=0C090D5A", "local=", "remote=",
                    "sessionCreatedAtMillis=", "lastReadAtMillis=", "lastWriteAtMillis=");
            log.await("event=transport-closed", "ioSession=" + oldSession + " ");
            Assert.assertEquals(binds.get(), 2, "Diagnostics must not issue additional binds");
            Assert.assertEquals(searches.get(), rejectRebind ? 0 : 1, "Diagnostics must not probe LDAP");
            Assert.assertFalse(log.text().contains(PASSWORD));
            Assert.assertFalse(log.text().contains(BIND_DN));
            Assert.assertFalse(log.text().contains(BASE_DN));
        } finally {
            if (pool != null) {
                pool.close("test cleanup");
            }
            server.shutDown(true);
        }
    }

    @Test
    public void testNewTransportOnSameConnectionObject() throws Exception {
        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig(BASE_DN);
        serverConfig.addAdditionalBindCredentials(BIND_DN, PASSWORD);
        InMemoryDirectoryServer server = new InMemoryDirectoryServer(serverConfig);
        try {
            server.startListening();
            RecordingLog log = new RecordingLog();
            LdapConnectionConfig config = new LdapConnectionConfig();
            config.setLdapHost("127.0.0.1");
            config.setLdapPort(server.getListenPort());
            try (LoggingLdapNetworkConnection connection = new LoggingLdapNetworkConnection(config, log)) {
                connection.bind(BIND_DN, PASSWORD);
                long firstSession = connection.getDiagnosticSession().getId();
                connection.unBind();
                connection.bind(BIND_DN, PASSWORD);
                long secondSession = connection.getDiagnosticSession().getId();
                Assert.assertNotEquals(firstSession, secondSession);
                String identity = "connectionObject=" + Integer.toHexString(System.identityHashCode(connection));
                log.await("event=transport-created", identity, "ioSession=" + firstSession + " ");
                log.await("event=transport-closed", identity, "ioSession=" + firstSession + " ");
                log.await("event=transport-created", identity, "ioSession=" + secondSession + " ");
                log.await("type=BIND_RESPONSE", "resultCode=SUCCESS", "ioSession=" + secondSession + " ");
            }
        } finally {
            server.shutDown(true);
        }
    }

    @Test
    public void testOnlySafeProtocolMetadataIsLogged() throws Exception {
        RecordingLog log = new RecordingLog();
        log.traceEnabled = true;
        BindRequestImpl bind = new BindRequestImpl();
        bind.setName(BIND_DN);
        bind.setCredentials(PASSWORD);
        bind.setMessageId(10);
        log.logProtocol(null, null, "sent", bind);
        SearchRequestImpl search = new SearchRequestImpl();
        search.setFilter("(userPassword=" + PASSWORD + ")");
        search.setMessageId(11);
        log.logProtocol(null, null, "sent", search);
        SearchResultDoneImpl result = new SearchResultDoneImpl(11);
        result.getLdapResult().setResultCode(ResultCodeEnum.OPERATIONS_ERROR);
        result.getLdapResult().setDiagnosticMessage(DIAGNOSTIC);
        log.logProtocol(null, null, "received", result);
        int records = log.size();
        log.logProtocol(null, null, "received", new SearchResultEntryImpl());
        Assert.assertEquals(log.size(), records, "Do not log returned entries");
        log.debugFailure(null, null, "transport-exception", new IllegalStateException(DIAGNOSTIC));
        Assert.assertTrue(log.text().contains("messageId=10 type=BIND_REQUEST"));
        Assert.assertTrue(log.text().contains("messageId=11 type=SEARCH_REQUEST"));
        Assert.assertTrue(log.text().contains("resultCode=OPERATIONS_ERROR adCode=000004DC dsid=0C090D5A"));
        Assert.assertFalse(log.text().contains(PASSWORD));
        Assert.assertFalse(log.text().contains(BIND_DN));
        Assert.assertFalse(log.text().contains("userPassword"));
    }

    @Test
    public void testDisabledDebugDoesNotInspectConnection() {
        RecordingLog log = new RecordingLog();
        log.enabled = false;
        LdapNetworkConnection connection = new LdapNetworkConnection() {
            @Override
            public boolean isConnected() {
                throw new AssertionError("Should not inspect a connection when DEBUG is off");
            }
        };
        log.debugState(connection, "test");
        log.logProtocol(connection, null, "sent", new BindRequestImpl());
        log.logProtocol(connection, null, "sent", new SearchRequestImpl());
        Assert.assertEquals(log.size(), 0);
    }

    @Test
    public void testHealthySearchIsCompactAndTraceOnly() throws Exception {
        RecordingLog log = new RecordingLog();
        LdapNetworkConnection connection = new LdapNetworkConnection() {
            @Override
            public boolean isConnected() {
                throw new AssertionError("A healthy search must not collect a connection state snapshot");
            }
        };
        SearchRequestImpl request = new SearchRequestImpl();
        request.setMessageId(42);
        request.setFilter("(userPassword=" + PASSWORD + ")");
        SearchResultDoneImpl response = new SearchResultDoneImpl(42);
        response.getLdapResult().setResultCode(ResultCodeEnum.SUCCESS);

        log.logProtocol(connection, null, "sent", request);
        log.logProtocol(connection, null, "received", response);
        Assert.assertEquals(log.size(), 0, "Healthy search protocol must be silent at DEBUG");

        log.traceEnabled = true;
        log.logProtocol(connection, null, "sent", request);
        log.logProtocol(connection, null, "received", response);
        log.logProtocol(connection, null, "received", new SearchResultEntryImpl());
        Assert.assertEquals(log.size(), 2, "TRACE should log only the request and final result, not entries");
        Assert.assertTrue(log.text().contains("TRACE event=ldap-sent messageId=42 type=SEARCH_REQUEST"));
        Assert.assertTrue(log.text().contains("TRACE event=ldap-received messageId=42 type=SEARCH_RESULT_DONE resultCode=SUCCESS"));
        Assert.assertTrue(log.text().contains("connectionObject="));
        Assert.assertTrue(log.text().contains("ioSession=unavailable"));
        Assert.assertFalse(log.text().contains("DEBUG event="));
        Assert.assertFalse(log.text().contains("clientConnected="));
        Assert.assertFalse(log.text().contains("local="));
        Assert.assertFalse(log.text().contains("sessionCreatedAtMillis="));
        Assert.assertFalse(log.text().contains(PASSWORD));
    }

    @Test
    public void testFailedSearchStaysAtDebugWithoutTrace() {
        RecordingLog log = new RecordingLog();
        LdapNetworkConnection connection = new LdapNetworkConnection();
        SearchResultDoneImpl response = new SearchResultDoneImpl(43);
        response.getLdapResult().setResultCode(ResultCodeEnum.OPERATIONS_ERROR);
        response.getLdapResult().setDiagnosticMessage(DIAGNOSTIC);
        log.logProtocol(connection, null, "received", response);
        Assert.assertEquals(log.size(), 1);
        Assert.assertTrue(log.text().contains("DEBUG event=ldap-received messageId=43 type=SEARCH_RESULT_DONE"));
        Assert.assertTrue(log.text().contains("resultCode=OPERATIONS_ERROR adCode=000004DC dsid=0C090D5A"));
        Assert.assertTrue(log.text().contains("clientConnected=false"));
        Assert.assertTrue(log.text().contains("clientAuthenticated=false"));
        Assert.assertFalse(log.text().contains(PASSWORD));
    }

    @DataProvider
    public Object[][] comparisonResults() {
        return new Object[][] { { ResultCodeEnum.COMPARE_TRUE }, { ResultCodeEnum.COMPARE_FALSE } };
    }

    @Test(dataProvider = "comparisonResults")
    public void testComparisonResultIsNotFailure(ResultCodeEnum code) {
        RecordingLog log = new RecordingLog();
        CompareResponseImpl response = new CompareResponseImpl(44);
        response.getLdapResult().setResultCode(code);
        log.logProtocol(null, null, "received", response);
        Assert.assertEquals(log.size(), 0);
        log.traceEnabled = true;
        log.logProtocol(null, null, "received", response);
        Assert.assertEquals(log.size(), 1);
        Assert.assertTrue(log.text().contains("TRACE event=ldap-received"));
        Assert.assertTrue(log.text().contains("resultCode=" + code));
    }

    @Test
    public void testUnavailableStateDoesNotBreakOperation() {
        RecordingLog log = new RecordingLog();
        LdapNetworkConnection connection = new LdapNetworkConnection() {
            @Override
            public boolean isConnected() {
                throw new IllegalStateException(PASSWORD);
            }
        };
        log.debugState(connection, "test");
        Assert.assertTrue(log.text().contains("state unavailable (error=IllegalStateException)"));
        Assert.assertFalse(log.text().contains(PASSWORD));
    }

    /** Per-test recorder; no changes to JVM-global logging configuration. */
    private static class RecordingLog extends ConnectionLog {
        private final List<String> messages = new ArrayList<>();
        private boolean enabled = true;
        private boolean traceEnabled;

        @Override
        public boolean isDebug() {
            return enabled;
        }

        @Override
        public boolean isTrace() {
            return enabled && traceEnabled;
        }

        @Override
        protected synchronized void debug(String message) {
            Assert.assertTrue(isDebug(), "DEBUG output must respect the level gate");
            messages.add(message);
            notifyAll();
        }

        @Override
        protected synchronized void trace(String message) {
            Assert.assertTrue(isTrace(), "TRACE output must respect the level gate");
            messages.add(message);
            notifyAll();
        }

        synchronized int size() {
            return messages.size();
        }

        synchronized String text() {
            return String.join("\n", messages);
        }

        synchronized void await(String... parts) throws InterruptedException {
            long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
            while (true) {
                for (String message : messages) {
                    boolean matches = true;
                    for (String part : parts) {
                        matches &= message.contains(part);
                    }
                    if (matches) { return; }
                }
                long remaining = deadline - System.nanoTime();
                Assert.assertTrue(remaining > 0, "Missing diagnostic " + String.join(", ", parts) + "\n" + text());
                TimeUnit.NANOSECONDS.timedWait(this, remaining);
            }
        }
    }
}

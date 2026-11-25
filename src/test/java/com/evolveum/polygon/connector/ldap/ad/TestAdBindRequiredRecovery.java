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
package com.evolveum.polygon.connector.ldap.ad;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

import com.unboundid.ldap.listener.InMemoryDirectoryServer;
import com.unboundid.ldap.listener.InMemoryDirectoryServerConfig;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSearchRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindRequest;
import com.unboundid.ldap.listener.interceptor.InMemoryInterceptedSimpleBindResult;
import com.unboundid.ldap.listener.interceptor.InMemoryOperationInterceptor;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.RetryableException;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.test.common.TestHelpers;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;

/**
 * A wire-level reproducer for an AD connection that starts returning X_BIND_REQUIRED.
 *
 * <p>The test LDAP server marks the connection used for the first account read as stale. Every account read on that
 * connection then returns the diagnostic from MID-11136. A reconnect and bind on a new connection would make the
 * same read succeed.</p>
 *
 * <p>The server simulates AD's error response; it does not reproduce the customer's authentication-loss cause.
 * Run with {@code mvn -Dtest=TestAdBindRequiredRecovery test}. No external server or Docker is needed.</p>
 */
public class TestAdBindRequiredRecovery {

    private static final int MAX_ATTEMPTS = 3;

    private static final String BASE_DN = "dc=example,dc=com";
    private static final String USER_DN = "uid=alice," + BASE_DN;
    private static final String BIND_DN = "cn=Directory Manager";
    private static final String BIND_PASSWORD = "secret";

    private static final String AD_BIND_REQUIRED_DIAGNOSTIC =
            "000004DC: LdapErr: DSID-0C090D5A, comment: In order to perform this operation a successful bind "
                    + "must be completed on the connection., data 0, v4563";

    private BindRequiredInterceptor interceptor;

    private InMemoryDirectoryServer directoryServer;
    private ConnectorFacade connector;

    @BeforeMethod
    public void startServer() throws Exception {
        connector = null;
        interceptor = new BindRequiredInterceptor();
        InMemoryDirectoryServerConfig serverConfig = new InMemoryDirectoryServerConfig(BASE_DN);
        serverConfig.addAdditionalBindCredentials(BIND_DN, BIND_PASSWORD);
        serverConfig.addInMemoryOperationInterceptor(interceptor);

        directoryServer = new InMemoryDirectoryServer(serverConfig);
        directoryServer.startListening();
        directoryServer.add(
                "dn: " + BASE_DN,
                "objectClass: top",
                "objectClass: domain",
                "dc: example");
        directoryServer.add(
                "dn: " + USER_DN,
                "objectClass: top",
                "objectClass: person",
                "objectClass: organizationalPerson",
                "objectClass: inetOrgPerson",
                "uid: alice",
                "cn: Alice Example",
                "sn: Example");

    }

    private void startConnector(String pagingStrategy) {
        AdLdapConfiguration configuration = createConfiguration();
        configuration.setPagingStrategy(pagingStrategy);
        APIConfiguration apiConfiguration = TestHelpers.createTestConfiguration(AdLdapConnector.class, configuration);
        apiConfiguration.getResultsHandlerConfiguration().setEnableFilteredResultsHandler(false);
        connector = ConnectorFacadeFactory.getInstance().newInstance(apiConfiguration);

        connector.test();
        connector.schema();
        interceptor.arm();
    }

    @AfterMethod(alwaysRun = true)
    public void stopServerAndConnector() {
        if (connector != null) {
            connector.dispose();
        }
        if (directoryServer != null) {
            directoryServer.shutDown(true);
        }
    }

    @Test
    public void testConnectorReconnectsAndRetriesBindRequired() {
        startConnector(AbstractLdapConfiguration.PAGING_STRATEGY_NONE);
        ConnectorObject object = connector.getObject(new ObjectClass("inetOrgPerson"), new Uid(USER_DN), null);

        Assert.assertNotNull(object);
        Assert.assertEquals(interceptor.getTargetSearchCount(), 2,
                "The account read should be retried once after X_BIND_REQUIRED");
        Assert.assertEquals(interceptor.getTargetConnectionCount(), 2,
                "The retry should use a freshly bound LDAP connection");
        Assert.assertTrue(interceptor.wasFreshConnectionUsed(),
                "The connector did not recover on a fresh connection");
        Assert.assertEquals(interceptor.successfullyBoundConnectionIds.size(), 2);
    }

    @DataProvider
    public Object[][] searchStrategies() {
        return new Object[][] {
                { AbstractLdapConfiguration.PAGING_STRATEGY_NONE },
                { AbstractLdapConfiguration.PAGING_STRATEGY_SPR },
                { AbstractLdapConfiguration.PAGING_STRATEGY_VLV }
        };
    }

    @Test(dataProvider = "searchStrategies")
    public void testSearchRecoversAfterBindRequired(String pagingStrategy) {
        startConnector(pagingStrategy);
        List<ConnectorObject> objects = new ArrayList<>();
        connector.search(new ObjectClass("inetOrgPerson"), null, object -> {
            objects.add(object);
            return true;
        }, null);

        Assert.assertEquals(objects.size(), 1);
        Assert.assertEquals(objects.get(0).getUid().getUidValue(), USER_DN);
        Assert.assertEquals(interceptor.getTargetConnectionCount(), 2);
        Assert.assertTrue(interceptor.wasFreshConnectionUsed());
        Assert.assertEquals(interceptor.successfullyBoundConnectionIds.size(), 2);
    }

    @Test(dataProvider = "searchStrategies")
    public void testSearchReturnsAllPagesAfterRecovery(String pagingStrategy) throws Exception {
        for (String uid : new String[] { "bob", "carol" }) {
            directoryServer.add("dn: uid=" + uid + "," + BASE_DN,
                    "objectClass: inetOrgPerson", "uid: " + uid, "cn: " + uid, "sn: " + uid);
        }
        startConnector(pagingStrategy);
        List<String> uids = new ArrayList<>();
        connector.search(new ObjectClass("inetOrgPerson"), null, object -> {
            uids.add(object.getUid().getUidValue());
            return true;
        }, null);

        Assert.assertEquals(uids.size(), 3, "Recovery must not lose or duplicate accounts");
        Assert.assertEquals(Set.copyOf(uids), Set.of(USER_DN, "uid=bob," + BASE_DN, "uid=carol," + BASE_DN));
        Assert.assertEquals(interceptor.getTargetConnectionCount(), 2);
        Assert.assertTrue(interceptor.wasFreshConnectionUsed());
    }

    @DataProvider
    public Object[][] interruptedPagedSearches() {
        return new Object[][] {
                { null, 1, null, 1 }, // Unbounded search: the first page was already delivered.
                { 2, 1, null, 1 }, // A repeated first page must not satisfy the requested page size.
                { 2, 2, null, 0 }, // A skipped page also establishes a server-side paging sequence.
                { 2, 1, "AQ==", 0 } // Opaque continuation token; inject the error before the server interprets it.
        };
    }

    @Test(dataProvider = "interruptedPagedSearches")
    public void testInterruptedPagedSearchDoesNotRestartFromBeginning(
            Integer pageSize, int offset, String initialCookie, int expectedDelivered)
            throws Exception {
        directoryServer.add("dn: uid=bob," + BASE_DN,
                "objectClass: inetOrgPerson", "uid: bob", "cn: Bob", "sn: Example");
        directoryServer.add("dn: uid=carol," + BASE_DN,
                "objectClass: inetOrgPerson", "uid: carol", "cn: Carol", "sn: Example");
        startConnector(AbstractLdapConfiguration.PAGING_STRATEGY_SPR);
        interceptor.successfulSearchesBeforeFailure = initialCookie == null ? 1 : 0;
        OperationOptionsBuilder options = new OperationOptionsBuilder();
        options.setPagedResultsOffset(offset);
        if (initialCookie != null) {
            options.setPagedResultsCookie(initialCookie);
        }
        if (pageSize != null) {
            options.setPageSize(pageSize);
        }
        List<String> uids = new ArrayList<>();

        RetryableException exception = Assert.expectThrows(RetryableException.class,
                () -> connector.search(new ObjectClass("inetOrgPerson"), null, object -> {
                    uids.add(object.getUid().getUidValue());
                    return true;
                }, options.build()));

        Assert.assertTrue(exception.getMessage().contains("restart the search without a paging cookie"));
        Assert.assertEquals(uids.size(), expectedDelivered, "Do not replay entries after a paging interruption");
        Assert.assertEquals(Set.copyOf(uids).size(), uids.size(), "No duplicate objects may be delivered");
        Assert.assertEquals(interceptor.getTargetSearchCount(), initialCookie == null ? 2 : 1,
                "Do not silently retry from page one");
        Assert.assertEquals(interceptor.successfullyBoundConnectionIds.size(), 2,
                "Repair the connection for the next operation even when this search cannot continue");

        // A new operation, explicitly started without a cookie, can use the repaired connection.
        List<String> retriedUids = new ArrayList<>();
        connector.search(new ObjectClass("inetOrgPerson"), null, object -> {
            retriedUids.add(object.getUid().getUidValue());
            return true;
        }, null);
        Assert.assertEquals(retriedUids.size(), 3);
        Assert.assertEquals(Set.copyOf(retriedUids), Set.of(USER_DN, "uid=bob," + BASE_DN, "uid=carol," + BASE_DN));
    }

    @Test
    public void testPersistentBindRequiredStopsAtAttemptLimit() {
        startConnector(AbstractLdapConfiguration.PAGING_STRATEGY_NONE);
        interceptor.alwaysRequireBind = true;

        ConnectorIOException exception = Assert.expectThrows(ConnectorIOException.class,
                () -> connector.getObject(new ObjectClass("inetOrgPerson"), new Uid(USER_DN), null));

        Assert.assertTrue(exception.getMessage().contains("Maximum number of attempts exceeded"));
        Assert.assertEquals(interceptor.getTargetSearchCount(), MAX_ATTEMPTS);
        Assert.assertEquals(interceptor.getTargetConnectionCount(), MAX_ATTEMPTS);
        Assert.assertFalse(interceptor.wasFreshConnectionUsed());
    }

    @Test(dataProvider = "searchStrategies")
    public void testPersistentSearchErrorHasBoundedRetries(String pagingStrategy) {
        startConnector(pagingStrategy);
        interceptor.alwaysRequireBind = true;

        ConnectorIOException exception = Assert.expectThrows(ConnectorIOException.class,
                () -> connector.search(new ObjectClass("inetOrgPerson"), null, object -> true, null));

        Assert.assertTrue(exception.getMessage().contains("Maximum number of attempts exceeded"));
        // The default strategy counts attempts; the paged strategies count retries after the initial attempt.
        int expectedSearches = AbstractLdapConfiguration.PAGING_STRATEGY_NONE.equals(pagingStrategy)
                ? MAX_ATTEMPTS : MAX_ATTEMPTS + 1;
        Assert.assertEquals(interceptor.getTargetSearchCount(), expectedSearches);
        Assert.assertEquals(interceptor.getTargetConnectionCount(), expectedSearches);
        Assert.assertFalse(interceptor.wasFreshConnectionUsed());
    }

    @Test
    public void testFailedRebindIsReported() {
        startConnector(AbstractLdapConfiguration.PAGING_STRATEGY_NONE);
        interceptor.rejectRebind = true;

        Assert.expectThrows(ConnectionFailedException.class,
                () -> connector.getObject(new ObjectClass("inetOrgPerson"), new Uid(USER_DN), null));

        Assert.assertEquals(interceptor.getTargetSearchCount(), 1);
        Assert.assertEquals(interceptor.rejectedBindCount.get(), 1);
        Assert.assertFalse(interceptor.wasFreshConnectionUsed());
    }

    @Test
    public void testSecurityErrorDoesNotReconnect() {
        startConnector(AbstractLdapConfiguration.PAGING_STRATEGY_NONE);
        interceptor.rejectSearchWithSecurityError = true;

        Assert.expectThrows(ConnectorSecurityException.class,
                () -> connector.getObject(new ObjectClass("inetOrgPerson"), new Uid(USER_DN), null));

        Assert.assertEquals(interceptor.getTargetSearchCount(), 1);
        Assert.assertEquals(interceptor.successfullyBoundConnectionIds.size(), 1);
    }

    private AdLdapConfiguration createConfiguration() {
        AdLdapConfiguration configuration = new AdLdapConfiguration();
        configuration.setHost("127.0.0.1");
        configuration.setPort(directoryServer.getListenPort());
        configuration.setBindDn(BIND_DN);
        configuration.setBindPassword(new GuardedString(BIND_PASSWORD.toCharArray()));
        configuration.setBaseContext(BASE_DN);
        configuration.setUidAttribute(AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME);
        configuration.setPagingStrategy(AbstractLdapConfiguration.PAGING_STRATEGY_NONE);
        configuration.setDefaultSearchScope("sub");
        configuration.setUserObjectClass("inetOrgPerson");
        configuration.setGroupObjectClass("groupOfNames");
        configuration.setGroupObjectClasses(new String[] { "groupOfNames" });
        configuration.setNativeAdSchema(false);
        configuration.setTweakSchema(false);
        configuration.setSynchronizationStrategy(AbstractLdapConfiguration.SYNCHRONIZATION_STRATEGY_NONE);
        configuration.setGlobalCatalogServers(new String[0]);
        configuration.setMaximumNumberOfAttempts(MAX_ATTEMPTS);
        configuration.setVlvSortAttribute("cn");
        configuration.setPagingBlockSize(1);
        return configuration;
    }

    private static class BindRequiredInterceptor extends InMemoryOperationInterceptor {

        private final AtomicBoolean armed = new AtomicBoolean();
        private final AtomicLong staleConnectionId = new AtomicLong(-1);
        private final AtomicBoolean freshConnectionUsed = new AtomicBoolean();
        private final AtomicInteger targetSearchCount = new AtomicInteger();
        private final Set<Long> targetConnectionIds = ConcurrentHashMap.newKeySet();
        private final Set<Long> successfullyBoundConnectionIds = ConcurrentHashMap.newKeySet();
        private final AtomicInteger rejectedBindCount = new AtomicInteger();
        private volatile boolean alwaysRequireBind;
        private volatile boolean rejectRebind;
        private volatile boolean rejectSearchWithSecurityError;
        private volatile int successfulSearchesBeforeFailure;

        void arm() {
            armed.set(true);
        }

        @Override
        public void processSimpleBindRequest(InMemoryInterceptedSimpleBindRequest request) throws LDAPException {
            if (armed.get() && rejectRebind) {
                rejectedBindCount.incrementAndGet();
                throw new LDAPException(ResultCode.INVALID_CREDENTIALS, "Rebind rejected by test server");
            }
        }

        @Override
        public void processSimpleBindResult(InMemoryInterceptedSimpleBindResult result) {
            if (ResultCode.SUCCESS.equals(result.getResult().getResultCode())) {
                successfullyBoundConnectionIds.add(result.getConnectionID());
            }
        }

        @Override
        public void processSearchRequest(InMemoryInterceptedSearchRequest request) throws LDAPException {
            if (!armed.get() || !(USER_DN.equalsIgnoreCase(request.getRequest().getBaseDN())
                    || BASE_DN.equalsIgnoreCase(request.getRequest().getBaseDN()))) {
                return;
            }

            long connectionId = request.getConnectionID();
            int searchNumber = targetSearchCount.incrementAndGet();
            targetConnectionIds.add(connectionId);

            if (rejectSearchWithSecurityError) {
                throw new LDAPException(ResultCode.INVALID_CREDENTIALS, "80090308: Logon failed, data 52e");
            }

            if (searchNumber <= successfulSearchesBeforeFailure) {
                return;
            }

            staleConnectionId.compareAndSet(-1, connectionId);
            if (alwaysRequireBind || staleConnectionId.get() == connectionId
                    || !successfullyBoundConnectionIds.contains(connectionId)) {
                throw new LDAPException(ResultCode.OPERATIONS_ERROR, AD_BIND_REQUIRED_DIAGNOSTIC);
            }

            freshConnectionUsed.set(true);
        }

        int getTargetSearchCount() {
            return targetSearchCount.get();
        }

        int getTargetConnectionCount() {
            return targetConnectionIds.size();
        }

        boolean wasFreshConnectionUsed() {
            return freshConnectionUsed.get();
        }
    }
}

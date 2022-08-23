/*
 * Copyright (c) 2016-2021 Evolveum
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

import java.util.*;
import java.util.function.Function;

import com.evolveum.polygon.connector.ldap.*;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.OperationOptions;

import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * Manager of connection for the entire LDAP replication hierarchy.
 * Handles connections to all base contexts, albeit indirectly.
 *
 * @author Radovan Semancik
 */
public class ConnectionManager<C extends AbstractLdapConfiguration> {

    private static final Log LOG = Log.getLog(ConnectionManager.class);

    private final C configuration;
    private final ErrorHandler errorHandler;
    private final ConnectionLog connectionLog;

    // Schema translator is initialized quite late, usually after we have at least one connection to fetch the schema
    // Hence schemaTranslator cannot be final
    private AbstractSchemaTranslator<C> schemaTranslator;

    private final List<ServerConnectionPool<C>> pools = new ArrayList<>();
    private ServerConnectionPool<C> defaultPool;

    /** Root DSE fetched from one of the top-level base-context servers. */
    private Entry rootDse = null;
    private List<String> supportedControls = null;

    public ConnectionManager(C configuration, ErrorHandler errorHandler, ConnectionLog connectionLog) {
        this.configuration = configuration;
        this.errorHandler = errorHandler;
        this.connectionLog = connectionLog;
        buildServerDefinitions();
    }

    protected C getConfiguration() {
        return configuration;
    }

    protected String[] getServersConfiguration() {
        return configuration.getServers();
    }

    protected boolean includeDefaultServerDefinition() {
        return true;
    }

    private void buildServerDefinitions() {
        if (includeDefaultServerDefinition()) {
            ServerDefinition defaultServerDefinition = ServerDefinition.createDefaultDefinition(configuration);
            this.defaultPool = addServerDefinition(defaultServerDefinition);
        }
        String[] serversConfiguration = getServersConfiguration();
        if (serversConfiguration != null) {
            for(int line = 0; line < serversConfiguration.length; line++) {
                addServerDefinition(ServerDefinition.parse(configuration, serversConfiguration[line], line));
            }
        }
    }

    private ServerConnectionPool<C> addServerDefinition(ServerDefinition serverDefinition) {
        ServerConnectionPool<C> pool = findPoolExact(serverDefinition.getBaseContextString());
        if (pool == null) {
            pool = new ServerConnectionPool<>(configuration, errorHandler, connectionLog);
            pool.setSchemaTranslator(schemaTranslator);
            pools.add(pool);
        }
        pool.addServerDefinition(serverDefinition);
        return pool;
    }

    public void setSchemaTranslator(AbstractSchemaTranslator<C> schemaTranslator) {
        this.schemaTranslator = schemaTranslator;
        for (ServerConnectionPool<C> pool : pools) {
            pool.setSchemaTranslator(schemaTranslator);
        }
    }

    private ServerConnectionPool<C> findPoolExact(String baseContextString) {
        for(ServerConnectionPool<C> pool: pools) {
            if (baseContextString.equals(pool.getBaseContextString())) {
                return pool;
            }
        }
        return null;
    }

    /**
     * Returns working connection (as far as we know) for new operations.
     */
    public LdapNetworkConnection getConnection(Dn base, OperationOptions options) {
        ServerConnectionPool<C> pool = selectPool(base);
        if (pool == null) {
            // Dumping configuration here, to make diagnotic easier
            LOG.info("Server configuration:\n{0}", dump());
            throw new ConfigurationException("No LDAP server configured for DN " + base);
        }
        LdapNetworkConnection connection = pool.getConnection(options);

        if (rootDse == null && pool == defaultPool) {
            // Take this opportunity to fetch root DSE from top-level base-context servers.
            // This is also additional check that the connection works.
            try {
                rootDse = fetchRootDse(connection);
            } catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
                // Try to reconnect and retry root DSE fetch. The connection might be stale here.
                connection = getConnectionReconnect(connection, base, options, e);
                try {
                    rootDse = fetchRootDse(connection);
                } catch (LdapException e2) {
                    throw errorHandler.processLdapException("Failed to retrieve root DSE (after reconnect attempt)", e2);
                }
            } catch (LdapException e) {
                throw errorHandler.processLdapException("Failed to retrieve root DSE", e);
            }
        }

        return connection;
    }

    /**
     * Returns new working connection, handling failures that happen in a middle of an operation.
     * As we are in the middle of an operation, we prefer to reconnect to the same server, if possible.
     */
    public LdapNetworkConnection getConnectionReconnect(LdapNetworkConnection failedConnection, Dn base, OperationOptions options, Exception reconnectException) {
        ServerConnectionPool<C> pool = selectPool(base);
        return pool.getConnectionReconnect(failedConnection, options, reconnectException);
    }

    /**
     * Select server connection pool that can handle the provided DN.
     */
    private ServerConnectionPool<C> selectPool(Dn dn) {
        if (dn == null) {
            return defaultPool;
        }
        String stringDn = dn != null ? dn.getName() : null;
        ServerConnectionPool<C> selectedPool = null;
        if (StringUtils.isBlank(stringDn) || !Character.isAlphabetic(stringDn.charAt(0))) {
            // Do not even bother to choose. There are the strange
            // things such as empty DN or the <GUID=...> insanity.
            // The selection will not work anyway.
//            LOG.ok("SELECT: Abnormal DN, falling back to default pool : {0}", dn);
            if (defaultPool == null) {
                throw new IllegalStateException("No default connection in this connection manager");
            }
            return defaultPool;
        } else {
//            LOG.ok("SELECT: Selecting pool for DN {0}", dn);
            for(ServerConnectionPool<C> pool: pools) {
                Dn poolBaseContext = pool.getBaseContext();
                // Too loud for normal operation, but may be useful for debugging
//                LOG.ok("SELECT: considering POOL {0} for {1}", pool.shortDesc(), dn);
                if (poolBaseContext == null) {
                    continue;
                }
                if (poolBaseContext.equals(dn)) {
                    // we cannot get tighter match than this
                    selectedPool = pool;
                    // Too loud for normal operation, but may be useful for debugging
//                    LOG.ok("SELECT: accepting POOL {0} because {1} is an exact match", pool.shortDesc(), poolBaseContext);
                    break;
                }
                if (LdapUtil.isAncestorOf(poolBaseContext, dn)) {
                    if (selectedPool == null || LdapUtil.isDescendantOf(poolBaseContext, selectedPool.getBaseContext())) {
                        // Too loud for normal operation, but may be useful for debugging
//                        LOG.ok("SELECT: accepting POOL {0} because {1} is under {2} and it is the best we have",
//                                pool.shortDesc(), dn, poolBaseContext);
                        selectedPool = pool;
                    } else {
                        // Too loud for normal operation, but may be useful for debugging
//                        LOG.ok("SELECT: refusing POOL {0} because {1} is under {2} but it is NOT the best we have, POOL {3} is better",
//                                pool.shortDesc(), dn, poolBaseContext, selectedPool.shortDesc());
                    }
                } else {
                    // Too loud for normal operation, but may be useful for debugging
//                    LOG.ok("SELECT: refusing POOL {0} because {1} ({2}) is not under {3} ({4})",
//                            pool.shortDesc(), dn, dn.isSchemaAware(), poolBaseContext, poolBaseContext.isSchemaAware());
                }
            }
        }
        // Too loud for normal operation, but may be useful for debugging
        LOG.ok("SELECT: selected POOL {0} for {1}", selectedPool==null?null:selectedPool.shortDesc(), dn);
        return selectedPool;
    }

    public LdapNetworkConnection getRandomConnection() {
        return LdapUtil.selectRandomItem(pools).getRandomConnection();
    }

    public void close(String reason) {
        // Make sure that we attempt to close all connection even if there are some exceptions during the close.
        for(ServerConnectionPool<C> pool: pools) {
            pool.close(reason);
        }
    }

    /**
     * Executes brutal search over all servers in all pools.
     * The first searcher that returns a result (non-null value) ends the search.
     */
    public <T> T brutalSearch(Function<LdapNetworkConnection, T> searcher) {
        for (ServerConnectionPool<C> pool : pools) {
            T result = pool.brutalSearch(searcher);
            if (result != null) {
                return result;
            }
        }
        return null;
    }


    /**
     *  Returns connection back to connection manager for future use.
     *  This would not be normally needed for concurrency purposes, as connectors
     *  are single-threaded. But we want to make sure that connections are closed
     *  and there are no leaks.
     */
    public void returnConnection(LdapNetworkConnection connection) {
        if (connection == null) {
            return;
        }

        ServerConnectionPool<C> pool = findPool(connection);
        if (pool != null) {
            // This is a server connection belonging to a pool.
            pool.returnConnection(connection);
            return;
        }

        // Those are "special" connections that are not default server connections.
        // For example connections that were created for runAs feature.

        // Does not really belong to a pool, therefore any pool can close the connection
        pools.get(0).returnConnection(connection);
    }

    /**
     * Reconnect the connection.
     * Existing connection will be torn down (unbound, closed).
     * Fresh connection to the same server will be established.
     *
     * Used in case that the current connection went into a weird state, e.g. the strange "bind required" AD errors.
     */
    public LdapNetworkConnection reconnect(LdapNetworkConnection connection, Exception reconnectReasonException) {
        LOG.warn("Reconnecting connection {0}, reason: {1}", LdapUtil.formatConnectionInfo(connection), reconnectReasonException);
        ServerConnectionPool<C> pool = findPool(connection);

        if (pool == null) {
            // It is not a pooled connection, therefore no point in reconnecting.
            if (reconnectReasonException instanceof LdapException) {
                throw errorHandler.processLdapException(null, (LdapException)reconnectReasonException);
            }
            if (reconnectReasonException instanceof RuntimeException) {
                throw (RuntimeException)reconnectReasonException;
            }
            // Should not happen, just catch-all
            throw new RuntimeException(reconnectReasonException.getMessage(), reconnectReasonException);
        }

        return pool.reconnect(connection, reconnectReasonException);
    }

    private ServerConnectionPool<C> findPool(LdapNetworkConnection connection) {
        for (ServerConnectionPool<C> pool : pools) {
            if (pool.isServerConnection(connection)) {
                return pool;
            }
        }
        return null;
    }

    public void test() {
        LOG.ok("Closing connections before the test ... to reopen them again");

        close("connection test");

        LdapNetworkConnection defaultPoolConnection =  null;
        if (AbstractLdapConfiguration.TEST_MODE_FULL.equals(configuration.getTestMode())) {
            // Connect to all servers in all pools explicitly. Skip default server selection algorithm.
            for (ServerConnectionPool<C> pool: pools) {
                for (ServerDefinition server: pool.getServers()) {
                    LdapNetworkConnection connection = pool.connectServer(server);
                    if (pool == defaultPool) {
                        defaultPoolConnection = connection;
                    }
                }
            }
        } else if (AbstractLdapConfiguration.TEST_MODE_PRIMARY.equals(configuration.getTestMode())) {
            // Explicitly get primary server form the default pool. Skip default server selection algorithm.
            defaultPoolConnection = defaultPool.connectServer(defaultPool.getPrimaryServer());
        } else if (AbstractLdapConfiguration.TEST_MODE_ANY.equals(configuration.getTestMode())) {
            // Try to get any connection from the default pool. This invokes the default selection algorithm.
            defaultPoolConnection = defaultPool.getConnection(null);
        } else {
            throw new ConfigurationException("Unknown test mode '"+configuration.getTestMode()+"'");
        }

        try {
            rootDse = fetchRootDse(defaultPoolConnection);
        } catch (LdapException e) {
            // Fail quickly here, without an attempt to reconnect.
            // The connection is supposed to be very fresh.
            // If it does not work at this point, then there are some problems.
            // This is a connection test, it is a good thing to report all suspicious things.
            throw errorHandler.processLdapException("Failed to retrieve root DSE", e);
        }

    }

    private Entry fetchRootDse(LdapNetworkConnection connection, String... attributesToGet) throws LdapException {
        if (attributesToGet == null || attributesToGet.length == 0) {
            attributesToGet = SchemaConstants.ALL_ATTRIBUTES_ARRAY;
        }
        try {
            Entry rootDse = connection.getRootDse(attributesToGet);
            connectionLog.success(connection, "rootDSE", Arrays.toString(attributesToGet));
            return rootDse;
        } catch (LdapException e) {
            connectionLog.error(connection, "rootDSE", e, Arrays.toString(attributesToGet));
            throw e;
        }
    }

    public Entry getRootDse() {
        return getRootDse(true);
    }

    public Entry getRootDseFresh() {
        return getRootDse(false);
    }

    private Entry getRootDse(boolean allowCached) {
        if (rootDse == null || !allowCached) {
            LdapNetworkConnection connection = defaultPool.getConnection(null);
            try {
                rootDse = fetchRootDse(connection);
            } catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
                // Try to reconnect and retry root DSE fetch. The connection might be stale here.
                connection = defaultPool.getConnectionReconnect(connection, null, e);
                try {
                    rootDse = fetchRootDse(connection);
                } catch (LdapException e2) {
                    throw errorHandler.processLdapException("Failed to retrieve root DSE (after reconnect attempt)", e2);
                }
            } catch (LdapException e) {
                throw errorHandler.processLdapException("Failed to retrieve root DSE", e);
            }
        }
        return rootDse;
    }


    public boolean isControlSupported(String oid) {
        return getSupportedControls().contains(oid);
    }

    public List<String> getSupportedControls() {
        if (supportedControls == null) {
            parseSupportedControls();
        }
        return supportedControls;
    }

    private void parseSupportedControls() {
        Entry rootDse = getRootDse();
        Attribute attr = rootDse.get( SchemaConstants.SUPPORTED_CONTROL_AT );
        if (attr == null) {
            // Unlikely. Perhaps the server does not respond properly to "+" attribute query
            // (such as 389ds server). So let's try again and let's be more explicit.
            // This forces us to read root DSE twice ... but what the heck. What can we do?
            LOG.info("Getting root DSE again, as your lame LDAP server does not properly respond to '+'");
            try {
                rootDse = fetchRootDse(defaultPool.getConnection(null), SchemaConstants.SUPPORTED_CONTROL_AT);
            } catch (LdapException e) {
                throw new ConnectorIOException("Error getting changelog data from root DSE: " + e.getMessage(), e);
            }
            attr = rootDse.get(SchemaConstants.SUPPORTED_CONTROL_AT);
        }
        if (attr == null) {
            // Still no luck? Bad, bad server! We have nothing to do here, but at least warn the user.
            LOG.warn("Cannot fetch supported controls from root DSE. Is security too tight or is your server mad?");
        } else {
            supportedControls = new ArrayList<>(attr.size());
            for ( Value value : attr ) {
                supportedControls.add(value.getString());
            }
        }
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        dump(sb);
        return sb.toString();
    }

    public void dump(StringBuilder sb) {
        Iterator<ServerConnectionPool<C>> iterator = pools.iterator();
        while (iterator.hasNext()) {
            ServerConnectionPool<C> pool = iterator.next();
            if (pool == defaultPool) {
                sb.append("DEFAULT ");
            }
            pool.dump(sb);
            if (iterator.hasNext()) {
                sb.append("\n");
            }
        }
    }
}

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

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.connector.ldap.*;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.schema.manager.impl.DefaultSchemaManager;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.NoVerificationTrustManager;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.apache.mina.transport.socket.DefaultSocketSessionConfig;
import org.apache.mina.transport.socket.SocketSessionConfig;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.objects.OperationOptions;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Set of server connections for the same base context.
 *
 * Not really a "pool" and definitely not a "connection pool", but you know,
 * there are only two hard things in computer science.
 *
 * @author Radovan Semancik
 */
public class ServerConnectionPool<C extends AbstractLdapConfiguration> {

    private static final Log LOG = Log.getLog(ServerConnectionPool.class);

    private final C configuration;
    private AbstractSchemaTranslator<C> schemaTranslator;
    private final ErrorHandler errorHandler;
    private final ConnectionLog connectionLog;

    private final List<ServerDefinition> servers = new ArrayList<>();
    private final ConnectorBinaryAttributeDetector<C> binaryAttributeDetector = new ConnectorBinaryAttributeDetector<>();

    public ServerConnectionPool(C configuration, ErrorHandler errorHandler, ConnectionLog connectionLog) {
        this.configuration = configuration;
        this.errorHandler = errorHandler;
        this.connectionLog = connectionLog;
    }

    public void setSchemaTranslator(AbstractSchemaTranslator<C> schemaTranslator) {
        this.schemaTranslator = schemaTranslator;
        binaryAttributeDetector.setSchemaTranslator(schemaTranslator);
        // Make sure all base contexts of all servers are schema aware, and that we have proper normalized string values.
        for (ServerDefinition server : servers) {
            server.applySchema(schemaTranslator);
        }

    }

    public void addServerDefinition(ServerDefinition serverDefinition) {
        if (serverDefinition.isPrimary()) {
            if (servers.size() > 0 && servers.get(0).isPrimary()) {
                throw new ConfigurationException("More than one primary server specified for base context " + serverDefinition.getBaseContext());
            }
            // We want primary server to be always first.
            // This makes server lookup easier, as we can simply follow list ordering.
            servers.add(0, serverDefinition);
        } else {
            servers.add(serverDefinition);
        }
    }

    public List<ServerDefinition> getServers() {
        return servers;
    }

    public Dn getBaseContext() {
        // We can use any definition here, all should have the same value
        return getPrimaryServer().getBaseContext();
    }

    public String getBaseContextString() {
        // We can use any definition here, all should have the same value
        return getPrimaryServer().getBaseContextString();
    }

    /**
     * Returns working connection (as far as we know) for new operations.
     */
    public LdapNetworkConnection getConnection(OperationOptions options) {
        // Too loud for normal operation, but may be useful for debugging
//        LOG.ok("Selecting server for {0} from servers:\n{1}", base, dumpServers());

        for (ServerDefinition server : servers) {
            server.resetAttempt();
        }

        long now = System.currentTimeMillis();
        ConnectionFailedException lastException = null;

        // Try primary server first, if available.
        // We always want to stick to primary if we can.

//        LOG.info("POOL STATE(0):\n{0}", dump());

        ServerDefinition primaryServer = getPrimaryServer();
        if (primaryServer.isAvailable(now)) {
            primaryServer.setAttempt();
            try {
                LdapNetworkConnection connection = getServerConnection(primaryServer, options);
                setActiveServer(primaryServer);
                return connection;
            } catch (ConnectionFailedException e) {
                lastException = e;
                LOG.ok("Failed to connect to primary server {0} for base context {1} (still trying other servers): {2}",
                        primaryServer.shortDesc(), primaryServer.getBaseContext(), e.getMessage());
                primaryServer.markDown(now);
            }
        } else {
            if (LOG.isOk()) {
                LOG.ok("Primary server {0} is not available, trying other servers", primaryServer.shortDesc());
            }
        }

//        LOG.info("POOL STATE(1):\n{0}", dump());

        // Try current active server second.
        // Once we choose a secondary server, we want to stick with it as long as we can.
        // Switching severs around wildly (randomly) is a recipe for getting consistency problems.

        ServerDefinition activeServer = getActiveServer();
        if (activeServer != null && activeServer != primaryServer && activeServer.isAvailable(now)) {
            activeServer.setAttempt();
            try {
                LdapNetworkConnection connection = getServerConnection(activeServer, options);
                setActiveServer(activeServer);
                return connection;
            } catch (ConnectionFailedException e) {
                lastException = e;
                LOG.ok("Failed to connect to active server {0} for base context {1} (still trying other servers): {2}",
                        activeServer.shortDesc(), activeServer.getBaseContext(), e.getMessage());
                activeServer.markDown(now);
            }
        }

        // Try all other available servers third.
        // If any of them works, it becomes a new active.

        for (ServerDefinition server : servers) {
            if (!server.wasAttempt() && server.isAvailable(now)) {
                server.setAttempt();
                try {
                    LdapNetworkConnection connection = getServerConnection(server, options);
                    setActiveServer(server);
                    return connection;
                } catch (ConnectionFailedException e) {
                    lastException = e;
                    LOG.ok("Failed to connect to server {0} for base context {1} (still trying other servers): {2}",
                            server.shortDesc(), server.getBaseContext(), e.getMessage());
                    server.markDown(now);
                }
            }
        }

        // We are getting desperate now. Re-try connection to all servers that we have not tried yet,
        // regardless of downtime intervals. Any connection is better than no connection.

        for (ServerDefinition server : servers) {
            if (!server.wasAttempt()) {
                server.setAttempt();
                try {
                    LdapNetworkConnection connection = getServerConnection(server, options);
                    setActiveServer(server);
                    return connection;
                } catch (ConnectionFailedException e) {
                    lastException = e;
                    LOG.ok("Failed to connect to server {0} for base context {1} (desperate attempt): {2}",
                            server.shortDesc(), server.getBaseContext(), e.getMessage());
                    // NOT marking the server as down here.
                    // The server was not available in previous pass, therefore it is down already.
                    // Re-marking it as down would ruin the timestamp.
                }
            }
        }

        // No servers are accessible. Just re-throw the last exception. This is as good as any.
        throw lastException;
    }

    private ServerDefinition findServerDefinition(LdapNetworkConnection connection) {
        if (connection == null) {
            return null;
        }
        for (ServerDefinition server : servers) {
            if (server.getConnection() == connection) {
                return server;
            }
        }
        return null;
    }

    public boolean isServerConnection(LdapNetworkConnection connection) {
        return findServerDefinition(connection) != null;
    }

    public ServerDefinition getPrimaryServer() {
        return servers.get(0);
    }

    private ServerDefinition getActiveServer() {
        for (ServerDefinition server : servers) {
            if (server.isActive()) {
                return server;
            }
        }
        return null;
    }

    private void setActiveServer(ServerDefinition activeServer) {
        for (ServerDefinition server : servers) {
            // We really want to == instead of equals() here.
            // This is faster, and good enough for this case.
            if (server == activeServer) {
                server.setActive(true);
            } else {
                server.setActive(false);
            }
        }
    }

    private LdapNetworkConnection getServerConnection(ServerDefinition server, OperationOptions options) {
        if (needsSpecialConnection(options)) {
            return createSpecialConnection(server, options);
        }
        if (!server.isConnected()) {
            connectServer(server);
        }
        return server.getConnection();
    }

    // TODO TODO TODO TODO TODO TODO

    /**
     * Returns new working connection, handling failures that happen in a middle of an operation.
     * As we are in the middle of an operation, we prefer to reconnect to the same server, if possible.
     */
    public LdapNetworkConnection getConnectionReconnect(LdapNetworkConnection failedConnection, OperationOptions options, Exception reconnectException) {
        // This error happened in the middle of an operation.
        // We will try to reconnect to the same server as we were connected to, even if we are failed over to other server.
        // There may be state stored on the original server, such as paging/sorting state, therefore there may be
        // Significant benefit in not switching the severs right now, even if primary is available again.
        ServerDefinition server = findServerDefinition(failedConnection);
        if (server == null) {
            throw new IllegalStateException("No server for connection, probably a connector bug");
        }
        String closeReason = "unknown reason";
        if (reconnectException != null) {
            closeReason = "reconnect due to " + reconnectException.getClass().getSimpleName();
            LOG.ok("Reconnecting server {0} due to {1}: {2}", server, closeReason, reconnectException.getMessage());
        } else {
            LOG.ok("Reconnecting server {0} due to unknown reason", server);
        }
        if (server.isConnected()) {
            closeServerConnection(server, closeReason, reconnectException);
        }
        try {
            return getServerConnection(server, options);
        } catch (ConnectionFailedException e) {
            LOG.ok("Cannot reconnect to the same server {0}, trying other servers", server);
        }
        return getConnection(options);
    }

    public LdapNetworkConnection getRandomConnection() {
        ServerDefinition server = selectRandomServer();
        return getServerConnection(server, null);
    }

    private ServerDefinition selectRandomServer() {
        return LdapUtil.selectRandomItem(servers);
    }

    public void close(String reason) {
        // Make sure that we attempt to close all connection even if there are some exceptions during the close.
        for (ServerDefinition serverDef: servers) {
            closeServerConnection(serverDef, reason,null);
        }
    }

    private void closeServerConnection(ServerDefinition serverDef, String closeReason, Exception reconnectReasonException) {
        if (serverDef.getConnection() != null) {
            try {
                unbindIfNeeded(serverDef, serverDef.getConnection(), reconnectReasonException);
                // Checking for isConnected() is not enough here.
                // Even if the connection is NOT connected it still
                // maintains some resources (pipes) and needs to be
                // explicitly closed from the client side.
                LOG.ok("Closing connection {0}", serverDef);
                serverDef.getConnection().close();
                connectionLog.success(serverDef, "close", closeReason);
            } catch (IOException e) {
                if (reconnectReasonException == null) {
                    LOG.error("Error closing connection {0}: {1}", serverDef, e.getMessage(), e);
                    connectionLog.errorTagged(serverDef, "close", e, "ignored", closeReason);
                } else {
                    LOG.info("Error closing connection {0} while reconnecting: {1}", serverDef, e.getMessage());
                    connectionLog.errorTagged(serverDef, "close", e, "reconnect,ignored", closeReason);
                }
                // Otherwise ignore the error and reconnect anyway
            }
            serverDef.setConnection(null);
        } else {
            LOG.ok("Not closing connection {0} because there is no connection", serverDef);
        }
    }

    private void unbindIfNeeded(ServerDefinition serverDef, LdapNetworkConnection ldapConnection, Exception reconnectReasonException) throws IOException {
        if (isUnbindNeeded(ldapConnection, reconnectReasonException)) {
            try {
                // This log may be too loud, but needed for diagnostics. At least now.
                LOG.ok("Unbinding connection {0}", LdapUtil.formatConnectionInfo(ldapConnection));
                ldapConnection.unBind();
                connectionLog.success(serverDef, "unbind");
            } catch (LdapException e) {
                connectionLog.errorTagged(serverDef, "unbind", e,"ignored");
                LOG.warn("Unbind operation failed on {0} (ignoring): {1}", LdapUtil.formatConnectionInfo(ldapConnection), e.getMessage());
            }
        }
    }

    private boolean isUnbindNeeded(LdapNetworkConnection ldapConnection, Exception reconnectReasonException) {
        if (ldapConnection == null) {
            return false;
        }
        if (!configuration.isUseUnbind()) {
            return false;
        }
        if (!ldapConnection.isConnected()) {
            return false;
        }
        if (reconnectReasonException != null && reconnectReasonException instanceof LdapConnectionTimeOutException) {
            // Attempt to issue unbind command after a connection/operation timeout.
            // Attempt to unbind in this situation is formally correct.
            // The timeout might have occurred due to client (connector) impatience, waiting for LDAP operation to complete.
            // In such a case the TCP connection may still be active, attempting to close it without unbind may cause server warnings.
            // However, in this case the server is probably overloaded, or there is some network problem.
            // Attempt to unbind may take a long time, probably also timing out.
            // In this case we would rather leave without saying proper goodbye than risking being stuck for seconds or minutes waiting for timeout.
            LOG.ok("Skipping unbind on connection {0} due to previous timeout ({1})", LdapUtil.formatConnectionInfo(ldapConnection), reconnectReasonException.getMessage());
            return false;
        }
        return true;
    }

    private LdapConnectionConfig createLdapConnectionConfig(ServerDefinition serverDefinition) {
        LdapConnectionConfig connectionConfig = new LdapConnectionConfig();
        connectionConfig.setLdapHost(serverDefinition.getHost());
        connectionConfig.setLdapPort(serverDefinition.getPort());
        connectionConfig.setTimeout(serverDefinition.getTimeout());
        connectionConfig.setConnectTimeout(serverDefinition.getConnectTimeout());
        connectionConfig.setWriteOperationTimeout(serverDefinition.getWriteOperationTimeout());
        connectionConfig.setReadOperationTimeout(serverDefinition.getReadOperationTimeout());
        connectionConfig.setCloseTimeout(serverDefinition.getCloseTimeout());
        connectionConfig.setSendTimeout(serverDefinition.getSendTimeout());

        String connectionSecurity = serverDefinition.getConnectionSecurity();
        //noinspection StatementWithEmptyBody
        if (connectionSecurity == null || LdapConfiguration.CONNECTION_SECURITY_NONE.equals(connectionSecurity)) {
            // Nothing to do
        } else if (LdapConfiguration.CONNECTION_SECURITY_SSL.equals(connectionSecurity)) {
            connectionConfig.setUseSsl(true);
            connectionConfig.setTrustManagers(createTrustManager());
        } else if (LdapConfiguration.CONNECTION_SECURITY_STARTTLS.equals(connectionSecurity)) {
            connectionConfig.setUseTls(true);
            connectionConfig.setTrustManagers(createTrustManager());
        } else {
            throw new ConfigurationException("Unknown value for connectionSecurity: "+connectionSecurity);
        }

        String[] enabledSecurityProtocols = configuration.getEnabledSecurityProtocols();
        if (enabledSecurityProtocols != null) {
            connectionConfig.setEnabledProtocols(enabledSecurityProtocols);
        }

        String[] enabledCipherSuites = configuration.getEnabledCipherSuites();
        if (enabledCipherSuites != null) {
            connectionConfig.setEnabledCipherSuites(enabledCipherSuites);
        }

        String sslProtocol = configuration.getSslProtocol();
        if (sslProtocol != null) {
            connectionConfig.setSslProtocol(sslProtocol);
        }

        connectionConfig.setBinaryAttributeDetector(binaryAttributeDetector);

        return connectionConfig;
    }

    public LdapNetworkConnection connectServer(ServerDefinition serverDef) {
        if (serverDef.getConnection() != null) {
            closeServerConnection(serverDef, "strange close/open", new RuntimeException("old connection open while creating new connection"));
        }
        final LdapConnectionConfig connectionConfig = createLdapConnectionConfig(serverDef);
        LdapNetworkConnection connection = connectConnection(serverDef, connectionConfig, configuration.getBindDn());
        try {
            bind(connection, serverDef);
        } catch (RuntimeException e) {
            closeServerConnection(serverDef, "failed bind", e);
            // This is always connection failed, even if other error is indicated.
            // E.g. if this is a wrong password, we do nor really want to indicate wrong password.
            // If we did and if this happen during password change operation, then midPoint code could
            // think that the new password does not satisfy password policies. Which would be wrong.
            // Therefore just use the message from the processed exception. But always clearly indicate
            // that this is a connection problem.
            throw new ConnectionFailedException(e.getMessage(), e);
        }
        serverDef.setConnection(connection);
        return connection;
    }

    private TrustManager[] createTrustManager() {
        if (configuration.isAllowUntrustedSsl()) {
            return new TrustManager[]{new NoVerificationTrustManager()}; // this is apache ldap default
        }

        String defaultAlgorithm = TrustManagerFactory.getDefaultAlgorithm();
        try {
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(defaultAlgorithm);
            tmf.init((KeyStore) null); // load system default keystore (e.g. JDK cacerts)
            return tmf.getTrustManagers();
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            LOG.error("Error creating trust manager: {0}", e);
        }
        throw new ConnectionFailedException("Unable to create trust manager.");
    }

    private LdapNetworkConnection connectConnection(ServerDefinition serverDef, LdapConnectionConfig connectionConfig, String userDn) {
        LdapNetworkConnection connection = new LdapNetworkConnection(connectionConfig);
        if (configuration.isTcpKeepAlive()) {
            SocketSessionConfig socketSessionConfig = new DefaultSocketSessionConfig();
            socketSessionConfig.setKeepAlive(configuration.isTcpKeepAlive());
            connection.setSocketSessionConfig(socketSessionConfig);
        }
        try {
            LOG.info("Connecting to {0}:{1} as {2}", connectionConfig.getLdapHost(), connectionConfig.getLdapPort(), userDn);
            if (LOG.isOk()) {
                String connectionSecurity = "none";
                if (connectionConfig.isUseSsl()) {
                    connectionSecurity = "ssl";
                } else if (connectionConfig.isUseTls()) {
                    connectionSecurity = "tls";
                }
                LOG.ok("Connection security: {0} (sslProtocol={1}, enabledSecurityProtocols={2}, enabledCipherSuites={3}", connectionSecurity, connectionConfig.getSslProtocol(), connectionConfig.getEnabledProtocols(), connectionConfig.getEnabledCipherSuites());
                LOG.ok("Connection networking parameters: timeout={0}, keepalive={1}", configuration.getConnectTimeout(), configuration.isTcpKeepAlive());
            }
            boolean connected = connection.connect();
            LOG.ok("Connected ({0})", connected);
            if (connectionLog.isSuccess()) {
                connectionLog.success(connection, "connect", connectionConfig.getLdapHost() + ":" + connectionConfig.getLdapPort());
            }
            if (!connected) {
                connectionLog.error(connection, "connect", "Not connected after connect", connectionConfig.getLdapHost() + ":" + connectionConfig.getLdapPort());
                throw new ConnectionFailedException("Unable to connect to LDAP server " + configuration.getHost() + ":" + configuration.getPort() + " due to unknown reasons");
            }
        } catch (LdapException e) {
            connectionLog.error(connection, "connect", e, connectionConfig.getLdapHost() + ":" + connectionConfig.getLdapPort());
            try {
                connection.close();
            } catch (Exception closeException) {
                connectionLog.error(connection, "close", "close after connect failure: " + closeException.getMessage(), connectionConfig.getLdapHost() + ":" + connectionConfig.getLdapPort());
                LOG.error("Error closing connection (handling error during creation of a new connection): {1}", closeException.getMessage(), closeException);
            }
            RuntimeException processedException = errorHandler.processLdapException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort(), e);
            // This is always connection failed, even if other error is indicated.
            // E.g. if this is a wrong password, we do nor really want to indicate wrong password.
            // If we did and if this happen during password change operation, then midPoint code could
            // think that the new password does not satisfy password policies. Which would be wrong.
            // Therefore just use the message from the processed exception. But always clearly indicate
            // that this is a connection problem.
            throw new ConnectionFailedException(processedException.getMessage(), e);
        }

        return connection;
    }

    private void bind(LdapNetworkConnection connection, ServerDefinition server) {
        bind(connection, server, server.getBindDn(), server.getBindPassword());
    }

    private void bind(LdapNetworkConnection connection, ServerDefinition serverDef, String bindDn, GuardedString bindPassword) {
        final BindRequest bindRequest = new BindRequestImpl();
        try {
            bindRequest.setDn(new Dn(createBindSchemaManager(), bindDn));
        } catch (LdapInvalidDnException e) {
            throw new ConfigurationException("bindDn is not in DN format (server "+serverDef+"): "+e.getMessage(), e);
        }

        if (bindPassword != null) {
            // I hate this GuardedString!
            bindPassword.access(new GuardedStringAccessor() {
                @Override
                public void access(char[] chars) {
                    bindRequest.setCredentials(new String(chars));
                }
            });
        }

        BindResponse bindResponse;
        try {
            bindResponse = connection.bind(bindRequest);
        } catch (LdapException e) {
            RuntimeException processedException = errorHandler.processLdapException("Unable to bind to LDAP server "
                    + connection.getConfig().getLdapHost() + ":" + connection.getConfig().getLdapPort()
                    + " as " + bindDn, e);
            // This is always connection failed, even if other error is indicated.
            // E.g. if this is a wrong password, we do nor really want to indicate wrong password.
            // If we did and if this happens during password change operation, then midPoint code could
            // think that the new password does not satisfy password policies. Which would be wrong.
            // Therefore, just use the message from the processed exception. But always clearly indicate
            // that this is a connection problem.
            throw new ConnectionFailedException(processedException.getMessage(), e);
        }
        LdapResult ldapResult = bindResponse.getLdapResult();
        if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
            connectionLog.error(connection, "bind", ldapResult, bindDn);
            RuntimeException processedException =  errorHandler.processLdapResult("Unable to bind to LDAP server "
                    + connection.getConfig().getLdapHost() + ":" + connection.getConfig().getLdapPort()
                    + " as " + bindDn, ldapResult);
            // This is always connection failed, even if other error is indicated.
            // E.g. if this is a wrong password, we do nor really want to indicate wrong password.
            // If we did and if this happens during password change operation, then midPoint code could
            // think that the new password does not satisfy password policies. Which would be wrong.
            // Therefore, just use the message from the processed exception. But always clearly indicate
            // that this is a connection problem.
            throw new ConnectionFailedException(processedException.getMessage());
        }
        LOG.info("Bound to {0}:{1} as {2}: {3} ({4})",
                connection.getConfig().getLdapHost(), connection.getConfig().getLdapPort(),
                bindDn, ldapResult.getDiagnosticMessage(), ldapResult.getResultCode());
        connectionLog.success(connection, "bind", bindDn);
    }

    private SchemaManager createBindSchemaManager() {
        if (schemaTranslator != null && schemaTranslator.getSchemaManager() != null) {
            return schemaTranslator.getSchemaManager();
        }
        Collection<Schema> emptySchemaCollection = new ArrayList<>(0);
        DefaultSchemaManager schemaManager = new DefaultSchemaManager(emptySchemaCollection);
        schemaManager.setRelaxed();
        return schemaManager;
    }

    private boolean needsSpecialConnection(OperationOptions options) {
        if (options == null) {
            return false;
        }
        if (options.getRunAsUser() == null) {
            return false;
        }
        switch (configuration.getRunAsStrategy()) {
            case AbstractLdapConfiguration.RUN_AS_STRATEGY_NONE:
                LOG.ok("runAsUser option present, but runAsStrategy set to none, ignoring the option");
                return false;
            case AbstractLdapConfiguration.RUN_AS_STRATEGY_BIND:
                if (options.getRunWithPassword() == null) {
                    LOG.ok("runAsUser option present, but runWithPassword NOT present, ignoring the option");
                    return false;
                } else {
                    return true;
                }
            default:
                throw new IllegalArgumentException("Unknown runAsStrategy: "+configuration.getRunAsStrategy());
        }
    }

    private LdapNetworkConnection createSpecialConnection(ServerDefinition server, OperationOptions options) {
        //noinspection SwitchStatementWithTooFewBranches
        switch (configuration.getRunAsStrategy()) {
            case AbstractLdapConfiguration.RUN_AS_STRATEGY_BIND:
                return createSpecialConnectionBind(server, options);
            default:
                throw new IllegalArgumentException("Internal error with runAsStrategy "+configuration.getRunAsStrategy());
        }
    }


    private LdapNetworkConnection createSpecialConnectionBind(ServerDefinition server,
            OperationOptions options) {
        String runAsUser = options.getRunAsUser();
        GuardedString runWithPassword = options.getRunWithPassword();

        final LdapConnectionConfig connectionConfig = createLdapConnectionConfig(server);
        LOG.ok("Connecting to server {0} as user {1} (runAs)", connectionConfig.getLdapHost(), runAsUser);
        LdapNetworkConnection connection = connectConnection(server, connectionConfig, runAsUser);
        try {
            bind(connection, server, runAsUser, runWithPassword);
        } catch (RuntimeException e) {
            closeServerConnection(server, "failed bind", e);
            // This is a special runAs situation. We really want to throw the real error here.
            // If we would throw ConnectionFailedException here, then midPoint would consider that to be a network error.
            // But here we know that this is no ordinary network error. It is an authentication error.
            //
            // This may be some kind of a gray zone here. But we cannot throw just generic ConnectionFailedException
            // here. In that case midPoint would think that this is a common communication error and it would retry.
            // We do not wan to retry in case that user has supplied wrong password.
            throw e;
        }
        return connection;
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
        if (isServerConnection(connection)) {
            // We do not care about connections that are associated with server.
            // We leave those open for reuse. That won't leak much as there is
            // only one connection per server - and the number of servers is small.
            return;
        } else {
            // Those are "special" connections that are not default server connections.
            // For example connections that were created for runAs feature.
            try {
                unbindIfNeeded(null, connection, null);
                connection.close();
                connectionLog.success(connection, "close");
            } catch (Exception e) {
                LOG.error("Error closing special connection: {0}", e.getMessage(), e);
                connectionLog.errorTagged(connection, "close", e,"ignored");
            }
        }
    }

    /**
     * Reconnect the connection.
     * Existing connection will be torn down (unbound, closed).
     * Fresh connection to the same server will be established.
     */
    public LdapNetworkConnection reconnect(LdapNetworkConnection connection, Exception reconnectReasonException) {
        LOG.warn("Reconnecting connection {0}, reason: {1}", LdapUtil.formatConnectionInfo(connection), reconnectReasonException);
        ServerDefinition serverDefinition = findServerDefinition(connection);
        String closeReason = "unspecified reconnect";
        if (reconnectReasonException != null) {
            closeReason = "reconnect due to " + reconnectReasonException.getClass().getSimpleName();
        }
        closeServerConnection(serverDefinition, closeReason, reconnectReasonException);
        connectServer(serverDefinition);
        return serverDefinition.getConnection();
    }

    public <T> T brutalSearch(Function<LdapNetworkConnection, T> searcher) {
        for (ServerDefinition server : servers) {
            LdapNetworkConnection connection = getServerConnection(server, null);
            T result = searcher.apply(connection);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

    public String dump() {
        StringBuilder sb = new StringBuilder();
        dump(sb);
        return sb.toString();
    }

    public void dump(StringBuilder sb) {
        sb.append("POOL ").append(getBaseContextString()).append("\n");
        Iterator<ServerDefinition> iterator = servers.iterator();
        while (iterator.hasNext()) {
            ServerDefinition server = iterator.next();
            sb.append("  ");
            server.dump(sb);
            if (iterator.hasNext()) {
                sb.append("\n");
            }
        }
    }

    public String shortDesc() {
        return getBaseContext() + " (" + servers.size() + " servers)";
    }

}

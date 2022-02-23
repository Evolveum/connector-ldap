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
package com.evolveum.polygon.connector.ldap;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.*;

import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapURLEncodingException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.registries.Schema;
import org.apache.directory.api.ldap.model.url.LdapUrl;
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
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.OperationOptions;

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.connector.ldap.ServerDefinition.Origin;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

/**
 * @author Radovan Semancik
 *
 */
public class ConnectionManager<C extends AbstractLdapConfiguration> {

    private static final Log LOG = Log.getLog(ConnectionManager.class);
    private static final Random rnd = new Random();

    private final C configuration;
    private final String[] serversConfiguration;
    private ServerDefinition defaultServerDefinition = null;
    private List<ServerDefinition> servers;
    private AbstractSchemaTranslator<C> schemaTranslator;
    private ErrorHandler errorHandler;
    private final ConnectorBinaryAttributeDetector<C> binaryAttributeDetector = new ConnectorBinaryAttributeDetector<>();
    private ConnectionLog connectionLog;

    public ConnectionManager(C configuration) {
        this(configuration, configuration.getServers(), true);
    }

    public ConnectionManager(C configuration, String[] serversConfiguration, boolean useDefaultConnection) {
        this.configuration = configuration;
        this.serversConfiguration = serversConfiguration;
        buildServerList(useDefaultConnection);
    }

    private void buildServerList(boolean useDefaultConnection) {
        servers = new ArrayList<>();
        if (useDefaultConnection) {
            defaultServerDefinition = ServerDefinition.createDefaultDefinition(configuration);
            servers.add(defaultServerDefinition);
        }
        if (serversConfiguration != null) {
            for(int line = 0; line < serversConfiguration.length; line++) {
                servers.add(ServerDefinition.parse(configuration, serversConfiguration[line], line));
            }
        }
    }

    public AbstractSchemaTranslator<C> getSchemaTranslator() {
        return schemaTranslator;
    }

    public void setSchemaTranslator(AbstractSchemaTranslator<C> schemaTranslator) {
        this.schemaTranslator = schemaTranslator;
        binaryAttributeDetector.setSchemaTranslator(schemaTranslator);
    }

    public void setErrorHandler(ErrorHandler errorHandler) {
        this.errorHandler = errorHandler;
    }

    public ConnectionLog getConnectionLog() {
        return connectionLog;
    }

    public void setConnectionLog(ConnectionLog connectionLog) {
        this.connectionLog = connectionLog;
    }

    private LdapNetworkConnection getConnection(ServerDefinition server) {
        if (server == null) {
            server = defaultServerDefinition;
        }
        if (!server.isConnected()) {
            connectServer(server);
        }
        return server.getConnection();
    }

    public LdapNetworkConnection getDefaultConnection() {
        if (defaultServerDefinition == null) {
            throw new IllegalStateException("No default connection in this connection manager");
        }
        return getConnection(defaultServerDefinition);
    }

    public LdapNetworkConnection getConnectionReconnect(Dn base, Referral referral, OperationOptions options, Exception reconnectException) {
        LdapUrl ldapUrl = getLdapUrl(referral);
        ServerDefinition server = selectServer(base, ldapUrl);
        if (needsSpecialConnection(options)) {
            return createSpecialConnection(server, options);
        }
        String closeReason = "unknown reason";
        if (reconnectException != null) {
            closeReason = "reconnect due to " + reconnectException.getClass().getSimpleName();
            LOG.ok("Reconnecting server {0} due to {1}: {2}", server, closeReason, reconnectException.getMessage());
        }
        if (referral != null) {
            closeReason = "referral";
            LOG.ok("Reconnecting server {0} due to referral {1}: {2}", server, referral);
        }
        if (reconnectException == null && referral == null) {
            if (referral != null) {
                LOG.ok("Reconnecting server {0} due to unknown reason", server);
            }
        }
        if (server.isConnected()) {
            closeConnection(server, closeReason, reconnectException);
        }
        connectServer(server);
        return server.getConnection();
    }

    public LdapNetworkConnection getConnection(Dn base, OperationOptions options) {
        // Too loud for normal operation, but may be useful for debugging
//        LOG.ok("Selecting server for {0} from servers:\n{1}", base, dumpServers());
        ServerDefinition server = selectServer(base);
        if (needsSpecialConnection(options)) {
            return createSpecialConnection(server, options);
        }
        return getConnection(server);
    }

    public LdapNetworkConnection getConnection(Dn base, Referral referral, OperationOptions options) {
        return getConnection(base, getLdapUrl(referral), options);
    }

    private LdapUrl getLdapUrl(Referral referral) {
        if (referral == null) {
            return null;
        }
        Collection<String> ldapUrls = referral.getLdapUrls();
        if (ldapUrls == null || ldapUrls.isEmpty()) {
            return null;
        }
        String urlString = selectRandomItem(ldapUrls);
        LdapUrl ldapUrl;
        try {
            ldapUrl = new LdapUrl(urlString);
        } catch (LdapURLEncodingException e) {
            throw new IllegalArgumentException("Wrong LDAP URL '"+urlString+"': "+e.getMessage());
        }
        return ldapUrl;
    }

    public LdapNetworkConnection getConnection(Dn base, LdapUrl url, OperationOptions options) {
        ServerDefinition server = selectServer(base, url);
        if (needsSpecialConnection(options)) {
            return createSpecialConnection(server, options);
        }
        if (!server.isConnected()) {
            connectServer(server);
        }
        return server.getConnection();
    }

    public LdapNetworkConnection getRandomConnection() {
        ServerDefinition server = selectRandomServer();
        if (!server.isConnected()) {
            connectServer(server);
        }
        return server.getConnection();
    }

    public Iterable<LdapNetworkConnection> getAllConnections() {

        final Iterator<ServerDefinition> serversIterator = servers.iterator();

        //noinspection Convert2Lambda
        return new Iterable<LdapNetworkConnection>() {

            @Override
            public Iterator<LdapNetworkConnection> iterator() {
                return new Iterator<LdapNetworkConnection>() {

                    @Override
                    public boolean hasNext() {
                        return serversIterator.hasNext();
                    }

                    @Override
                    public LdapNetworkConnection next() {
                        return getConnection(serversIterator.next());
                    }

                    @Override
                    public void remove() {
                            serversIterator.remove();
                    }

                };
            }
        };

    }

    private ServerDefinition selectServer(Dn dn) {
        String stringDn = dn != null ? dn.getName() : null;
        if (StringUtils.isBlank(stringDn) || !Character.isAlphabetic(stringDn.charAt(0))) {
            // Do not even bother to choose. There are the strange
            // things such as empty DN or the <GUID=...> insanity.
            // The selection will not work anyway.
            if (defaultServerDefinition == null) {
                throw new IllegalStateException("No default connection in this connection manager");
            }
            return defaultServerDefinition;
        }
        Dn selectedBaseContext = null;
        for (ServerDefinition server: servers) {
            Dn serverBaseContext = server.getBaseContext();
            // Too loud for normal operation, but may be useful for debugging
//            LOG.ok("SELECT: considering {0} ({1}) for {2}", server.getHost(), serverBaseContext, dn);
            if (serverBaseContext == null) {
                continue;
            }
            if (serverBaseContext.equals(dn)) {
                // we cannot get tighter match than this
                selectedBaseContext = dn;
                // Too loud for normal operation, but may be useful for debugging
//                LOG.ok("SELECT: accepting {0} because {1} is an exact match", server.getHost(), serverBaseContext);
                break;
            }
            if (LdapUtil.isAncestorOf(serverBaseContext, dn, schemaTranslator)) {
                if (serverBaseContext.isDescendantOf(selectedBaseContext)) {
                    // Too loud for normal operation, but may be useful for debugging
//                    LOG.ok("SELECT: accepting {0} because {1} is under {2} and it is the best we have", server.getHost(), dn, serverBaseContext);
                    selectedBaseContext = serverBaseContext;
                } else {
                    // Too loud for normal operation, but may be useful for debugging
//                    LOG.ok("SELECT: accepting {0} because {1} is under {2} but it is NOT the best we have, {3} is better",
//                            server.getHost(), dn, serverBaseContext, selectedBaseContext);
                }
            } else {
                // Too loud for normal operation, but may be useful for debugging
//                LOG.ok("SELECT: refusing {0} because {1} ({2}) is not under {3} ({4})", server.getHost(),
//                        dn, dn.isSchemaAware(),
//                        serverBaseContext, serverBaseContext.isSchemaAware());
            }
        }
        // Too loud for normal operation, but may be useful for debugging
//        LOG.ok("SELECT: selected base context: {0}", selectedBaseContext);
        List<ServerDefinition> selectedServers = new ArrayList<>();
        for (ServerDefinition server: servers) {
            if (selectedBaseContext == null && server.getBaseContext() == null) {
                if (server.getOrigin() == Origin.REFERRAL) {
                    // avoid using dynamically added servers as a fallback
                    // for all queries
                    continue;
                } else {
                    selectedServers.add(server);
                }
            }
            if (selectedBaseContext == null || server.getBaseContext() == null) {
                continue;
            }
            if (selectedBaseContext.equals(server.getBaseContext())) {
                selectedServers.add(server);
            }
        }
        // Too loud for normal operation, but may be useful for debugging
//        LOG.ok("SELECT: selected server list: {0}", selectedServers);
        ServerDefinition selectedServer = selectRandomItem(selectedServers);
        if (selectedServer == null) {
            // Too loud for normal operation, but may be useful for debugging
//            LOG.ok("SELECT: selected default for {0}", dn);
            if (defaultServerDefinition == null) {
                throw new IllegalStateException("No default connection in this connection manager");
            }
            return defaultServerDefinition;
        } else {
            // Too loud for normal operation, but may be useful for debugging
//            LOG.ok("SELECT: selected {0} for {1}", selectedServer.getHost(), dn);
            return selectedServer;
        }
    }

    private ServerDefinition selectServer(Dn dn, LdapUrl url) {
        if (url == null) {
            return selectServer(dn);
        }
        for (ServerDefinition server: servers) {
            if (server.matches(url)) {
                return server;
            }
        }
        ServerDefinition server = ServerDefinition.createDefinition(configuration, url);
        servers.add(server);
        return server;
    }

    private ServerDefinition selectRandomServer() {
        return selectRandomItem(servers);
    }

    @SuppressWarnings("unused")
    public ConnectorBinaryAttributeDetector<C> getBinaryAttributeDetector() {
        return binaryAttributeDetector;
    }

    public boolean isConnected() {
        if (defaultServerDefinition == null) {
            throw new IllegalStateException("No default connection in this connection manager");
        }
        return defaultServerDefinition.getConnection() != null && defaultServerDefinition.getConnection().isConnected();
    }

    public void close(String reason) {
        // Make sure that we attempt to close all connection even if there are some exceptions during the close.
        for (ServerDefinition serverDef: servers) {
            closeConnection(serverDef, reason,null);
        }
    }

    private void closeConnection(ServerDefinition serverDef, String closeReason, Exception reconnectReasonException) {
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

    public void connect() {
        if (defaultServerDefinition != null) {
            connectServer(defaultServerDefinition);
        }
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

    private void connectServer(ServerDefinition serverDef) {
        if (serverDef.getConnection() != null) {
            closeConnection(serverDef, "strange close/open", new RuntimeException("old connection open while creating new connection"));
        }
        final LdapConnectionConfig connectionConfig = createLdapConnectionConfig(serverDef);
        LdapNetworkConnection connection = connectConnection(serverDef, connectionConfig, configuration.getBindDn());
        try {
            bind(connection, serverDef);
        } catch (RuntimeException e) {
            closeConnection(serverDef, "failed bind", e);
            // This is always connection failed, even if other error is indicated.
            // E.g. if this is a wrong password, we do nor really want to indicate wrong password.
            // If we did and if this happen during password change operation, then midPoint code could
            // think that the new password does not satisfy password policies. Which would be wrong.
            // Therefore just use the message from the processed exception. But always clearly indicate
            // that this is a connection problem.
            throw new ConnectionFailedException(e.getMessage(), e);
        }
        serverDef.setConnection(connection);
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
                LOG.ok("Connection security: {0} (sslProtocol={1}, enabledSecurityProtocols={2}, enabledCipherSuites={3}",
                        connectionSecurity, connectionConfig.getSslProtocol(),
                        connectionConfig.getEnabledProtocols(), connectionConfig.getEnabledCipherSuites());
                LOG.ok("Connection networking parameters: timeout={0}, keepalive={1}", configuration.getConnectTimeout(), configuration.isTcpKeepAlive());
            }
            boolean connected = connection.connect();
            LOG.ok("Connected ({0})", connected);
            if (connectionLog.isSuccess()) {
                connectionLog.success(connection, "connect", connectionConfig.getLdapHost() + ":" + connectionConfig.getLdapPort());
            }
            if (!connected) {
                connectionLog.error(connection, "connect", "Not connected after connect", connectionConfig.getLdapHost() + ":" + connectionConfig.getLdapPort());
                throw new ConnectionFailedException("Unable to connect to LDAP server "+configuration.getHost()+":"+configuration.getPort()+" due to unknown reasons");
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
            throw errorHandler.processLdapException("Unable to bind to LDAP server "
                    + connection.getConfig().getLdapHost() + ":" + connection.getConfig().getLdapPort()
                    + " as " + bindDn, e);
        }
        LdapResult ldapResult = bindResponse.getLdapResult();
        if (ldapResult.getResultCode() != ResultCodeEnum.SUCCESS) {
            connectionLog.error(connection, "bind", ldapResult, bindDn);
            throw errorHandler.processLdapResult("Unable to bind to LDAP server "
                    + connection.getConfig().getLdapHost() + ":" + connection.getConfig().getLdapPort()
                    + " as " + bindDn, ldapResult);
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
            closeConnection(server, "failed bind", e);
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

    public boolean isAlive() {
        if (defaultServerDefinition == null) {
            throw new IllegalStateException("No default connection in this connection manager");
        }

        if (defaultServerDefinition.getConnection() == null) {
            return false;
        }
        if (!defaultServerDefinition.getConnection().isConnected()) {
            connectionLog.failedCheckAlive(defaultServerDefinition.getConnection(), "server-initiated connection close");
            return false;
        }
        if (configuration.isCheckAliveRootDse()) {
            SearchRequest rootDseRequest = new SearchRequestImpl();
            rootDseRequest.setBase(Dn.ROOT_DSE);
            rootDseRequest.setScope(SearchScope.OBJECT);
            rootDseRequest.setFilter(LdapUtil.createAllSearchFilter());
            // Fetch "no attributes" to make the search as efficient as possible (low overhead).
            // We do not care whether server works, we want to check that network works.
            rootDseRequest.addAttributes("1.1");
            SearchCursor rootDseCursor;
            try {
                rootDseCursor = defaultServerDefinition.getConnection().search(rootDseRequest, configuration.getCheckAliveTimeout());
            } catch (LdapException e) {
                connectionLog.failedCheckAlive(defaultServerDefinition.getConnection(), "root DSE search request: " + e.getMessage());
                return false;
            }
            try {
                if (rootDseCursor.next()) {
                    Response rootDseResponse = rootDseCursor.get();
                    if (rootDseResponse == null) {
                        // Very strange case indeed
                        connectionLog.failedCheckAlive(defaultServerDefinition.getConnection(), "root DSE search response: null entry in response");
                        return false;
                    }
                    // We have a response. We do not really care what is it.
                    // The mere fact that we have it tells us that the network works.
                    // Let's invoke curson.next() here to properly close the cursor without abandon.
                    rootDseCursor.next();
                    rootDseCursor.close();
                    connectionLog.success(defaultServerDefinition.getConnection(), "rootDSE", "checkAlive");
                } else {
                    // No entries in root DSE search
                    connectionLog.failedCheckAlive(defaultServerDefinition.getConnection(), "root DSE search response: no entry in response");
                    return false;
                }
            } catch (LdapException | CursorException | IOException e) {
                connectionLog.failedCheckAlive(defaultServerDefinition.getConnection(), "root DSE search response: " + e.getMessage());
                return false;
            }
        }
        return true;
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
        closeConnection(serverDefinition, closeReason, reconnectReasonException);
        connectServer(serverDefinition);
        return serverDefinition.getConnection();
    }

    public ServerDefinition getDefaultServerDefinition() {
        return defaultServerDefinition;
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

    private boolean isServerConnection(LdapNetworkConnection connection) {
        return findServerDefinition(connection) != null;
    }

    private <T> T selectRandomItem(Collection<T> collection) {
        if (collection == null || collection.isEmpty()) {
            return null;
        }
        if (collection.size() == 1) {
            return collection.iterator().next();
        }
        int index = rnd.nextInt(collection.size());
        T selected = null;
        Iterator<T> iterator = collection.iterator();
        for (int i=0; i<=index; i++) {
            selected = iterator.next();
        }
        return selected;
    }

    public Entry getRootDse(ServerDefinition serverDef) {
        if (serverDef == null) {
            serverDef = defaultServerDefinition;
        }
        if (serverDef.getRootDse() == null) {
            try {
                serverDef.setRootDse(getRootDseForce(serverDef, null));
            } catch (LdapException e) {
                throw new ConnectorIOException("Error getting changelog data from root DSE: " + e.getMessage(), e);
            }
        }
        return serverDef.getRootDse();
    }

    /**
     * Always explicitly fetch root DSE from server, even if we already have it.
     * Used during "test connection", also can be used to obtain specific versions of rootDSE from broken LDAP servers.
     */
    public Entry getRootDseForce(ServerDefinition serverDef, String... attributesToGet) throws LdapException {
        if (attributesToGet == null || attributesToGet.length == 0) {
            attributesToGet = SchemaConstants.ALL_ATTRIBUTES_ARRAY;
        }
        if (serverDef == null) {
            serverDef = defaultServerDefinition;
        }
        LdapNetworkConnection connection = getConnection(serverDef);
        try {
            Entry rootDse = connection.getRootDse(attributesToGet);
            connectionLog.success(connection, "rootDSE", Arrays.toString(attributesToGet));
            return rootDse;
        } catch (LdapException e) {
            connectionLog.error(connection, "rootDSE", e, Arrays.toString(attributesToGet));
            // TODO: reconnect?
            throw e;
        }
    }

    public boolean supportsControl(ServerDefinition serverDef, String oid) {
        if (serverDef == null) {
            serverDef = defaultServerDefinition;
        }
        return getSupportedControls(serverDef).contains(oid);
    }

    public List<String> getSupportedControls(ServerDefinition serverDef) {
        if (serverDef == null) {
            serverDef = defaultServerDefinition;
        }
        if (serverDef.getSupportedControls() == null) {
            List<String> supportedControls = new ArrayList<>();
            Entry rootDse = getRootDse(serverDef);
            Attribute attr = rootDse.get( SchemaConstants.SUPPORTED_CONTROL_AT );
            if (attr == null) {
                // Unlikely. Perhaps the server does not respond properly to "+" attribute query
                // (such as 389ds server). So let's try again and let's be more explicit.
                try {
                    LOG.info("Getting root DSE again, as your lame LDAP server does not properly respond to '+'");
                    rootDse = getRootDseForce(serverDef, SchemaConstants.SUPPORTED_CONTROL_AT);
                } catch (LdapException e) {
                    throw new ConnectorIOException("Error getting changelog data from root DSE: " + e.getMessage(), e);
                }
                attr = rootDse.get(SchemaConstants.SUPPORTED_CONTROL_AT);
            }
            if (attr == null) {
                // Still no luck? Bad, bad server! We have nothing to do here, but at least warn the user.
                LOG.warn("Cannot fetch supported controls from root DSE. Is security too tight or is your server mad?");
            } else {
                for ( Value value : attr ) {
                    supportedControls.add(value.getString());
                }
            }
            serverDef.setSupportedControls(supportedControls);
        }
        return serverDef.getSupportedControls();
    }


    public String dumpServers() {
        StringBuilder sb = new StringBuilder();
        Iterator<ServerDefinition> iterator = servers.iterator();
        while (iterator.hasNext()) {
            ServerDefinition server = iterator.next();
            sb.append(server.toString());
            if (server == defaultServerDefinition) {
                sb.append(" DEFAULT");
            }
            if (iterator.hasNext()) {
                sb.append("\n");
            }
        }
        return sb.toString();
    }
}

/*
 * Copyright (c) 2022 Evolveum
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

import org.apache.commons.io.FileUtils;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.test.common.TestHelpers;
import org.opends.messages.Message;
import org.opends.server.config.ConfigException;
import org.opends.server.protocols.internal.InternalClientConnection;
import org.opends.server.types.DirectoryEnvironmentConfig;
import org.opends.server.types.InitializationException;
import org.opends.server.util.EmbeddedUtils;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;

import java.io.File;

public class AbstractOpenDjTest {

    private static final int PORT_NUMBER = 10389;
    protected static final String BASE_CONTEXT = "dc=example,dc=com";
    private static final String BIND_DN = "cn=directory manager";
    private static final String BIND_PASSWORD = "secret";
    protected static final File SERVER_ROOT_DIRECTORY = new File("target/opendj");
    private static final File SERVER_CONFIG_FILE = new File(SERVER_ROOT_DIRECTORY, "config/config.ldif");
    protected static final File SERVER_TEMPLATE_ROOT_DIRECTORY = new File("src/test/resources/opendj-template");

    public static final String[] OPERATIONAL_ATTRIBUTES = {
            LdapConstants.ATTRIBUTE_OPENDJ_DS_PWP_ACCOUNT_DISABLED_NAME,
            LdapConstants.ATTRIBUTE_IS_MEMBER_OF_NAME,
            LdapConstants.ATTRIBUTE_CREATETIMESTAMP_NAME
    };

    private InternalClientConnection internalConnection;

    @BeforeClass
    public void startServer() throws Exception {
        if (SERVER_ROOT_DIRECTORY.exists()) {
            FileUtils.deleteDirectory(SERVER_ROOT_DIRECTORY);
        }
        SERVER_ROOT_DIRECTORY.mkdirs();
        FileUtils.copyDirectory(SERVER_TEMPLATE_ROOT_DIRECTORY, SERVER_ROOT_DIRECTORY);

        DirectoryEnvironmentConfig envConfig = new DirectoryEnvironmentConfig();
        try {
            envConfig.setServerRoot(SERVER_ROOT_DIRECTORY);
            envConfig.setConfigFile(SERVER_CONFIG_FILE);
            // envConfig.setDisableConnectionHandlers(true);
        } catch (InitializationException ex) {
            throw new RuntimeException("OpenDJ initialization failed", ex);
        }

        // Check if the server is already running
        if (EmbeddedUtils.isRunning()) {
            throw new RuntimeException("Server already running");
        } else {
            System.out.println("Starting OpenDJ server");
            try {
                EmbeddedUtils.startServer(envConfig);
            } catch (ConfigException ex) {
                throw new RuntimeException("OpenDJ startup failed", ex);
            } catch (InitializationException ex) {
                throw new RuntimeException("OpenDJ startup failed", ex);
            }
        }

        internalConnection = InternalClientConnection.getRootConnection();
        if (internalConnection == null) {
            throw new RuntimeException("OpenDS cannot get internal connection (null)");
        }

        System.out.println("OpenDJ server started");
    }


    @AfterClass
    public void stopServer() {
        if (EmbeddedUtils.isRunning()) {
            System.out.println("Stopping OpenDJ server");
            EmbeddedUtils.stopServer(this.getClass().getName(), Message.EMPTY);
            System.out.println("OpenDJ server is stopped");
        } else {
            System.out.println("Attempt to stop OpenDJ server that is already stopped.");
        }
    }

    public boolean isServerRunning() {
        return EmbeddedUtils.isRunning();
    }

    protected ConnectorFacade createConnectorInstance() {
        return createConnectorInstance(createConnectorConfiguration());
    }

    protected ConnectorFacade createConnectorInstance(LdapConfiguration configuration) {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration apiConfiguration = TestHelpers.createTestConfiguration(LdapConnector.class, configuration);
        return factory.newInstance(apiConfiguration);
    }

    protected ConnectorFacade createMinimalConnectorInstance() {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration apiConfiguration = TestHelpers.createTestConfiguration(LdapConnector.class, createMinimalConnectorConfiguration());
        return factory.newInstance(apiConfiguration);
    }

    protected LdapConfiguration createConnectorConfiguration() {
        LdapConfiguration config = createMinimalConnectorConfiguration();
        config.setBaseContext(BASE_CONTEXT);
        config.setPagingStrategy(LdapConfiguration.PAGING_STRATEGY_AUTO);
        config.setVlvSortAttribute(LdapConstants.ATTRIBUTE_ENTRYUUID_NAME);
        config.setOperationalAttributes(OPERATIONAL_ATTRIBUTES);
        config.setEnableExtraTests(true);
        return config;
    }

    protected LdapConfiguration createMinimalConnectorConfiguration() {
        LdapConfiguration config = new LdapConfiguration();
        config.setHost("localhost");
        config.setPort(PORT_NUMBER);
        config.setBindDn(BIND_DN);
        config.setBindPassword(new GuardedString(BIND_PASSWORD.toCharArray()));
        return config;
    }

}

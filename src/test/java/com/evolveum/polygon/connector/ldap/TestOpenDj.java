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

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SuggestedValues;
import org.identityconnectors.framework.common.objects.ValueListOpenness;
import org.identityconnectors.test.common.TestHelpers;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import static org.testng.AssertJUnit.assertEquals;

import java.util.List;
import java.util.Map;

public class TestOpenDj extends AbstractOpenDjTest {

    @Test
    public void testOpTest() throws Exception {
        ConnectorFacade connector = createConnectorInstance();
        connector.test();
        // No exception = no problem
    }

    // We try test() operation with minimal configuration, which does not include a valid base context.
    // The test should fail.
    @Test
    public void testOpTestWithoutBaseContext() throws Exception {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        LdapConfiguration minimalConnectorConfiguration = createMinimalConnectorConfiguration();
        APIConfiguration minimalApiConfiguration = TestHelpers.createTestConfiguration(LdapConnector.class, minimalConnectorConfiguration);
        ConnectorFacade minimalConnectorFacade = factory.newInstance(minimalApiConfiguration);

        try {
            // Expecting failure
            minimalConnectorFacade.test();
            AssertJUnit.fail("Unexpected success of test()");
        } catch (ConfigurationException e) {
            // This is expected
        }
    }

    @Test
    public void testOpSchema() throws Exception {
        ConnectorFacade connector = createConnectorInstance();
        Schema schema = connector.schema();
        // TODO: asserts
    }

    // Try partial configuration with a wrong password
    @Test
    public void testPartialConfigurationNegative() throws Exception {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        LdapConfiguration minimalConnectorConfiguration = createMinimalConnectorConfiguration();
        minimalConnectorConfiguration.setBindPassword(new GuardedString("Ceci n'est pas une mot de passe".toCharArray()));
        APIConfiguration minimalApiConfiguration = TestHelpers.createTestConfiguration(LdapConnector.class, minimalConnectorConfiguration);
        ConnectorFacade minimalConnectorFacade = factory.newInstance(minimalApiConfiguration);

        try {
            // Expecting failure
            minimalConnectorFacade.testPartialConfiguration();
            AssertJUnit.fail("Unexpected success of testPartialConfiguration()");
        } catch (ConnectionFailedException e) {
            // This is expected
        }
    }

    @Test
    public void testDiscovery() throws Exception {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        APIConfiguration apiConfiguration = TestHelpers.createTestConfiguration(LdapConnector.class, createMinimalConnectorConfiguration());
        ConnectorFacade minimalConnectorFacade = factory.newInstance(apiConfiguration);

        // Nothing to assert here, just make sure it does not throws an exception
        minimalConnectorFacade.testPartialConfiguration();

        Map<String, SuggestedValues> suggestions = minimalConnectorFacade.discoverConfiguration();
        System.out.println("Discovered LDAP configuration: " + suggestions);
        assertEquals("Unexpected number of suggestions", 3, suggestions.size());

        assertEquals("Unexpected number of base context suggestions", 1, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_BASE_CONTEXT).getValues().size());
        assertEquals("Unexpected base context suggestion", "dc=example,dc=com", suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_BASE_CONTEXT).getValues().get(0));
        assertEquals("Base context suggestion is not closed", ValueListOpenness.CLOSED, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_BASE_CONTEXT).getOpenness());

        assertEquals("Unexpected number of vlvSortAttribute suggestions", 1, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_VLV_SORT_ATTRIBUTE).getValues().size());
        assertEquals("Unexpected vlvSortAttribute suggestion", SchemaConstants.UID_AT, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_VLV_SORT_ATTRIBUTE).getValues().get(0));
        assertEquals("vlvSortAttribute suggestion is not open", ValueListOpenness.OPEN, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_VLV_SORT_ATTRIBUTE).getOpenness());

        assertEquals("Unexpected number of operational attributes suggestions", 4, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_OPERATIONAL_ATTRIBUTES).getValues().size());
        assertEquals("Operational attributes suggestion is not open", ValueListOpenness.OPEN, suggestions.get(AbstractLdapConfiguration.CONF_PROP_NAME_OPERATIONAL_ATTRIBUTES).getOpenness());

        // Apply all suggestions to config, creating full configuration.
        for (Map.Entry<String, SuggestedValues> suggestionEntry : suggestions.entrySet()) {
            SuggestedValues suggestion = suggestionEntry.getValue();
            if (suggestion.getValues().size() == 0) {
                // Nothing to do
            } else if (suggestion.getValues().size() == 1) {
                apiConfiguration.getConfigurationProperties().setPropertyValue(suggestionEntry.getKey(), suggestion.getValues().get(0));
            } else {
                apiConfiguration.getConfigurationProperties().setPropertyValue(suggestionEntry.getKey(), ((List)suggestion.getValues()).toArray(new String[0]));
            }
        }

        ConnectorFacade fullConnectorFacade = factory.newInstance(apiConfiguration);
        fullConnectorFacade.test();
        // No exception = no problem
    }


}

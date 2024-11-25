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

package com.exclamationlabs.polygon.connector.ldap;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConfigurationProperty;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.test.common.TestHelpers;
import org.testng.AssertJUnit;
import org.testng.annotations.Test;

import java.time.ZonedDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.testng.AssertJUnit.*;
import static org.testng.internal.junit.ArrayAsserts.assertArrayEquals;

public class TestOpenDj extends AbstractOpenDjTest {

    @Test
    public void testConfiguration() throws Exception {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        LdapConfiguration connectorConfiguration = createConnectorConfiguration();
        APIConfiguration apiConfiguration = TestHelpers.createTestConfiguration(LdapConnector.class, connectorConfiguration);

        ConfigurationProperty propHost = apiConfiguration.getConfigurationProperties().getProperty(AbstractLdapConfiguration.CONF_PROP_NAME_HOST);
        assertNoAllowedValues(propHost);

        ConfigurationProperty propPort = apiConfiguration.getConfigurationProperties().getProperty(AbstractLdapConfiguration.CONF_PROP_NAME_PORT);
        assertAllowedValues(propPort, ValueListOpenness.OPEN, 389, 636);

        ConfigurationProperty propConnectionSecurity = apiConfiguration.getConfigurationProperties().getProperty(AbstractLdapConfiguration.CONF_PROP_NAME_CONNECTION_SECURITY);
        assertAllowedValues(propConnectionSecurity, ValueListOpenness.CLOSED,
                AbstractLdapConfiguration.CONNECTION_SECURITY_NONE, AbstractLdapConfiguration.CONNECTION_SECURITY_SSL, AbstractLdapConfiguration.CONNECTION_SECURITY_STARTTLS);
    }

    private void assertNoAllowedValues(ConfigurationProperty prop) {
        assertNotNull(prop);
        SuggestedValues allowedValues = prop.getAllowedValues();
        System.out.println("PROP " + prop.getName() + " allowed values: " + allowedValues);
        assertNull("Unexpected allowed values in " + prop, allowedValues);
    }

    private void assertAllowedValues(ConfigurationProperty prop, ValueListOpenness openness, Object... expectedValues) {
        assertNotNull(prop);
        SuggestedValues allowedValues = prop.getAllowedValues();
        System.out.println("PROP " + prop.getName() + " allowed values: " + allowedValues);
        assertNotNull("No allowed values in " + prop, allowedValues);
        assertArrayEquals("Wrong list of allowed values in " + prop, expectedValues, allowedValues.getValues().toArray(new Object[0]));
        assertEquals("Wrong openness in allowed values in " + prop, openness, allowedValues.getOpenness());
    }

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

        // Nothing to assert here, just make sure it does not throw an exception
        minimalConnectorFacade.testPartialConfiguration();

        Map<String, SuggestedValues> suggestions = minimalConnectorFacade.discoverConfiguration();
        System.out.println("Discovered LDAP configuration: " + suggestions);
        assertEquals("Unexpected number of suggestions", 5, suggestions.size());

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
                apiConfiguration.getConfigurationProperties().setPropertyValue(suggestionEntry.getKey(), ((List) suggestion.getValues()).toArray(new String[0]));
            }
        }

        ConnectorFacade fullConnectorFacade = factory.newInstance(apiConfiguration);
        fullConnectorFacade.test();
        // No exception = no problem
    }

    private AttributeInfo findAttributeInfo(ObjectClassInfo classInfo, String name) {
        return classInfo.getAttributeInfo().stream()
                .filter(ai -> name.equals(ai.getName()))
                .findFirst()
                .orElse(null);
    }

    @Test
    public void testLastLoginDate() throws Exception {
        final ObjectClass inetOrgPerson = new ObjectClass("inetOrgPerson");

        ConnectorFacade connector = createConnectorInstance();

        Set<Attribute> attributes = new HashSet<>();
        attributes.add(AttributeBuilder.build(Name.NAME, "uid=test,ou=People," + BASE_CONTEXT));
        attributes.add(AttributeBuilder.build("uid", "test"));
        attributes.add(AttributeBuilder.build("cn", "Test User"));
        attributes.add(AttributeBuilder.build("sn", "User"));
        Uid uid = connector.create(inetOrgPerson, attributes, null);

        ConnectorObject object = connector.getObject(inetOrgPerson, uid, null);
        assertLastLoginDate(object, false, connector.schema().findObjectClassInfo(inetOrgPerson.getObjectClassValue()));

        LdapConfiguration config = createConnectorConfiguration();
        config.setLastLoginDateAttribute("createTimestamp");
        connector = createConnectorInstance(config);

        object = connector.getObject(inetOrgPerson, uid, null);
        assertLastLoginDate(object, true, connector.schema().findObjectClassInfo(inetOrgPerson.getObjectClassValue()));
    }

    private void assertLastLoginDate(ConnectorObject object, Boolean exists, ObjectClassInfo ocInfo) {
        assertNotNull(object);
        assertNotNull(ocInfo);

        AttributeInfo createTimestampInfo = findAttributeInfo(ocInfo, "createTimestamp");
        AttributeInfo lastLoginDateInfo = findAttributeInfo(ocInfo, PredefinedAttributes.LAST_LOGIN_DATE_NAME);

        Attribute createTimetamp = object.getAttributeByName("createTimestamp");
        Attribute lastLoginDate = object.getAttributeByName(PredefinedAttributes.LAST_LOGIN_DATE_NAME);

        if (!exists) {
            assertNotNull(createTimestampInfo);
            assertNull(lastLoginDateInfo);

            assertNotNull(createTimetamp);
            assertEquals(ZonedDateTime.class, createTimetamp.getValue().get(0).getClass());

            assertNull(lastLoginDate);
        } else {
            assertNull(createTimestampInfo);
            assertNotNull(lastLoginDateInfo);

            assertNull(createTimetamp);
            assertNotNull(lastLoginDate);
            assertEquals(Long.class, lastLoginDate.getValue().get(0).getClass());
        }
    }
}

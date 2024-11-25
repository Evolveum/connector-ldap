package com.exclamationlabs.polygon.connector.ldap;

import com.exclamationlabs.polygon.connector.ldap.ad.AdLdapConfiguration;
import com.exclamationlabs.polygon.connector.ldap.ad.AdLdapConnector;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.*;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.test.common.TestHelpers;
import org.testng.AssertJUnit;
import org.testng.SkipException;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.time.ZonedDateTime;
import java.util.*;

public class TestAD {

    private static final ObjectClass OBJECT_CLASS_USER = new ObjectClass("user");

    private static final String PROPERTY_PREFIX = "test.ad.";

    private static final String PROPERTY_HOST = PROPERTY_PREFIX + "host";
    private static final String PROPERTY_PORT = PROPERTY_PREFIX + "port";
    private static final String PROPERTY_CONNECTION_SECURITY = PROPERTY_PREFIX + "connectionSecurity";
    private static final String PROPERTY_BIND_DN = PROPERTY_PREFIX + "bindDn";
    private static final String PROPERTY_BIND_PASSWORD = PROPERTY_PREFIX + "bindPassword";
    private static final String PROPERTY_BASE_CONTEXT = PROPERTY_PREFIX + "baseContext";

    private static final String[] PROPERTIES = {
            PROPERTY_HOST,
            PROPERTY_PORT,
            PROPERTY_CONNECTION_SECURITY,
            PROPERTY_BIND_DN,
            PROPERTY_BIND_PASSWORD,
            PROPERTY_BASE_CONTEXT
    };

    private ConnectorFacade connector;

    @BeforeClass
    public void beforeClass() {
        String[] missingProperties = Arrays.stream(PROPERTIES)
                .filter(p -> System.getProperty(p) == null)
                .sorted()
                .toArray(String[]::new);

        if (missingProperties.length != 0) {
            throw new SkipException(
                    "Missing properties for AD connection configuration: " + Arrays.toString(missingProperties));
        }

        connector = createConnectorInstance();
        connector.test();
    }

    @Test
    public void test000LastLoginDateAttributeInSchema() {
        Schema schema = connector.schema();
        ObjectClassInfo oci = schema.getObjectClassInfo().stream()
                .filter(oc -> OBJECT_CLASS_USER.is(oc.getType()))
                .findFirst()
                .orElse(null);
        AssertJUnit.assertNotNull(oci);

        AttributeInfo lastLoginTimestamp = oci.getAttributeInfo().stream()
                .filter(ai -> ai.getName().equalsIgnoreCase(AdLdapConfiguration.LAST_LOGIN_DATE_ATTRIBUTE_LAST_LOGON_TIMESTAMP))
                .findFirst()
                .orElse(null);
        AssertJUnit.assertNull(lastLoginTimestamp);

        AttributeInfo lastLoginDate = oci.getAttributeInfo().stream()
                .filter(ai -> ai.getName().equalsIgnoreCase(PredefinedAttributes.LAST_LOGIN_DATE_NAME))
                .findFirst()
                .orElse(null);
        AssertJUnit.assertNotNull(lastLoginDate);

        AdLdapConfiguration config = createConfiguration();
        AssertJUnit.assertEquals(Long.class, lastLoginDate.getType());

        List<ConnectorObject> results = new ArrayList<>();
        connector.search(
                new ObjectClass(oci.getType()),
                new EqualsFilter(new Name(config.getBindDn())),
                connectorObject -> {
                    results.add(connectorObject);
                    return true;
                },
                null);

        AssertJUnit.assertEquals(1, results.size());

        ConnectorObject obj = results.get(0);
        Attribute attr = obj.getAttributeByName(PredefinedAttributes.LAST_LOGIN_DATE_NAME);
        AssertJUnit.assertNotNull(attr);

        Object value = attr.getValue().get(0);
        AssertJUnit.assertNotNull(value);

        AssertJUnit.assertEquals(Long.class, value.getClass());
    }

    /**
     * It seems that {@link PredefinedAttributes#LAST_LOGIN_DATE_NAME} can't be added via LDAP even
     * though schema doesn't say it's not creatable.
     *
     * @throws Exception
     */
    @Test(enabled = false)
    public void test100CreateAccount() throws Exception {
        ZonedDateTime lastLoginDate = ZonedDateTime.now();

        ConnectorObject obj = createAccount(lastLoginDate);

        assertLastLoginDate(obj, lastLoginDate);

        connector.delete(OBJECT_CLASS_USER, obj.getUid(), null);
    }

    private void assertLastLoginDate(ConnectorObject obj, Object expected) {
        Attribute lastLoginDateAttr = obj.getAttributeByName(PredefinedAttributes.LAST_LOGIN_DATE_NAME);
        AssertJUnit.assertNotNull(lastLoginDateAttr);
        AssertJUnit.assertEquals(expected, lastLoginDateAttr.getValue().get(0));
    }

    private ConnectorObject createAccount(ZonedDateTime lastLoginDate) {
        String cn = "test" + System.currentTimeMillis();
        String dn = "CN=" + cn + ",CN=Users,DC=ad2019,DC=lab,DC=evolveum,DC=com";

        Set<Attribute> createAttributes = new HashSet<>();
        createAttributes.add(AttributeBuilder.build(Name.NAME, dn));
        createAttributes.add(AttributeBuilder.build("cn", cn));
        createAttributes.add(AttributeBuilder.build(OperationalAttributes.PASSWORD_NAME, new GuardedString("qwe.123".toCharArray())));
        if (lastLoginDate != null) {
            createAttributes.add(AttributeBuilder.build(PredefinedAttributes.LAST_LOGIN_DATE_NAME, lastLoginDate));
        }

        Uid uid = connector.create(OBJECT_CLASS_USER, createAttributes, null);
        AssertJUnit.assertNotNull(uid);

        try {
            return connector.getObject(OBJECT_CLASS_USER, uid, null);
        } catch (Exception ex) {
            connector.delete(OBJECT_CLASS_USER, uid, null);
            throw ex;
        }
    }

    /**
     * It seems that {@link PredefinedAttributes#LAST_LOGIN_DATE_NAME} can't be updated via LDAP even
     * though schema doesn't say it's not creatable.
     *
     * @throws Exception
     */
    @Test(enabled = false)
    public void test200UpdateAccount() throws Exception {
        ConnectorObject object = createAccount(null);

        ZonedDateTime newLastLoginDate = ZonedDateTime.now().minusYears(10);

        connector.updateDelta(
                OBJECT_CLASS_USER,
                object.getUid(),
                Set.of(AttributeDeltaBuilder.build(PredefinedAttributes.LAST_LOGIN_DATE_NAME, newLastLoginDate)),
                null);

        ConnectorObject updated = connector.getObject(OBJECT_CLASS_USER, object.getUid(), null);
        assertLastLoginDate(updated, newLastLoginDate);

        connector.delete(OBJECT_CLASS_USER, object.getUid(), null);
    }

    private ConnectorFacade createConnectorInstance() {
        AdLdapConfiguration config = createConfiguration();

        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();

        APIConfiguration impl = TestHelpers.createTestConfiguration(AdLdapConnector.class, config);
        return factory.newInstance(impl);
    }

    private AdLdapConfiguration createConfiguration() {
        AdLdapConfiguration config = new AdLdapConfiguration();
        config.setHost(System.getProperty(PROPERTY_HOST));
        config.setPort(Integer.parseInt(System.getProperty(PROPERTY_PORT)));
        config.setConnectionSecurity(System.getProperty(PROPERTY_CONNECTION_SECURITY));
        config.setBindDn(System.getProperty(PROPERTY_BIND_DN));
        config.setBindPassword(new GuardedString(System.getProperty(PROPERTY_BIND_PASSWORD).toCharArray()));
        config.setBaseContext(System.getProperty(PROPERTY_BASE_CONTEXT));
        config.setPagingStrategy("spr");
        config.setUidAttribute("objectGUID");
        config.setOperationalAttributes(new String[]{"member", "memberOf", "msDS-parentdistname", "manager", "managedBy", "adminDescription", "groupType", "employeeNumber"});
        config.setIncludeObjectClassFilter(true);
        config.setDefaultSearchScope("sub");
        config.setNativeAdSchema(true);
        config.setIncludeObjectCategoryFilter(true);
        config.setAddDefaultObjectCategory(true);
        config.setAllowFSPProcessing(true);

        config.setAllowUntrustedSsl(true);

        return config;
    }
}

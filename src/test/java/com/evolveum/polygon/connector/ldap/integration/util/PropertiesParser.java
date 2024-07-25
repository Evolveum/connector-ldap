/*
 * Copyright (c) 2010-2023 Evolveum
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

package com.evolveum.polygon.connector.ldap.integration.util;

import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class PropertiesParser {

    private static final Log LOGGER = Log.getLog(PropertiesParser.class);

    private static final Properties PROPERTIES = new Properties();

    private static final String PROPERTIES_PATH = "/integration/test.properties";
    private static final String _HOST = "host";
    private static final String _PORT = "port";
    private static final String _BIND_DN = "bindDn";
    private static final String _BIND_PASSWORD = "bindPassword";
    private static final String _BASE_CONTEXT = "baseContext";
    private static final String _PASSWORD_HASH_ALGORITHM = "passwordHashAlgorithm";
    private static final String _PAGING_STRATEGY = "pagingStrategy";
    private static final String _VLV_SORT_ATTRIBUTE = "vlvSortAttribute";
    private static final String _VLV_SORT_ORDERING_RULE = "vlvSortOrderingRule";
    private static final String _USE_PERMISSIVE_MODIFY = "usePermissiveModify";
    private static final String _MANAGED_ASSOCIATION_PAIRS = "managedAssociationPairs";
    private static final String _LOCKOUT_STRATEGY = "lockoutStrategy";
    private static final String _MEMBER_ATTR = "membershipAttribute";
    private static final String _OPERATIONAL_ATTR = "operationalAttributes";

    public PropertiesParser() {

        try {
            PROPERTIES.load(getClass().getResourceAsStream(PROPERTIES_PATH));
        } catch (FileNotFoundException e) {
            LOGGER.error(e, "File not found: {0}", e.getLocalizedMessage());
        } catch (IOException e) {
            LOGGER.error(e, "IO exception occurred {0}", e.getLocalizedMessage());
        } catch (NullPointerException e) {
            LOGGER.error(e, "Properties file not found", e.getLocalizedMessage());
        }
    }

    public String getHost() {
        return (String) PROPERTIES.get(_HOST);
    }

    public int getPort() {

        String port = (String) PROPERTIES.get(_PORT);

        return Integer.parseInt(port);
    }

    private String[] getValues(String name) {
        Set<String> values = new HashSet<>();

        if (PROPERTIES.containsKey(name)) {
            String value = (String) PROPERTIES.get(name);
            values.addAll(Arrays.asList(value.split(",")));
        }

        return values.toArray(new String[values.size()]);
    }


    public String getPagingStrategy() {
        return (String) PROPERTIES.get(_PAGING_STRATEGY);
    }

    public String getVlvSortAttribute() {
        return (String) PROPERTIES.get(_VLV_SORT_ATTRIBUTE);
    }

    public String getBindDn() {
        return (String) PROPERTIES.get(_BIND_DN);
    }

    public GuardedString getBindPassword() {
        return new GuardedString(((String) PROPERTIES.get(_BIND_PASSWORD)).toCharArray());
    }

    public String getBaseContext() {
        return (String) PROPERTIES.get(_BASE_CONTEXT);
    }

    public String getPasswordHashAlgorithm() {
        return (String) PROPERTIES.get(_PASSWORD_HASH_ALGORITHM);
    }

    public String getVlvSortOrderingRule() {
        return (String) PROPERTIES.get(_VLV_SORT_ORDERING_RULE);
    }

    public String getUsePermissiveModify() {
        return (String) PROPERTIES.get(_USE_PERMISSIVE_MODIFY);
    }

    public String getMemberAttr() {
        return (String) PROPERTIES.get(_MEMBER_ATTR);
    }

    public String[] getManagedAssociationPairs() {
        return getValues(_MANAGED_ASSOCIATION_PAIRS);
    }

    public String getLockoutStrategy() {
        return (String) PROPERTIES.get(_LOCKOUT_STRATEGY);
    }

    public String[] getOperationalAttributes() {
        return getValues(_OPERATIONAL_ATTR);
    }
}
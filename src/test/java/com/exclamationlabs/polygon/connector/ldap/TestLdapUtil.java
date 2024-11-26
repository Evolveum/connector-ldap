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

import org.apache.directory.api.ldap.model.name.Dn;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.testng.annotations.Test;

public class TestLdapUtil {

    @Test
    public void testDnAncestor() throws Exception {
        assertAncestor("dc=example,dc=com", "uid=foo,ou=people,dc=example,dc=com", true);
        assertAncestor("uid=foo,ou=people,dc=example,dc=com", "dc=example,dc=com", false);
        assertAncestor("dc=example,dc=com", "dc=example,dc=com", true);
        assertAncestor("dc=example,dc=com", "CN=foo bar,OU=people,DC=example,DC=com", true);
        assertAncestor("dc=example,dc=com", "CN=foo bar,OU=people,DC=EXamPLE,DC=COM", true);
        assertAncestor("DC=example,DC=com", "cn=foo bar,ou=people,dc=example,dc=com", true);
        assertAncestor("DC=exAMple,DC=com", "CN=foo bar,OU=people,DC=EXamPLE,dc=COM", true);
        assertAncestor("DC=badEXAMPLE,DC=com", "CN=foo bar,OU=people,DC=EXamPLE,dc=COM", false);
        assertAncestor("DC=badexample,DC=com", "CN=foo bar,OU=people,DC=example,dc=com", false);
        assertAncestor("dc=badexample,dc=com", "cn=foo bar,ou=people,dc=example,dc=com", false);

        assertAncestor("DC=ad2019,DC=lab,DC=evolveum,DC=com", "CN=Users,DC=ad2019,DC=lab,DC=evolveum,DC=com", true);
        assertAncestor("CN=Users,DC=ad2019,DC=lab,DC=evolveum,DC=com", "DC=ad2019,DC=lab,DC=evolveum,DC=com", false);

    }

    protected void assertAncestor(String upper, String lower, boolean expectedMatch) {
        Dn upperDn = LdapUtil.asDn(upper);
        Dn lowerDn = LdapUtil.asDn(lower);
        boolean ancestorOf = LdapUtil.isAncestorOf(upperDn, lowerDn);
        if (ancestorOf && !expectedMatch) {
            String msg = "Dn '"+upper+"' is wrongly evaluated as ancestor of '"+
                    lower+"' (it should NOT be).";
            error(msg);
            throw new ConnectorException(msg);
        }
        if (!ancestorOf && expectedMatch) {
            String msg = "Dn '"+upper+"' is NOT evaluated as ancestor of '"+
                    lower+"' (but it should be).";
            error(msg);
            throw new ConnectorException(msg);
        }

        if (ancestorOf) {
            info("Dn '"+upper+"' is correctly evaluated as ancestor of '"+
                    lower+"'");
        } else {
            info("Dn '"+upper+"' is correctly evaluated NOT yo be ancestor of '"+
                    lower+"'");
        }
    }

    private void info(String msg) {
        System.out.println(msg);
    }

    private void error(String msg) {
        System.err.println(msg);
    }


}

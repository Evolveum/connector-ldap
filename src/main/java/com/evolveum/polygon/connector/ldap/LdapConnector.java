/*
 * Copyright (c) 2015 Evolveum
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

import java.util.List;

import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.name.Dn;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

@ConnectorClass(displayNameKey = "connector.ldap.display", configurationClass = LdapConfiguration.class)
public class LdapConnector extends AbstractLdapConnector<LdapConfiguration> {

    private static final Log LOG = Log.getLog(LdapConnector.class);
    
	@Override
	protected AbstractSchemaTranslator<LdapConfiguration> createSchemaTranslator() {
		return new LdapSchemaTranslator(getSchemaManager(), getConfiguration());
	}

	@Override
	protected void addAttributeModification(Dn dn, List<Modification> modifications,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
			ObjectClass icfObjectClass, Attribute icfAttr, ModificationOperation modOp) {
		
		if (icfAttr.is(OperationalAttributes.LOCK_OUT_NAME) 
				&& LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP.equals(getConfiguration().getLockoutStrategy())) {
			List<Object> values = icfAttr.getValue();
			if (values.size() != 1) {
				throw new InvalidAttributeValueException("Unexpected number of values in attribute "+icfAttr);
			}
			Boolean value = (Boolean)values.get(0);
			if (value) {
				throw new UnsupportedOperationException("Locking object is not supported (only unlocking is)");
			}
			modifications.add(
					new DefaultModification(modOp, LdapConstants.ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_NAME)); // no value
			
		} else {
			super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, icfObjectClass, icfAttr, modOp);
		}
	}
    
    

}

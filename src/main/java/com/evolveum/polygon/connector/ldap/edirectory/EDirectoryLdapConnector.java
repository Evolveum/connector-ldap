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

package com.evolveum.polygon.connector.ldap.edirectory;

import java.util.List;

import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.AbstractLdapConnector;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;

@ConnectorClass(displayNameKey = "connector.ldap.display", configurationClass = EDirectoryLdapConfiguration.class)
public class EDirectoryLdapConnector extends AbstractLdapConnector<EDirectoryLdapConfiguration> {

    private static final Log LOG = Log.getLog(EDirectoryLdapConnector.class);

	@Override
	protected SchemaTranslator<EDirectoryLdapConfiguration> createSchemaTranslator() {
		return new EDirectorySchemaTranslator(getSchemaManager(), getConfiguration());
	}

	@Override
	protected LdapFilterTranslator createLdapFilterTranslator(ObjectClass ldapObjectClass) {
		return new EDirectoryLdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
	}

	@Override
	protected void addAttributeModification(List<Modification> modifications,
			ObjectClass ldapStructuralObjectClass,
			org.identityconnectors.framework.common.objects.ObjectClass icfObjectClass, Attribute icfAttr,
			ModificationOperation modOp) {
		LOG.ok("XXX attr={0}", icfAttr);
		if (icfAttr.is(OperationalAttributes.LOCK_OUT_NAME)) {
			List<Object> values = icfAttr.getValue();
			if (values.size() != 1) {
				throw new InvalidAttributeValueException("Unexpected number of values in attribute "+icfAttr);
			}
			Boolean value = (Boolean)values.get(0);
			LOG.ok("XXX LOCK val={0}", value);
			if (value) {
				throw new UnsupportedOperationException("Locking object is not supported (only unlocking is)");
			}
			modifications.add(
					new DefaultModification(modOp, EDirectoryConstants.LOCKOUT_ATTRIBUTE_LOCKED_NAME, 
							AbstractLdapConfiguration.BOOLEAN_FALSE));
			modifications.add(
					new DefaultModification(modOp, EDirectoryConstants.LOCKOUT_ATTRIBUTE_RESET_TIME_NAME)); // no value

		} else {
			super.addAttributeModification(modifications, ldapStructuralObjectClass, icfObjectClass, icfAttr, modOp);
		}
	}
    
	
    
}

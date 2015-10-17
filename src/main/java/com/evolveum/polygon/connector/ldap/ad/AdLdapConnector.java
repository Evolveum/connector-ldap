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

package com.evolveum.polygon.connector.ldap.ad;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.AbstractLdapConnector;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;

@ConnectorClass(displayNameKey = "connector.ldap.ad.display", configurationClass = AdLdapConfiguration.class)
public class AdLdapConnector extends AbstractLdapConnector<AdLdapConfiguration> {

    private static final Log LOG = Log.getLog(AdLdapConnector.class);

	@Override
	protected SchemaTranslator<AdLdapConfiguration> createSchemaTranslator() {
		return new AdSchemaTranslator(getSchemaManager(), getConfiguration());
	}

	@Override
	protected LdapFilterTranslator createLdapFilterTranslator(ObjectClass ldapObjectClass) {
		return new AdLdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
	}

	@Override
	protected AdSchemaTranslator getSchemaTranslator() {
		return (AdSchemaTranslator)super.getSchemaTranslator();
	}

	@Override
	protected void preCreate(Entry entry) {
		super.preCreate(entry);
		if (entry.get(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME) == null) {
			try {
				entry.add(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, Integer.toString(AdConstants.USER_ACCOUNT_CONTROL_NORMAL));
			} catch (LdapException e) {
				throw new IllegalStateException("Error adding attribute "+AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME+" to entry");
			}
		}
	}

	@Override
	protected void addAttributeModification(String dn, List<Modification> modifications, ObjectClass ldapStructuralObjectClass,
			org.identityconnectors.framework.common.objects.ObjectClass icfObjectClass, Attribute icfAttr, ModificationOperation modOp) {
		Dn dndn;
		try {
			dndn = new Dn(dn);
		} catch (LdapInvalidDnException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		Rdn firstRdn = dndn.getRdns().get(0);
		String firstRdnAttrName = firstRdn.getAva().getType();
		AttributeType modAttributeType = getSchemaTranslator().toLdapAttribute(ldapStructuralObjectClass, icfAttr.getName());
		if (firstRdnAttrName.equalsIgnoreCase(modAttributeType.getName())) {
			// Ignore this modification. It is already done by the rename operation.
			// Attempting to do it will result in an error.
			return;
		} else {
			super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, icfObjectClass, icfAttr, modOp);
		}
	}
	
	
	    
}

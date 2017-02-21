/**
 * Copyright (c) 2016 Evolveum
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

import java.util.Arrays;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;

import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class LdapSchemaTranslator extends AbstractSchemaTranslator<LdapConfiguration> {
		
	private static final Log LOG = Log.getLog(LdapSchemaTranslator.class);
	
	private String[] computedOperationalAttributes = null;
	
	public LdapSchemaTranslator(SchemaManager schemaManager, LdapConfiguration configuration) {
		super(schemaManager, configuration);
	}

	@Override
	protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		super.extendObjectClassDefinition(ocib, ldapObjectClass);
		
		if (!LdapConfiguration.LOCKOUT_STRATEGY_NONE.equals(getConfiguration().getLockoutStrategy())) {
			AttributeInfoBuilder lockoutAb = new AttributeInfoBuilder(OperationalAttributes.LOCK_OUT_NAME);
			lockoutAb.setType(boolean.class);
//			lockoutAb.setReturnedByDefault(false);
			ocib.addAttributeInfo(lockoutAb.build());
		}
	}
	
	@Override
	public String[] getOperationalAttributes() {
		if (computedOperationalAttributes == null) {
			if (LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP.equals(getConfiguration().getLockoutStrategy())) {
				String[] schemaOperationalAttributes = super.getOperationalAttributes();
				computedOperationalAttributes = new String[schemaOperationalAttributes.length + 1];
				computedOperationalAttributes = Arrays.copyOf(schemaOperationalAttributes, schemaOperationalAttributes.length + 1);
				computedOperationalAttributes[schemaOperationalAttributes.length] = LdapConstants.ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_NAME;
			} else {
				computedOperationalAttributes = super.getOperationalAttributes();
			}
		}
		return computedOperationalAttributes;
	}

	@Override
	protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
		super.extendConnectorObject(cob, entry, objectClassName);
		
		if (LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP.equals(getConfiguration().getLockoutStrategy())) {
			Long pwdAccountLockedTime = LdapUtil.getTimestampAttribute(entry, LdapConstants.ATTRIBUTE_OPENLDAP_PWD_ACCOUNT_LOCKED_TIME_NAME);
			if (pwdAccountLockedTime != null) {
				// WARNING: this is not exact. The lock might have already expired. But we do not have
				// any good way to check that without access to cn=config
				cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.TRUE);
			} else {
				cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.FALSE);
			}
		}
	}

}

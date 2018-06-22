/**
 * Copyright (c) 2015-2018 Evolveum
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

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
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
public class EDirectorySchemaTranslator extends AbstractSchemaTranslator<EDirectoryLdapConfiguration> {
		
	private static final Log LOG = Log.getLog(EDirectorySchemaTranslator.class);
	
	public EDirectorySchemaTranslator(SchemaManager schemaManager, EDirectoryLdapConfiguration configuration) {
		super(schemaManager, configuration);
	}

	@Override
	protected void extendObjectClassDefinition(ObjectClassInfoBuilder ocib,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		super.extendObjectClassDefinition(ocib, ldapObjectClass);
		if (isUserObjectClass(ldapObjectClass.getName())) {
			AttributeInfoBuilder lockoutAb = new AttributeInfoBuilder(OperationalAttributes.LOCK_OUT_NAME);
			lockoutAb.setType(boolean.class);
//			lockoutAb.setReturnedByDefault(false);
			ocib.addAttributeInfo(lockoutAb.build());
			
			AttributeInfoBuilder enableAb = new AttributeInfoBuilder(OperationalAttributes.ENABLE_NAME);
			enableAb.setType(boolean.class);
			ocib.addAttributeInfo(enableAb.build());
		}
	}
	
	@Override
	protected boolean shouldTranslateAttribute(String attrName) {
		return !attrName.equals(EDirectoryConstants.ATTRIBUTE_LOCKOUT_LOCKED_NAME)
				&& !attrName.equals(EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME);
	}
	
	@Override
	public AttributeType toLdapAttribute(
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, String icfAttributeName) {
		if (icfAttributeName.equals(OperationalAttributes.ENABLE_NAME)) {
			return super.toLdapAttribute(ldapObjectClass, EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME);
		} else if (icfAttributeName.equals(OperationalAttributes.LOCK_OUT_NAME)) {
			return super.toLdapAttribute(ldapObjectClass, EDirectoryConstants.ATTRIBUTE_LOCKOUT_LOCKED_NAME);
		} else {
			return super.toLdapAttribute(ldapObjectClass, icfAttributeName);
		}
	}
	
	@Override
	public Value toLdapValue(AttributeType ldapAttributeType, Object icfAttributeValue) {
		if (EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME.equals(ldapAttributeType.getName())) {
			// This is translated from __ENABLE__. So we need to negate it.
			return super.toLdapValue(ldapAttributeType, !((Boolean)icfAttributeValue));
		}
		return super.toLdapValue(ldapAttributeType, icfAttributeValue);
	}

	@Override
	protected void extendConnectorObject(ConnectorObjectBuilder cob, Entry entry, String objectClassName) {
		super.extendConnectorObject(cob, entry, objectClassName);
		Boolean ldapDisabled = LdapUtil.getBooleanAttribute(entry, EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME, null);
		if (ldapDisabled == null) {
			if (isUserObjectClass(objectClassName)) {
				cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.TRUE);
			}
		} else {
			if (ldapDisabled) {
				cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.FALSE);
			} else {
				cob.addAttribute(OperationalAttributes.ENABLE_NAME, Boolean.TRUE);
			}
		}
		boolean ldapLocked = LdapUtil.getBooleanAttribute(entry, EDirectoryConstants.ATTRIBUTE_LOCKOUT_LOCKED_NAME, Boolean.FALSE);
		if (ldapLocked) {
			Long resetTime = LdapUtil.getTimestampAttribute(entry, EDirectoryConstants.ATTRIBUTE_LOCKOUT_RESET_TIME_NAME);
			long now = System.currentTimeMillis();
			LOG.ok("LOCK reset={0}, now={1}", resetTime, now);
			if (resetTime!=null && resetTime > now) {
				cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.TRUE);
			} else {
				cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.FALSE);
			}
		} else {
			cob.addAttribute(OperationalAttributes.LOCK_OUT_NAME, Boolean.FALSE);
		}
	}

	public boolean isUserObjectClass(String ldapObjectClass) {
		return getConfiguration().getUserObjectClass().equals(ldapObjectClass);
	}

	public boolean isGroupObjectClass(String ldapObjectClass) {
		return getConfiguration().getGroupObjectClass().equals(ldapObjectClass);
	}
	
	// TODO: OID_NOVELL_SYNTAX_NDS_TIMESTAMP
	
	@Override
	public Class<?> toIcfType(LdapSyntax syntax, String icfAttributeName) {
		if (syntax != null && (EDirectoryConstants.OID_NOVELL_SYNTAX_CASE_IGNORE_LIST.equals(syntax.getOid())
				|| EDirectoryConstants.OID_NOVELL_SYNTAX_TAGGED_STRING.equals(syntax.getOid())
				|| EDirectoryConstants.OID_NOVELL_SYNTAX_TAGGED_NAME_AND_STRING.equals(syntax.getOid())
				|| EDirectoryConstants.OID_NOVELL_SYNTAX_NDS_ACL.equals(syntax.getOid())
				|| EDirectoryConstants.OID_NOVELL_SYNTAX_COUNTER.equals(syntax.getOid())
				|| EDirectoryConstants.OID_NOVELL_SYNTAX_TAGGED_NAME.equals(syntax.getOid())
				|| EDirectoryConstants.OID_NOVELL_SYNTAX_TYPED_NAME.equals(syntax.getOid())
			)) {
			return String.class;
		} else if (syntax != null && EDirectoryConstants.OID_NOVELL_SYNTAX_NDS_TIMESTAMP.equals(syntax.getOid())) {
			// String now. But we should convert this to date
			return String.class;
		} else if (syntax != null && EDirectoryConstants.OID_NOVELL_SYNTAX_NETADDRESS.equals(syntax.getOid())) {
			return byte[].class;
		}
		return super.toIcfType(syntax, icfAttributeName);
	}
	
	@Override
	protected boolean isBinarySyntax(String syntaxOid) {
		return EDirectoryConstants.OID_NOVELL_SYNTAX_NETADDRESS.equals(syntaxOid) ||
				super.isBinarySyntax(syntaxOid);
	}
	
	@Override
	protected boolean acceptsFractionalGeneralizedTime() {
		return false;
	}

}

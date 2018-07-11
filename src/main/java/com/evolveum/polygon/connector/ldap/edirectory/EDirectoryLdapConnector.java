/*
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

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.message.AddResponse;
import org.apache.directory.api.ldap.model.message.ModifyResponse;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.name.Dn;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.AbstractLdapConnector;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

@ConnectorClass(displayNameKey = "connector.ldap.edirectory.display", configurationClass = EDirectoryLdapConfiguration.class)
public class EDirectoryLdapConnector extends AbstractLdapConnector<EDirectoryLdapConfiguration> {

    private static final Log LOG = Log.getLog(EDirectoryLdapConnector.class);

	@Override
	protected AbstractSchemaTranslator<EDirectoryLdapConfiguration> createSchemaTranslator() {
		return new EDirectorySchemaTranslator(getSchemaManager(), getConfiguration());
	}

	@Override
	protected LdapFilterTranslator<EDirectoryLdapConfiguration> createLdapFilterTranslator(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		return new EDirectoryLdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
	}

	@Override
	protected EDirectorySchemaTranslator getSchemaTranslator() {
		return (EDirectorySchemaTranslator)super.getSchemaTranslator();
	}
	
	@Override
	protected void addAttributeModification(Dn dn, List<Modification> modifications,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
			ObjectClass connIdObjectClass, AttributeDelta delta) {
		if (delta.is(OperationalAttributes.ENABLE_NAME)) {
			Boolean enableValue = SchemaUtil.getSingleReplaceValue(delta, Boolean.class);
			if (enableValue == null) {
				enableValue = true;
			}
			if (enableValue) {
				modifications.add(
						new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME, 
								AbstractLdapConfiguration.BOOLEAN_FALSE));
			} else {
				modifications.add(
						new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, EDirectoryConstants.ATTRIBUTE_LOGIN_DISABLED_NAME, 
								AbstractLdapConfiguration.BOOLEAN_TRUE));
			}
		} else if (delta.is(OperationalAttributes.LOCK_OUT_NAME)) {
			Boolean lockoutValue = SchemaUtil.getSingleReplaceValue(delta, Boolean.class);
			if (lockoutValue == null) {
				lockoutValue = false;
			}
			if (lockoutValue) {
				throw new UnsupportedOperationException("Locking object is not supported (only unlocking is)");
			}
			modifications.add(
					new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, EDirectoryConstants.ATTRIBUTE_LOCKOUT_LOCKED_NAME, 
							AbstractLdapConfiguration.BOOLEAN_FALSE));
			modifications.add(
					new DefaultModification(ModificationOperation.REPLACE_ATTRIBUTE, EDirectoryConstants.ATTRIBUTE_LOCKOUT_RESET_TIME_NAME)); // no value

		} else if (getSchemaTranslator().isGroupObjectClass(ldapStructuralObjectClass.getName())) {
			// modification handles modification of ordinary attributes - and also modification of "member" itself
			super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, connIdObjectClass, delta);
			if (delta.is(getConfiguration().getGroupObjectMemberAttribute())) {
				if (getConfiguration().isManageEquivalenceAttributes()) {
					// do the same operation with a equivalentToMe attribute
					super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, connIdObjectClass, 
							duplicateDelta(EDirectoryConstants.ATTRIBUTE_EQUIVALENT_TO_ME_NAME, delta));
				}
			}
		} else {
			super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, connIdObjectClass, delta);
		}
	}
	
	private AttributeDelta duplicateDelta(String newAttributeName, AttributeDelta origDelta) {
		AttributeDeltaBuilder builder = new AttributeDeltaBuilder();
		builder.setName(newAttributeName);
		if (origDelta.getValuesToReplace() != null) {
			builder.addValueToReplace(origDelta.getValuesToReplace());
		}
		if (origDelta.getValuesToAdd() != null) {
			builder.addValueToAdd(origDelta.getValuesToAdd());
		}
		if (origDelta.getValuesToRemove() != null) {
			builder.addValueToRemove(origDelta.getValuesToRemove());
		}
		return null;
	}

	@Override
	protected RuntimeException processCreateResult(String dn, AddResponse addResponse) {
		if (addResponse.getLdapResult().getResultCode() == ResultCodeEnum.CONSTRAINT_VIOLATION &&
				addResponse.getLdapResult().getDiagnosticMessage().contains("password")) {
			return new InvalidAttributeValueException("Error adding LDAP entry " + dn + ": " + addResponse.getLdapResult().getDiagnosticMessage());
		}
		return super.processCreateResult(dn, addResponse);
	}
	
	@Override
	protected RuntimeException processModifyResult(Dn dn, List<Modification> modifications, ModifyResponse modifyResponse) {
		if (modifyResponse.getLdapResult().getResultCode() == ResultCodeEnum.CONSTRAINT_VIOLATION &&
				modifyResponse.getLdapResult().getDiagnosticMessage().contains("password")) {
			return new InvalidAttributeValueException("Error modifying LDAP entry " + dn + ": " + dumpModifications(modifications) + ": " + modifyResponse.getLdapResult().getDiagnosticMessage());
		}
		return super.processModifyResult(dn, modifications, modifyResponse);
	}
	
	@Override
	protected RuntimeException processModifyResult(String dn, List<Modification> modifications, LdapException e) {
		if ((e instanceof LdapInvalidAttributeValueException) && 
		((LdapInvalidAttributeValueException)e).getResultCode() == ResultCodeEnum.CONSTRAINT_VIOLATION && e.getMessage().contains("password")) {
			return new InvalidAttributeValueException("Error modifying LDAP entry " + dn + ": " + e.getMessage(), e);
		}
		return super.processModifyResult(dn, modifications, e);
	}

	@Override
	protected void postUpdate(ObjectClass connIdObjectClass, Uid uid, Set<AttributeDelta> deltas,
			OperationOptions options, 
			Dn dn, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass, List<Modification> ldapModifications) {
		super.postUpdate(connIdObjectClass, uid, deltas, options, dn, ldapStructuralObjectClass, ldapModifications);
		if (!getConfiguration().isManageReciprocalGroupAttributes()) {
			return;
		}
		if (getSchemaTranslator().isGroupObjectClass(ldapStructuralObjectClass.getName())) {
			for (AttributeDelta delta: deltas) {
				if (delta.is(getConfiguration().getGroupObjectMemberAttribute())) {
					// this is for group of users; "members"
					if (delta.getValuesToReplace() != null) {
						throw new UnsupportedOperationException("Replace of group members is not supported");
					}
					updateGroupMemeberShip(dn, delta);
				}
				if (delta.is(getConfiguration().getGroupObjectGroupMemberAttribute())) {
					// this is for group of groups (nested); "groupMember"
					if (delta.getValuesToReplace() != null) {
						throw new UnsupportedOperationException("Replace of group members is not supported");
					}
					updateGroupMemeberShip(dn, delta);
				}
			}
		}
	}
	
	private void updateGroupMemeberShip(Dn groupDn, AttributeDelta delta) {
		addGroupMemeberShipModifications(groupDn, ModificationOperation.ADD_ATTRIBUTE, delta.getValuesToAdd());
		addGroupMemeberShipModifications(groupDn, ModificationOperation.REMOVE_ATTRIBUTE, delta.getValuesToRemove());
	}

	private void addGroupMemeberShipModifications(Dn groupDn, ModificationOperation modOp, List<Object> values) {
		if (values == null) {
			return;
		}
		for (Object val: values) {
			Dn memberDn = getSchemaTranslator().toDn((String)val);
			List<Modification> mods = new ArrayList<Modification>(1);
			mods.add(new DefaultModification(modOp, EDirectoryConstants.ATTRIBUTE_GROUP_MEMBERSHIP_NAME, groupDn.toString()));
			// No need to update securityEquals. eDirectory is doing that by itself
			// (the question is why it cannot do also to the groupMemberhip?)
			modify(memberDn, mods);
		}
	}
    
}

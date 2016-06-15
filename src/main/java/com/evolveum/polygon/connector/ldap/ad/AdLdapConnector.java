/*
 * Copyright (c) 2015-2016 Evolveum
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

import java.util.List;

import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.AbstractLdapConnector;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;

@ConnectorClass(displayNameKey = "connector.ldap.ad.display", configurationClass = AdLdapConfiguration.class)
public class AdLdapConnector extends AbstractLdapConnector<AdLdapConfiguration> {

    private static final Log LOG = Log.getLog(AdLdapConnector.class);
    
    private GlobalCatalogConnectionManager globalCatalogConnectionManager;

	@Override
	public void init(Configuration configuration) {
		super.init(configuration);
		globalCatalogConnectionManager = new GlobalCatalogConnectionManager(getConfiguration());
	}

	@Override
	protected AbstractSchemaTranslator<AdLdapConfiguration> createSchemaTranslator() {
		return new AdSchemaTranslator(getSchemaManager(), getConfiguration());
	}

	@Override
	protected LdapFilterTranslator<AdLdapConfiguration> createLdapFilterTranslator(ObjectClass ldapObjectClass) {
		return new AdLdapFilterTranslator(getSchemaTranslator(), ldapObjectClass);
	}

	@Override
	protected AdSchemaTranslator getSchemaTranslator() {
		return (AdSchemaTranslator)super.getSchemaTranslator();
	}
	
	@Override
    protected boolean isLogSchemaErrors() {
		// There are too many built-in schema errors in AD that this only pollutes the logs
		return false;
	}

	@Override
	protected void preCreate(org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass, Entry entry) {
		super.preCreate(ldapStructuralObjectClass, entry);
		if (getSchemaTranslator().isUserObjectClass(ldapStructuralObjectClass.getName()) && !getConfiguration().isRawUserAccountControlAttribute()) {
			if (entry.get(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME) == null) {
				try {
					entry.add(AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME, Integer.toString(AdConstants.USER_ACCOUNT_CONTROL_NORMAL));
				} catch (LdapException e) {
					throw new IllegalStateException("Error adding attribute "+AdConstants.ATTRIBUTE_USER_ACCOUNT_CONTROL_NAME+" to entry");
				}
			}
		}
	}

	@Override
	protected void addAttributeModification(Dn dn, List<Modification> modifications, ObjectClass ldapStructuralObjectClass,
			org.identityconnectors.framework.common.objects.ObjectClass icfObjectClass, Attribute icfAttr, ModificationOperation modOp) {
		Rdn firstRdn = dn.getRdns().get(0);
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
	
	@Override
	protected SearchStrategy<AdLdapConfiguration> chooseSearchStrategy(org.identityconnectors.framework.common.objects.ObjectClass objectClass,
			ObjectClass ldapObjectClass, ResultsHandler handler, OperationOptions options) {
		SearchStrategy<AdLdapConfiguration> searchStrategy = super.chooseSearchStrategy(objectClass, ldapObjectClass, handler, options);
		searchStrategy.setAttributeHandler(new AdAttributeHandler(searchStrategy));
		return searchStrategy;
	}
	
	@Override
	protected SearchStrategy<AdLdapConfiguration> getDefaultSearchStrategy(org.identityconnectors.framework.common.objects.ObjectClass objectClass,
			ObjectClass ldapObjectClass, ResultsHandler handler, OperationOptions options) {
		SearchStrategy<AdLdapConfiguration> searchStrategy =  super.getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
		searchStrategy.setAttributeHandler(new AdAttributeHandler(searchStrategy));
		return searchStrategy;

	}

	@Override
	protected SearchStrategy<AdLdapConfiguration> searchByUid(String uidValue, org.identityconnectors.framework.common.objects.ObjectClass objectClass,
			ObjectClass ldapObjectClass, ResultsHandler handler, OperationOptions options) {
		if (LdapUtil.isDnAttribute(getConfiguration().getUidAttribute())) {
			
			return searchByDn(getSchemaTranslator().toDn(uidValue), objectClass, ldapObjectClass, handler, options);
		
		} else {
			
			if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_NONE.equals(getConfiguration().getGlobalCatalogStrategy())) {
				// Make search with <GUID=....> baseDn on default connection. Rely on referrals to point our head to
				// the correct domain controller in multi-domain environment.
				// We know that this can return at most one object. Therefore always use simple search.
				SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
				String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
				Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
				try {
					searchStrategy.search(guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, attributesToGet);
				} catch (LdapException e) {
					throw LdapUtil.processLdapException("Error searching for GUID '"+uidValue+"'", e);
				}
				
				return searchStrategy;

			} else if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_READ.equals(getConfiguration().getGlobalCatalogStrategy())) {
				// Make a search directly to the global catalog server. Present that as final result.
				// We know that this can return at most one object. Therefore always use simple search.
				SearchStrategy<AdLdapConfiguration> searchStrategy = new DefaultSearchStrategy<>(globalCatalogConnectionManager, 
						getConfiguration(), getSchemaTranslator(), objectClass, ldapObjectClass, handler, options);
				String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
				Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
				try {
					searchStrategy.search(guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, attributesToGet);
				} catch (LdapException e) {
					throw LdapUtil.processLdapException("Error searching for GUID '"+uidValue+"'", e);
				}
				
				return searchStrategy;
				
			} else if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_RESOLVE.equals(getConfiguration().getGlobalCatalogStrategy())) {
				Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
				Entry entry = searchSingleEntry(globalCatalogConnectionManager, guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT,
						new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "global catalog entry for GUID "+uidValue);
				if (entry == null) {
					throw new UnknownUidException("Entry for GUID "+uidValue+" was not found in global catalog");
				}
				LOG.ok("Resolved GUID {0} in glogbal catalog to DN {1}", uidValue, entry.getDn());
				Dn dn = entry.getDn();
				
				SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
				// We need to force the use of explicit connection here. The search is still using the <GUID=..> dn
				// The search strategy cannot use that to select a connection. So we need to select a connection
				// based on the DN returned from global catalog explicitly.
				// We also cannot use the DN from the global catalog as the base DN for the search.
				// The global catalog may not be replicated yet and it may not have the correct DN
				// (e.g. the case of quick read after rename)
				LdapNetworkConnection connection = getConnectionManager().getConnection(dn);
				searchStrategy.setExplicitConnection(connection);
				
				String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
				try {
					searchStrategy.search(guidDn, null, SearchScope.OBJECT, attributesToGet);
				} catch (LdapException e) {
					throw LdapUtil.processLdapException("Error searching for DN '"+guidDn+"'", e);
				}
				return searchStrategy;
				
			} else {
				throw new IllegalStateException("Unknown global catalog strategy '"+getConfiguration().getGlobalCatalogStrategy()+"'");
			}
		}
	}

	@Override
	protected Dn resolveDn(org.identityconnectors.framework.common.objects.ObjectClass objectClass, Uid uid, OperationOptions options) {
		Dn guidDn = getSchemaTranslator().getGuidDn(uid.getUidValue());
		
		if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_NONE.equals(getConfiguration().getGlobalCatalogStrategy())) {
			Entry entry = searchSingleEntry(getConnectionManager(), guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
					new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+uid.getUidValue());
			if (entry == null) {
				throw new UnknownUidException("Entry for GUID "+uid.getUidValue()+" was not found");
			}
			return entry.getDn();
			
		} else {
			Entry entry = searchSingleEntry(globalCatalogConnectionManager, guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
					new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+uid.getUidValue());
			if (entry == null) {
				throw new UnknownUidException("Entry for GUID "+uid.getUidValue()+" was not found in global catalog");
			}
			LOG.ok("Resolved GUID {0} in glogbal catalog to DN {1}", uid.getUidValue(), entry.getDn());
			return entry.getDn();
		}
	}
	
	
	    
}

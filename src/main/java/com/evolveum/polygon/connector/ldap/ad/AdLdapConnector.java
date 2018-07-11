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

package com.evolveum.polygon.connector.ldap.ad;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapOtherException;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapComparator;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.MutableMatchingRule;
import org.apache.directory.api.ldap.model.schema.Normalizer;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaErrorHandler;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
import org.apache.directory.api.ldap.model.schema.comparators.ComparableComparator;
import org.apache.directory.api.ldap.model.schema.comparators.NormalizingComparator;
import org.apache.directory.api.ldap.model.schema.comparators.StringComparator;
import org.apache.directory.api.ldap.model.schema.normalizers.DeepTrimToLowerNormalizer;
import org.apache.directory.api.ldap.model.schema.registries.AttributeTypeRegistry;
import org.apache.directory.api.ldap.model.schema.registries.MatchingRuleRegistry;
import org.apache.directory.api.ldap.model.schema.registries.ObjectClassRegistry;
import org.apache.directory.api.ldap.model.schema.registries.Registries;
import org.apache.directory.api.ldap.model.schema.registries.SchemaObjectRegistry;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.DirectoryStringSyntaxChecker;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.http.client.config.AuthSchemes;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeDelta;
import org.identityconnectors.framework.common.objects.AttributeDeltaBuilder;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.ScriptContext;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.ScriptOnResourceOp;

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.common.SchemaUtil;
import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.AbstractLdapConnector;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.OperationLog;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;
import com.evolveum.powerhell.AbstractPowerHellImpl;
import com.evolveum.powerhell.AbstractPowerHellWinRmImpl;
import com.evolveum.powerhell.ArgumentStyle;
import com.evolveum.powerhell.PowerHell;
import com.evolveum.powerhell.PowerHellCommunicationException;
import com.evolveum.powerhell.PowerHellException;
import com.evolveum.powerhell.PowerHellExecutionException;
import com.evolveum.powerhell.PowerHellLocalExecImpl;
import com.evolveum.powerhell.PowerHellLocalExecPowerShellImpl;
import com.evolveum.powerhell.PowerHellLocalExecWinRsPowerShellImpl;
import com.evolveum.powerhell.PowerHellSecurityException;
import com.evolveum.powerhell.PowerHellWinRmExecImpl;
import com.evolveum.powerhell.PowerHellWinRmExecPowerShellImpl;
import com.evolveum.powerhell.PowerHellWinRmLoopImpl;

import io.cloudsoft.winrm4j.winrm.WinRmTool;
import io.cloudsoft.winrm4j.winrm.WinRmToolResponse;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.transport.https.httpclient.DefaultHostnameVerifier;

@ConnectorClass(displayNameKey = "connector.ldap.ad.display", configurationClass = AdLdapConfiguration.class)
public class AdLdapConnector extends AbstractLdapConnector<AdLdapConfiguration> implements ScriptOnResourceOp {

    private static final Log LOG = Log.getLog(AdLdapConnector.class);

	private static final String PING_COMMAND = "hostname.exe";
	private static final String EXCHANGE_INIT_SCRIPT = "Add-PSSnapin *Exchange*";
    
    private GlobalCatalogConnectionManager globalCatalogConnectionManager;
    
    // SCRIPTING
    private String winRmUsername;
    private String winRmHost;
    private HostnameVerifier hostnameVerifier;
    private Map<String,PowerHell> powerHellMap = new HashMap<>(); // key: scripting language
    
    private boolean busInitialized = false;
	private boolean isWinRmInitialized;
	
    private static int busUsageCount = 0;

	@Override
	public void init(Configuration configuration) {
		super.init(configuration);
		globalCatalogConnectionManager = new GlobalCatalogConnectionManager(getConfiguration());
	}
	
	@Override
    public void dispose() {
		super.dispose();
		disposeScripting();
	}
	
	@Override
	protected void cleanupBeforeTest() {
		cleanupScriptingBeforeTest();
	}
	
	@Override
	protected void additionalConnectionTests() {
		if (isScriptingExplicitlyConfigured()) {
			pingScripting();
		}		
	}
	
	@Override
	protected void reconnectAfterTest() {
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
	
    protected SchemaErrorHandler createSchemaErrorHandler() {
		// null by default. This means that a default logging error handler from directory API
    	// will be used. May be overridden by subsclasses.
		return new MutedLoggingSchemaErrorHandler();
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
			org.identityconnectors.framework.common.objects.ObjectClass icfObjectClass, AttributeDelta delta) {
		Rdn firstRdn = dn.getRdns().get(0);
		String firstRdnAttrName = firstRdn.getAva().getType();
		AttributeType modAttributeType = getSchemaTranslator().toLdapAttribute(ldapStructuralObjectClass, delta.getName());
		if (firstRdnAttrName.equalsIgnoreCase(modAttributeType.getName())) {
			// Ignore this modification. It is already done by the rename operation.
			// Attempting to do it will result in an error.
			return;
		} else {
			super.addAttributeModification(dn, modifications, ldapStructuralObjectClass, icfObjectClass, delta);
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
	protected SearchStrategy<AdLdapConfiguration> searchByUid(Uid uid, org.identityconnectors.framework.common.objects.ObjectClass objectClass,
			ObjectClass ldapObjectClass, final ResultsHandler handler, OperationOptions options) {
		final String uidValue = SchemaUtil.getSingleStringNonBlankValue(uid);
		
		
		// Trivial (but not really realistic) case: UID is DN
		
		if (LdapUtil.isDnAttribute(getConfiguration().getUidAttribute())) {
			
			return searchByDn(getSchemaTranslator().toDn(uidValue), objectClass, ldapObjectClass, handler, options);
		
		}
		
		if (uid.getNameHint() != null) {
			
			// First attempt: name hint, GUID search (last seen DN)
			
			// Name hint is the last DN that we have seen for this object. However, the object may have
			// been renamed or may have moved. Therefore use the name hint just to select the connection.
			// Once we have the connection then forget name hint and use GUID DN to get the entry.
			// This is the most efficient and still very reliable way to get the entry.
						
			Dn nameHintDn = getSchemaTranslator().toDn(uid.getNameHint());
			SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
			LdapNetworkConnection connection = getConnectionManager().getConnection(nameHintDn);
			searchStrategy.setExplicitConnection(connection);
			
			Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			try {
				searchStrategy.search(guidDn, null, SearchScope.OBJECT, attributesToGet);
			} catch (LdapException e) {
				throw LdapUtil.processLdapException("Error searching for DN '"+guidDn+"'", e);
			}
			
			if (searchStrategy.getNumberOfEntriesFound() > 0) {
				return searchStrategy;
			}
		}

		// Second attempt: global catalog
		
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
			
			if (searchStrategy.getNumberOfEntriesFound() > 0) {
				return searchStrategy;
			}

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
			
			if (searchStrategy.getNumberOfEntriesFound() > 0) {
				return searchStrategy;
			}
			
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
			
			if (searchStrategy.getNumberOfEntriesFound() > 0) {
				return searchStrategy;
			}
			
		} else {
			throw new IllegalStateException("Unknown global catalog strategy '"+getConfiguration().getGlobalCatalogStrategy()+"'");
		}
		
		// Third attempt: brutal search over all the servers
		
		if (getConfiguration().isAllowBruteForceSearch()) {
			LOG.ok("Cannot find object with GUID {0} by using name hint or global catalog. Resorting to brute-force search",
					uidValue);
			Dn guidDn = getSchemaTranslator().getGuidDn(uidValue);
			String[] attributesToGet = getAttributesToGet(ldapObjectClass, options);
			for (LdapNetworkConnection connection: getConnectionManager().getAllConnections()) {
				SearchStrategy<AdLdapConfiguration> searchStrategy = getDefaultSearchStrategy(objectClass, ldapObjectClass, handler, options);
				searchStrategy.setExplicitConnection(connection);
				
				try {
					searchStrategy.search(guidDn, null, SearchScope.OBJECT, attributesToGet);
				} catch (LdapException e) {
					throw LdapUtil.processLdapException("Error searching for DN '"+guidDn+"'", e);
				}
				
				if (searchStrategy.getNumberOfEntriesFound() > 0) {
					return searchStrategy;
				}
			}
			
		} else {
			LOG.ok("Cannot find object with GUID {0} by using name hint or global catalog. Brute-force search is disabled. Found nothing.",
					uidValue);
		}
		
		// Found nothing
		return null;
		
	}

	@Override
	protected Dn resolveDn(org.identityconnectors.framework.common.objects.ObjectClass objectClass, Uid uid, OperationOptions options) {
		
		String guid = uid.getUidValue();
		
		if (uid.getNameHint() != null) {
			// Try to use name hint to select the correct server, but still search by GUID. The entry might
			// have been renamed since we looked last time and the name hint may be out of date. But it is
			// likely that it is still OK for selecting correct server.
			// Global catalog updates are quite lazy. Looking at global catalog can get even worse results
			// than name hint.
			
			String dnHintString = uid.getNameHintValue();
			Dn dnHint = getSchemaTranslator().toDn(dnHintString);
			LOG.ok("Resolvig DN by using name hint {0} and guid", dnHint, guid);

			Dn guidDn = getSchemaTranslator().getGuidDn(guid);
						
			LOG.ok("Resolvig DN by search for {0} (no global catalog)", guidDn);
			Entry entry = searchSingleEntry(getConnectionManager(), guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
					new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+guid, dnHint);

			if (entry != null) {
					return entry.getDn();
			} else {
				LOG.ok("Resolvig DN for name hint {0} returned no object", dnHintString);
			}
		}
		
		Dn guidDn = getSchemaTranslator().getGuidDn(guid);
		
		if (AdLdapConfiguration.GLOBAL_CATALOG_STRATEGY_NONE.equals(getConfiguration().getGlobalCatalogStrategy())) {
			LOG.ok("Resolvig DN by search for {0} (no global catalog)", guidDn);
			Entry entry = searchSingleEntry(getConnectionManager(), guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
					new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+guid);
			if (entry == null) {
				throw new UnknownUidException("Entry for GUID "+guid+" was not found");
			}
			return entry.getDn();
			
		} else {
			LOG.ok("Resolvig DN by search for {0} (global catalog)", guidDn);
			Entry entry = searchSingleEntry(globalCatalogConnectionManager, guidDn, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
					new String[]{AbstractLdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME}, "LDAP entry for GUID "+guid);
			if (entry == null) {
				throw new UnknownUidException("Entry for GUID "+guid+" was not found in global catalog");
			}
			LOG.ok("Resolved GUID {0} in glogbal catalog to DN {1}", guid, entry.getDn());
			return entry.getDn();
		}
	}
	
	@Override
	protected void postUpdate(org.identityconnectors.framework.common.objects.ObjectClass connIdObjectClass,
			Uid uid, Set<AttributeDelta> deltas, OperationOptions options,
			Dn dn, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
			List<Modification> ldapModifications) {
		super.postUpdate(connIdObjectClass, uid, deltas, options, dn, ldapStructuralObjectClass, ldapModifications);
		
		AttributeDelta forcePasswordChangeDelta = SchemaUtil.findDelta(deltas, OperationalAttributes.FORCE_PASSWORD_CHANGE_NAME);
		if (forcePasswordChangeDelta != null) {
			Boolean forcePasswordChangeValue = SchemaUtil.getSingleReplaceValue(forcePasswordChangeDelta, Boolean.class);
			// This may not be entirely correct: TODO review & test later
			if (forcePasswordChangeValue != null && forcePasswordChangeValue) {
				List<Modification> modificationsPwdLastSet = new ArrayList<Modification>();
				AttributeDelta attrPwdLastSetDelta = AttributeDeltaBuilder.build(AdConstants.ATTRIBUTE_PWD_LAST_SET_NAME, "0");					
				addAttributeModification(dn, modificationsPwdLastSet, ldapStructuralObjectClass, connIdObjectClass, attrPwdLastSetDelta);
				modify(dn, modificationsPwdLastSet);
			}
		} else if (getConfiguration().isForcePasswordChangeAtNextLogon() && isUserPasswordChanged(deltas, ldapStructuralObjectClass)) {
			List<Modification> modificationsPwdLastSet = new ArrayList<Modification>();
			AttributeDelta attrPwdLastSetDelta = AttributeDeltaBuilder.build(AdConstants.ATTRIBUTE_PWD_LAST_SET_NAME, "0");					
			addAttributeModification(dn, modificationsPwdLastSet, ldapStructuralObjectClass, connIdObjectClass, attrPwdLastSetDelta);
			modify(dn, modificationsPwdLastSet);
		}
	}
	
	private boolean isUserPasswordChanged(Set<AttributeDelta> deltas, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass) {
		//if password is in modifications set pwdLastSet=0 ("must change password at next logon")
		if (getSchemaTranslator().isUserObjectClass(ldapStructuralObjectClass.getName())) {
			for (AttributeDelta delta: deltas) {
				// coming from midpoint password is __PASSWORD__
				// TODO: should we additionally ask for  icfAttr.getName().equals(getConfiguration().getPasswordAttribute()?
				if (OperationalAttributeInfos.PASSWORD.is(delta.getName())) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	protected void patchSchemaManager(SchemaManager schemaManager) {
		super.patchSchemaManager(schemaManager);
		if (!getConfiguration().isTweakSchema()) {
			return;
		}
		
		Registries registries = schemaManager.getRegistries();
		MatchingRuleRegistry matchingRuleRegistry = registries.getMatchingRuleRegistry();
		
		
		MatchingRule mrCaseIgnoreMatch = matchingRuleRegistry.get(SchemaConstants.CASE_IGNORE_MATCH_MR_OID);
		// Microsoft ignores matching rules. Completely. There is not even a single definition.
		if (mrCaseIgnoreMatch == null) {
			MutableMatchingRule correctMrCaseIgnoreMatch = new MutableMatchingRule(SchemaConstants.CASE_IGNORE_MATCH_MR_OID);
			correctMrCaseIgnoreMatch.setSyntaxOid(SchemaConstants.DIRECTORY_STRING_SYNTAX);
			Normalizer normalizer = new DeepTrimToLowerNormalizer(SchemaConstants.CASE_IGNORE_MATCH_MR_OID);
			correctMrCaseIgnoreMatch.setNormalizer(normalizer);
			LdapComparator<?> comparator = new NormalizingComparator(correctMrCaseIgnoreMatch.getOid(), normalizer, 
			    new StringComparator(correctMrCaseIgnoreMatch.getOid()));
			correctMrCaseIgnoreMatch.setLdapComparator(comparator);
			mrCaseIgnoreMatch = correctMrCaseIgnoreMatch;
			register(matchingRuleRegistry, correctMrCaseIgnoreMatch);
		}
		
		// Microsoft violates RFC4519
		fixAttribute(schemaManager, SchemaConstants.CN_AT_OID, SchemaConstants.CN_AT,
				createStringSyntax(SchemaConstants.DIRECTORY_STRING_SYNTAX), mrCaseIgnoreMatch);
		fixAttribute(schemaManager, SchemaConstants.DOMAIN_COMPONENT_AT_OID, SchemaConstants.DC_AT,
				createStringSyntax(SchemaConstants.DIRECTORY_STRING_SYNTAX), mrCaseIgnoreMatch);
		fixAttribute(schemaManager, SchemaConstants.OU_AT_OID, SchemaConstants.OU_AT,
				createStringSyntax(SchemaConstants.DIRECTORY_STRING_SYNTAX), mrCaseIgnoreMatch);
	}
	
	private LdapSyntax createStringSyntax(String syntaxOid) {
		LdapSyntax syntax = new LdapSyntax(syntaxOid);
		syntax.setHumanReadable(true);
		syntax.setSyntaxChecker(DirectoryStringSyntaxChecker.INSTANCE);
		return syntax;
	}

	private void fixAttribute(SchemaManager schemaManager, String attrOid, String attrName,
			LdapSyntax syntax, MatchingRule equalityMr) {
		Registries registries = schemaManager.getRegistries();
		AttributeTypeRegistry attributeTypeRegistry = registries.getAttributeTypeRegistry();
		ObjectClassRegistry objectClassRegistry = registries.getObjectClassRegistry();
		
		AttributeType attrDcType = attributeTypeRegistry.get(attrOid);
		if (attrDcType == null || attrDcType.getEquality() == null) {
			MutableAttributeType correctAttrDcType;
			if (attrDcType != null) {
				try {
					attributeTypeRegistry.unregister(attrDcType);
				} catch (LdapException e) {
					throw new IllegalStateException("Error unregistering "+attrDcType+": "+e.getMessage(), e);
				}
				correctAttrDcType = new MutableAttributeType(attrDcType.getOid());
				correctAttrDcType.setNames(attrDcType.getNames());
			} else {
				correctAttrDcType = new MutableAttributeType(attrOid);
				correctAttrDcType.setNames(attrName);
			}
			
			correctAttrDcType.setSyntax(syntax);
			correctAttrDcType.setEquality(equalityMr);
			correctAttrDcType.setSingleValued(true);
			LOG.ok("Registering replacement attributeType: {0}", correctAttrDcType);
			register(attributeTypeRegistry, correctAttrDcType);
			fixObjectClasses(objectClassRegistry, attrDcType, correctAttrDcType);
		}
		
	}
	
	private void fixObjectClasses(ObjectClassRegistry objectClassRegistry, AttributeType oldAttributeType, AttributeType newAttributeType) {
		for (ObjectClass objectClass: objectClassRegistry) {
			fixOblectClassAttributes(objectClass.getMayAttributeTypes(), oldAttributeType, newAttributeType);
			fixOblectClassAttributes(objectClass.getMustAttributeTypes(), oldAttributeType, newAttributeType);
		}
		
	}
	
	private void fixOblectClassAttributes(List<AttributeType> attributeTypes, AttributeType oldAttributeType, AttributeType newAttributeType) {
		for (int i = 0; i < attributeTypes.size(); i++) {
			AttributeType current = attributeTypes.get(i);
			if (current.equals(oldAttributeType)) {
				attributeTypes.set(i, newAttributeType);
				break;
			}
		}
	}

	private <T extends SchemaObject> void register(SchemaObjectRegistry<T> registry, T object) {
		try {
			registry.register(object);
		} catch (LdapException e) {
			throw new IllegalStateException("Error registering "+object+": "+e.getMessage(), e);
		}
	}
	
	@Override
	protected RuntimeException processLdapResult(String connectorMessage, LdapResult ldapResult) {
		if (ldapResult.getResultCode() == ResultCodeEnum.UNWILLING_TO_PERFORM) {
			WillNotPerform willNotPerform = WillNotPerform.parseDiagnosticMessage(ldapResult.getDiagnosticMessage());
			if (willNotPerform != null) {
				try {
					Class<? extends RuntimeException> exceptionClass = willNotPerform.getExceptionClass();
					Constructor<? extends RuntimeException> exceptionConstructor;
					exceptionConstructor = exceptionClass.getConstructor(String.class);
					String exceptionMessage = LdapUtil.sanitizeString(ldapResult.getDiagnosticMessage()) + ": " + willNotPerform.name() + ": " + willNotPerform.getMessage();
					RuntimeException exception = exceptionConstructor.newInstance(exceptionMessage);
					LdapUtil.logOperationError(connectorMessage, ldapResult, exceptionMessage);
					throw exception;
				} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
					LOG.error("Error during LDAP error handling: {0}: {1}", e.getClass(), e.getMessage(), e);
					// fallback
					return LdapUtil.processLdapResult(connectorMessage, ldapResult);
				}
			}

		}
		if (ldapResult.getResultCode() == ResultCodeEnum.OTHER) {
			RuntimeException otherExpression = processOtherError(connectorMessage, ldapResult.getDiagnosticMessage(), ldapResult, null);
			if (otherExpression != null) {
				return otherExpression;
			}
		}
		return LdapUtil.processLdapResult(connectorMessage, ldapResult);
	}
	
	@Override
	protected RuntimeException processLdapException(String connectorMessage, LdapException ldapException) {
		if (ldapException instanceof LdapOtherException) {
			RuntimeException otherExpression = processOtherError(connectorMessage, ldapException.getMessage(), null, (LdapOtherException) ldapException);
			if (otherExpression != null) {
				return otherExpression;
			}
		}
		return super.processLdapException(connectorMessage, ldapException);
	}

	
	/**
	 * This is category of errors that we do not know anything just a string error message.
	 * And we have to figure out what is going on just from the message.
	 */
	private RuntimeException processOtherError(String connectorMessage, String diagnosticMessage, LdapResult ldapResult, LdapOperationException ldapException) {
		WindowsErrorCode errorCode = WindowsErrorCode.parseDiagnosticMessage(diagnosticMessage);
		if (errorCode == null) {
			return null;
		}
		try {
			Class<? extends RuntimeException> exceptionClass = errorCode.getExceptionClass();
			Constructor<? extends RuntimeException> exceptionConstructor;
			exceptionConstructor = exceptionClass.getConstructor(String.class);
			String exceptionMessage = LdapUtil.sanitizeString(diagnosticMessage) + ": " + errorCode.name() + ": " + errorCode.getMessage();
			RuntimeException exception = exceptionConstructor.newInstance(exceptionMessage);
			if (ldapResult != null) {
				LdapUtil.logOperationError(connectorMessage, ldapResult, exceptionMessage);
			} else {
				LdapUtil.logOperationError(connectorMessage, ldapException, exceptionMessage);
			}
			return exception;
		} catch (NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {
			LOG.error("Error during LDAP error handling: {0}: {1}", e.getClass(), e.getMessage(), e);
			// fallback
			return null;
		}
	}

	// SCRIPTING
	// All of this will eventually go to a separate connector
	
	@Override
	public Object runScriptOnResource(ScriptContext scriptCtx, OperationOptions options) {
		String scriptLanguage = scriptCtx.getScriptLanguage();
		PowerHell powerHell = getPowerHell(scriptLanguage);
		
		String command = scriptCtx.getScriptText();
		OperationLog.log("{0} Script REQ {1}: {2}", winRmHost, scriptLanguage, command);
		LOG.ok("Executing {0} script on {0} as {1} using {2}: {3}", scriptLanguage, winRmHost, winRmUsername, powerHell.getImplementationName(), command);
		
		String output;
		try {
			
			output = powerHell.runCommand(command, scriptCtx.getScriptArguments());
			
		} catch (PowerHellException e) {
			OperationLog.error("{0} Script ERR {1}", winRmHost, e.getMessage());
			throw new ConnectorException("Script execution failed: "+e.getMessage(), e);
		}
					
		OperationLog.log("{0} Script RES {1}", winRmHost, (output==null||output.isEmpty())?"no output":("output "+output.length()+" chars"));
		LOG.ok("Script returned output\n{0}", output);
		
		return output;
	}
	
	private PowerHell getPowerHell(String scriptLanguage) {
		if (scriptLanguage == null) {
			throw new IllegalArgumentException("Script language not specified");
		}
		PowerHell powerHell = powerHellMap.get(scriptLanguage);
		if (powerHell == null) {
			powerHell = createPowerHell(scriptLanguage);
			try {
				powerHell.connect();
			} catch (PowerHellExecutionException e) {
				throw new ConnectorException("Cannot connect PowerHell "+powerHell.getImplementationName()+": "+e.getMessage(), e);
			} catch (PowerHellSecurityException e) {
				throw new ConnectorSecurityException("Cannot connect PowerHell "+powerHell.getImplementationName()+": "+e.getMessage(), e);
			} catch (PowerHellCommunicationException e) {
				throw new ConnectorIOException("Cannot connect PowerHell "+powerHell.getImplementationName()+": "+e.getMessage(), e);
			}
			powerHellMap.put(scriptLanguage, powerHell);
		}
		return powerHell;
	}
	
	private PowerHell createPowerHell(String scriptLanguage) {
		if (!isWinRmInitialized) {
			initWinRm();
		}
		PowerHell powerHell;
		switch (scriptLanguage) {
			case AdLdapConfiguration.SCRIPT_LANGUAGE_CMD:
				powerHell = createCmdPowerHell();
				break;
			case AdLdapConfiguration.SCRIPT_LANGUAGE_POWERSHELL:
				powerHell = createPowershellPowerHell();
				break;
			case AdLdapConfiguration.SCRIPT_LANGUAGE_EXCHANGE:
				powerHell = createLoopPowerHell(EXCHANGE_INIT_SCRIPT);
				break;
			case AdLdapConfiguration.SCRIPT_LANGUAGE_POWERHELL:
				powerHell = createLoopPowerHell(null);
				break;
			default:
				throw new IllegalArgumentException("Unknown script language "+scriptLanguage);
		}
		LOG.ok("Initialized PowerHell {0} ({1}) for language {2}", powerHell.getImplementationName(), powerHell.getClass().getSimpleName(), scriptLanguage);
		return powerHell;
	}
	
	private PowerHell createCmdPowerHell() {
		if (isScriptingWinRm()) {
			PowerHellWinRmExecImpl powerHell = new PowerHellWinRmExecImpl();
			setWinRmParameters(powerHell);
			return powerHell;
		} else if (isScriptingLocal()) {
			PowerHellLocalExecImpl powerHell = new PowerHellLocalExecImpl();
			setLocalParameters(powerHell);
			return powerHell;
		} else {
			throw new IllegalArgumentException("Unknown scripting execution mechanism "+getConfiguration().getScriptExecutionMechanism());
		}
	}
	
	private PowerHell createPowershellPowerHell() {
		if (isScriptingWinRm()) {
			PowerHellWinRmExecPowerShellImpl powerHell = new PowerHellWinRmExecPowerShellImpl();
			setWinRmParameters(powerHell);
			return powerHell;
		} else if (isScriptingLocal()) {
			PowerHellLocalExecPowerShellImpl powerHell = new PowerHellLocalExecPowerShellImpl();
			setLocalParameters(powerHell);
			return powerHell;
		} else {
			throw new IllegalArgumentException("Unknown scripting execution mechanism "+getConfiguration().getScriptExecutionMechanism());
		}
	}

	private PowerHell createLoopPowerHell(String initSctip) {
		if (isScriptingWinRm()) {
			PowerHellWinRmLoopImpl powerHell = new PowerHellWinRmLoopImpl();
			setWinRmParameters(powerHell);
			powerHell.setInitScriptlet(initSctip);
			return powerHell;
		} else if (isScriptingLocal()) {
			throw new UnsupportedOperationException("PowerHell loop is not supported for local script execution mechanism");
		} else {
			throw new IllegalArgumentException("Unknown scripting execution mechanism "+getConfiguration().getScriptExecutionMechanism());
		}
	}

	private boolean isScriptingWinRm() {
		return getConfiguration().getScriptExecutionMechanism() == null || AdLdapConfiguration.SCRIPT_EXECUTION_MECHANISM_WINRM.equals(getConfiguration().getScriptExecutionMechanism());
	}

	private boolean isScriptingLocal() {
		return AdLdapConfiguration.SCRIPT_EXECUTION_MECHANISM_LOCAL.equals(getConfiguration().getScriptExecutionMechanism());
	}
	
	private void setWinRmParameters(AbstractPowerHellWinRmImpl powerHell) {
		setCommonParameters(powerHell);
		String winRmDomain = getConfiguration().getWinRmDomain();
		powerHell.setDomainName(winRmDomain);
		powerHell.setEndpointUrl(getWinRmEndpointUrl());
		powerHell.setUserName(winRmUsername);
		powerHell.setPassword(getWinRmPassword());
		powerHell.setAuthenticationScheme(getAuthenticationScheme());
		powerHell.setHostnameVerifier(hostnameVerifier);
	}
	
	private void setLocalParameters(PowerHellLocalExecImpl powerHell) {
		setCommonParameters(powerHell);
	}
	
	private void setCommonParameters(AbstractPowerHellImpl powerHell) {
		powerHell.setArgumentStyle(getArgumentStyle());
	}

	private ArgumentStyle getArgumentStyle() {
		if (getConfiguration().getPowershellArgumentStyle() == null) {
			return ArgumentStyle.PARAMETERS_DASH;
		}
		switch (getConfiguration().getPowershellArgumentStyle()) {
			case AdLdapConfiguration.ARGUMENT_STYLE_DASHED:
				return ArgumentStyle.PARAMETERS_DASH;
			case AdLdapConfiguration.ARGUMENT_STYLE_SLASHED:
				return ArgumentStyle.PARAMETERS_SLASH;
			case AdLdapConfiguration.ARGUMENT_STYLE_VARIABLES:
				return ArgumentStyle.VARIABLES;
			default:
				throw new IllegalArgumentException("Unknown argument style "+getConfiguration().getPowershellArgumentStyle());
		}
	}

	private String getAuthenticationScheme() {
		if (getConfiguration().getWinRmAuthenticationScheme() == null) {
			return AuthSchemes.NTLM;
		}
		if (AdLdapConfiguration.WINDOWS_AUTHENTICATION_SCHEME_BASIC.equals(getConfiguration().getWinRmAuthenticationScheme())) {
			return AuthSchemes.BASIC;
		}
		if (AdLdapConfiguration.WINDOWS_AUTHENTICATION_SCHEME_NTLM.equals(getConfiguration().getWinRmAuthenticationScheme())) {
			return AuthSchemes.NTLM;
		}
		if (AdLdapConfiguration.WINDOWS_AUTHENTICATION_SCHEME_CREDSSP.equals(getConfiguration().getWinRmAuthenticationScheme())) {
			return AuthSchemes.CREDSSP;
		}
		throw new ConfigurationException("Unknown authentication scheme: "+getConfiguration().getWinRmAuthenticationScheme());
	}
	
	private void initWinRm() {
		if (!busInitialized) {
			initBus();
			busInitialized = true;
		}
		winRmUsername = getWinRmUsername();
		winRmHost = getWinRmHost();
		hostnameVerifier = new DefaultHostnameVerifier(null);
		isWinRmInitialized = true;
	}


	private boolean isScriptingExplicitlyConfigured() {
		if (getConfiguration().getScriptExecutionMechanism() != null) {
			return true;
		}
		if (getConfiguration().getWinRmUsername() != null) {
			return true;
		}
		if (getConfiguration().getWinRmPassword() != null) {
			return true;
		}
		if (getConfiguration().getWinRmDomain() != null) {
			return true;
		}
		if (getConfiguration().getWinRmAuthenticationScheme() != null) {
			return true;
		}
		return false;
	}
	
	
	
	private void pingScripting() {
		String command = PING_COMMAND;
		PowerHell powerHell = getPowerHell(AdLdapConfiguration.SCRIPT_LANGUAGE_CMD);
		
		OperationLog.log("{0} Script REQ ping cmd: {1}", winRmHost, command);
		LOG.ok("Executing ping cmd script on {0} as {1}: {2}", winRmHost, winRmUsername, command);
		
		try {
			
			String output = powerHell.runCommand(PING_COMMAND, null);

			OperationLog.log("{0} Script RES ping: {1}", winRmHost, output);
		
		} catch (PowerHellExecutionException e) {
			OperationLog.error("{0} Script ERR ping status={1}: {2}", winRmHost, e.getExitCode(), e.getMessage());
			LOG.error("Script ping error, exit status = {0}\nOUT:\n{1}\nERR:\n{2}", e.getExitCode(), e.getStdout(), e.getStderr());
			throw new ConnectorException("Ping script execution failed (status code "+e.getExitCode()+"): "+e.getMessage(), e);
		} catch (PowerHellSecurityException | PowerHellCommunicationException e) {
			OperationLog.error("{0} Script ERR ping: {2}", winRmHost, e.getMessage());
			throw new ConnectorException("Ping script execution failed: "+e.getMessage(), e);
		}
	}

	private void cleanupScriptingBeforeTest() {
		for (Map.Entry<String,PowerHell> entry: powerHellMap.entrySet()) {
			entry.getValue().disconnect();
		}
		powerHellMap.clear();
		winRmUsername = null;
		winRmHost = null;
		hostnameVerifier = null;
		isWinRmInitialized = false;
	}

	
	private void disposeScripting() {
		for (Map.Entry<String,PowerHell> entry: powerHellMap.entrySet()) {
			entry.getValue().disconnect();
		}
		if (busInitialized) {
			disposeBus();
			busInitialized = false;
		}
	} 

	/*
	 * Init and dispose methods for the CXF bus. These are based on static usage
	 * counter and static default bus. Which means that the bus will be reused by
	 * all the connector instances (even those that have different configuration).
	 * But as  WinRmTool tool creates new WinRmClient for each invocation which 
	 * in turn creates a new CXF service then this approach should be safe.
	 * This is the best that we can do as ConnId does not provide any
	 * connector context that we could use to store per-resource bus instance.
	 */
	private static synchronized void initBus() {
		busUsageCount++;
		LOG.ok("bus init (usage count = {0})", busUsageCount);
		// make sure that the bus is created here while we are synchronized
		BusFactory.getDefaultBus(true);
	}

	private static synchronized void disposeBus() {
		busUsageCount--;
		LOG.ok("bus dispose (usage count = {0})", busUsageCount);
		if (busUsageCount == 0) {
			Bus bus = BusFactory.getDefaultBus(false);
			if (bus != null) {
				LOG.ok("Shutting down WinRm CXF bus {0}", bus);
				bus.shutdown(true);
				LOG.ok("Bus shut down");
			}
		}
	}

	private String getWinRmHost() {
		if (getConfiguration().getWinRmHost() != null) {
			return getConfiguration().getWinRmHost();
		}
		return getConfiguration().getHost();
	}

	private String getWinRmUsername() {
		if (getConfiguration().getWinRmUsername() != null) {
			return getConfiguration().getWinRmUsername();
		}
		return getConfiguration().getBindDn();
	}
	
	private String getWinRmPassword() {
		GuardedString winRmPassword = getConfiguration().getWinRmPassword();
		if (winRmPassword == null) {
			winRmPassword = getConfiguration().getBindPassword();
		}
		if (winRmPassword == null) {
			return null;
		}
		GuardedStringAccessor accessor = new GuardedStringAccessor();
		winRmPassword.access(accessor);
		return new String(accessor.getClearChars());
	}

	

	private String getWinRmEndpointUrl() {
		StringBuilder sb = new StringBuilder();
		if (getConfiguration().isWinRmUseHttps()) {
			sb.append("https://");
		} else {
			sb.append("http://");
		}
		sb.append(winRmHost).append(":").append(getConfiguration().getWinRmPort());
		sb.append("/wsman");
		return sb.toString();
	}
	
}

/*
 * Copyright (c) 2015-2017 Evolveum
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
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.LdapSyntax;
import org.apache.directory.api.ldap.model.schema.MatchingRule;
import org.apache.directory.api.ldap.model.schema.MutableAttributeType;
import org.apache.directory.api.ldap.model.schema.MutableMatchingRule;
import org.apache.directory.api.ldap.model.schema.ObjectClass;
import org.apache.directory.api.ldap.model.schema.SchemaManager;
import org.apache.directory.api.ldap.model.schema.SchemaObject;
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
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributeInfos;
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

import io.cloudsoft.winrm4j.winrm.WinRmTool;
import io.cloudsoft.winrm4j.winrm.WinRmToolResponse;

import org.apache.cxf.Bus;
import org.apache.cxf.BusFactory;
import org.apache.cxf.transport.https.httpclient.DefaultHostnameVerifier;

@ConnectorClass(displayNameKey = "connector.ldap.ad.display", configurationClass = AdLdapConfiguration.class)
public class AdLdapConnector extends AbstractLdapConnector<AdLdapConfiguration> implements ScriptOnResourceOp {

    private static final Log LOG = Log.getLog(AdLdapConnector.class);
    
    private GlobalCatalogConnectionManager globalCatalogConnectionManager;
    private String winRmUsername;
    private String winRmHost;
    private WinRmTool winRmTool;
    private HostnameVerifier hostnameVerifier;
    private PowerHell powerHell;
    private PowerHell exchangePowerHell;
    
    private static int busUsageCount = 0;

	@Override
	public void init(Configuration configuration) {
		super.init(configuration);
		globalCatalogConnectionManager = new GlobalCatalogConnectionManager(getConfiguration());
		
		initWinRm();
	}
	
	@Override
    public void dispose() {
		super.dispose();
		disposePowerHell();
		disposeWinRm();
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
	protected SearchStrategy<AdLdapConfiguration> searchByUid(Uid uid, org.identityconnectors.framework.common.objects.ObjectClass objectClass,
			ObjectClass ldapObjectClass, final ResultsHandler handler, OperationOptions options) {
		final String uidValue = SchemaUtil.getSingleStringNonBlankValue(uid);
		
		// Trivial (but not really realistic) case: UID is DN
		
		if (LdapUtil.isDnAttribute(getConfiguration().getUidAttribute())) {
			
			return searchByDn(getSchemaTranslator().toDn(uidValue), objectClass, ldapObjectClass, handler, options);
		
		}
			
		// First attempt: name hint (last seen DN)
		
		if (uid.getNameHint() != null) {
			// We have name hint here. Name hint is the DN of the entry as we have seen it last time. 
			// If the entry haven't moved since the last read then this is the most efficient way to
			// read the entry. However, we need to check if the GUID matches before returning the entry
			// to the primary handler. The original object may be moved and a new object might take its
			// DN while we were not watching.
			
			final String lastDn = uid.getNameHintValue();
			LOG.ok("We have name hint {0} for GUID {1}, trying to use it",
					lastDn, uidValue);
			
			final boolean[] found = new boolean[1];
			found[0] = false;
			
			ResultsHandler checkingHandler = new ResultsHandler() {
				@Override
				public boolean handle(ConnectorObject connectorObject) {
					String foundUidValue = connectorObject.getUid().getUidValue();
					if (foundUidValue.equals(uidValue)) {
						found[0] = true;
						LOG.ok("Use of name hint {0} for GUID {1} successful.", lastDn, uidValue);
						return handler.handle(connectorObject);
					} else {
						LOG.ok("Attempt to use name hint {0} for GUID {1} produced a different GUID: {2}, ignoring it.",
								lastDn, uidValue, foundUidValue);
						return true;
					}
				}
			};
			
			SearchStrategy<AdLdapConfiguration> nameHintSearchStrategy = searchByDn(
					getSchemaTranslator().toDn(lastDn), objectClass, ldapObjectClass, checkingHandler, options);
			
			if (found[0]) {
				return nameHintSearchStrategy;
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
			// Try to use name hint first. Let's read the entry using the name hint and check the GUID.
			// It is the same overhead as reading global catalog and usually there is a better chance that
			// this is going to work. Global catalog updates are quite lazy.
			
			String dnHintString = uid.getNameHintValue();
			Dn dnHint = getSchemaTranslator().toDn(dnHintString);
			LOG.ok("Resolvig DN by using name hint {0}", dnHint);
			Entry entry = searchSingleEntry(getConnectionManager(), dnHint, LdapUtil.createAllSearchFilter(), SearchScope.OBJECT, 
					new String[]{ AdLdapConfiguration.ATTRIBUTE_OBJECT_GUID_NAME }, 
					"LDAP entry for DN hint "+uid.getUidValue());
			if (entry != null) {
				String foundGuid = getSchemaTranslator().getGuidAsDashedString(entry);
				if (guid.equals(foundGuid)) {
					LOG.ok("Resolved DN for name hint {0} returned object with GUID matched ({1})",
							dnHintString, foundGuid);
					return entry.getDn();
				} else {
					LOG.ok("Resolvig DN for name hint {0} returned object with GUID mismatch (expected {1}, was {2})",
							dnHintString, guid, foundGuid);
				}
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
	
	private void initWinRm() {
		initBus();
		winRmUsername = getWinRmUsername();
		winRmHost = getWinRmHost();
		String winRmDomain = getConfiguration().getWinRmDomain();
		WinRmTool.Builder builder = WinRmTool.Builder.builder(winRmHost, 
				winRmDomain, winRmUsername, getWinRmPassword());
		builder.setAuthenticationScheme(getAuthenticationScheme());
		builder.port(getConfiguration().getWinRmPort());
		builder.useHttps(getConfiguration().isWinRmUseHttps());
		// No suffix matcher here. The suffix matcher is problematic. E.g. it will
		// cause mismatch between chimera.ad.evolveum.com and chimera.ad.evolveum.com
		hostnameVerifier = new DefaultHostnameVerifier(null);
		builder.hostnameVerifier(hostnameVerifier);
		winRmTool =  builder.build();
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

	private void disposePowerHell() {
		if (powerHell != null) {
			powerHell.disconnect();
		}
		if (exchangePowerHell != null) {
			exchangePowerHell.disconnect();
		}
	} 
	
	private void disposeWinRm() {
		disposeBus();
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

	@Override
	public Object runScriptOnResource(ScriptContext scriptCtx, OperationOptions options) {
		switch (scriptCtx.getScriptLanguage()) {
			case AdLdapConfiguration.SCRIPT_LANGUAGE_EXCHANGE:
			case AdLdapConfiguration.SCRIPT_LANGUAGE_POWERHELL:
				return runPowerHellScript(scriptCtx, options);
			default:
				return runWinRmToolScript(scriptCtx, options);
		}
	}
	
	private Object runWinRmToolScript(ScriptContext scriptCtx, OperationOptions options) {
		String scriptLanguage = scriptCtx.getScriptLanguage();
		WinRmToolResponse response;
		if (scriptLanguage == null || scriptLanguage.equals(AdLdapConfiguration.SCRIPT_LANGUAGE_POWERSHELL)) {
			String command = getScriptCommand(scriptCtx, getConfiguration().getPowershellArgumentStyle());
			OperationLog.log("{0} Script REQ powershell: {1}", winRmHost, command);
			LOG.ok("Executing powershell script on {0} as {1}: {2}", winRmHost, winRmUsername, command);
			response = winRmTool.executePs(command);
			
		} else if (scriptLanguage.equals(AdLdapConfiguration.SCRIPT_LANGUAGE_CMD)) {
			String command = getScriptCommand(scriptCtx, AdLdapConfiguration.ARGUMENT_STYLE_DASHED);
			OperationLog.log("{0} Script REQ cmd: {1}", winRmHost, command);
			LOG.ok("Executing cmd script on {0} as {1}: {2}", winRmHost, winRmUsername, command);
			response = winRmTool.executeCommand(command);
			
		} else {
			throw new IllegalArgumentException("Unknown script language '"+scriptLanguage+"'");
		}
		
		LOG.ok("Script returned status {0}\nSTDOUT:\n{1}\nSTDERR:\n{2}", response.getStatusCode(), response.getStdOut(), response.getStdErr());
		
		if (response.getStatusCode() == 0) {
			OperationLog.log("{0} Script RES status={1}", winRmHost, response.getStatusCode());
		} else {
			String errorMessage = getScriptError(response);
			OperationLog.error("{0} Script ERR status={1}: {2}", winRmHost, response.getStatusCode(), errorMessage);
			throw new ConnectorException("Script execution failed (status code "+response.getStatusCode()+"): "+errorMessage);
		}
		
		return response.getStdOut();
	}
	
	private Object runPowerHellScript(ScriptContext scriptCtx, OperationOptions options) {
		PowerHell powerHell;
		switch (scriptCtx.getScriptLanguage()) {
			case AdLdapConfiguration.SCRIPT_LANGUAGE_EXCHANGE:
				powerHell = getExchangePowerHell();
				break;
			case AdLdapConfiguration.SCRIPT_LANGUAGE_POWERHELL:
				powerHell = getPowerHell();
				break;
			default:
				throw new IllegalArgumentException("Unknown script language "+scriptCtx.getScriptLanguage());
		}
		
		String command = getScriptCommand(scriptCtx, getConfiguration().getPowershellArgumentStyle());
		
		OperationLog.log("{0} Script REQ exchange: {1}", winRmHost, command);
		LOG.ok("Executing exchange script on {0} as {1}: {2}", winRmHost, winRmUsername, command);
		
		String output;
		try {
			
			output = powerHell.runCommand(command);
			
		} catch (PowerHellExecutionException e) {
			OperationLog.error("{0} Script ERR {1}", winRmHost, e.getMessage());
			throw new ConnectorException("Script execution failed: "+e.getMessage(), e);
		}
					
		OperationLog.log("{0} Script RES {1}", winRmHost, (output==null||output.isEmpty())?"no output":("output "+output.length()+" chars"));
		LOG.ok("Script returned output\n{0}", output);
				
		return output;
	}

	private PowerHell getExchangePowerHell() {
		if (exchangePowerHell == null) {
			LOG.ok("Initializing exchange PowerHell");
			exchangePowerHell = initPowerHell("Add-PSSnapin *Exchange*");
		}
		return exchangePowerHell;
	}
	
	private PowerHell getPowerHell() {
		if (powerHell == null) {
			LOG.ok("Initializing PowerHell");
			powerHell = initPowerHell(null);
		}
		return powerHell;
	}

	private PowerHell initPowerHell(String initiScriptlet) {
		PowerHell powerHell = new PowerHell();
		String winRmDomain = getConfiguration().getWinRmDomain();
		powerHell.setDomainName(winRmDomain);
		powerHell.setEndpointUrl(getWinRmEndpointUrl());
		powerHell.setUserName(winRmUsername);
		powerHell.setPassword(getWinRmPassword());
		powerHell.setAuthenticationScheme(getAuthenticationScheme());
		powerHell.setHostnameVerifier(hostnameVerifier);
		powerHell.setInitScriptlet(initiScriptlet);
		
		try {
			powerHell.connect();
		} catch (PowerHellExecutionException e) {
			throw new ConnectionFailedException("Cannot connect PowerHell: "+e.getMessage(), e);
		}
		
		return powerHell;
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

	private String getScriptCommand(ScriptContext scriptCtx, String argumentStyle) {
		Map<String, Object> scriptArguments = scriptCtx.getScriptArguments();
		if (scriptArguments == null || scriptArguments.isEmpty()) {
			scriptCtx.getScriptText();
		}
		StringBuilder cmdSb = new StringBuilder();
		if (AdLdapConfiguration.ARGUMENT_STYLE_VARIABLES.equals(argumentStyle)) {
		    if (scriptArguments != null) {
    			for (java.util.Map.Entry<String,Object> argEntry: scriptArguments.entrySet()) {
    				Object val = argEntry.getValue();
    				if (val != null) {
    					cmdSb.append("$");
    					cmdSb.append(argEntry.getKey());
    					cmdSb.append(" = ");
    					cmdSb.append(quoteSingle(argEntry.getValue()));
    					cmdSb.append("; ");
    				}
    			}
			}
		}
		cmdSb.append(scriptCtx.getScriptText());
		if (AdLdapConfiguration.ARGUMENT_STYLE_DASHED.equals(argumentStyle)) {
		    if (scriptArguments != null) {
    			for (java.util.Map.Entry<String,Object> argEntry: scriptArguments.entrySet()) {
    				cmdSb.append(" -");
    				cmdSb.append(argEntry.getKey());
    				cmdSb.append(" ");
    				cmdSb.append(argEntry.getValue());
    			}
		    }
		}
		return cmdSb.toString();
	}
	
	private String quoteSingle(Object value) {
		if (value == null) {
			return "";
		}
		return "'" + value.toString().replaceAll("'", "''") + "'";
	}

	private String getScriptError(WinRmToolResponse response) {
		String stdErr = response.getStdErr();
		if (stdErr == null) {
			return null;
		}
		return stdErr;
	}
	
	@Override
	protected void postUpdate(org.identityconnectors.framework.common.objects.ObjectClass icfObjectClass,
			Uid uid, Set<Attribute> values, OperationOptions options, ModificationOperation modOp, 
			Dn dn, org.apache.directory.api.ldap.model.schema.ObjectClass ldapStructuralObjectClass,
			List<Modification> modifications) {
		super.postUpdate(icfObjectClass, uid, values, options, modOp, dn, ldapStructuralObjectClass, modifications);
		
		if (getConfiguration().isForcePasswordChangeAtNextLogon()) {
			
			//if password is in modifications set pwdLastSet=0 ("must change password at next logon")
			if (getSchemaTranslator().isUserObjectClass(ldapStructuralObjectClass.getName())) {
				for (Attribute icfAttr: values) {
					
					// coming from midpoint password is __PASSWORD__
					// TODO: should we additionally ask for  icfAttr.getName().equals(getConfiguration().getPasswordAttribute()?
					if (OperationalAttributeInfos.PASSWORD.is(icfAttr.getName())){
						
							List<Modification> modificationsPwdLastSet = new ArrayList<Modification>();	
							Attribute attrPwdLastSet = AttributeBuilder.build(AdConstants.ATTRIBUTE_PWD_LAST_SET_NAME, "0");					
							addAttributeModification(dn, modificationsPwdLastSet, ldapStructuralObjectClass, icfObjectClass, attrPwdLastSet, ModificationOperation.REPLACE_ATTRIBUTE);
							modify(dn, modificationsPwdLastSet);
							break;
						}
				}
				
			}
		}
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
			correctMrCaseIgnoreMatch.setNormalizer(new DeepTrimToLowerNormalizer(SchemaConstants.CASE_IGNORE_MATCH_MR_OID));
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
		syntax.setSyntaxChecker(new DirectoryStringSyntaxChecker());
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
		    
}

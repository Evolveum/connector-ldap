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
import java.util.Map;
import java.util.Set;

import javax.net.ssl.HostnameVerifier;

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
import org.apache.http.client.config.AuthSchemes;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.ScriptContext;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.operations.ScriptOnResourceOp;

import com.evolveum.polygon.common.GuardedStringAccessor;
import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.AbstractLdapConnector;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.OperationLog;
import com.evolveum.polygon.connector.ldap.schema.LdapFilterTranslator;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;
import com.evolveum.polygon.connector.ldap.search.DefaultSearchStrategy;
import com.evolveum.polygon.connector.ldap.search.SearchStrategy;

import io.cloudsoft.winrm4j.winrm.WinRmTool;
import io.cloudsoft.winrm4j.winrm.WinRmToolResponse;

import org.apache.commons.lang.StringUtils;
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
	
	private void initWinRm() {
		initBus();
		winRmUsername = getWinRmUsername();
		winRmHost = getWinRmHost();
		WinRmTool.Builder builder = WinRmTool.Builder.builder(winRmHost, 
				winRmUsername, getWinRmPassword());
		builder.setAuthenticationScheme(AuthSchemes.NTLM);
		builder.port(getConfiguration().getWinRmPort());
		builder.useHttps(getConfiguration().isWinRmUseHttps());
		// No suffix matcher here. The suffix matcher is problematic. E.g. it will
		// cause mismatch between chimera.ad.evolveum.com and chimera.ad.evolveum.com
		HostnameVerifier hostnameVerifier = new DefaultHostnameVerifier(null);
		builder.hostnameVerifier(hostnameVerifier);
		winRmTool =  builder.build();
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
		
		OperationLog.log("{0} Script RES status={1}", winRmHost, response.getStatusCode());
		LOG.ok("Script returned status {0}\nSTDOUT:\n{1}\nSTDERR:\n{2}", response.getStatusCode(), response.getStdOut(), response.getStdErr());
		
		if (response.getStatusCode() != 0) {
			String errorMessage = getScriptError(response);
			throw new ConnectorException("Script execution failed (status code "+response.getStatusCode()+"): "+errorMessage);
		}
		
		return response.getStdOut();
	}

	private String getScriptCommand(ScriptContext scriptCtx, String argumentStyle) {
		Map<String, Object> scriptArguments = scriptCtx.getScriptArguments();
		if (scriptArguments == null || scriptArguments.isEmpty()) {
			scriptCtx.getScriptText();
		}
		StringBuilder cmdSb = new StringBuilder();
		if (AdLdapConfiguration.ARGUMENT_STYLE_VARIABLES.equals(argumentStyle)) {
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
		cmdSb.append(scriptCtx.getScriptText());
		if (AdLdapConfiguration.ARGUMENT_STYLE_DASHED.equals(argumentStyle)) {
			for (java.util.Map.Entry<String,Object> argEntry: scriptArguments.entrySet()) {
				cmdSb.append(" -");
				cmdSb.append(argEntry.getKey());
				cmdSb.append(" ");
				cmdSb.append(argEntry.getValue());
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
	
	    
}

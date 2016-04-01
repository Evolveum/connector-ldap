/**
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
package com.evolveum.polygon.connector.ldap.search;

import java.util.Map;

import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.message.controls.SortRequestControlImpl;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.Base64;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.QualifiedUid;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.SortKey;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.OperationLog;
import com.evolveum.polygon.connector.ldap.schema.AttributeHandler;
import com.evolveum.polygon.connector.ldap.schema.SchemaTranslator;

/**
 * @author Radovan Semancik
 *
 */
public abstract class SearchStrategy<C extends AbstractLdapConfiguration> {
	
	private static final Log LOG = Log.getLog(SearchStrategy.class);
	
	private ConnectionManager<C> connectionManager;
	private AbstractLdapConfiguration configuration;
	private SchemaTranslator<C> schemaTranslator;
	private ObjectClass objectClass;
	private org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass;
	private ResultsHandler handler;
	private OperationOptions options;
	private boolean isCompleteResultSet = true;
	private AttributeHandler attributeHandler;
	
	protected SearchStrategy(ConnectionManager<C> connectionManager, AbstractLdapConfiguration configuration,
			SchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			ResultsHandler handler, OperationOptions options) {
		super();
		this.connectionManager = connectionManager;
		this.configuration = configuration;
		this.schemaTranslator = schemaTranslator;
		this.objectClass = objectClass;
		this.ldapObjectClass = ldapObjectClass;
		this.handler = handler;
		this.options = options;
	}

	public ConnectionManager<C> getConnectionManager() {
		return connectionManager;
	}

	public AbstractLdapConfiguration getConfiguration() {
		return configuration;
	}
	
	public OperationOptions getOptions() {
		return options;
	}

	public SchemaTranslator getSchemaTranslator() {
		return schemaTranslator;
	}
	
	public ObjectClass getObjectClass() {
		return objectClass;
	}

	public org.apache.directory.api.ldap.model.schema.ObjectClass getLdapObjectClass() {
		return ldapObjectClass;
	}

	public abstract void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException;
	
	public int getRemainingPagedResults() {
		return -1;
	}
        
	public String getPagedResultsCookie() {
		return null;
	}
	
	public boolean isCompleteResultSet() {
		return isCompleteResultSet;
	}
	
	public void setCompleteResultSet(boolean isCompleteResultSet) {
		this.isCompleteResultSet = isCompleteResultSet;
	}

	public AttributeHandler getAttributeHandler() {
		return attributeHandler;
	}

	public void setAttributeHandler(AttributeHandler attributeHandler) {
		this.attributeHandler = attributeHandler;
	}

	public boolean allowPartialResults() {
		if (options == null) {
			return false;
		}
		return options.getAllowPartialResults() == Boolean.TRUE;
	}
	
	public boolean allowPartialAttributeValues() {
		if (options == null) {
			return false;
		}
		return options.getAllowPartialAttributeValues() == Boolean.TRUE;
	}
	
	protected int getDefaultPageSize() {
		return configuration.getPagingBlockSize();
	}
	
	protected void applyCommonConfiguration(SearchRequest req) {
		if (configuration.isReferralStrategyFollow()) {
			req.followReferrals();
		} else if (configuration.isReferralStrategyIgnore()) {
			req.ignoreReferrals();
		} else if (configuration.isReferralStrategyThrow()) {
			// nothing to do
		}
		req.setDerefAliases(AliasDerefMode.NEVER_DEREF_ALIASES);
	}
	
	protected SearchCursor executeSearch(LdapNetworkConnection connection, SearchRequest req) throws LdapException {
		if (req.getFilter() == null) {
			req.setFilter(LdapConfiguration.SEARCH_FILTER_ALL);
		}
		logSearchRequest(connection, req);
		SearchCursor searchCursor;
		try {
			searchCursor = connection.search(req);
		} catch (LdapReferralException e) {
			logSearchError(connection, e);
			String referralStrategy = configuration.getReferralStrategy();
			if (configuration.isReferralStrategyFollow()) {
				// This should not happen!
				throw new IllegalStateException("Got referral "+e.getReferralInfo()+" while not expecting it: "+e.getMessage(),e);
			} else if (configuration.isReferralStrategyIgnore()) {
				LOG.ok("Ignoring referral {0}", e.getReferralInfo());
				return null;
			} else if (configuration.isReferralStrategyThrow()) {
				throw e;
			} else {
				throw new ConfigurationException("Unknown value of referralStrategy configuration property: "+referralStrategy);
			}
		} catch (LdapException e) {
			logSearchError(connection, e);
			throw e;
		}
		return searchCursor;
	}
	
	protected void logSearchRequest(LdapNetworkConnection connection, SearchRequest req) {
		if (LOG.isOk()) {
			OperationLog.logOperationReq(connection, "Search REQ base={0}, filter={1}, scope={2}, attributes={3}, controls={4}",
					req.getBase(), req.getFilter(), req.getScope(), req.getAttributes(), LdapUtil.toShortString(req.getControls()));
		}
	}

	protected void logSearchResult(LdapNetworkConnection connection, Entry entry) {
		if (LOG.isOk()) {
			OperationLog.logOperationRes(connection, "Search RES {0}", entry);
		}
	}
	
	protected void logSearchResult(LdapNetworkConnection connection, String type, LdapResult ldapResult) {
		if (LOG.isOk()) {
			OperationLog.logOperationRes(connection, "Search RES {0}:\n{1}", type, ldapResult);
		}
	}

	protected void logSearchResult(LdapNetworkConnection connection, String type, LdapResult ldapResult, String extra) {
		if (LOG.isOk()) {
			OperationLog.logOperationRes(connection, "Search RES {0}: {1}\n{2}", type, extra, ldapResult);
		}
	}

	protected void logSearchError(LdapNetworkConnection connection, LdapException e) {
		OperationLog.logOperationErr(connection, "Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
	}
	
	protected boolean handleResult(LdapNetworkConnection connection, Entry entry) {
		return handler.handle(schemaTranslator.toIcfObject(connection, objectClass, entry, attributeHandler));
	}

	protected boolean hasSortOption() {
		return getOptions() != null && getOptions().getSortKeys() != null && getOptions().getSortKeys().length > 0;
	}
	
	protected SortRequest createSortControl(String defaultSortLdapAttribute, String defaultSortOrderingRule) {
		SortRequest sortReqControl = null;
		if (hasSortOption()) {
			sortReqControl = new SortRequestControlImpl();
			sortReqControl.setCritical(true);
			for (SortKey icfSortKey: getOptions().getSortKeys()) {
				AttributeType attributeType = getSchemaTranslator().toLdapAttribute(getLdapObjectClass(), icfSortKey.getField());
				String attributeTypeDesc = attributeType.getName();
				String matchingRuleId = attributeType.getOrderingOid();
				if (matchingRuleId == null) {
					matchingRuleId = defaultSortOrderingRule;
				}
				boolean reverseOrder = !icfSortKey.isAscendingOrder();
				org.apache.directory.api.ldap.model.message.controls.SortKey ldapSortKey = 
						new org.apache.directory.api.ldap.model.message.controls.SortKey(attributeTypeDesc, matchingRuleId, reverseOrder);
				sortReqControl.addSortKey(ldapSortKey);
			}
		} else if (defaultSortLdapAttribute != null) {
			sortReqControl = new SortRequestControlImpl();
			AttributeType attributeType = getSchemaTranslator().toLdapAttribute(getLdapObjectClass(), defaultSortLdapAttribute);
			String matchingRuleId = attributeType.getOrderingOid();
			if (matchingRuleId == null) {
				matchingRuleId = defaultSortOrderingRule;
			}
			org.apache.directory.api.ldap.model.message.controls.SortKey ldapSortKey = 
					new org.apache.directory.api.ldap.model.message.controls.SortKey(defaultSortLdapAttribute, matchingRuleId, false); 
			sortReqControl.addSortKey(ldapSortKey);
		}
		return sortReqControl;
	}
	
	protected LdapNetworkConnection getConnection(Dn base) {
		return connectionManager.getConnection(getEffectiveBase(base));
	}

	protected LdapNetworkConnection getConnection(Dn base, Referral referral) {
		return connectionManager.getConnection(getEffectiveBase(base), referral);
	}
	
	protected LdapNetworkConnection getConnectionReconnect(Dn base) {
		return connectionManager.getConnectionReconnect(getEffectiveBase(base));
	}
	
	private Dn getEffectiveBase(Dn origBase) {
		if (origBase.isSchemaAware()) {
			return origBase;
		} else {
			// Insanity such as <GUID=....>. No good using that to select
			// the connection. Try to use the container from options instead.
			if (options != null && options.getContainer() != null) {
				QualifiedUid containerQUid = options.getContainer();
				// HACK WARNING: this is a hack to overcome bad framework design.
				// Even though this has to be Uid, we interpret it as a DN.
				// The framework uses UID to identify everything. This is naive.
				// Strictly following the framework contract would mean to always
				// do two LDAP searches instead of one in this case.
				// So we deviate from the contract here. It is naughty, but it
				// is efficient.
				return schemaTranslator.toDn(containerQUid.getUid());
			} else {
				return origBase;
			}
		}
	}
}

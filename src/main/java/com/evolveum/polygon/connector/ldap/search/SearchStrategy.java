/**
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
package com.evolveum.polygon.connector.ldap.search;

import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapReferralException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import com.evolveum.polygon.connector.ldap.LdapConfiguration;
import com.evolveum.polygon.connector.ldap.SchemaTranslator;

/**
 * @author Radovan Semancik
 *
 */
public abstract class SearchStrategy {
	
	private static final Log LOG = Log.getLog(SearchStrategy.class);
	
	private LdapNetworkConnection connection;
	private LdapConfiguration configuration;
	private SchemaTranslator schemaTranslator;
	private ResultsHandler handler;
	
	protected SearchStrategy(LdapNetworkConnection connection, LdapConfiguration configuration,
			SchemaTranslator schemaTranslator, ResultsHandler handler) {
		super();
		this.connection = connection;
		this.configuration = configuration;
		this.schemaTranslator = schemaTranslator;
		this.handler = handler;
	}

	public LdapNetworkConnection getConnection() {
		return connection;
	}

	public LdapConfiguration getConfiguration() {
		return configuration;
	}

	public abstract void search(String baseDn, ExprNode filterNode, SearchScope scope, String[] attributes) throws LdapException;

	protected void applyCommonConfiguration(SearchRequest req) {
		String referralStrategy = configuration.getReferralStrategy();
		if (referralStrategy == null) {
			req.followReferrals();
		} else if (LdapConfiguration.REFERRAL_STRATEGY_FOLLOW.equals(referralStrategy)) {
			req.followReferrals();
		} else if (LdapConfiguration.REFERRAL_STRATEGY_IGNORE.equals(referralStrategy)) {
			req.ignoreReferrals();
		} else if (LdapConfiguration.REFERRAL_STRATEGY_THROW.equals(referralStrategy)) {
			// nothing to do
		} else {
			throw new ConfigurationException("Unknown value of referralStrategy configuration property: "+referralStrategy);
		}
	}
	
	protected SearchCursor executeSearch(SearchRequest req) throws LdapException {
		try {
			return connection.search(req);
		} catch (LdapReferralException e) {
			String referralStrategy = configuration.getReferralStrategy();
			if (referralStrategy == null) {
				// This should not happen!
				throw new IllegalStateException("Got referral exception while not expecting it: "+e.getMessage(),e);
			} else if (LdapConfiguration.REFERRAL_STRATEGY_FOLLOW.equals(referralStrategy)) {
				// This should not happen!
				throw new IllegalStateException("Got referral exception while not expecting it: "+e.getMessage(),e);
			} else if (LdapConfiguration.REFERRAL_STRATEGY_IGNORE.equals(referralStrategy)) {
				LOG.ok("Ignoring referral");
				return null;
			} else if (LdapConfiguration.REFERRAL_STRATEGY_THROW.equals(referralStrategy)) {
				throw e;
			} else {
				throw new ConfigurationException("Unknown value of referralStrategy configuration property: "+referralStrategy);
			}
		} catch (LdapException e) {
			throw e;
		}
	}
	
	protected void handleResult(Entry entry) {
		handler.handle(schemaTranslator.toIcfObject(entry));
	}

}

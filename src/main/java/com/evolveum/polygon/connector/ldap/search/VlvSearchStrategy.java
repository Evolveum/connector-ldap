/**
 * Copyright (c) 2014-2018 Evolveum
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

import java.util.Base64;
import java.util.List;

import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequestImpl;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResponse;
import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewResultCode;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Referral;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultDone;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.apache.directory.ldap.client.api.exception.LdapConnectionTimeOutException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.ResultsHandler;

import com.evolveum.polygon.connector.ldap.AbstractLdapConfiguration;
import com.evolveum.polygon.connector.ldap.ConnectionManager;
import com.evolveum.polygon.connector.ldap.LdapUtil;
import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class VlvSearchStrategy<C extends AbstractLdapConfiguration> extends SearchStrategy<C> {
	
	private static final Log LOG = Log.getLog(VlvSearchStrategy.class);
	
	private int lastListSize = -1;
	private byte[] cookie = null;
	
	public VlvSearchStrategy(ConnectionManager<C> connectionManager, AbstractLdapConfiguration configuration,
			AbstractSchemaTranslator<C> schemaTranslator, ObjectClass objectClass,
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, ResultsHandler handler,
			OperationOptions options) {
		super(connectionManager, configuration, schemaTranslator, objectClass, ldapObjectClass, handler, options);
	}

	/* (non-Javadoc)
	 * @see com.evolveum.polygon.connector.ldap.search.SearchStrategy#search(java.lang.String, org.apache.directory.api.ldap.model.filter.ExprNode, org.apache.directory.api.ldap.model.message.SearchScope, java.lang.String[])
	 */
	@Override
	public void search(Dn baseDn, ExprNode filterNode, SearchScope scope, String[] attributes)
			throws LdapException {
		
		
		boolean proceed = true;
		int index = 1;
        if (getOptions() != null && getOptions().getPagedResultsOffset() != null) {
        	if (getOptions().getPagedResultsOffset() < 1) {
        		throw new UnsupportedOperationException("Offset "+getOptions().getPagedResultsOffset()+" is not supported when VLV is used");
        	}
        	index = getOptions().getPagedResultsOffset();
        }
        Integer numberOfEntriesToReturn = null; // null means "as many as there are"
        if (getOptions() != null && getOptions().getPageSize() != null) {
        	numberOfEntriesToReturn = getOptions().getPageSize();
        }
        
        String vlvSortAttributeName = null;
        if (!hasSortOption()) {
        	// Do not even try to do this if there is explicit sort option. This saves times and avoid some failures.
	        String vlvSortAttributeConfig = getConfiguration().getVlvSortAttribute();
	        List<String> vlvSortAttributeCandidateList = LdapUtil.splitComma(vlvSortAttributeConfig);
	        vlvSortAttributeName = getSchemaTranslator().selectAttribute(getLdapObjectClass(), vlvSortAttributeCandidateList);
	        if (vlvSortAttributeName == null) {
	        	throw new ConfigurationException("Cannot find appropriate sort attribute for object class "+getLdapObjectClass().getName()
	        			+", tried "+vlvSortAttributeCandidateList + " ("+vlvSortAttributeConfig+")");
	        }
        }
        SortRequest sortReqControl = createSortControl(vlvSortAttributeName, getConfiguration().getVlvSortOrderingRule());
        sortReqControl.setCritical(true);
                
        lastListSize = 0;
        cookie = null;
        if (getOptions() != null && getOptions().getPagedResultsCookie() != null) {
        	cookie = Base64.getDecoder().decode(getOptions().getPagedResultsCookie());
        }
		
        LdapNetworkConnection connection = getConnection(baseDn);
        Referral referral = null; // remember this in case we need a reconnect
        
        Dn lastResultDn = null;
        int numberOfResutlsReturned = 0;
        int retryAttempts = 0;
        OUTER: while (proceed) {
        	
        	SearchRequest req = new SearchRequestImpl();
    		req.setBase(baseDn);
    		req.setFilter(preProcessSearchFilter(filterNode));
    		req.setScope(scope);
    		applyCommonConfiguration(req);
    		if (attributes != null) {
    			req.addAttributes(attributes);
    		}
    		
    		if (sortReqControl != null) {
    			req.addControl(sortReqControl);
    		}
        	
    		// VLV
        	int afterCount = getDefaultPageSize() - 1;
        	if (numberOfEntriesToReturn != null && (numberOfResutlsReturned + afterCount + 1 > numberOfEntriesToReturn)) {
            	afterCount = numberOfEntriesToReturn - numberOfResutlsReturned - 1;
            }
        	VirtualListViewRequest vlvReqControl = new VirtualListViewRequestImpl();
        	vlvReqControl.setCritical(true);
        	vlvReqControl.setBeforeCount(0);
        	vlvReqControl.setAfterCount(afterCount);
			vlvReqControl.setOffset(index);
        	vlvReqControl.setContentCount(lastListSize);
        	vlvReqControl.setContextId(cookie);
        	req.addControl(vlvReqControl);
        	
        	int responseResultCount = 0;
        	SearchCursor searchCursor = executeSearch(connection, req);
    		try {
    			while (proceed) {
    				try {
						boolean hasNext = searchCursor.next();
						if (!hasNext) {
							break;
						}
					} catch (LdapConnectionTimeOutException | InvalidConnectionException e) {
						logSearchError(connection, e);
						// Server disconnected. And by some miracle this was not caught by
						// checkAlive or connection manager.
						retryAttempts++;
		    			if (retryAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
		    				// TODO: better exception. Maybe re-throw exception from the last error?
		    				throw new ConnectorIOException("Maximum reconnect number of attemps exceeded");
		    			}
						LOG.ok("Connection error ({0}), reconnecting", e.getMessage(), e);
						LdapUtil.closeCursor(searchCursor);
						connection = getConnectionReconnect(baseDn, referral);
						continue OUTER;
					}
    				Response response = searchCursor.get();
    				if (response instanceof SearchResultEntry) {
    					responseResultCount++;
    					Entry entry = ((SearchResultEntry)response).getEntry();
    			        logSearchResult(connection, entry);
    			        boolean overlap = false;
    			        if (lastResultDn != null) {
                            if (lastResultDn.equals(entry.getDn())) {
                            	LOG.warn("Working around rounding error overlap at index {0} (name={1})", index, lastResultDn);
                            	overlap = true;
                            }
                            lastResultDn = null;
    			        }
    			        if (!overlap) {
    			        	proceed = handleResult(connection, entry);
    			        	numberOfResutlsReturned++;
    			        }
    			        index++;
    			        if (!proceed) {
                        	LOG.ok("Ending search because handler returned false");
                        	break;
                        }
    			        lastResultDn = entry.getDn();
    			        
    				} else {
    			    	LOG.warn("Got unexpected response: {0}", response);
    			    }
    			}
    			
    			SearchResultDone searchResultDone = searchCursor.getSearchResultDone();
    			LdapUtil.closeCursor(searchCursor);
    			
    			if (searchResultDone == null) {
					break;
				} else {
    				LdapResult ldapResult = searchResultDone.getLdapResult();
			    	// process VLV response
			    	VirtualListViewResponse vlvResponseControl = (VirtualListViewResponse)searchResultDone.getControl(VirtualListViewResponse.OID);
			    	String extra = "no VLV response control";
			    	if (vlvResponseControl != null) {
			    		StringBuilder sb = new StringBuilder();
			    		sb.append("VLV targetPosition=");
			    		sb.append(vlvResponseControl.getTargetPosition());
			    		sb.append(", contentCount=");
			    		sb.append(vlvResponseControl.getContentCount());
			    		if (vlvResponseControl.getContextId() != null) {
			    			sb.append(", contextID=");
			    			byte[] contextId = vlvResponseControl.getContextId();
			    			if (contextId == null) {
			    				sb.append("null");
			    			} else {
			    				sb.append(Base64.getEncoder().encodeToString(vlvResponseControl.getContextId()));
			    			}
			    		}
			    		sb.append(", result=");
			    		if (vlvResponseControl.getVirtualListViewResult() == null) {
			    			sb.append("null");
			    		} else {
			    			sb.append(vlvResponseControl.getVirtualListViewResult().name());
			    			sb.append("(").append(vlvResponseControl.getVirtualListViewResult().getValue()).append(")");
			    		}
			    		extra = sb.toString();
			    		cookie = vlvResponseControl.getContextId();
			    		if (vlvResponseControl.getContentCount() == 0) {
			    			lastListSize = -1;
			    		} else {
			    			lastListSize = vlvResponseControl.getContentCount();
			    		}
			    		if (vlvResponseControl.getVirtualListViewResult() == VirtualListViewResultCode.OFFSETRANGEERROR 
			    				|| vlvResponseControl.getVirtualListViewResult() == VirtualListViewResultCode.OPENLDAP_RANGEERRROR) {
			    			// The offset is out of range. Do not indicate that as an error. Just return empty search results.
			    			LOG.ok("Ending search because VLV response indicated offset out of range (resultCode={0})", vlvResponseControl.getVirtualListViewResult().getValue());
                        	break;
			    		}
			    	} else {
			    		cookie = null;
			    		lastListSize = -1;
			    	}
			    	logSearchResult(connection, "Done", ldapResult, extra);
			    	
			    	if (ldapResult.getResultCode() == ResultCodeEnum.REFERRAL && !getConfiguration().isReferralStrategyThrow()) {
			    		referral = ldapResult.getReferral();
			    		if (getConfiguration().isReferralStrategyIgnore()) {
			    			LOG.ok("Ignoring referral {0}", referral);
			    		} else {
			    			LOG.ok("Following referral {0}", referral);
			    			retryAttempts++;
			    			if (retryAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
			    				// TODO: better exception. Maybe re-throw exception from the last error?
			    				throw new ConnectorIOException("Maximum number of attemps exceeded");
			    			}
			    			connection = getConnection(baseDn, referral);
			    			if (connection == null) {
			    				throw new ConnectorIOException("Cannot get connection based on referral "+referral);
			    			}
			    			lastListSize = 0;
			    	        cookie = null;
			    			continue;
			    		}
			    		
			    	} else if (ldapResult.getResultCode() == ResultCodeEnum.SUCCESS) {
			    		// continue the loop
			    		
			    	} else if (ldapResult.getResultCode() == ResultCodeEnum.BUSY) {
			    		// OpenLDAP gives this error when the server SSS/VLV resources are depleted. It looks like there is no
			    		// better way how to clean that up than to drop connection and reconnect.
			    		retryAttempts++;
		    			if (retryAttempts > getConfiguration().getMaximumNumberOfAttempts()) {
		    				// TODO: better exception. Maybe re-throw exception from the last error?
		    				throw new ConnectorIOException("Maximum number of attemps exceeded");
		    			}
			    		LOG.ok("Got BUSY response after VLV search. reconnecting and retrying");
			    		connection = getConnectionReconnect(baseDn);
			    		if (connection == null) {
		    				throw new ConnectorIOException("Cannot reconnect (baseDn="+baseDn+")");
		    			}
			    		lastListSize = 0;
		    	        cookie = null;
		    			continue;
			    		
			    	} else {
						String msg = "LDAP error during search in "+baseDn+": "+LdapUtil.formatLdapMessage(ldapResult);
						if (ldapResult.getResultCode() == ResultCodeEnum.SIZE_LIMIT_EXCEEDED && getOptions() != null && getOptions().getAllowPartialResults() != null && getOptions().getAllowPartialResults()) {
							LOG.ok("{0} (allowed error)", msg);
							setCompleteResultSet(false);
							break;
						} else {
							LOG.error("{0}", msg);
							throw LdapUtil.processLdapResult("LDAP error during search in "+baseDn, ldapResult);
						}
					}
			    	
    			}
    			
    			
    		} catch (CursorException e) {
    			// TODO: better error handling
    			throw new ConnectorIOException(e.getMessage(), e);
    		}

    		if (lastListSize > 0 && index > lastListSize) {
            	LOG.ok("Ending VLV search because index ({0}) went over list size ({1})", index, lastListSize);
                break;
            }
            if (numberOfEntriesToReturn != null && numberOfEntriesToReturn <= numberOfResutlsReturned) {
            	LOG.ok("Ending VLV search because enough entries already returned");
            	break;
            }
    		
			if (responseResultCount == 0) {
				LOG.warn("Ending VLV search because received no results");
				break;
			}

        }
        
        // TODO: close connection to purge the search state
	}

	@Override
	public int getRemainingPagedResults() {
		
		if (lastListSize < 0) {
			return lastListSize;
		}
		
		int offset = 0;
        if (getOptions() != null && getOptions().getPagedResultsOffset() != null) {
        	offset = getOptions().getPagedResultsOffset() - 1;
        }
		
		return lastListSize - offset - getNumberOfEntriesFound();
	}
        
    @Override
	public String getPagedResultsCookie() {
		if (cookie == null) {
			return null;
		}
		return Base64.getEncoder().encodeToString(cookie);
	}
}

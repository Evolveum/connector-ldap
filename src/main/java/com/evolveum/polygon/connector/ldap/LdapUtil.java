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
package com.evolveum.polygon.connector.ldap;

import java.io.IOException;
import java.text.ParseException;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Map;

import org.apache.directory.api.ldap.extras.controls.vlv.VirtualListViewRequest;
import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.CursorException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Value;
import org.apache.directory.api.ldap.model.exception.LdapAdminLimitExceededException;
import org.apache.directory.api.ldap.model.exception.LdapAffectMultipleDsaException;
import org.apache.directory.api.ldap.model.exception.LdapAliasDereferencingException;
import org.apache.directory.api.ldap.model.exception.LdapAliasException;
import org.apache.directory.api.ldap.model.exception.LdapAttributeInUseException;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationException;
import org.apache.directory.api.ldap.model.exception.LdapAuthenticationNotSupportedException;
import org.apache.directory.api.ldap.model.exception.LdapConfigurationException;
import org.apache.directory.api.ldap.model.exception.LdapContextNotEmptyException;
import org.apache.directory.api.ldap.model.exception.LdapEntryAlreadyExistsException;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeTypeException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidAttributeValueException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.exception.LdapInvalidSearchFilterException;
import org.apache.directory.api.ldap.model.exception.LdapLoopDetectedException;
import org.apache.directory.api.ldap.model.exception.LdapNoPermissionException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchAttributeException;
import org.apache.directory.api.ldap.model.exception.LdapNoSuchObjectException;
import org.apache.directory.api.ldap.model.exception.LdapOperationException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaException;
import org.apache.directory.api.ldap.model.exception.LdapSchemaViolationException;
import org.apache.directory.api.ldap.model.exception.LdapStrongAuthenticationRequiredException;
import org.apache.directory.api.ldap.model.exception.LdapUnwillingToPerformException;
import org.apache.directory.api.ldap.model.filter.AndNode;
import org.apache.directory.api.ldap.model.filter.EqualityNode;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.message.Control;
import org.apache.directory.api.ldap.model.message.LdapResult;
import org.apache.directory.api.ldap.model.message.Response;
import org.apache.directory.api.ldap.model.message.ResultCodeEnum;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.api.ldap.model.message.SearchRequestImpl;
import org.apache.directory.api.ldap.model.message.SearchResultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.message.controls.SortKey;
import org.apache.directory.api.ldap.model.message.controls.SortRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.util.GeneralizedTime;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.directory.ldap.client.api.exception.InvalidConnectionException;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.exceptions.ConnectionFailedException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorIOException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.Uid;

import com.evolveum.polygon.connector.ldap.schema.AbstractSchemaTranslator;

/**
 * @author semancik
 *
 */
public class LdapUtil {
	
	private static final Log LOG = Log.getLog(LdapUtil.class);
	
	public static boolean isDnAttribute(String attributeName) {
		return LdapConfiguration.PSEUDO_ATTRIBUTE_DN_NAME.equals(attributeName);
	}
	
	public static boolean isEntryUuidAttribute(String attributeName) {
		return SchemaConstants.ENTRY_UUID_AT.equalsIgnoreCase(attributeName) 
				|| LdapConstants.ATTRIBUTE_NSUNIQUEID_NAME.equalsIgnoreCase(attributeName);
	}

	public static String getStringAttribute(Entry entry, String attrName) {
		Attribute attribute = entry.get(attrName);
		if (attribute == null) {
			return null;
		}
		Value value = attribute.get();
		if (value == null) {
			return null;
		}
		return value.getValue();
	}
	
	public static Integer getIntegerAttribute(Entry entry, String attrName, Integer defaultVal) {
		String stringVal = getStringAttribute(entry, attrName);
		if (stringVal == null) {
			return defaultVal;
		}
		return Integer.parseInt(stringVal);
	}
	
	public static Boolean getBooleanAttribute(Entry entry, String attrName, Boolean defaultVal) {
		String stringVal = getStringAttribute(entry, attrName);
		if (stringVal == null) {
			return defaultVal;
		}
		if (stringVal.compareToIgnoreCase("true") == 0) {
			return Boolean.TRUE;
		}
		if (stringVal.compareToIgnoreCase("false") == 0) {
			return Boolean.FALSE;
		}
		throw new InvalidAttributeValueException("Invalid boolean value '"+stringVal+"' in attribute "+attrName+" of entry "+entry.getDn());
	}
	
	public static Long getTimestampAttribute(Entry entry, String attrName) {
		String stringVal = getStringAttribute(entry, attrName);
		if (stringVal == null) {
			return null;
		}
		GeneralizedTime gt;
		try {
			gt = new GeneralizedTime(stringVal);
		} catch (ParseException e) {
			throw new InvalidAttributeValueException("Invalid generalized time value '"+stringVal+"' in attribute "+attrName+" of entry "+entry.getDn()+": "+e.getMessage(), e);
		}
		return gt.getCalendar().getTimeInMillis();
	}
	
	public static String toGeneralizedTime(long millis, boolean fractionalPart) {
		GeneralizedTime gtime = new GeneralizedTime(new Date(millis));
		if (fractionalPart) {
			return gtime.toGeneralizedTime();
		} else {
			return gtime.toGeneralizedTimeWithoutFraction();
		}
	}

	public static String toGeneralizedTime(ZonedDateTime zdt, boolean fractionalPart) {
		// Maybe we can do a nicer and simpler time conversion?
		GregorianCalendar calendar = GregorianCalendar.from(zdt);
		GeneralizedTime gtime = new GeneralizedTime(calendar);
		if (fractionalPart) {
			return gtime.toGeneralizedTime();
		} else {
			return gtime.toGeneralizedTimeWithoutFraction();
		}
	}

	public static ZonedDateTime generalizedTimeStringToZonedDateTime(String generalizedTimeString) throws ParseException {
		// Maybe we can do a nicer and simpler time conversion?
		GeneralizedTime gt = new GeneralizedTime(generalizedTimeString);
		GregorianCalendar gcal;
		Calendar cal = gt.getCalendar();
		if (cal instanceof GregorianCalendar) {
			gcal = (GregorianCalendar) cal;
		} else {
			gcal = new GregorianCalendar();
			gcal.setTimeInMillis(cal.getTimeInMillis());
		}
		return gcal.toZonedDateTime();
	}

	
	public static Boolean toBoolean(String stringVal, Boolean defaultVal) {
		if (stringVal == null) {
			return defaultVal;
		}
		if (stringVal.compareToIgnoreCase("true") == 0) {
			return Boolean.TRUE;
		}
		if (stringVal.compareToIgnoreCase("false") == 0) {
			return Boolean.FALSE;
		}
		throw new InvalidAttributeValueException("Invalid boolean value '"+stringVal+"'");
	}
	
	public static String[] getAttributesToGet(org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			OperationOptions options, AbstractSchemaTranslator schemaTranslator, String... additionalAttributes) {
		String[] operationalAttributes = schemaTranslator.getOperationalAttributes();
		if (options == null || options.getAttributesToGet() == null) {
			String[] ldapAttrs = new String[2 + operationalAttributes.length + additionalAttributes.length];
			ldapAttrs[0] = "*";
			ldapAttrs[1] = schemaTranslator.getUidAttribute();
			int i = 2;
			for (String operationalAttribute: operationalAttributes) {
				ldapAttrs[i] = operationalAttribute;
				i++;
			}
			for (String additionalAttribute: additionalAttributes) {
				ldapAttrs[i] = additionalAttribute;
				i++;
			}
			return ldapAttrs;
		}
		String[] icfAttrs = options.getAttributesToGet();
		int extraAttrs = 2;
		if (options.getReturnDefaultAttributes() != null && options.getReturnDefaultAttributes()) {
			extraAttrs++;
		}
		List<String> ldapAttrs = new ArrayList<String>(icfAttrs.length + operationalAttributes.length + extraAttrs);
		if (options.getReturnDefaultAttributes() != null && options.getReturnDefaultAttributes()) {
			ldapAttrs.add("*");
		}
		for (String icfAttr: icfAttrs) {
			if (Name.NAME.equals(icfAttr)) {
				continue;
			}
			AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, icfAttr);
			if (ldapAttributeType == null) {
				// No definition for this attribute. It is most likely operational attribute that is not in the schema.
				if (isOperationalAttribute(schemaTranslator, icfAttr)) {
					ldapAttrs.add(icfAttr);
				} else {
					throw new InvalidAttributeValueException("Unknown attribute '"+icfAttr+"' (in attributesToGet)");
				}
			} else {
				ldapAttrs.add(ldapAttributeType.getName());
			}
		}
		for (String operationalAttribute: operationalAttributes) {
			ldapAttrs.add(operationalAttribute);
		}
		for (String additionalAttribute: additionalAttributes) {
			ldapAttrs.add(additionalAttribute);
		}
		ldapAttrs.add(schemaTranslator.getUidAttribute());
		ldapAttrs.add(SchemaConstants.OBJECT_CLASS_AT);
		return ldapAttrs.toArray(new String[ldapAttrs.size()]);
	}

	public static boolean isOperationalAttribute(AbstractSchemaTranslator schemaTranslator, String icfAttr) {
		String[] operationalAttributes = schemaTranslator.getOperationalAttributes();
		if (operationalAttributes == null) {
			return false;
		}
		for (String opAt: operationalAttributes) {
			if (opAt.equals(icfAttr)) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Fetch a single entry using its DN.
	 * 
	 * @param connection The LDAP connection to use
	 * @param dn The entry's DN
	 * @param ldapObjectClass The entry's ObjectClass
	 * @param options The options to use 
	 * @param schemaTranslator The Schema translator instance
	 * @return The found entry, or null if none is found.
	 */
	public static Entry fetchEntry(LdapNetworkConnection connection, String dn, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			OperationOptions options, AbstractSchemaTranslator schemaTranslator) {
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options, schemaTranslator);
		Entry entry = null;
		LOG.ok("Search REQ base={0}, filter={1}, scope={2}, attributes={3}", 
				dn, AbstractLdapConfiguration.SEARCH_FILTER_ALL, SearchScope.OBJECT, attributesToGet);
		
		try {
		    entry = connection.lookup( dn, attributesToGet );
		} catch (LdapException e) {
			LOG.error("Search ERR {0}: {1}", e.getClass().getName(), e.getMessage(), e);
			throw processLdapException("Search for "+dn+" failed", e);
		}
		
		LOG.ok("Search RES {0}", entry);
		
		return entry;
	}
	
	public static Entry fetchEntryByUid(LdapNetworkConnection connection, String uid, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, 
			OperationOptions options, AbstractLdapConfiguration configuration, AbstractSchemaTranslator schemaTranslator) {
		String[] attributesToGet = getAttributesToGet(ldapObjectClass, options, schemaTranslator);
		ExprNode filter = createUidSearchFilter(uid, ldapObjectClass, schemaTranslator);
		return searchSingleEntry(connection, configuration.getBaseContext(), SearchScope.SUBTREE, filter, attributesToGet);
	}
	
	public static Entry searchSingleEntry(LdapNetworkConnection connection, String baseDn, SearchScope scope,
			ExprNode filter, String[] attributesToGet) {
		SearchRequest req = new SearchRequestImpl();
		try {
			req.setBase(new Dn(baseDn));
		} catch (LdapInvalidDnException e) {
			throw new IllegalArgumentException(e.getMessage(), e);
		}
		req.setScope(scope);
		req.setFilter(filter);
		if (attributesToGet != null) {
			req.addAttributes(attributesToGet);
		}
		Entry entry = null;
		try {
			SearchCursor searchCursor = connection.search(req);
			while (searchCursor.next()) {
				Response response = searchCursor.get();
				if (response instanceof SearchResultEntry) {
					if (entry != null) {
						LOG.error("Search for {0} in {1} (scope {2}) returned more than one entry:\n{1}", 
								filter, baseDn, scope, searchCursor.get());
						throw new IllegalStateException("Search for "+filter+" in "+baseDn+" returned unexpected entries");
					}
					entry = ((SearchResultEntry)response).getEntry();
				}
			}
			closeCursor(searchCursor);
		} catch (LdapException e) {
			throw processLdapException("Search for "+filter+" in "+baseDn+" failed", e);
		} catch (CursorException e) {
			throw new ConnectorIOException("Search for "+filter+" in "+baseDn+" failed: "+e.getMessage(), e);
		}
		return entry;
	}
	
	public static ExprNode filterAnd(ExprNode f1, ExprNode f2) {
		if (f1 == null) {
			return f2;
		}
		if (f2 == null) {
			return f1;
		}
		if (f1 instanceof AndNode) {
			return filterAndOptimized((AndNode) f1, f2);
		}
		if (f2 instanceof AndNode) {
			return filterAndOptimized((AndNode) f2, f1);
		}
		return new AndNode(f1, f2);
	}
	
	private static ExprNode filterAndOptimized(AndNode f1, ExprNode f2) {
		List<ExprNode> subnodes = new ArrayList<>();
		subnodes.addAll(f1.getChildren());
		if (f2 instanceof AndNode) {
			subnodes.addAll(((AndNode) f2).getChildren());
		} else {
			subnodes.add(f2);
		}
		return new AndNode(subnodes);
	}
	
	public static ExprNode createObjectClassFilter(
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		return new EqualityNode<>(SchemaConstants.OBJECT_CLASS_AT, ldapObjectClass.getName());
	}
	
	public static boolean containsFilter(ExprNode filterNode, String attrName) {
		if (filterNode instanceof EqualityNode<?>) {
			return attrName.equalsIgnoreCase(((EqualityNode<?>)filterNode).getAttribute());
		} else if (filterNode instanceof PresenceNode) {
			return attrName.equalsIgnoreCase(((PresenceNode)filterNode).getAttribute());
		} else if (filterNode instanceof AndNode) {
			for (ExprNode subfilter: ((AndNode)filterNode).getChildren()) {
				if (containsFilter(subfilter, attrName)) {
					return true;
				}
			}
		}
		return false;
	}
	
	public static boolean containsObjectClassFilter(ExprNode filterNode) {
		return containsFilter(filterNode, SchemaConstants.OBJECT_CLASS_AT);
	}

	public static ExprNode createAllSearchFilter() {
		return new PresenceNode(SchemaConstants.OBJECT_CLASS_AT);
	}
	
	public static ExprNode createUidSearchFilter(String uidValue, 
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass, AbstractSchemaTranslator schemaTranslator) {
		AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, Uid.NAME);
		Value ldapValue = schemaTranslator.toLdapIdentifierValue(ldapAttributeType, uidValue);
		return new EqualityNode<>(ldapAttributeType, ldapValue);
	}

	public static String getUidValue(Entry entry, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass,
			AbstractLdapConfiguration configuration, AbstractSchemaTranslator schemaTranslator) {
		if (isDnAttribute(configuration.getUidAttribute())) {
			return entry.getDn().toString();
		}
		Attribute uidAttribute = entry.get(configuration.getUidAttribute());
		AttributeType ldapAttributeType = schemaTranslator.toLdapAttribute(ldapObjectClass, Uid.NAME);
		return schemaTranslator.toIcfIdentifierValue(uidAttribute.get(), uidAttribute.getUpId(), ldapAttributeType);
	}
	
	
	public static RuntimeException processLdapException(String connectorMessage, LdapException ldapException) {
		// AD returns non-printable chars in the message. Remove them, otherwise we will havve problems
		// displaying the message in upper layers
		String exceptionMessage = null;
		if (ldapException.getMessage() != null) {
			exceptionMessage = ldapException.getMessage().replaceAll("\\p{C}", "?");
		}
    	if (connectorMessage == null) {
    		connectorMessage = "";
    	} else {
    		connectorMessage = connectorMessage + ": ";
    	}
    	RuntimeException re;
		if (ldapException instanceof LdapEntryAlreadyExistsException) {
			re = new AlreadyExistsException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapSchemaViolationException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapStrongAuthenticationRequiredException) {
			re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAdminLimitExceededException) {
			re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAffectMultipleDsaException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAliasDereferencingException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAliasException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAttributeInUseException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAuthenticationException) {
			re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapAuthenticationNotSupportedException) {
			re = new ConnectorSecurityException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapConfigurationException) {
			re = new ConfigurationException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof InvalidConnectionException) {
			re = new ConnectionFailedException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapContextNotEmptyException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapInvalidAttributeTypeException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapInvalidAttributeValueException) {
			if (((LdapInvalidAttributeValueException)ldapException).getResultCode() == ResultCodeEnum.CONSTRAINT_VIOLATION) {
				// CONSTRAINT_VIOLATION is usually returned when uniqueness plugin is triggered
				re = new AlreadyExistsException(connectorMessage + exceptionMessage, ldapException);
			} else {
				re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
			}
		} else if (ldapException instanceof LdapInvalidDnException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapInvalidSearchFilterException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapLoopDetectedException) {
			re = new ConfigurationException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapNoPermissionException) {
			re = new PermissionDeniedException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapNoSuchAttributeException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapNoSuchObjectException) {
			re = new UnknownUidException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapSchemaException) {
			re = new ConfigurationException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapSchemaViolationException) {
			re = new InvalidAttributeValueException(connectorMessage + exceptionMessage, ldapException);
		} else if (ldapException instanceof LdapUnwillingToPerformException) {
			re = new PermissionDeniedException(connectorMessage + exceptionMessage, ldapException);
		} else {
			re = new ConnectorIOException(connectorMessage + exceptionMessage, ldapException);
		}
		if (LOG.isOk()) {
			if (ldapException instanceof LdapOperationException) {
				LOG.ok("Operation \"{0}\" ended with error ({1}: {2}): {3}", connectorMessage, 
						ldapException.getClass().getSimpleName(), 
						((LdapOperationException)ldapException).getResultCode().getResultCode(), 
						exceptionMessage);
			} else {
				LOG.ok("Operation \"{0}\" ended with error ({1}): {2}", connectorMessage, 
						ldapException.getClass().getSimpleName(), exceptionMessage);
			}
		}
		return re;
	}
	
	public static RuntimeException processLdapResult(String connectorMessage, LdapResult ldapResult) {
		ResultCodeEnum resultCode = ldapResult.getResultCode();
		RuntimeException re;
		switch (resultCode) {
		    case SUCCESS :
		        re = null;
		        break;
		        
		    case ENTRY_ALREADY_EXISTS:
		    case CONSTRAINT_VIOLATION:
	            // CONSTRAINT_VIOLATION is usually returned when uniqueness plugin is triggered
	            re =  new AlreadyExistsException(connectorMessage + ": " + formatLdapMessage(ldapResult));
	            break;
		        
            case OBJECT_CLASS_VIOLATION : 
            case NOT_ALLOWED_ON_RDN :
            case OBJECT_CLASS_MODS_PROHIBITED :
            case NOT_ALLOWED_ON_NON_LEAF :
            case AFFECTS_MULTIPLE_DSAS :
            case ALIAS_DEREFERENCING_PROBLEM :
            case ALIAS_PROBLEM :
            case ATTRIBUTE_OR_VALUE_EXISTS :
            case UNDEFINED_ATTRIBUTE_TYPE :
            case INVALID_ATTRIBUTE_SYNTAX :
            case INVALID_DN_SYNTAX :
            case NAMING_VIOLATION :
            case INAPPROPRIATE_MATCHING :
            case NO_SUCH_ATTRIBUTE :
                re =  new InvalidAttributeValueException(connectorMessage + ": " + formatLdapMessage(ldapResult));
                break;

            case STRONG_AUTH_REQUIRED :
            case ADMIN_LIMIT_EXCEEDED :
            case INVALID_CREDENTIALS :
            case INAPPROPRIATE_AUTHENTICATION :
            case CONFIDENTIALITY_REQUIRED :
            case AUTH_METHOD_NOT_SUPPORTED:
                re =  new ConnectorSecurityException(connectorMessage + ": " + formatLdapMessage(ldapResult));
                break;
                
            case OTHER :
            case LOOP_DETECT :
                re =  new ConfigurationException(connectorMessage + ": " + formatLdapMessage(ldapResult));
                break;
                
            case INSUFFICIENT_ACCESS_RIGHTS :
            case UNWILLING_TO_PERFORM :
            case SIZE_LIMIT_EXCEEDED :
            case TIME_LIMIT_EXCEEDED :
                re =  new PermissionDeniedException(connectorMessage + ": " + formatLdapMessage(ldapResult));
                break;
                
            case NO_SUCH_OBJECT :
                re =  new UnknownUidException(connectorMessage + ": " + formatLdapMessage(ldapResult));
                break;
                
            case PROTOCOL_ERROR :
    			// Do not classify this as IO exception. The IO exception often means network error and therefore it is
    			// the IDM will re-try. There is no point in re-try if there is a protocol error.
    			re =  new ConnectorException(connectorMessage + ": " + formatLdapMessage(ldapResult));
    			break;
    			
    		default :
    		    re =  new ConnectorIOException(connectorMessage + ": " + formatLdapMessage(ldapResult));
    		    break;
		}
		logOperationError(connectorMessage, ldapResult, null);
		return re;
	}
	
	public static void logOperationError(String message, LdapResult ldapResult, String additionalErrorMessage) {
		if (LOG.isOk()) {
			if (additionalErrorMessage != null) {
				LOG.ok("Operation \"{0}\" ended with error ({1}): {2}", message, ldapResult.getResultCode().getResultCode(), ldapResult.getDiagnosticMessage());
			} else {
				LOG.ok("Operation \"{0}\" ended with error ({1}): {2}: {3}", message, ldapResult.getResultCode().getResultCode(), ldapResult.getDiagnosticMessage(), additionalErrorMessage);
			}
		}		
	}
	
	public static void logOperationError(String message, LdapOperationException exception, String additionalErrorMessage) {
		if (LOG.isOk()) {
			if (additionalErrorMessage != null) {
				LOG.ok("Operation \"{0}\" ended with error ({1}): {2}", message, exception.getResultCode().getResultCode(), exception.getMessage());
			} else {
				LOG.ok("Operation \"{0}\" ended with error ({1}): {2}: {3}", message, exception.getResultCode().getResultCode(), exception.getMessage(), additionalErrorMessage);
			}
		}		
	}
	
	public static String formatLdapMessage(LdapResult ldapResult) {
		return sanitizeString(ldapResult.getResultCode().getMessage()) +
				": " + sanitizeString(ldapResult.getDiagnosticMessage()) + " ("+ ldapResult.getResultCode().getResultCode()+")";
	}
	
	public static String sanitizeString(String in) {
		return in.replaceAll("\\p{C}", "?");
	}

	public static Entry getRootDse(ConnectionManager<? extends AbstractLdapConfiguration> connectionManager, String... attributesToGet) {
		try {
			return connectionManager.getDefaultConnection().getRootDse(attributesToGet);
		} catch (LdapException e) {
			throw new ConnectorIOException("Error getting changelog data from root DSE: "+e.getMessage(), e);
		}
	}
	
	/**
	 * Check if a given ObjectClass is present in the entry.
	 * 
	 * @param entry The entry to check
	 * @param ldapObjectClass The objectClass to retrieve
	 * @return <tt>TRUE</tt> if the objectClass is part of the entry
	 */
	public static boolean isObjectClass(Entry entry, org.apache.directory.api.ldap.model.schema.ObjectClass ldapObjectClass) {
		if (ldapObjectClass == null) {
			return true;
		}
		
		// Should be :
	    // return entry.contains( SchemaConstants.OBJECT_CLASS_AT, ldapObjectClass.getName() );
		// but we can't be sure that the ObjectClass will be correctly cased... 
		// Looking at the directory API code it is not sure whether the object class would be
		// matched in a case-ignore way in all the cases. Butter keep this code for now.
		// It may be less efficient, but it looks like it is more reliable.
		Attribute objectClassAttribute = entry.get(SchemaConstants.OBJECT_CLASS_AT); 
		
		for (Value objectClassVal: objectClassAttribute) {
			if (ldapObjectClass.getName().equalsIgnoreCase(objectClassVal.getValue())) {
				return true;
			}
		}
		
		return false;
	}
	
	public static String binaryToHex(byte[] bytes) {
		if (bytes == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder(bytes.length * 2);
		for (byte b : bytes) {
			sb.append(String.format("%02x", b & 0xff));
		}
		return sb.toString();
	}

	public static byte[] hexToBinary(String hex) {
		int l = hex.length();
		byte[] bytes = new byte[l/2];
		for (int i = 0; i < l; i += 2) {
			bytes[i/2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) 
					+ Character.digit(hex.charAt(i + 1), 16));
		}
		return bytes;
	}
	
	public static boolean hasModifierName(Entry entry, String[] modifiersNamesToFilterOut) {
		org.apache.directory.api.ldap.model.entry.Attribute modifiersNameAttribute = entry.get(SchemaConstants.MODIFIERS_NAME_AT);
		if (modifiersNameAttribute == null) {
			return false;
		}
		for (Value modifiersNameVal: modifiersNameAttribute) {
			for (String modifiersNameToFilterOut: modifiersNamesToFilterOut) {
				if (modifiersNameToFilterOut.equals(modifiersNameVal.getValue())) {
					return true;
				}
			}
		}
		return false;
	}

	public static String formatConnectionInfo(LdapNetworkConnection connection) {
		StringBuilder sb = new StringBuilder();
		LdapConnectionConfig config = connection.getConfig();
		Integer port = null;
		if (config.isUseSsl()) {
			sb.append("ldaps://");
			if (config.getLdapPort() != 636) {
				port = config.getLdapPort();
			}
		} else {
			sb.append("ldap://");
			if (config.getLdapPort() != 389) {
				port = config.getLdapPort();
			}
		}
		sb.append(config.getLdapHost());
		if (port != null) {
			sb.append(":").append(port);
		}
		sb.append("/ ");
		return sb.toString();
	}
	
	public static List<String> splitComma(String configValue) {
		if (configValue == null) {
			return null;
		}
		String[] splits = configValue.split(",");
		List<String> list = new ArrayList<>(splits.length);
		for (String split: splits) {
			list.add(split.trim());
		}
		return list;
	}

	public static void closeCursor(SearchCursor cursor) {
		try {
			cursor.close();
		} catch (IOException e) {
			// Log the error, but otherwise ignore it. This is unlikely to cause
			// any serious harm for the operation.
			LOG.warn("Error closing the search cursor (continuing the operation anyway):", e);
		}
	}

	public static void closeCursor(EntryCursor cursor) {
		try {
			cursor.close();
		} catch (IOException e) {
			// Log the error, but otherwise ignore it. This is unlikely to cause
			// any serious harm for the operation.
			LOG.warn("Error closing the search cursor (continuing the operation anyway):", e);
		}		
	}
	
	public static String toShortString(Map<String, Control> controlsMap) {
		if (controlsMap != null && !controlsMap.isEmpty()) {
			StringBuilder sb = new StringBuilder();
            // We want just a short list here. toString methods of control implementations are too long. Avoid them.
			boolean isFirst = true;
			for ( Control control : controlsMap.values() ) {
			    if ( isFirst ) {
			        isFirst = false;
			    } else {
			        sb.append( ',' );
			    }
			    toShortString(sb, control);
			}
			return sb.toString();
		}
		return null;
	}

	public static String toShortString(Control control) {
		if (control == null) {
			return null;
		}
		StringBuilder sb = new StringBuilder();
		toShortString(sb, control);
		return sb.toString();
	}
	
	public static void toShortString(StringBuilder sb, Control control) {
		if (control == null) {
			return;
		}
		if (control instanceof PagedResults) {
			sb.append("PagedResults(size=");
			sb.append(((PagedResults)control).getSize());
			sb.append(", cookie=");
			byte[] cookie = ((PagedResults)control).getCookie();
			if (cookie == null) {
				sb.append("null");
			} else {
				sb.append(Base64.getEncoder().encodeToString(cookie));
			}
			sb.append("),");
		} else if (control instanceof VirtualListViewRequest) {
			sb.append("VLV(beforeCount=");
			sb.append(((VirtualListViewRequest)control).getBeforeCount());
			sb.append(", afterCount=");
			sb.append(((VirtualListViewRequest)control).getAfterCount());
			sb.append(", offset=");
			sb.append(((VirtualListViewRequest)control).getOffset());
			sb.append(", contentCount=");
			sb.append(((VirtualListViewRequest)control).getContentCount());
			sb.append(", contextID=");
			byte[] contextId = ((VirtualListViewRequest)control).getContextId();
			if (contextId == null) {
				sb.append("null");
			} else {
				sb.append(Base64.getEncoder().encodeToString(contextId));
			}
			sb.append("),");
		} else if (control instanceof SortRequest) {
			sb.append("Sort(");
			for (SortKey sortKey: ((SortRequest)control).getSortKeys()) {
				sb.append(sortKey.getAttributeTypeDesc());
				sb.append(":");
				sb.append(sortKey.getMatchingRuleId());
				sb.append(":");
				if (sortKey.isReverseOrder()) {
					sb.append("D");
				} else {
					sb.append("A");
				}
				sb.append("),");
			}
		} else {
			String controlDesc = null;
			Class<? extends Control> controlClass = control.getClass();
			Class<?>[] interfaces = controlClass.getInterfaces();
			if (interfaces != null) {
				for (Class<?> iface: interfaces) {
					if (iface.getPackage().getName().startsWith("org.apache.directory.api")) {
						controlDesc = iface.getSimpleName();
						break;
					}
				}
			}
			if (controlDesc == null) {
				controlDesc = controlClass.getName();
			}
			sb.append(controlDesc);
		}
	}

	public static boolean isAncestorOf(Dn upper, Dn lower, AbstractSchemaTranslator<?> schemaTranslator) {
		// We have two non-schema-aware DNs here. So simple upper.isAncestorOf(lower) will
		// not really do because there may be DN capitalization issues. So just we need to
		// create schema-aware versions and compare these.
		
		Dn upperSA;
		try {
			upperSA = new Dn(schemaTranslator.getSchemaManager(), upper.toString());
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Invalid DN: " + upper.toString() + ": " + e.getMessage(), e);
		}

		Dn lowerSA;
		try {
			lowerSA = new Dn(schemaTranslator.getSchemaManager(), lower.toString());
		} catch (LdapInvalidDnException e) {
			throw new InvalidAttributeValueException("Invalid DN: " + lower.toString() + ": " + e.getMessage(), e);
		}
		
		return upperSA.isAncestorOf(lowerSA);
	}
	
}

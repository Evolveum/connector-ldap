/*
 * Copyright (c) 2015-2022 Evolveum
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

import static org.identityconnectors.common.StringUtil.isBlank;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.common.objects.ValueListOpenness;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.ConfigurationProperty;

import java.util.Objects;

/**
 * LDAP Connector configuration.
 *
 * @author Radovan Semancik
 *
 */
public abstract class AbstractLdapConfiguration extends AbstractConfiguration {

    private static final Log LOG = Log.getLog(AbstractLdapConfiguration.class);

    public static final int DEFAULT_PORT = 389;

    public static final String SCOPE_SUB = "sub";
    public static final String SCOPE_ONE = "one";
    public static final String SCOPE_BASE = "base";

    public static final String PSEUDO_ATTRIBUTE_DN_NAME = "dn";
    public static final String SEARCH_FILTER_ALL = "(objectClass=*)";
    public static final String BOOLEAN_TRUE = "TRUE";
    public static final String BOOLEAN_FALSE = "FALSE";

    public static final String OBJECTCLASS_TOP_NAME = "top";

    private static final long DEFAULT_SWITCH_BACK_INTERVAL = 10000L;

    /**
     * The LDAP server hostname.
     */
    private String host;

    public static final String CONF_PROP_NAME_HOST = "host";

    /**
     * The LDAP server port.
     */
    private int port = DEFAULT_PORT;

    public static final String CONF_PROP_NAME_PORT = "port";

    /**
     * What connection security to use.
     * Possible values: null, "ssl", "starttls".
     * Default value: null
     */
    private String connectionSecurity;

    public static final String CONNECTION_SECURITY_NONE = "none";
    public static final String CONNECTION_SECURITY_SSL = "ssl";
    public static final String CONNECTION_SECURITY_STARTTLS = "starttls";

    public static final String CONF_PROP_NAME_CONNECTION_SECURITY = "connectionSecurity";

    /**
     * The standard name of the SSL protocol.
     * This name is used to instantiate javax.net.ssl.SSLContext.
     * See the SSLContext section in the Java Cryptography Architecture Standard Algorithm Name Documentation.
     * E.g. SSL, SSLv2, SSLv3, TLS, TLSv1, TLSv1.1, TLSv1.2
     */
    private String sslProtocol = null;
    public static final String CONF_PROP_NAME_SSL_PROTOCOL = "sslProtocol";
    public static final String CONF_ASSOC_DELIMITER = "-#";
    public static final String CONF_ASSOC_ATTR_DELIMITER = "\"\\+";

    /**
     * Whether connector skips certificate validity check against its default truststore (e.g. Java cacerts)
     * When set to false, connector checks server certificate validity in SSL/TLS mode (recommended).
     * When set to true, connector does not check server certificate validity. Do not use this option in the production.
     */
    private boolean allowUntrustedSsl = false;

    /**
     * Set of security protocols that are acceptable for protocol negotiation.
     * This name is used to set up SSLEngine.
     * See the SSLContext section in the Java Cryptography Architecture Standard Algorithm Name Documentation.
     * E.g. SSL, SSLv2, SSLv3, TLS, TLSv1, TLSv1.1, TLSv1.2
     */
    private String[] enabledSecurityProtocols = null;

    private String[] enabledCipherSuites = null;

    /**
     * The authentication mechanism to use.
     * Possible values: "simple", "SASL-GSSAPI"
     * Default value: "simple"
     */
    private String authenticationType = "simple";

    /**
     * The DN of the object to bind to.
     */
    private String bindDn;

    /**
     * Bind password.
     */
    private GuardedString bindPassword;

    /**
     * Global timeout (in milliseconds).
     * This timeout will be used for all operations as default.
     */
    private Long timeout;

    private static final long DEFAULT_TIMEOUT = 10000;

    /**
     * Connect timeout (in milliseconds).
     * The timeout will be used for connect and bind operations.
     * If not specified, global timeout will be used instead.
     *
     * For compatibility reasons, if connectTimeout is the only timeout value specified,
     * it will be used as global timeout.
     *
     * Note: Connectors before 3.3 had connectTimeout only, it was used for all operations.
     */
    private Long connectTimeout;

    /**
     * Write operation timeout (in milliseconds).
     * The timeout will be used for LDAP write operations such as add, modify and delete.
     * If not specified, global timeout will be used instead.
     */
    private Long writeOperationTimeout;

    /**
     * Read operation timeout (in milliseconds).
     * The timeout will be used for read LDAP operations such as search and compare.
     * If not specified, global timeout will be used instead.
     */
    private Long readOperationTimeout;

    /**
     * Close timeout (in milliseconds).
     * The timeout will be used for unbind and connection close.
     * If not specified, global timeout will be used instead.
     */
    private Long closeTimeout;

    /**
     * Send timeout (in milliseconds).
     * The timeout will be used for I/O (TCP) writes.
     * If not specified, global timeout will be used instead.
     */
    private Long sendTimeout;

    /**
     * Timeout for connection liveliness test (checkAlive connector operation, in milliseconds).
     */
    private Long checkAliveTimeout;

    /**
     * Fetch root DSE as part of connection liveliness test.
     * OBSOLETE. This option no longer works. It is ignored.
     * Since 3.4, the connector pretends that the liveness check always passes,
     * handling connection failures during operations as needed.
     */
    private boolean checkAliveRootDse = false;

    /**
     * Enable use of TCP keepalives on LDAP connections.
     */
    private boolean tcpKeepAlive = false;

    /**
     * Maximum number of attempts to retrieve the entry or to re-try the operation.
     * This number is applicable in replicated topology when handling connection failures
     * and re-trying on another server, when following referrals and in similar situations.
     */
    private int maximumNumberOfAttempts = 10;

    /**
     * The base DN that the connector will use if the base DN is not specified explicitly.
     */
    private String baseContext;

    public static final String CONF_PROP_NAME_BASE_CONTEXT = "baseContext";

    /**
     * Structured definition of a server in the directory topology.
     * It contains attribute-value pairs that define each individual server.
     * The names of configuration properties can be used, separated by equal
     * signs and semicolons, such as this:
     *
     * baseContext=dc=sub,dc=example,dc=com; host=sub.example.com; port=389
     *
     * The server will be selected for each operation according to the baseContext
     * that is specified in server definition. The most specific DN match will
     * be used. If there are more multiple servers specified for the same
     * baseContext then one of them will be selected randomly. The server
     * which does not specify any baseContext is considered to be the default
     * and that server will be used if the DN cannot be matched. This is equivalent
     * to the server which is specified by ordinary configuration properties.
     *
     *  The configuration properties that are not explicitly specified in the
     *  server configuration line are taken from the ordinary configuration.
     */
    private String[] servers;

    /**
     * The referral handling strategy. OBSOLETE. THIS OPTION IS NO LONGER SUPPORTED. It will be ignored.
     */
    private String referralStrategy;

    /**
     * The name of the attribute which contains the password.
     */
    private String passwordAttribute = null;

    /**
     * Hash the passwords with a specified algorithm before they are sent to the server.
     */
    private String passwordHashAlgorithm;

    public static final String CONF_PROP_NAME_PASSWORD_HASH_ALGORITHM = "passwordHashAlgorithm";

    public static final String PASSWORD_HASH_ALGORITHM_NONE = "none";
    public static final String PASSWORD_HASH_ALGORITHM_SSHA = "SSHA";

    /**
     * Strategy for reading the password. LDAP schema itself cannot reliably indicate whether
     * a password is readable or not. Therefore there this can be configured. Possible values:
     * "unreadable":     Password is not readable, it is never returned by the connector.
     *                   This is the default.
     * "incompleteRead": If password is returned by the LDAP server then connector will
     *                   remove the value. Connector will indicate that the value is
     *                   incomplete. Therefore IDM system can learn that there is
     *                   password without knowing the password value.
     * "readable":       If password is returned by the LDAP server then it is passed
     *                   to the IDM system in the same form as it was returned.
     */
    private String passwordReadStrategy = PASSWORD_READ_STRATEGY_UNREADABLE;

    public static final String PASSWORD_READ_STRATEGY_UNREADABLE = "unreadable";
    public static final String PASSWORD_READ_STRATEGY_INCOMPLETE_READ = "incompleteRead";
    public static final String PASSWORD_READ_STRATEGY_READABLE = "readable";

    /**
     * Specifies strategy of using paging mechanisms such as VLV or Simple Paged Results.
     * Possible values: "none", "auto", "spr", "vlv"
     * Default value: "auto"
     */
    private String pagingStrategy = null;

    public static final String PAGING_STRATEGY_NONE = "none";
    public static final String PAGING_STRATEGY_AUTO = "auto";
    public static final String PAGING_STRATEGY_SPR = "spr";
    public static final String PAGING_STRATEGY_VLV = "vlv";

    /**
     * Number of entries in one "page" when paging is used.
     */
    private int pagingBlockSize = 100;

    /**
     * The attribute used for sorting for the VLV searches if no explicit sorting attribute was specified.
     * It may also contain a comma-separated list of attribute names. The first attribute that is found
     * in the applicable object class definition will be used for sorting.
     */
    private String vlvSortAttribute = null;

    public static final String CONF_PROP_NAME_VLV_SORT_ATTRIBUTE = "vlvSortAttribute";

    /**
     * The ordering rule for VLV searches if no other ordering was specified.
     */
    private String vlvSortOrderingRule = null;

    public static final String CONF_PROP_NAME_VLV_SORT_ORDERING_RULE = "vlvSortOrderingRule";

    /**
     * Name of the attribute which will be used as ICF UID.
     */
    private String uidAttribute;

    /**
     * Operational attributes that apply to all object classes.
     */
    private String[] operationalAttributes = { };

    public static final String CONF_PROP_NAME_OPERATIONAL_ATTRIBUTES = "operationalAttributes";

    /**
     * If set to false then the schema will not be retrieved from the server.
     */
    private boolean readSchema = true;

    /**
     * If set to false then the schema parsers will be very strict.
     * If set to true then various "quirks" in the schema will be accepted, such as
     * non-numeric OIDs.
     */
    private boolean schemaQuirksMode = true;

    /**
     * Accept also attributes that are not defined in schema.
     * Single-value string is assumed as the attribute type.
     */
    private boolean allowUnknownAttributes = false;

    /**
     * Use permissive modify LDAP control for modify operations.
     * Possible values: "never", "auto", "always"
     * Default value: auto
     */
    private String usePermissiveModify = USE_PERMISSIVE_MODIFY_AUTO;

    public static final String CONF_PROP_NAME_USE_PERMISSIVE_MODIFY = "usePermissiveModify";

    public static final String USE_PERMISSIVE_MODIFY_NEVER = "never";
    public static final String USE_PERMISSIVE_MODIFY_AUTO = "auto";
    public static final String USE_PERMISSIVE_MODIFY_ALWAYS = "always";

    /**
     * Use tree delete LDAP control for delete operations. This control allows to delete non-leaf entries.
     * As this control may be dangerous the default value is "never".
     * Possible values: "never", "auto", "always"
     * Default value: never
     */
    private String useTreeDelete = USE_TREE_DELETE_NEVER;

    public static final String USE_TREE_DELETE_NEVER = "never";
    public static final String USE_TREE_DELETE_AUTO = "auto";
    public static final String USE_TREE_DELETE_ALWAYS = "always";

    /**
     * Enforces tree deletion for specified object classes.
     * This overrides the useTreeDelete for the specified object classes.
     */
    private String[] forceTreeDeleteObjectClasses = { };

    /**
     * Synchronization strategy to detect changes in real time.
     * Possible values: "none", "auto", ... TODO
     * Default value: auto
     */
    private String synchronizationStrategy = null;

    public static final String SYNCHRONIZATION_STRATEGY_NONE = "none";
    public static final String SYNCHRONIZATION_STRATEGY_AUTO = "auto";
    public static final String SYNCHRONIZATION_STRATEGY_SUN_CHANGE_LOG = "sunChangeLog";
    public static final String SYNCHRONIZATION_STRATEGY_MODIFY_TIMESTAMP = "modifyTimestamp";
    public static final String SYNCHRONIZATION_STRATEGY_OPEN_LDAP_ACCESSLOG = "openLdapAccessLog";
    public static final String SYNCHRONIZATION_STRATEGY_AD_DIR_SYNC = "adDirSync";

    /**
     * Base context DN that will be accepted during synchronization.
     * If set to empty then all DNs will be accepted.
     */
    private String baseContextToSynchronize = null;

    /**
     * List of object classes that will be accepted during synchronization.
     * If set to empty then all object classes will be accepted.
     */
    private String[] objectClassesToSynchronize = { };

    /**
     * List of attributes that will be passed during synchronization.
     * If set to empty then all non-operational attributes will be passed.
     */
    private String[] attributesToSynchronize = { };

    /**
     * List of modifiers DNs that will NOT be accepted during synchronization.
     */
    private String[] modifiersNamesToFilterOut = { };

    /**
     * Number of change log entries to fetch in a single request.
     */
    private int changeLogBlockSize = 100;

    /**
     * "Change number" attribute - unique indentifier of the change in the change log.
     */
    private String changeNumberAttribute = "changeNumber";

    /**
     * Entry DN can be provided to the connector as a "name hint". Connector will use the name hint whenever
     * it can use it safely. But there are some cases when the name hint cannot be used safely. There are
     * mostly modify and delete operations when in a rare case a wrong object can be modified or deleted.
     * The connector will not use the name hint in these cases by default. It will make explicit search
     * to make sure that everything is fair and square before attempting the operation. However this comes
     * at the expense of performance. If this switch is set to true then the connector will try to use
     * the name hint even if it is not completely safe. This may mean significant perfomacne boost for
     * modify and delete operations.
     */
    private boolean useUnsafeNameHint = false;

    /**
     * Mode of connection tests.
     * "full" test mode will test all configured connections (all servers).
     * "primary" mode will test only the connection to primary server (one specific server).
     * "any" test mode will succeed as long as the connector can connect to any server specified for the root base context (any one server).
     * Possible values: "full", "primary", "any"
     * Default value: full
     */
    private String testMode = TEST_MODE_FULL;

    public static final String TEST_MODE_FULL = "full";
    public static final String TEST_MODE_PRIMARY = "primary";
    public static final String TEST_MODE_ANY = "any";

    /**
     * Enable extra tests during the test connection operations.
     * Those tests may take longer and they may make more LDAP requests.
     * These tests try to test some tricky situations and border conditions
     * and they are generally useful only for connector developers or when
     * diagnosing connector bugs.
     */
    private boolean enableExtraTests = false;

    /**
     * Timestamp presentation mode. This controls the way how connector presents the timestamps
     * to the client. It can present them in native framework format (which is the default).
     * Or it can present them as unix epoch (number of seconds since 1970) or the
     * timestamps can be presented in LDAP-native string form (ISO 8601). Unix epoch and
     * string representation are provided mostly for compatibility reasons.
     * Possible values: "native", "unixEpoch", "string"
     * Default value: native
     */
    private String timestampPresentation = TIMESTAMP_PRESENTATION_NATIVE;

    public static final String TIMESTAMP_PRESENTATION_NATIVE = "native";
    public static final String TIMESTAMP_PRESENTATION_UNIX_EPOCH = "unixEpoch";
    public static final String TIMESTAMP_PRESENTATION_STRING = "string";

    /**
     * Enables inclusion of explicit object class filter in all searches. Normally the connector would
     * derive search filter only based on the attributes specified in the query. E.g. (&(uid=foo)(cn=bar)).
     * If includeObjectClassFilter is set to true, then also explicit filter for objectclass will be included.
     * E.g (&(objectClass=inetOrgPerson)(uid=foo)(cn=bar)).
     * Default value: true
     */
    private boolean includeObjectClassFilter = true;

    /**
     * Enabled more tolerant algorithm to detect which object class is structural and which is auxiliary.
     */
    private boolean alternativeObjectClassDetection = false;

    /**
     * If set to true, adds all additional structural object classes without children to the auxiliary object classes list on the connector.
     */
    private boolean structuralObjectClassesToAuxiliary = false;

    /**
     * Controls "run as" feature. This feature allows execution of operations under different identity
     * that is configured in the connector. This feature is disabled by default because it is very
     * difficult to correctly autoconfigure it. And there may be some risks involved.
     * Possible values: "none", "bind"
     * Default value: none
     */
    private String runAsStrategy = RUN_AS_STRATEGY_NONE;

    public static final String RUN_AS_STRATEGY_NONE = "none";
    public static final String RUN_AS_STRATEGY_BIND = "bind";

    /**
     * Search filter that will be added to all searche operations that the connector does.
     */
    private String additionalSearchFilter;

    // TODO: accountSynchronizationFilter
    // MAYBE TODO: respectResourcePasswordPolicyChangeAfterReset? filterWithOrInsteadOfAnd?
    //               removeLogEntryObjectClassFromFilter? synchronizePasswords? passwordAttributeToSynchronize?

    /**
     * Default search scope used for ordinary searches.
     * Possible values: "sub", "one"
     * Default value: sub
     */
    private String defaultSearchScope = SEARCH_SCOPE_SUB;

    public static final String SEARCH_SCOPE_SUB = "sub";
    public static final String SEARCH_SCOPE_ONE = "one";

    /**
     * If set to true, then the connector will explicitly invoke LDAP unbind operation before connection is closed.
     * Default value: false
     */
    private boolean useUnbind = false;

    /**
     * Interval (in milliseconds) for which the connector fails over to secondary server, in case the primary fails.
     * The connector will use the secondary server during this interval.
     * When the interval is over, the connector will try to use the primary server again.
     */
    private long switchBackInterval = DEFAULT_SWITCH_BACK_INTERVAL;

    /**
     * If set to true, connector will return only values of memberOf attribute that contains specified sequence.
     * If set to false, no filtering will occur and all values will be returned.
     * Default value: false
     */
    private boolean filterOutMemberOfValues = false;

    /**
     * List of allowed value for memberOf attribute to be returned, only values ending with specified will be returned. If no value defined, baseContext will be used.
     * This will be processed only when 'Filter memberOf' set to true
     */
    private String[] memberOfAllowedValues = { };

    /**
     * Names of object classes representing objects which can be used as a grouping mechanism.
     * Parameter is used solely in configuration discovery to compute configuration suggestions for "managedAssociationPairs" parameter.
     * Default "groupOfNames".
     */

    protected String[] groupObjectClasses = { };

    public static final String CONF_PROP_MNGD_ASSOC_PAIRS = "managedAssociationPairs";

    /**
     * The attribute contains the list of subject and object classes and their parameters which is used by the connector to identify associations between object classes.
     * The convention is the list is as follows: '"subject objectClass name"+subject parameter -# "object objectClass name" + object parameter'.
     * The convention of the imputed value is significant for the connector po parse out the association subject and object pairs and their parameters.
     * Example "inetOrgPerson"+memberOf -# "groupOfNames"+member.
     *
     * EXPERIMENTAL. Not completely tested yet.
     */
    protected String[] managedAssociationPairs = { };

    /**
     * The property is used in case an "I18n.ERR_13247_INVALID_VALUE_CANT_NORMALIZE" error has occurred during connId to
     * ldap value normalization. If 'true' the operation is retried with the original string value encoded as a
     * sequence of bytes in the "StandardCharsets.UTF_8" charset.
     * EXPERIMENTAL.
     */
    private boolean encodeStringOnNormalizationFailure = false;

    /**
     * The property represents a list of standard object schema attributes which should be set with the schema
     * flag "NOT_RETURNED_BY_DEFAULT". Such attributes will be by default omitted from ldap search requests. They will
     * be returned only if they are a part of the operation options "ATTRS_TO_GET" set.
     */
    private String[] attributesNotReturnedByDefault;
    public static final String CONF_PROP_NAME_ATTRS_NOT_RETURNED_BY_DEFAULT = "attributesNotReturnedByDefault";

    @ConfigurationProperty(required = true, order = 1)
    public String getHost() {
        return host;
    }

    @SuppressWarnings("unused")
    public void setHost(String host) {
        this.host = host;
    }

    @ConfigurationProperty(order = 2, allowedValues = { "389", "636" }, allowedValuesOpenness = ValueListOpenness.OPEN)
    public int getPort() {
        return port;
    }

    @SuppressWarnings("unused")
    public void setPort(int port) {
        this.port = port;
    }

    @ConfigurationProperty(order = 3, allowedValues = { CONNECTION_SECURITY_NONE, CONNECTION_SECURITY_SSL, CONNECTION_SECURITY_STARTTLS })
    public String getConnectionSecurity() {
        return connectionSecurity;
    }

    @SuppressWarnings("unused")
    public void setConnectionSecurity(String connectionSecurity) {
        this.connectionSecurity = connectionSecurity;
    }

    @ConfigurationProperty(order = 4, allowedValues = { "TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" }, allowedValuesOpenness = ValueListOpenness.OPEN)
    public String getSslProtocol() {
        return sslProtocol;
    }

    @SuppressWarnings("unused")
    public void setSslProtocol(String sslProtocol) {
        this.sslProtocol = sslProtocol;
    }

    @ConfigurationProperty(order = 5, allowedValues = { "TLS", "TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3" }, allowedValuesOpenness = ValueListOpenness.OPEN)
    public String[] getEnabledSecurityProtocols() {
        return enabledSecurityProtocols;
    }

    @SuppressWarnings("unused")
    public void setEnabledSecurityProtocols(String[] enabledSecurityProtocols) {
        this.enabledSecurityProtocols = enabledSecurityProtocols;
    }

    @ConfigurationProperty(order = 6)
    public String[] getEnabledCipherSuites() {
        return enabledCipherSuites;
    }

    @SuppressWarnings("unused")
    public void setEnabledCipherSuites(String[] enabledCipherSuites) {
        this.enabledCipherSuites = enabledCipherSuites;
    }

    @ConfigurationProperty(order = 7)
    public String getAuthenticationType() {
        return authenticationType;
    }

    @SuppressWarnings("unused")
    public void setAuthenticationType(String authenticationType) {
        this.authenticationType = authenticationType;
    }

    @ConfigurationProperty(order = 8)
    public String getBindDn() {
        return bindDn;
    }

    @SuppressWarnings("unused")
    public void setBindDn(String bindDn) {
        this.bindDn = bindDn;
    }

    @ConfigurationProperty(order = 9)
    public GuardedString getBindPassword() {
        return bindPassword;
    }

    @SuppressWarnings("unused")
    public void setBindPassword(GuardedString bindPassword) {
        this.bindPassword = bindPassword;
    }

    @ConfigurationProperty(order = 10)
    public Long getTimeout() {
        return timeout;
    }

    @SuppressWarnings("unused")
    public void setTimeout(Long timeout) {
        this.timeout = timeout;
    }

    @ConfigurationProperty(order = 11)
    public Long getConnectTimeout() {
        return connectTimeout;
    }

    @SuppressWarnings("unused")
    public void setConnectTimeout(Long connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    @ConfigurationProperty(order = 12)
    public Long getWriteOperationTimeout() {
        return writeOperationTimeout;
    }

    @SuppressWarnings("unused")
    public void setWriteOperationTimeout(Long writeOperationTimeout) {
        this.writeOperationTimeout = writeOperationTimeout;
    }

    @ConfigurationProperty(order = 13)
    public Long getReadOperationTimeout() {
        return readOperationTimeout;
    }

    @SuppressWarnings("unused")
    public void setReadOperationTimeout(Long readOperationTimeout) {
        this.readOperationTimeout = readOperationTimeout;
    }

    @ConfigurationProperty(order = 14)
    public Long getCloseTimeout() {
        return closeTimeout;
    }

    @SuppressWarnings("unused")
    public void setCloseTimeout(Long closeTimeout) {
        this.closeTimeout = closeTimeout;
    }

    @ConfigurationProperty(order = 15)
    public Long getSendTimeout() {
        return sendTimeout;
    }

    @SuppressWarnings("unused")
    public void setSendTimeout(Long sendTimeout) {
        this.sendTimeout = sendTimeout;
    }

    @ConfigurationProperty(order = 16)
    public Long getCheckAliveTimeout() {
        return checkAliveTimeout;
    }

    @SuppressWarnings("unused")
    public void setCheckAliveTimeout(Long checkAliveTimeout) {
        this.checkAliveTimeout = checkAliveTimeout;
    }

    @ConfigurationProperty(order = 17)
    public boolean isCheckAliveRootDse() {
        return checkAliveRootDse;
    }

    @SuppressWarnings("unused")
    public void setCheckAliveRootDse(boolean checkAliveRootDse) {
        this.checkAliveRootDse = checkAliveRootDse;
    }

    @ConfigurationProperty(order = 18)
    public boolean isTcpKeepAlive() { return tcpKeepAlive; }

    @SuppressWarnings("unused")
    public void setTcpKeepAlive(boolean tcpKeepAlive) {
        this.tcpKeepAlive = tcpKeepAlive;
    }

    @ConfigurationProperty(order = 19)
    public int getMaximumNumberOfAttempts() {
        return maximumNumberOfAttempts;
    }

    @SuppressWarnings("unused")
    public void setMaximumNumberOfAttempts(int maximumNumberOfAttempts) {
        this.maximumNumberOfAttempts = maximumNumberOfAttempts;
    }

    @ConfigurationProperty(order = 20)
    public String getBaseContext() {
        return baseContext;
    }

    @SuppressWarnings("unused")
    public void setBaseContext(String baseContext) {
        this.baseContext = baseContext;
    }

    @ConfigurationProperty(order = 21)
    public String[] getServers() {
        return servers;
    }

    @SuppressWarnings("unused")
    public void setServers(String[] servers) {
        this.servers = servers;
    }

    @ConfigurationProperty(order = 22)
    public String getReferralStrategy() {
        return referralStrategy;
    }

    @SuppressWarnings("unused")
    public void setReferralStrategy(String referralStrategy) {
        this.referralStrategy = referralStrategy;
    }

    @ConfigurationProperty(order = 23)
    public String getPasswordAttribute() {
        return passwordAttribute;
    }

    public void setPasswordAttribute(String passwordAttribute) {
        this.passwordAttribute = passwordAttribute;
    }

    @ConfigurationProperty(order = 24, allowedValues = { PASSWORD_HASH_ALGORITHM_NONE, PASSWORD_HASH_ALGORITHM_SSHA }, allowedValuesOpenness = ValueListOpenness.OPEN)
    public String getPasswordHashAlgorithm() {
        return passwordHashAlgorithm;
    }

    @SuppressWarnings("unused")
    public void setPasswordHashAlgorithm(String passwordHashAlgorithm) {
        this.passwordHashAlgorithm = passwordHashAlgorithm;
    }

    @ConfigurationProperty(order = 25, allowedValues = { PASSWORD_READ_STRATEGY_UNREADABLE, PASSWORD_READ_STRATEGY_READABLE, PASSWORD_READ_STRATEGY_INCOMPLETE_READ })
    public String getPasswordReadStrategy() {
        return passwordReadStrategy;
    }

    @SuppressWarnings("unused")
    public void setPasswordReadStrategy(String passwordReadStrategy) {
        this.passwordReadStrategy = passwordReadStrategy;
    }

    @ConfigurationProperty(order = 26, allowedValues = { PAGING_STRATEGY_NONE, PAGING_STRATEGY_AUTO, PAGING_STRATEGY_SPR, PAGING_STRATEGY_VLV })
    public String getPagingStrategy() {
        return pagingStrategy;
    }

    @SuppressWarnings("unused")
    public void setPagingStrategy(String pagingStrategy) {
        this.pagingStrategy = pagingStrategy;
    }

    @ConfigurationProperty(order = 27)
    public int getPagingBlockSize() {
        return pagingBlockSize;
    }

    @SuppressWarnings("unused")
    public void setPagingBlockSize(int pagingBlockSize) {
        this.pagingBlockSize = pagingBlockSize;
    }

    @ConfigurationProperty(order = 28)
    public String getVlvSortAttribute() {
        return vlvSortAttribute;
    }

    public void setVlvSortAttribute(String vlvSortAttribute) {
        this.vlvSortAttribute = vlvSortAttribute;
    }

    @ConfigurationProperty(order = 29)
    public String getVlvSortOrderingRule() {
        return vlvSortOrderingRule;
    }

    @SuppressWarnings("unused")
    public void setVlvSortOrderingRule(String vlvSortOrderingRule) {
        this.vlvSortOrderingRule = vlvSortOrderingRule;
    }

    @ConfigurationProperty(order = 30)
    public String getUidAttribute() {
        return uidAttribute;
    }

    public void setUidAttribute(String uidAttribute) {
        this.uidAttribute = uidAttribute;
    }

    @ConfigurationProperty(order = 31)
    public String[] getOperationalAttributes() {
        return operationalAttributes;
    }

    @SuppressWarnings("unused")
    public void setOperationalAttributes(String[] operationalAttributes) {
        this.operationalAttributes = operationalAttributes;
    }

    @ConfigurationProperty(order = 32)
    public boolean isReadSchema() {
        return readSchema;
    }

    @SuppressWarnings("unused")
    public void setReadSchema(boolean readSchema) {
        this.readSchema = readSchema;
    }

    @ConfigurationProperty(order = 33)
    public boolean isSchemaQuirksMode() {
        return schemaQuirksMode;
    }

    @SuppressWarnings("unused")
    public void setSchemaQuirksMode(boolean schemaQuirksMode) {
        this.schemaQuirksMode = schemaQuirksMode;
    }

    @ConfigurationProperty(order = 34)
    public boolean isAllowUnknownAttributes() {
        return allowUnknownAttributes;
    }

    @SuppressWarnings("unused")
    public void setAllowUnknownAttributes(boolean allowUnknownAttributes) {
        this.allowUnknownAttributes = allowUnknownAttributes;
    }

    @ConfigurationProperty(order = 35)
    public String getUsePermissiveModify() {
        return usePermissiveModify;
    }

    @SuppressWarnings("unused")
    public void setUsePermissiveModify(String usePermissiveModify) {
        this.usePermissiveModify = usePermissiveModify;
    }

    @ConfigurationProperty(order = 36)
    public String getUseTreeDelete() {
        return useTreeDelete;
    }

    @SuppressWarnings("unused")
    public void setUseTreeDelete(String useTreeDelete) {
        this.useTreeDelete = useTreeDelete;
    }

    @ConfigurationProperty(order = 37, allowedValues = { SYNCHRONIZATION_STRATEGY_NONE, SYNCHRONIZATION_STRATEGY_AUTO, SYNCHRONIZATION_STRATEGY_SUN_CHANGE_LOG, SYNCHRONIZATION_STRATEGY_OPEN_LDAP_ACCESSLOG, SYNCHRONIZATION_STRATEGY_MODIFY_TIMESTAMP, SYNCHRONIZATION_STRATEGY_AD_DIR_SYNC })
    public String getSynchronizationStrategy() {
        return synchronizationStrategy;
    }

    public void setSynchronizationStrategy(String synchronizationStrategy) {
        this.synchronizationStrategy = synchronizationStrategy;
    }

    @ConfigurationProperty(order = 38)
    public String getBaseContextToSynchronize() {
        return baseContextToSynchronize;
    }

    @SuppressWarnings("unused")
    public void setBaseContextToSynchronize(String baseContextToSynchronize) {
        this.baseContextToSynchronize = baseContextToSynchronize;
    }

    @ConfigurationProperty(order = 39)
    public String[] getObjectClassesToSynchronize() {
        return objectClassesToSynchronize;
    }

    @SuppressWarnings("unused")
    public void setObjectClassesToSynchronize(String[] objectClassesToSynchronize) {
        this.objectClassesToSynchronize = objectClassesToSynchronize;
    }

    @ConfigurationProperty(order = 40)
    public String[] getAttributesToSynchronize() {
        return attributesToSynchronize;
    }

    @SuppressWarnings("unused")
    public void setAttributesToSynchronize(String[] attributesToSynchronize) {
        this.attributesToSynchronize = attributesToSynchronize;
    }

    @ConfigurationProperty(order = 41)
    public String[] getModifiersNamesToFilterOut() {
        return modifiersNamesToFilterOut;
    }

    @SuppressWarnings("unused")
    public void setModifiersNamesToFilterOut(String[] modifiersNamesToFilterOut) {
        this.modifiersNamesToFilterOut = modifiersNamesToFilterOut;
    }

    @ConfigurationProperty(order = 42)
    public int getChangeLogBlockSize() {
        return changeLogBlockSize;
    }

    @SuppressWarnings("unused")
    public void setChangeLogBlockSize(int changeLogBlockSize) {
        this.changeLogBlockSize = changeLogBlockSize;
    }

    @ConfigurationProperty(order = 43)
    public String getChangeNumberAttribute() {
        return changeNumberAttribute;
    }

    @SuppressWarnings("unused")
    public void setChangeNumberAttribute(String changeNumberAttribute) {
        this.changeNumberAttribute = changeNumberAttribute;
    }

    @ConfigurationProperty(order = 44)
    public boolean isUseUnsafeNameHint() {
        return useUnsafeNameHint;
    }

    @SuppressWarnings("unused")
    public void setUseUnsafeNameHint(boolean useUnsafeNameHint) {
        this.useUnsafeNameHint = useUnsafeNameHint;
    }

    @ConfigurationProperty(order = 45, allowedValues = { TEST_MODE_FULL, TEST_MODE_ANY, TEST_MODE_PRIMARY })
    public String getTestMode() {
        return testMode;
    }

    @SuppressWarnings("unused")
    public void setTestMode(String testMode) {
        this.testMode = testMode;
    }

    @ConfigurationProperty(order = 46)
    public boolean isEnableExtraTests() {
        return enableExtraTests;
    }

    @SuppressWarnings("unused")
    public void setEnableExtraTests(boolean enableExtraTests) {
        this.enableExtraTests = enableExtraTests;
    }

    @ConfigurationProperty(order = 47, allowedValues = { TIMESTAMP_PRESENTATION_NATIVE, TIMESTAMP_PRESENTATION_STRING, TIMESTAMP_PRESENTATION_UNIX_EPOCH })
    public String getTimestampPresentation() {
        return timestampPresentation;
    }

    @SuppressWarnings("unused")
    public void setTimestampPresentation(String timestampPresentation) {
        this.timestampPresentation = timestampPresentation;
    }

    @ConfigurationProperty(order = 48)
    public boolean isIncludeObjectClassFilter() {
        return includeObjectClassFilter;
    }

    @SuppressWarnings("unused")
    public void setIncludeObjectClassFilter(boolean includeObjectClassFilter) {
        this.includeObjectClassFilter = includeObjectClassFilter;
    }

    @ConfigurationProperty(order = 49)
    public boolean isAlternativeObjectClassDetection() {
        return alternativeObjectClassDetection;
    }

    @SuppressWarnings("unused")
    public void setAlternativeObjectClassDetection(boolean alternativeObjectClassDetection) {
        this.alternativeObjectClassDetection = alternativeObjectClassDetection;
    }

    @ConfigurationProperty(order = 50)
    public boolean isStructuralObjectClassesToAuxiliary() {
        return structuralObjectClassesToAuxiliary;
    }

    @SuppressWarnings("unused")
    public void setStructuralObjectClassesToAuxiliary(boolean structuralObjectClassesToAuxiliary) {
        this.structuralObjectClassesToAuxiliary = structuralObjectClassesToAuxiliary;
    }

    @ConfigurationProperty(order = 51, allowedValues = { RUN_AS_STRATEGY_NONE, RUN_AS_STRATEGY_BIND })
    public String getRunAsStrategy() {
        return runAsStrategy;
    }

    @SuppressWarnings("unused")
    public void setRunAsStrategy(String runAsStrategy) {
        this.runAsStrategy = runAsStrategy;
    }

    @ConfigurationProperty(order = 52)
    public String getAdditionalSearchFilter() {
        return additionalSearchFilter;
    }

    @SuppressWarnings("unused")
    public void setAdditionalSearchFilter(String additionalSearchFilter) {
        this.additionalSearchFilter = additionalSearchFilter;
    }

    @ConfigurationProperty(order = 53, allowedValues = { SEARCH_SCOPE_SUB, SEARCH_SCOPE_ONE })
    public String getDefaultSearchScope() {
        return defaultSearchScope;
    }

    @SuppressWarnings("unused")
    public void setDefaultSearchScope(String searchScope) {
        this.defaultSearchScope = searchScope;
    }

    @ConfigurationProperty(order = 54)
    public boolean isAllowUntrustedSsl() {
        return allowUntrustedSsl;
    }

    @SuppressWarnings("unused")
    public void setAllowUntrustedSsl(boolean allowUntrustedSsl) {
        this.allowUntrustedSsl = allowUntrustedSsl;
    }

    @ConfigurationProperty(order = 55)
    public boolean isUseUnbind() {
        return useUnbind;
    }

    @SuppressWarnings("unused")
    public void setUseUnbind(boolean useUnbind) {
        this.useUnbind = useUnbind;
    }

    @ConfigurationProperty(order = 56)
    public long getSwitchBackInterval() {
        return switchBackInterval;
    }

    @SuppressWarnings("unused")
    public void setSwitchBackInterval(long switchBackInterval) {
        this.switchBackInterval = switchBackInterval;
    }

    @ConfigurationProperty(order = 57)
    public boolean isFilterOutMemberOfValues() {
        return filterOutMemberOfValues;
    }

    @SuppressWarnings("unused")
    public void setFilterOutMemberOfValues(boolean filterOutMemberOfValues) {
        this.filterOutMemberOfValues = filterOutMemberOfValues;
    }

    @ConfigurationProperty(order = 58)
    public String[] getMemberOfAllowedValues() {
        return memberOfAllowedValues;
    }

    @SuppressWarnings("unused")
    public void setMemberOfAllowedValues(String[] memberOfAllowedValues) {
        this.memberOfAllowedValues = memberOfAllowedValues;
    }

    @ConfigurationProperty(order = 59)
    public String[] getForceTreeDeleteObjectClasses() {
        return forceTreeDeleteObjectClasses;
    }

    @SuppressWarnings("unused")
    public void setForceTreeDeleteObjectClasses(String[] forceTreeDeleteObjectClasses) {
        this.forceTreeDeleteObjectClasses = forceTreeDeleteObjectClasses;

    }

    @ConfigurationProperty(order = 60)

    public String[] getGroupObjectClasses() {
        return groupObjectClasses;
    }

    public void setGroupObjectClasses(String[] groupObjectClasses) {
        this.groupObjectClasses = groupObjectClasses;
    }

    @ConfigurationProperty(order = 61)
    public String[] getManagedAssociationPairs() {
        return managedAssociationPairs;
    }

    public void setManagedAssociationPairs(String[] managedAssociationPairs) {
        this.managedAssociationPairs = managedAssociationPairs;
    }

    @ConfigurationProperty(order = 62)
    public boolean getEncodeStringOnNormalizationFailure() {
        return encodeStringOnNormalizationFailure;
    }
    @ConfigurationProperty(order = 62)
    public void setEncodeStringOnNormalizationFailure(boolean encodeStringOnNormalizationFailure) {
        this.encodeStringOnNormalizationFailure = encodeStringOnNormalizationFailure;
    }

    public void setAttributesNotReturnedByDefault(String[] attributesNotReturnedByDefault){
        this.attributesNotReturnedByDefault = attributesNotReturnedByDefault;
    }

    public String[] getAttributesNotReturnedByDefault() {
        return attributesNotReturnedByDefault;
    }

    @Override
    public void validate() {
        validateNotBlank(host, "host.blank");
        if (port < 0 || port > 65535) {
            throwConfigurationError("port.illegalValue");
        }
        if (baseContext != null) {
            validateBaseContext();
        }

        // TODO
    }

    public void validateBaseContext() {
        validateDn(baseContext, "baseContext.invalidDn");
    }

    private void validateNotBlank(String value, String errorKey) {
        if (isBlank(value)) {
            throwConfigurationError(errorKey);
        }
    }

    private void validateDn(String value, String errorKey) {
        if (isBlank(value)) {
            throwConfigurationError(errorKey);
        }
        // TODO
    }

    private void throwConfigurationError(String errorKey) {
        throw new ConfigurationException(getConnectorMessages().format(errorKey, null));
    }

    public void recompute() {
        if (passwordAttribute == null) {
            passwordAttribute = SchemaConstants.USER_PASSWORD_AT;
        }
        if (synchronizationStrategy == null) {
            synchronizationStrategy = SYNCHRONIZATION_STRATEGY_AUTO;
        }
        if (vlvSortAttribute == null) {
            vlvSortAttribute = SchemaConstants.UID_AT;
        }

        // Compatibility
        // There was only connectTimeout before version 3.3.
        // We want to set a global timeout when connectTimeout is the only thing that is set.
        // That is what users will typically have before 3.3.
        if (connectTimeout != null
                && timeout == null && writeOperationTimeout == null && readOperationTimeout == null
                && closeTimeout == null && sendTimeout == null) {
            timeout = connectTimeout;
        }

        if (timeout == null) {
            timeout = DEFAULT_TIMEOUT;
        }

        connectTimeout = recomputeTimeoutValue(connectTimeout, timeout);
        writeOperationTimeout = recomputeTimeoutValue(writeOperationTimeout, timeout);
        readOperationTimeout = recomputeTimeoutValue(readOperationTimeout, timeout);
        closeTimeout = recomputeTimeoutValue(closeTimeout, timeout);
        sendTimeout = recomputeTimeoutValue(sendTimeout, timeout);

        if (checkAliveTimeout == null) {
            checkAliveTimeout = timeout;
        }
    }

    private Long recomputeTimeoutValue(Long timeout, Long globalTimeout) {
        if (Objects.isNull(timeout)) {
            return globalTimeout;
        }
        return timeout;
    }

    // TODO: equals, hashCode

    public boolean useMultiDomain() {
        return servers != null && servers.length > 0;
    }

}

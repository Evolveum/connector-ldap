/*
 * Copyright (c) 2015-2019 Evolveum
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

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.spi.ConfigurationProperty;

import static com.evolveum.polygon.connector.ldap.LdapConstants.OBJECT_CLASS_GROUP_OF_NAMES;

/**
 * LDAP Connector configuration.
 *
 * @author Radovan Semancik
 *
 */
public class LdapConfiguration extends AbstractLdapConfiguration {

    private static final Log LOG = Log.getLog(LdapConfiguration.class);

    /**
     * Specifies strategy of handling account lockouts.
     * Please note that the "openldap" lockout strategy is EXPERIMENTAL.
     * Possible values: "none", "openldap"
     * Default value: "none"
     */
    private String lockoutStrategy = LOCKOUT_STRATEGY_NONE;

    public static final String CONF_PROP_NAME_LOCKOUT_STRATEGY = "lockoutStrategy";

    public static final String LOCKOUT_STRATEGY_NONE = "none";
    public static final String LOCKOUT_STRATEGY_OPENLDAP = "openldap";

    /**
     * DN of the OpenLDAP access log
     */
    private String openLdapAccessLogDn;

    /**
     * optional additional search filter in the OpenLDAP access log
     */
    private String openLdapAccessLogAdditionalFilter;

    /**
     * Attribute that supports language tag (RFC 3866).
     * Those attributes will be presented as Map in the schema. They are designed to match
     * midPoint PolyString, especially its "lang" part.
     * EXPERIMENTAL. Not officially supported. Use at your own risk only.
     */
    private String[] languageTagAttributes;

    /**
     * Normally, when multivalue attribute is used as single-valued attribute then an error is thrown.
     * This is the default behavior, as it is much better at detecting errors in the data. However, it
     * may be a problem, because throwing hard error may prohibit further attempts to correct the value.
     *
     * This configuration property changes that behavior. If tolerateMultivalueReduction is set to true,
     * then the connector will discard all the extra values. Just one of the values will be kept.
     * Connector will try to use the first value. But as LDAP does not guarantee value ordering,
     * that value may be quite arbitrary.
     *
     * EXPERIMENTAL. Not officially supported. Use at your own risk only.
     */
    private boolean tolerateMultivalueReduction;

//    TODO # A add documentation
    private String placeholderMember;

    public LdapConfiguration(){
        // TODO port to Server Specific
        groupObjectClasses = new String[]{OBJECT_CLASS_GROUP_OF_NAMES};
    }

    @ConfigurationProperty(order = 100, allowedValues = { LOCKOUT_STRATEGY_NONE , LOCKOUT_STRATEGY_OPENLDAP })
    public String getLockoutStrategy() {
        return lockoutStrategy;
    }

    public void setLockoutStrategy(String lockoutStrategy) {
        this.lockoutStrategy = lockoutStrategy;
    }

    public boolean isOpenLdapLockoutStrategy() {
        if (lockoutStrategy == null || LdapConfiguration.LOCKOUT_STRATEGY_NONE.equals(lockoutStrategy)) {
            return false;
        } else if (LdapConfiguration.LOCKOUT_STRATEGY_OPENLDAP.equals(lockoutStrategy)) {
            return true;
        } else {
            throw new IllegalStateException("Unknown lockout strategy " + lockoutStrategy);
        }
    }

    @ConfigurationProperty(order = 101)
    public String getOpenLdapAccessLogDn() {
        return this.openLdapAccessLogDn;
    }

    public void setOpenLdapAccessLogDn(String accessLogDn) {
        this.openLdapAccessLogDn = accessLogDn;
    }

    @ConfigurationProperty(order = 102)
    public String getOpenLdapAccessLogAdditionalFilter() {
        return this.openLdapAccessLogAdditionalFilter;
    }

    public void setOpenLdapAccessLogAdditionalFilter(String accessLogAditionalFilter) {
        this.openLdapAccessLogAdditionalFilter = accessLogAditionalFilter;
    }

    @ConfigurationProperty(order = 103)
    public String[] getLanguageTagAttributes() {
        return languageTagAttributes;
    }

    public void setLanguageTagAttributes(String[] languageTagAttribute) {
        this.languageTagAttributes = languageTagAttribute;
    }

    @ConfigurationProperty(order = 104)
    public boolean isTolerateMultivalueReduction() {
        return tolerateMultivalueReduction;
    }

    public void setTolerateMultivalueReduction(boolean tolerateMultivalueReduction) {
        this.tolerateMultivalueReduction = tolerateMultivalueReduction;
    }

    @ConfigurationProperty(order = 105)
    public String getPlaceholderMember() {
        return placeholderMember;
    }

    public void setPlaceholderMember(String placeholderMember) {
        this.placeholderMember = placeholderMember;
    }

    @Override
    public void recompute() {
        if (getUidAttribute() == null) {
            setUidAttribute(SchemaConstants.ENTRY_UUID_AT);
        }
        super.recompute();
    }

}

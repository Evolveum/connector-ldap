/*
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

package com.evolveum.polygon.connector.ldap;

import static org.identityconnectors.common.StringUtil.isBlank;

import org.identityconnectors.framework.common.exceptions.ConfigurationException;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.spi.ConfigurationProperty;

/**
 * LDAP Connector configuration.
 * 
 * @author Radovan Semancik
 *
 */
public class LdapConfiguration extends AbstractLdapConfiguration {

    private static final Log LOG = Log.getLog(LdapConfiguration.class);

    // Nothing to add

	@Override
	public void recompute() {
		if (getUidAttribute() == null) {
			setUidAttribute(ATTRIBUTE_ENTRYUUID_NAME);
		}
		super.recompute();
	}

}
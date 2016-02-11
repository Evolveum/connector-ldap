/**
 * Copyright (c) 2016 Evolveum
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

import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.identityconnectors.common.logging.Log;

/**
 * @author semancik
 *
 */
public class OperationLog {
	
	static final Log LOG = Log.getLog(OperationLog.class);

	public static void logOperationReq(LdapNetworkConnection connection, String format, Object... params) {
		if (LOG.isInfo()) {
			LOG.info(LdapUtil.formatConnectionInfo(connection) + format, params);
		}
	}

	public static void logOperationRes(LdapNetworkConnection connection, String format, Object... params) {
		if (LOG.isInfo()) {
			LOG.info(LdapUtil.formatConnectionInfo(connection) + format, params);
		}
	}

	public static void logOperationErr(LdapNetworkConnection connection, String format, Object... params) {
		if (LOG.isInfo()) {
			LOG.error(LdapUtil.formatConnectionInfo(connection) + format, params);
		}
	}

}

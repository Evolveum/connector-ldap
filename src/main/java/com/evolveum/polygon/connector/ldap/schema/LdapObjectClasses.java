/**
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
package com.evolveum.polygon.connector.ldap.schema;

import java.util.ArrayList;
import java.util.List;

/**
 * @author semancik
 *
 */
public class LdapObjectClasses {

	org.apache.directory.api.ldap.model.schema.ObjectClass ldapLowestStructuralObjectClass;
	List<org.apache.directory.api.ldap.model.schema.ObjectClass> ldapStructuralObjectClasses = new ArrayList<>();
	List<org.apache.directory.api.ldap.model.schema.ObjectClass> ldapAuxiliaryObjectClasses = new ArrayList<>();

	public org.apache.directory.api.ldap.model.schema.ObjectClass getLdapLowestStructuralObjectClass() {
		return ldapLowestStructuralObjectClass;
	}

	public void setLdapLowestStructuralObjectClass(
			org.apache.directory.api.ldap.model.schema.ObjectClass ldapLowestStructuralObjectClass) {
		this.ldapLowestStructuralObjectClass = ldapLowestStructuralObjectClass;
	}

	public List<org.apache.directory.api.ldap.model.schema.ObjectClass> getLdapStructuralObjectClasses() {
		return ldapStructuralObjectClasses;
	}

	public List<org.apache.directory.api.ldap.model.schema.ObjectClass> getLdapAuxiliaryObjectClasses() {
		return ldapAuxiliaryObjectClasses;
	}

	@Override
	public String toString() {
		return "LdapObjectClasses(ldapLowestStructuralObjectClass=" + ldapLowestStructuralObjectClass
				+ ", ldapStructuralObjectClasses=" + ldapStructuralObjectClasses
				+ ", ldapAuxiliaryObjectClasses=" + ldapAuxiliaryObjectClasses + ")";
	}
	
	
}

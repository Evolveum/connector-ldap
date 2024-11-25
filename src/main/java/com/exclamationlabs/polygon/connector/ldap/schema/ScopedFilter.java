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
package com.exclamationlabs.polygon.connector.ldap.schema;

import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.name.Dn;

/**
 * @author semancik
 *
 */
public class ScopedFilter {

    private ExprNode filter = null;
    private Dn baseDn = null;

    public ScopedFilter(ExprNode filter, Dn baseDn) {
        super();
        this.filter = filter;
        this.baseDn = baseDn;
    }

    public ScopedFilter(ExprNode filter) {
        super();
        this.filter = filter;
    }

    public ScopedFilter(Dn baseDn) {
        super();
        this.baseDn = baseDn;
    }

    public ExprNode getFilter() {
        return filter;
    }

    public Dn getBaseDn() {
        return baseDn;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((baseDn == null) ? 0 : baseDn.hashCode());
        result = prime * result + ((filter == null) ? 0 : filter.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        ScopedFilter other = (ScopedFilter) obj;
        if (baseDn == null) {
            if (other.baseDn != null)
                return false;
        } else if (!baseDn.equals(other.baseDn))
            return false;
        if (filter == null) {
            if (other.filter != null)
                return false;
        } else if (!filter.equals(other.filter))
            return false;
        return true;
    }

    @Override
    public String toString() {
        return "ScopedFilter(filter=" + filter + ", baseDn=" + baseDn + ")";
    }

}

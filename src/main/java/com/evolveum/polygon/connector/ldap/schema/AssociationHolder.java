package com.evolveum.polygon.connector.ldap.schema;

import java.util.Objects;

public class AssociationHolder {

    private String name;
    private String associationAttributeName;
    private String subtype;
    private Boolean isRequired;

    public AssociationHolder(String name, String associationAttributeName,String subtype ,Boolean isRequired) {
        this.name = name;
        this.associationAttributeName = associationAttributeName;
        this.subtype = subtype;
        this.isRequired = isRequired;
    }

    public String getName() {
        return name;
    }

    public String getAssociationAttributeName() {
        return associationAttributeName;
    }

    public String getSubtype() {
        return subtype;
    }

    public Boolean getRequired() {
        return isRequired;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AssociationHolder that = (AssociationHolder) o;
        return Objects.equals(getName(), that.getName()) && Objects.equals(getAssociationAttributeName(), that.getAssociationAttributeName()) && Objects.equals(isRequired, that.isRequired);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAssociationAttributeName(), isRequired);
    }

    @Override
    public String toString() {
        return "AssociationHolder{" +
                "name='" + name + '\'' +
                ", associationAttributeName='" + associationAttributeName + '\'' +
                ", subtype='" + subtype + '\'' +
                ", isRequired=" + isRequired +
                '}';
    }
}

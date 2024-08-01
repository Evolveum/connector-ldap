package com.evolveum.polygon.connector.ldap.schema;

import java.util.Objects;

public class AssociationHolder {

    private String name;
    private String associationAttributeName;
    private String otherAttributeInReferenceName;
    private String subtype;
    private String roleInReference;
    private String subjectObjectClassName;
    private String objectObjectClassName;
    private Boolean isRequired;

    public AssociationHolder(String name, String subjectObjectClassName, String objectObjectClassName, String associationAttributeName,
                             String subtype , String roleInReference, String otherAttributeInReferenceName) {

        this.name = name;
        this.subjectObjectClassName = subjectObjectClassName;
        this.objectObjectClassName = objectObjectClassName;
        this.associationAttributeName = associationAttributeName;
        this.subtype = subtype;
        this.roleInReference = roleInReference;
        this.otherAttributeInReferenceName = otherAttributeInReferenceName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getAssociationAttributeName() {
        return associationAttributeName;
    }

    public String getSubtype() {
        return subtype;
    }

    public Boolean isRequired() {
        return isRequired;
    }

    public void setRequired(Boolean required) {
        isRequired = required;
    }

    public String getRoleInReference() {
        return roleInReference;
    }

    public String getSubjectObjectClassName() {
        return subjectObjectClassName;
    }

    public String getObjectObjectClassName() {
        return objectObjectClassName;
    }

    public String getOtherAttributeInReferenceName() {
        return otherAttributeInReferenceName;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AssociationHolder holder = (AssociationHolder) o;
        return Objects.equals(getName(), holder.getName()) && Objects.equals(getAssociationAttributeName(), holder.getAssociationAttributeName()) && Objects.equals(getOtherAttributeInReferenceName(), holder.getOtherAttributeInReferenceName()) && Objects.equals(getSubtype(), holder.getSubtype()) && Objects.equals(getRoleInReference(), holder.getRoleInReference()) && Objects.equals(getSubjectObjectClassName(), holder.getSubjectObjectClassName()) && Objects.equals(getObjectObjectClassName(), holder.getObjectObjectClassName()) && Objects.equals(isRequired, holder.isRequired);
    }

    @Override
    public int hashCode() {
        return Objects.hash(getName(), getAssociationAttributeName(), getOtherAttributeInReferenceName(), getSubtype(), getRoleInReference(), getSubjectObjectClassName(), getObjectObjectClassName(), isRequired);
    }

    @Override
    public String toString() {
        return "AssociationHolder{" +
                "name='" + name + '\'' +
                ", associationAttributeName='" + associationAttributeName + '\'' +
                ", otherAttributeInReferenceName='" + otherAttributeInReferenceName + '\'' +
                ", subtype='" + subtype + '\'' +
                ", roleInReference='" + roleInReference + '\'' +
                ", subjectObjectClassName='" + subjectObjectClassName + '\'' +
                ", objectObjectClassName='" + objectObjectClassName + '\'' +
                ", isRequired=" + isRequired +
                '}';
    }
}

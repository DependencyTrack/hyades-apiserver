package org.dependencytrack.policy.cel.mapping;

public class ProjectPropertyProjection {

    @MappedField(sqlColumnName = "GROUPNAME")
    public String group;

    @MappedField(sqlColumnName = "PROPERTYNAME")
    public String name;

    @MappedField(sqlColumnName = "PROPERTYVALUE")
    public String value;

    @MappedField(sqlColumnName = "PROPERTYTYPE")
    public String type;

}

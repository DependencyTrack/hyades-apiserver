package org.dependencytrack.policy.cel.mapping;

public class LicenseGroupProjection {

    @MappedField(sqlColumnName = "UUID")
    public String uuid;

    @MappedField(sqlColumnName = "NAME")
    public String name;

}

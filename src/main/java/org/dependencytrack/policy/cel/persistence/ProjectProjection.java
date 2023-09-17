package org.dependencytrack.policy.cel.persistence;

import java.util.Date;

public class ProjectProjection {

    public long id;

    @MappedField(sqlColumnName = "UUID")
    public String uuid;

    @MappedField(sqlColumnName = "GROUP")
    public String group;

    @MappedField(sqlColumnName = "NAME")
    public String name;

    @MappedField(sqlColumnName = "VERSION")
    public String version;

    @MappedField(sqlColumnName = "CLASSIFIER")
    public String classifier;

    @MappedField(protoFieldName = "is_active", sqlColumnName = "ACTIVE")
    public Boolean isActive;

    @MappedField(sqlColumnName = "CPE")
    public String cpe;

    @MappedField(sqlColumnName = "PURL")
    public String purl;

    @MappedField(protoFieldName = "swid_tag_id", sqlColumnName = "SWIDTAGID")
    public String swidTagId;

    @MappedField(protoFieldName = "last_bom_import", sqlColumnName = "LAST_BOM_IMPORT")
    public Date lastBomImport;

}

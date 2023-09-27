package org.dependencytrack.policy.cel.mapping;

public class LicenseProjection {

    public static FieldMapping ID_FIELD_MAPPING = new FieldMapping("id", /* protoFieldName */ null, "ID");

    public long id;

    @MappedField(sqlColumnName = "UUID")
    public String uuid;

    @MappedField(protoFieldName = "id", sqlColumnName = "LICENSEID")
    public String licenseId;

    @MappedField(sqlColumnName = "NAME")
    public String name;

    @MappedField(protoFieldName = "is_osi_approved", sqlColumnName = "ISOSIAPPROVED")
    public Boolean isOsiApproved;

    @MappedField(protoFieldName = "is_fsf_libre", sqlColumnName = "FSFLIBRE")
    public Boolean isFsfLibre;

    @MappedField(protoFieldName = "is_deprecated_id", sqlColumnName = "ISDEPRECATED")
    public Boolean isDeprecatedId;

    @MappedField(protoFieldName = "is_custom", sqlColumnName = "ISCUSTOMLICENSE")
    public Boolean isCustomLicense;

    public String licenseGroupsJson;

}

package org.dependencytrack.model.sqlMapping;

import org.dependencytrack.policy.cel.mapping.MappedField;

import java.util.Date;

public class ComponentProjection {

    @MappedField(sqlColumnName = "ID")
    public long id;

    @MappedField(sqlColumnName = "UUID")
    public String uuid;

    @MappedField(sqlColumnName = "AUTHOR")
    public String author;

    @MappedField(sqlColumnName = "GROUP")
    public String group;

    @MappedField(sqlColumnName = "NAME")
    public String name;

    @MappedField(sqlColumnName = "TEXT")
    public String text;

    @MappedField(sqlColumnName = "PUBLISHER")
    public String publisher;

    @MappedField(sqlColumnName = "VERSION")
    public String version;

    @MappedField(sqlColumnName = "CLASSIFIER")
    public String classifier;

    @MappedField(sqlColumnName = "COPYRIGHT")
    public String copyright;

    @MappedField(sqlColumnName = "DESCRIPTION")
    public String description;

    @MappedField(sqlColumnName = "EXTENSION")
    public String extension;

    @MappedField(sqlColumnName = "FILENAME")
    public String filename;

    @MappedField(sqlColumnName = "EXTERNAL_REFERENCES")
    public String externalReferences;

    @MappedField(sqlColumnName = "DIRECT_DEPENDENCIES")
    public String directDependencies;

    @MappedField(sqlColumnName = "CPE")
    public String cpe;

    @MappedField(sqlColumnName = "PURL")
    public String purl;

    @MappedField(sqlColumnName = "PURLCOORDINATES")
    public String purlCoordinates;

    @MappedField(sqlColumnName = "SWIDTAGID")
    public String swidTagId;

    @MappedField(sqlColumnName = "INTERNAL")
    public Boolean internal;

    @MappedField(sqlColumnName = "LAST_RISKSCORE")
    public Double lastInheritedRiskscore;

    @MappedField(sqlColumnName = "MD5")
    public String md5;

    @MappedField(sqlColumnName = "SHA1")
    public String sha1;

    @MappedField(sqlColumnName = "SHA_256")
    public String sha256;

    @MappedField(sqlColumnName = "SHA_384")
    public String sha384;

    @MappedField(sqlColumnName = "SHA_512")
    public String sha512;

    @MappedField(sqlColumnName = "SHA3_256")
    public String sha3_256;

    @MappedField(sqlColumnName = "SHA3_384")
    public String sha3_384;

    @MappedField(sqlColumnName = "SHA3_512")
    public String sha3_512;

    @MappedField(sqlColumnName = "BLAKE2B_256")
    public String blake2b_256;

    @MappedField(sqlColumnName = "BLAKE2B_384")
    public String blake2b_384;

    @MappedField(sqlColumnName = "BLAKE2B_512")
    public String blake2b_512;

    @MappedField(sqlColumnName = "BLAKE3")
    public String blake3;
    @MappedField(sqlColumnName = "LICENSE_URL")
    public String licenseUrl;

    @MappedField(sqlColumnName = "LICENSE")
    public String licenseName;

    @MappedField(sqlColumnName = "LICENSE_EXPRESSION")
    public String licenseExpression;

    @MappedField(sqlColumnName = "PUBLISHED_AT")
    public Date publishedAt;

    @MappedField(sqlColumnName = "LAST_FETCH")
    public Date lastFetch;

    @MappedField(sqlColumnName = "INTEGRITY_CHECK_STATUS")
    public String integrityCheckStatus;

    @MappedField(sqlColumnName = "REPOSITORY_URL")
    public String integrityRepoUrl;

    @MappedField(sqlColumnName = "P_ID")
    public Long projectId;

    @MappedField(sqlColumnName = "P_UUID")
    public String projectUuid;

    @MappedField(sqlColumnName = "P_GROUP")
    public String projectGroup;

    @MappedField(sqlColumnName = "P_NAME")
    public String projectName;

    @MappedField(sqlColumnName = "P_VERSION")
    public String projectVersion;

    @MappedField(sqlColumnName = "P_CLASSIFIER")
    public String projectClassifier;

    @MappedField(sqlColumnName = "P_ACTIVE")
    public Boolean projectActive;

    @MappedField(sqlColumnName = "P_AUTHOR")
    public String projectAuthor;

    @MappedField(sqlColumnName = "P_CPE")
    public String projectCpe;

    @MappedField(sqlColumnName = "P_DESCRIPTION")
    public String projectDescription;

    @MappedField(sqlColumnName = "P_PURL")
    public String projectPurl;

    @MappedField(sqlColumnName = "P_SWIDTAGID")
    public String projectSwidTagId;

    @MappedField(sqlColumnName = "LAST_BOM_IMPORTED")
    public Date lastBomImport;

    @MappedField(sqlColumnName = "LAST_BOM_IMPORTED_FORMAT")
    public String lastBomImportFormat;

    @MappedField(sqlColumnName = "P_LAST_RISKSCORE")
    public Double projectLastInheritedRiskScore;

    @MappedField(sqlColumnName = "P_DIRECT_DEPENDENCIES")
    public String projectDirectDependencies;

    @MappedField(sqlColumnName = "P_EXTERNAL_REFERENCES")
    public String projectExternalReferences;

    @MappedField(sqlColumnName = "P_PUBLISHER")
    public String projectPublisher;

    @MappedField(sqlColumnName = "L_UUID")
    public String licenseUuid;

    @MappedField(sqlColumnName = "LICENSEID")
    public String licenseId;

    @MappedField(sqlColumnName = "ISOSIAPPROVED")
    public Boolean isOsiApproved;

    @MappedField(sqlColumnName = "FSFLIBRE")
    public Boolean isFsfLibre;

    @MappedField(sqlColumnName = "ISCUSTOMLICENSE")
    public Boolean isCustomLicense;

    @MappedField(sqlColumnName = "TOTAL_COUNT")
    public Long totalCount;
}

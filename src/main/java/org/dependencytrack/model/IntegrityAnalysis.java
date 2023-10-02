package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotNull;
import java.util.Date;

@PersistenceCapable(table = "INTEGRITY_ANALYSIS")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class IntegrityAnalysis {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;

    /**
     * This is a representation of the Package URL "name" field.
     */
    @Persistent
    @Column(name = "REPOSITORY_IDENTIFIER", allowsNull = "false")
    @NotNull
    private String repositoryIdentifier;

    /**
     * The latest version of the component.
     */
    @Persistent
    @Column(name = "MD5_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus md5HashMatchStatus;

    @Persistent
    @Column(name = "SHA256_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus sha256HashMatchStatus;

    @Persistent
    @Column(name = "SHA1_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus sha1HashMatchStatus;

    @Persistent
    @Column(name = "INTEGRITY_CHECK_PASSED", allowsNull = "false")
    @NotNull
    private boolean integrityCheckPassed;

    private Date updatedAt;


    public boolean isIntegrityCheckPassed() {
        return integrityCheckPassed;
    }

    public void setIntegrityCheckPassed(boolean integrityCheckPassed) {
        this.integrityCheckPassed = integrityCheckPassed;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }


    public String getRepositoryIdentifier() {
        return repositoryIdentifier;
    }

    public void setRepositoryIdentifier(String repositoryIdentifier) {
        this.repositoryIdentifier = repositoryIdentifier;
    }

    public Component getComponent() {
        return component;
    }

    public void setComponent(Component component) {
        this.component = component;
    }

    public IntegrityMatchStatus getMd5HashMatchStatus() {
        return md5HashMatchStatus;
    }

    public void setMd5HashMatchStatus(IntegrityMatchStatus md5HashMatchStatus) {
        this.md5HashMatchStatus = md5HashMatchStatus;
    }

    public IntegrityMatchStatus getSha256HashMatchStatus() {
        return sha256HashMatchStatus;
    }

    public void setSha256HashMatchStatus(IntegrityMatchStatus sha256HashMatchStatus) {
        this.sha256HashMatchStatus = sha256HashMatchStatus;
    }

    public IntegrityMatchStatus getSha1HashMatchStatus() {
        return sha1HashMatchStatus;
    }

    public void setSha1HashMatchStatus(IntegrityMatchStatus sha1HashMatchStatus) {
        this.sha1HashMatchStatus = sha1HashMatchStatus;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }
}

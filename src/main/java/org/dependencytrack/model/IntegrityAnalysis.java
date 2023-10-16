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

    @Persistent
    @Column(name = "COMPONENT_ID", allowsNull = "false")
    @NotNull
    private Component component;

    /**
     * The latest version of the component.
     */
    @Persistent
    @Column(name = "MD5_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus md5HashMatchStatus;

    @Persistent
    @Column(name = "SHA1_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus sha1HashMatchStatus;

    @Persistent
    @Column(name = "SHA256_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus sha256HashMatchStatus;

    @Persistent
    @Column(name = "SHA512_HASH_MATCH_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus sha512HashMatchStatus;

    @Persistent
    @Column(name = "INTEGRITY_CHECK_STATUS", allowsNull = "false")
    @NotNull
    private IntegrityMatchStatus integrityCheckStatus;

    @Persistent
    @Column(name = "UPDATED_AT", allowsNull = "false")
    @NotNull
    private Date updatedAt;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
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

    public IntegrityMatchStatus getSha512HashMatchStatus() {
        return sha512HashMatchStatus;
    }

    public void setSha512HashMatchStatus(IntegrityMatchStatus sha512HashMatchStatus) {
        this.sha512HashMatchStatus = sha512HashMatchStatus;
    }

    public IntegrityMatchStatus getIntegrityCheckStatus() {
        return integrityCheckStatus;
    }

    public void setIntegrityCheckStatus(IntegrityMatchStatus integrityCheckStatus) {
        this.integrityCheckStatus = integrityCheckStatus;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }
}

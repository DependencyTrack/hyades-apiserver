package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.Extension;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.jdo.annotations.Unique;
import javax.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;
import java.util.UUID;

@PersistenceCapable(table= "WORKFLOW_STATE")
@JsonInclude(JsonInclude.Include.NON_NULL)
@Unique(name = "WORKFLOW_STATE_COMPOSITE_IDX", members = {"token", "step"})
public class WorkflowState implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    // null allowed because first step will have no parent and will be the first step of recursion
    @Persistent
    @Column(name = "PARENT_STEP_ID" , allowsNull = "true")
    private WorkflowState parent;

    @Persistent
    @Column(name = "TOKEN", jdbcType = "VARCHAR", length = 36, allowsNull = "false")
    @NotNull
    private UUID token;

    @Persistent
    @Column(name = "STARTED_AT", allowsNull = "true")
    private Date startedAt;

    @Persistent
    @Column(name = "UPDATED_AT", allowsNull = "false")
    private Date updatedAt;

    @Persistent
    @Column(name = "STEP", jdbcType = "VARCHAR", length = 64, allowsNull = "false")
    @NotNull
    @Extension(vendorName = "datanucleus", key = "enum-check-constraint", value = "true")
    private WorkflowStep step;

    @Persistent
    @Column(name = "STATUS", jdbcType = "VARCHAR", length = 64, allowsNull = "false")
    @NotNull
    @Extension(vendorName = "datanucleus", key = "enum-check-constraint", value = "true")
    private WorkflowStatus status;

    @Persistent
    @Column(name = "FAILURE_REASON", jdbcType = "CLOB", allowsNull = "true")
    private String failureReason;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public WorkflowState getParent() {
        return parent;
    }

    public void setParent(WorkflowState parent) {
        this.parent = parent;
    }

    public UUID getToken() {
        return token;
    }

    public void setToken(UUID token) {
        this.token = token;
    }

    public Date getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Date startedAt) {
        this.startedAt = startedAt;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }

    public WorkflowStep getStep() {
        return step;
    }

    public void setStep(WorkflowStep step) {
        this.step = step;
    }

    public WorkflowStatus getStatus() {
        return status;
    }

    public void setStatus(WorkflowStatus status) {
        this.status = status;
    }

    public String getFailureReason() {
        return failureReason;
    }

    public void setFailureReason(String failureReason) {
        this.failureReason = failureReason;
    }
}

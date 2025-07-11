/*
 * This file is generated by jOOQ.
 */
package org.dependencytrack.persistence.jooq.generated.tables.records;


import java.time.OffsetDateTime;
import java.util.UUID;

import org.dependencytrack.persistence.jooq.generated.tables.PolicyViolation;
import org.jooq.Record1;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class PolicyViolationRecord extends UpdatableRecordImpl<PolicyViolationRecord> {

    private static final long serialVersionUID = -340769378;

    /**
     * Setter for <code>POLICYVIOLATION.ID</code>.
     */
    public PolicyViolationRecord setId(Long value) {
        set(0, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.ID</code>.
     */
    public Long getId() {
        return (Long) get(0);
    }

    /**
     * Setter for <code>POLICYVIOLATION.COMPONENT_ID</code>.
     */
    public PolicyViolationRecord setComponentId(Long value) {
        set(1, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.COMPONENT_ID</code>.
     */
    public Long getComponentId() {
        return (Long) get(1);
    }

    /**
     * Setter for <code>POLICYVIOLATION.POLICYCONDITION_ID</code>.
     */
    public PolicyViolationRecord setPolicyconditionId(Long value) {
        set(2, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.POLICYCONDITION_ID</code>.
     */
    public Long getPolicyconditionId() {
        return (Long) get(2);
    }

    /**
     * Setter for <code>POLICYVIOLATION.PROJECT_ID</code>.
     */
    public PolicyViolationRecord setProjectId(Long value) {
        set(3, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.PROJECT_ID</code>.
     */
    public Long getProjectId() {
        return (Long) get(3);
    }

    /**
     * Setter for <code>POLICYVIOLATION.TEXT</code>.
     */
    public PolicyViolationRecord setText(String value) {
        set(4, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.TEXT</code>.
     */
    public String getText() {
        return (String) get(4);
    }

    /**
     * Setter for <code>POLICYVIOLATION.TIMESTAMP</code>.
     */
    public PolicyViolationRecord setTimestamp(OffsetDateTime value) {
        set(5, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.TIMESTAMP</code>.
     */
    public OffsetDateTime getTimestamp() {
        return (OffsetDateTime) get(5);
    }

    /**
     * Setter for <code>POLICYVIOLATION.TYPE</code>.
     */
    public PolicyViolationRecord setType(String value) {
        set(6, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.TYPE</code>.
     */
    public String getType() {
        return (String) get(6);
    }

    /**
     * Setter for <code>POLICYVIOLATION.UUID</code>.
     */
    public PolicyViolationRecord setUuid(UUID value) {
        set(7, value);
        return this;
    }

    /**
     * Getter for <code>POLICYVIOLATION.UUID</code>.
     */
    public UUID getUuid() {
        return (UUID) get(7);
    }

    // -------------------------------------------------------------------------
    // Primary key information
    // -------------------------------------------------------------------------

    @Override
    public Record1<Long> key() {
        return (Record1) super.key();
    }

    // -------------------------------------------------------------------------
    // Constructors
    // -------------------------------------------------------------------------

    /**
     * Create a detached PolicyViolationRecord
     */
    public PolicyViolationRecord() {
        super(PolicyViolation.POLICYVIOLATION);
    }

    /**
     * Create a detached, initialised PolicyViolationRecord
     */
    public PolicyViolationRecord(Long id, Long componentId, Long policyconditionId, Long projectId, String text, OffsetDateTime timestamp, String type, UUID uuid) {
        super(PolicyViolation.POLICYVIOLATION);

        setId(id);
        setComponentId(componentId);
        setPolicyconditionId(policyconditionId);
        setProjectId(projectId);
        setText(text);
        setTimestamp(timestamp);
        setType(type);
        setUuid(uuid);
        resetTouchedOnNotNull();
    }
}

/*
 * This file is generated by jOOQ.
 */
package org.dependencytrack.persistence.jooq.generated.tables.records;


import java.util.UUID;

import org.dependencytrack.persistence.jooq.generated.tables.LicenseGroup;
import org.jooq.Record1;
import org.jooq.impl.UpdatableRecordImpl;


/**
 * This class is generated by jOOQ.
 */
@SuppressWarnings({ "all", "unchecked", "rawtypes", "this-escape" })
public class LicenseGroupRecord extends UpdatableRecordImpl<LicenseGroupRecord> {

    private static final long serialVersionUID = -728464739;

    /**
     * Setter for <code>LICENSEGROUP.ID</code>.
     */
    public LicenseGroupRecord setId(Long value) {
        set(0, value);
        return this;
    }

    /**
     * Getter for <code>LICENSEGROUP.ID</code>.
     */
    public Long getId() {
        return (Long) get(0);
    }

    /**
     * Setter for <code>LICENSEGROUP.NAME</code>.
     */
    public LicenseGroupRecord setName(String value) {
        set(1, value);
        return this;
    }

    /**
     * Getter for <code>LICENSEGROUP.NAME</code>.
     */
    public String getName() {
        return (String) get(1);
    }

    /**
     * Setter for <code>LICENSEGROUP.RISKWEIGHT</code>.
     */
    public LicenseGroupRecord setRiskweight(Integer value) {
        set(2, value);
        return this;
    }

    /**
     * Getter for <code>LICENSEGROUP.RISKWEIGHT</code>.
     */
    public Integer getRiskweight() {
        return (Integer) get(2);
    }

    /**
     * Setter for <code>LICENSEGROUP.UUID</code>.
     */
    public LicenseGroupRecord setUuid(UUID value) {
        set(3, value);
        return this;
    }

    /**
     * Getter for <code>LICENSEGROUP.UUID</code>.
     */
    public UUID getUuid() {
        return (UUID) get(3);
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
     * Create a detached LicenseGroupRecord
     */
    public LicenseGroupRecord() {
        super(LicenseGroup.LICENSEGROUP);
    }

    /**
     * Create a detached, initialised LicenseGroupRecord
     */
    public LicenseGroupRecord(Long id, String name, Integer riskweight, UUID uuid) {
        super(LicenseGroup.LICENSEGROUP);

        setId(id);
        setName(name);
        setRiskweight(riskweight);
        setUuid(uuid);
        resetTouchedOnNotNull();
    }
}

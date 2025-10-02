package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.*;

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CsafMapping {
    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    private Long id;

    @Persistent
    @ForeignKey(name="CSAFDOCUMENT_FK")
    @Column(name="CSAFDOCUMENT_ID")
    private CsafDocumentEntity csafDocument;

    @Persistent
    @ForeignKey(name="VULNERABILITY_FK")
    @Column(name="VULNERABILITY_ID")
    private Vulnerability vulnerability;

    public CsafMapping() {
    }

    public CsafMapping(CsafDocumentEntity csafDocument, Vulnerability vulnerability) {
        this.csafDocument = csafDocument;
        this.vulnerability = vulnerability;
    }

    public CsafMapping(Long id, CsafDocumentEntity csafDocument, Vulnerability vulnerability) {
        this.id = id;
        this.csafDocument = csafDocument;
        this.vulnerability = vulnerability;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public CsafDocumentEntity getCsafDocument() {
        return csafDocument;
    }

    public void setCsafDocument(CsafDocumentEntity csafDocument) {
        this.csafDocument = csafDocument;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }
}


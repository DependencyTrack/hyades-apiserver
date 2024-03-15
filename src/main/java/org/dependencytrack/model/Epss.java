package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import javax.validation.constraints.NotBlank;
import java.io.Serializable;
import java.math.BigDecimal;

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Epss implements Serializable {

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "CVE", allowsNull = "false")
    @NotBlank
    private String cve;

    @Persistent
    @Column(name = "EPSS", scale = 5)
    private BigDecimal epss;

    @Persistent
    @Column(name = "PERCENTILE", scale = 5)
    private BigDecimal Percentile;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getCve() {
        return cve;
    }

    public void setCve(String cve) {
        this.cve = cve;
    }

    public BigDecimal getEpss() {
        return epss;
    }

    public void setEpss(BigDecimal epss) {
        this.epss = epss;
    }

    public BigDecimal getPercentile() {
        return Percentile;
    }

    public void setPercentile(BigDecimal percentile) {
        Percentile = percentile;
    }
}

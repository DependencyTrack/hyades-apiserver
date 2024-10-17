/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.Index;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;
import jakarta.validation.constraints.NotNull;
import java.io.Serializable;
import java.util.Date;

/**
 * Metrics specific for cryptographic assets.
 *
 * @author Nicklas Körtge
 * @since 5.5.0
 */

@PersistenceCapable
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CryptographyMetrics implements Serializable {

    private static final long serialVersionUID = 1231893328584979791L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "NUMBER_OF_CRYPTOGRAPHIC_ASSETS")
    private int numberOfCryptographicAssets;

    @Persistent
    @Column(name = "MOST_USED_ALGORITHM_NAME")
    private String mostUsedAlgorithmName;

    @Persistent
    @Column(name = "MOST_USED_ALGORITHM_PERCENTAGE")
    private double mostUsedAlgorithmPercentage;

    @Persistent
    @Column(name = "NUMBER_OF_KEYS")
    private int numberOfKeys;

    @Persistent
    @Column(name = "FIRST_OCCURRENCE", allowsNull = "false")
    @NotNull
    @Index(name = "CRYPTOGRAPHY_METRICS_FIRST_OCCURRENCE_IDX")
    private Date firstOccurrence;

    @Persistent
    @Column(name = "LAST_OCCURRENCE", allowsNull = "false")
    @NotNull
    @Index(name = "CRYPTOGRAPHY_METRICS_LAST_OCCURRENCE_IDX")
    private Date lastOccurrence;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public int getNumberOfCryptographicAssets() {
        return numberOfCryptographicAssets;
    }

    public void setNumberOfCryptographicAssets(int numberOfCryptographicAssets) {
        this.numberOfCryptographicAssets = numberOfCryptographicAssets;
    }

    public String getMostUsedAlgorithmName() {
        return mostUsedAlgorithmName;
    }

    public void setMostUsedAlgorithmName(String mostUsedAlgorithmName) {
        this.mostUsedAlgorithmName = mostUsedAlgorithmName;
    }

    public double getMostUsedAlgorithmPercentage() {
        return mostUsedAlgorithmPercentage;
    }

    public void setMostUsedAlgorithmPercentage(double mostUsedAlgorithmPercentage) {
        this.mostUsedAlgorithmPercentage = mostUsedAlgorithmPercentage;
    }

    public int getNumberOfKeys() {
        return numberOfKeys;
    }

    public void setNumberOfKeys(int numberOfKeys) {
        this.numberOfKeys = numberOfKeys;
    }

    public @NotNull Date getFirstOccurrence() {
        return firstOccurrence;
    }

    public void setFirstOccurrence(@NotNull Date firstOccurrence) {
        this.firstOccurrence = firstOccurrence;
    }

    public @NotNull Date getLastOccurrence() {
        return lastOccurrence;
    }

    public void setLastOccurrence(@NotNull Date lastOccurrence) {
        this.lastOccurrence = lastOccurrence;
    }
}

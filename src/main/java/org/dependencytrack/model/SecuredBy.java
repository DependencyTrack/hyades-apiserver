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
package  org.dependencytrack.model;

import javax.jdo.annotations.Column;
import javax.jdo.annotations.IdGeneratorStrategy;
import javax.jdo.annotations.PersistenceCapable;
import javax.jdo.annotations.Persistent;
import javax.jdo.annotations.PrimaryKey;

import org.cyclonedx.model.component.crypto.enums.Mechanism;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;

@PersistenceCapable(table = "SECURED_BY")
@JsonInclude(JsonInclude.Include.NON_NULL)
public class SecuredBy {
    private static final long serialVersionUID = 6421255046930674875L;

    @PrimaryKey
    @Persistent(valueStrategy = IdGeneratorStrategy.NATIVE)
    @JsonIgnore
    private long id;

    @Persistent
    @Column(name = "MECHANISM", jdbcType = "VARCHAR", length=16)
    private Mechanism mechanism;

    @Persistent
    @Column(name = "ALGORITHM_REF", jdbcType = "VARCHAR", length=64)
    private String algorithmRef;

    public Mechanism getMechanism() {
        return mechanism;
    }

    public void setMechanism(Mechanism mechanism) {
        this.mechanism = mechanism;
    }

    public String getAlgorithmRef() {
        return algorithmRef;
    }

    public void setAlgorithmRef(String algorithmRef) {
        this.algorithmRef = algorithmRef;
    }
}

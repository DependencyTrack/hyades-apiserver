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
package org.dependencytrack.datasource.vuln.osv;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.google.protobuf.util.JsonFormat;
import net.javacrumbs.jsonunit.core.Option;
import org.cyclonedx.proto.v1_6.Bom;
import org.cyclonedx.proto.v1_6.Vulnerability;
import org.dependencytrack.datasource.vuln.osv.schema.OsvSchema;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.List;

import static net.javacrumbs.jsonunit.assertj.JsonAssertions.assertThatJson;
import static org.dependencytrack.datasource.vuln.osv.ModelConverter.trimSummary;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

public class ModelConverterTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .registerModule(new JavaTimeModule());

    @Test
    void testParseOsvToBomWithAliasEnabled() throws IOException {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-GHSA-77rv-6vfw-x4gc.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, true, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                            "components": [{
                              "bomRef": "${json-unit.any-string}",
                              "name": "org.springframework.security.oauth:spring-security-oauth",
                              "purl": "pkg:maven/org.springframework.security.oauth/spring-security-oauth"
                            }],
                            "vulnerabilities": [{
                              "id": "GHSA-77rv-6vfw-x4gc",
                              "source": {
                                "name": "GITHUB"
                              },
                              "references": [{
                                "id": "CVE-2019-3778",
                                "source": {
                                  "name": "NVD"
                                }
                              }],
                              "ratings": [{
                                "score": 9.0,
                                "severity": "SEVERITY_CRITICAL",
                                "method": "SCORE_METHOD_CVSSV31",
                                "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H"
                              }],
                              "cwes": [601],
                              "description": "Spring Security OAuth, versions 2.3 prior to 2.3.5, and 2.2 prior to 2.2.4, and 2.1 prior to 2.1.4, and 2.0 prior to 2.0.17, and older unsupported versions could be susceptible to an open redirector attack that can leak an authorization code.\\n\\nA malicious user or attacker can craft a request to the authorization endpoint using the authorization code grant type, and specify a manipulated redirection URI via the \\"redirect_uri\\" parameter. This can cause the authorization server to redirect the resource owner user-agent to a URI under the control of the attacker with the leaked authorization code.\\n\\nThis vulnerability exposes applications that meet all of the following requirements: Act in the role of an Authorization Server (e.g. @EnableAuthorizationServer) and uses the DefaultRedirectResolver in the AuthorizationEndpoint. \\n\\nThis vulnerability does not expose applications that: Act in the role of an Authorization Server and uses a different RedirectResolver implementation other than DefaultRedirectResolver, act in the role of a Resource Server only (e.g. @EnableResourceServer), act in the role of a Client only (e.g. @EnableOAuthClient).",
                              "published": "2019-03-14T15:39:30Z",
                              "updated": "2022-06-09T07:01:32Z",
                              "credits": {
                                "individuals": [{
                                  "name": "Skywalker"
                                }, {
                                  "name": "Solo"
                                }]
                              },
                              "affects": [{
                                "ref": "${json-unit.any-string}",
                                "versions": [{
                                  "range": "vers:maven/>=0|<2.0.17"
                                }]
                              }],
                              "properties": [
                                {
                                   "name": "dependency-track:vuln:title",
                                   "value": "Critical severity vulnerability that affects org.springframework.security.oauth:spring-security-oauth and org.springframework.security.oauth:spring-security-oauth2"
                                },
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                            }]
                          }
                        """);
    }

    @Test
    void testParseOsvToBomWithAliasDisabled() throws IOException {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-GHSA-77rv-6vfw-x4gc.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertNotNull(bom);

        List<Vulnerability> vulnerabilities = bom.getVulnerabilitiesList();
        assertNotNull(vulnerabilities);
        assertEquals(1, vulnerabilities.size());
        Vulnerability vulnerability = vulnerabilities.get(0);
        assertEquals(0, vulnerability.getReferencesList().size());
    }

    @Test
    void testVulnerabilityRanges() throws IOException {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-vulnerability-with-ranges.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "components": [{
                             "bomRef": "${json-unit.any-string}",
                             "name": "org.springframework.security.oauth:spring-security-oauth2",
                             "purl": "pkg:maven/org.springframework.security.oauth/spring-security-oauth2"
                           }, {
                             "bomRef": "${json-unit.any-string}",
                             "name": "org.springframework.security.oauth:spring-security-oauth",
                             "purl": "pkg:maven/org.springframework.security.oauth/spring-security-oauth"
                           }],
                           "vulnerabilities": [{
                             "id": "GSD-2022-1000008",
                             "source": {
                               "name": "OSV"
                             },
                             "ratings": [{
                               "severity": "SEVERITY_UNKNOWN"
                             }],
                             "description": "faker.js had it's version updated to 6.6.6 in NPM (which reports it as having 2,571 dependent packages that rely upon it) and the GitHub repo has been wiped of content. This appears to have been done intentionally as the repo only has a single commit (so it was likjely deleted, recreated and a single commit with \\"endgame\\" added). It appears that both GitHub and NPM have locked out the original developer accountbut that the faker.js package is still broken. Please note that this issue is directly related to GSD-2022-1000007 and appears to be part of the same incident. A fork of the repo with the original code appears to now be available at https://github.com/faker-js/faker",
                             "published": "2022-01-09T02:46:05Z",
                             "updated": "2022-01-09T11:37:01Z",
                             "affects": [{
                                "ref": "${json-unit.any-string}",
                                "versions": [
                                    {"version": "1.0.0.RELEASE"},
                                    {"version": "1.0.1.RELEASE"}
                                ]
                             }, {
                               "ref": "${json-unit.any-string}",
                               "versions": [
                                    { "range": "vers:maven/>=0|<2.0.17" }
                                ]
                             }, {
                               "ref": "${json-unit.any-string}",
                               "versions": [
                                    { "range": "vers:maven/>=1|<2|>=3|<4"}, 
                                    { "range":"vers:maven/>=0|<1" }
                               ]
                             }, {
                                "ref": "${json-unit.any-string}",
                                "versions": [
                                    {"version":"1.0.0.RELEASE"}, 
                                    {"version":"2.0.9.RELEASE"}
                                ]
                             }, {
                               "ref": "${json-unit.any-string}",
                               "versions": [{
                                 "range": "vers:maven/>=3.1.0|<3.3.0"
                               }]
                             }, {
                               "ref": "${json-unit.any-string}",
                               "versions": [{
                                 "range": "vers:maven/>=10|<13"
                               }]
                             }, {
                               "ref": "${json-unit.any-string}",
                               "versions": [
                                { "range": "vers:maven/>=10|<=29.0" }
                               ]
                             }],
                             "properties": [
                                {
                                   "name": "dependency-track:vuln:title",
                                   "value": "faker.js 6.6.6 is broken and the developer has wiped the original GitHub repo"
                                },
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                           }]
                         }
                        """);
    }

    @Test
    void testVulnerabilityRangeWithNoRange() throws IOException {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-vulnerability-no-range.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, true, "maven");

        //Then
        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "vulnerabilities": [{
                             "id": "GSD-2022-1000008",
                             "source": {
                               "name": "OSV"
                             },
                             "ratings": [{
                               "severity": "SEVERITY_UNKNOWN"
                             }],
                             "description": "faker.js had it's version updated to 6.6.6 in NPM (which reports it as having 2,571 dependent packages that rely upon it) and the GitHub repo has been wiped of content. This appears to have been done intentionally as the repo only has a single commit (so it was likjely deleted, recreated and a single commit with \\"endgame\\" added). It appears that both GitHub and NPM have locked out the original developer accountbut that the faker.js package is still broken. Please note that this issue is directly related to GSD-2022-1000007 and appears to be part of the same incident. A fork of the repo with the original code appears to now be available at https://github.com/faker-js/faker",
                             "published": "2022-01-09T02:46:05Z",
                             "updated": "2022-01-09T11:37:01Z",
                             "properties": [
                                {
                                   "name": "dependency-track:vuln:title",
                                   "value": "faker.js 6.6.6 is broken and the developer has wiped the original GitHub repo"
                                },
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                           }]
                         }
                        """);
    }

    @Test
    void testTrimSummary() {

        String osvLongSummary = "In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not needed for exploitation.";
        String trimmedSummary = trimSummary(osvLongSummary);
        assertNotNull(trimmedSummary);
        assertEquals(255, trimmedSummary.length());
        assertEquals("In uvc_scan_chain_forward of uvc_driver.c, there is a possible linked list corruption due to an unusual root cause. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed. User interaction is not ne..", trimmedSummary);

        osvLongSummary = "I'm a short Summary";
        trimmedSummary = trimSummary(osvLongSummary);
        assertNotNull(trimmedSummary);
        assertEquals("I'm a short Summary", trimmedSummary);

        osvLongSummary = null;
        trimmedSummary = trimSummary(osvLongSummary);
        assertNull(trimmedSummary);
    }

    @Test
    void testCommitHashRanges() throws IOException {

        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-git-commit-hash-ranges.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, true, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .when(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                           "components": [{
                             "bomRef": "${json-unit.any-string}",
                             "name": "radare2",
                             "purl": "pkg:generic/radare2"
                           }],
                           "externalReferences": [{
                             "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id\\u003d48098"
                           }],
                           "vulnerabilities": [{
                             "id": "OSV-2021-1820",
                             "source": {
                               "name": "OSV"
                             },
                             "ratings": [{
                               "severity": "SEVERITY_MEDIUM"
                             }],
                             "description": "details",
                             "published": "2022-06-19T00:00:52Z",
                             "updated": "2022-06-19T00:00:52Z",
                             "affects": [{
                               "ref": "${json-unit.any-string}",
                               "versions": [{
                                 "version": "5.4.0-git"
                               }, {
                                 "version": "release-5.0.0"
                               }]
                             }],
                             "properties": [
                                {
                                   "name": "dependency-track:vuln:title",
                                   "value": "Heap-buffer-overflow in r_str_utf8_codepoint"
                                },
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                           }]
                         }
                        """);
    }

    @Test
    void testParseWithTwoUpperBoundRangeConstraints() throws Exception {

        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-git-upper-bound-range.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "components": [
                            {
                              "bomRef": "${json-unit.any-string}",
                              "name": "k8s.io/kubernetes",
                              "purl": "pkg:golang/k8s.io/kubernetes"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "GHSA-g42g-737j-qx6j",
                              "source": {
                                "name": "GITHUB"
                              },
                              "ratings": [
                                {
                                  "severity": "SEVERITY_UNKNOWN"
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "${json-unit.any-string}",
                                  "versions": [
                                    {
                                      "range": "vers:golang/>=0|<1.18.18"
                                    }
                                  ]
                                }
                              ],
                              "properties": [
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testParseWithNoUpperBoundRangeConstraintsAndCallstack() throws Exception {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-git-no-upper-bound-range.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "components": [
                            {
                              "bomRef": "${json-unit.any-string}",
                              "name": "github.com/blevesearch/bleve",
                              "purl": "pkg:golang/github.com/blevesearch/bleve"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "GO-2022-0470",
                              "source": {
                                "name": "OSV"
                              },
                              "ratings": [
                                {
                                  "severity": "SEVERITY_UNKNOWN"
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "${json-unit.any-string}",
                                  "versions": [
                                    {
                                      "range": "vers:golang/>=0"
                                    }
                                  ]
                                }
                              ],
                              "properties": [
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testParseWithNoUpperBoundRangeConstraintButExactVersion() throws Exception {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-vulnerability-exact-version.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "components": [
                            {
                              "bomRef": "${json-unit.any-string}",
                              "name": "yandex-yt-yson-bindings",
                              "purl": "pkg:npm/yandex-yt-yson-bindings"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "MAL-2023-995",
                              "source": {
                                "name": "OSV"
                              },
                              "ratings": [
                                {
                                  "severity": "SEVERITY_UNKNOWN"
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "${json-unit.any-string}",
                                  "versions": [
                                    {
                                      "version":"103.99.99"
                                    }
                                  ]
                                }
                              ],
                              "properties": [
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testParseWithConflictingUpperBoundRangeConstraints() throws Exception {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-git-conflict-upper-bound-range.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "components": [
                            {
                              "bomRef": "${json-unit.any-string}",
                              "name": "github.com/argoproj/argo-cd",
                              "purl": "pkg:golang/github.com/argoproj/argo-cd"
                            }
                          ],
                          "vulnerabilities": [
                            {
                              "id": "GHSA-h4w9-6x78-8vrj",
                              "source": {
                                "name": "GITHUB"
                              },
                              "ratings": [
                                {
                                  "severity": "SEVERITY_UNKNOWN"
                                }
                              ],
                              "affects": [
                                {
                                  "ref": "${json-unit.any-string}",
                                  "versions": [
                                    {
                                      "range": "vers:golang/>=1.0.0|<2.1.16"
                                    }
                                  ]
                                }
                              ],
                              "properties": [
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                            }
                          ]
                        }
                        """);
    }

    @Test
    void testParseWithInvalidCvssVectors() throws Exception {
        //given
        var osvSchemaInput = MAPPER.readValue(getClass().getResource("/osv-vulnerability-invalid-cvss.json"), OsvSchema.class);

        //when
        Bom bom = ModelConverter.convert(osvSchemaInput, false, "maven");

        //then
        assertThatJson(JsonFormat.printer().print(bom))
                .withOptions(Option.IGNORING_ARRAY_ORDER)
                .isEqualTo("""
                        {
                          "vulnerabilities": [
                            {
                              "id": "GHSA-77rv-6vfw-x4gc",
                              "source": {
                                "name": "GITHUB"
                              },
                              "ratings": [
                                {
                                  "score": 7.2,
                                  "severity": "SEVERITY_HIGH",
                                  "method": "SCORE_METHOD_CVSSV3",
                                  "vector": "CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
                                },
                                {
                                  "score": 2.6,
                                  "severity": "SEVERITY_LOW",
                                  "method": "SCORE_METHOD_CVSSV2",
                                  "vector": "AV:N/AC:H/Au:N/C:P/I:N/A:N"
                                }
                              ],
                              "properties": [
                                {
                                    "name": "internal:osv:ecosystem",
                                    "value": "maven"
                                }]
                            }
                          ]
                        }
                        """);
    }
}

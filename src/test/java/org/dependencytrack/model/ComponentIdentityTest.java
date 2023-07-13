package org.dependencytrack.model;

import com.github.packageurl.PackageURL;
import junitparams.JUnitParamsRunner;
import junitparams.Parameters;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(JUnitParamsRunner.class)
public class ComponentIdentityTest {

    @SuppressWarnings("unused")
    private Object[] testEqualsAndHashCodeParams() throws Exception {
        return new Object[]{
                // Equal
                new Object[]{
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        true
                },
                // Different coordinates
                new Object[]{
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "otherGroup",
                                "otherName",
                                "otherVersion"
                        ),
                        false
                },
                // Different version
                new Object[]{
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "otherVersion"
                        ),
                        false
                },
                // Different PURLs
                new Object[]{
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/otherGroup/otherName@otherVersion"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        false
                },
                // Different CPEs
                new Object[]{
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "otherCpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        false
                },
                // Different SWID Tag ID
                new Object[]{
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "swidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        new ComponentIdentity(
                                new PackageURL("pkg:maven/group/name@version"),
                                "cpe",
                                "otherSwidTagId",
                                "group",
                                "name",
                                "version"
                        ),
                        false
                }
        };
    }

    @Test
    @Parameters(method = "testEqualsAndHashCodeParams")
    public void testEqualsAndHashCode(final ComponentIdentity left, final ComponentIdentity right, final boolean expectEqual) {
        if (expectEqual) {
            assertThat(left).isEqualTo(right);
            assertThat(right).isEqualTo(left);
            assertThat(left.hashCode()).isEqualTo(right.hashCode());
        } else {
            assertThat(left).isNotEqualTo(right);
            assertThat(right).isNotEqualTo(left);
            assertThat(left.hashCode()).isNotEqualTo(right.hashCode());
        }
    }


}
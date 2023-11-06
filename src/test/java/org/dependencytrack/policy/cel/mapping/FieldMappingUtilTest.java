package org.dependencytrack.policy.cel.mapping;

import com.google.protobuf.Descriptors.Descriptor;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.proto.policy.v1.Component;
import org.dependencytrack.proto.policy.v1.License;
import org.dependencytrack.proto.policy.v1.Project;
import org.dependencytrack.proto.policy.v1.Vulnerability;
import org.junit.Test;

import javax.jdo.PersistenceManagerFactory;
import javax.jdo.metadata.ColumnMetadata;
import javax.jdo.metadata.MemberMetadata;
import javax.jdo.metadata.TypeMetadata;

import static org.assertj.core.api.Assertions.assertThat;

public class FieldMappingUtilTest extends PersistenceCapableTest {


    @Test
    public void testGetFieldMappingsForComponentProjection() {
        assertValidProtoFieldsAndColumns(ComponentProjection.class, Component.getDescriptor(), org.dependencytrack.model.Component.class);
    }

    @Test
    public void testGetFieldMappingsForLicenseProjection() {
        assertValidProtoFieldsAndColumns(LicenseProjection.class, License.getDescriptor(), org.dependencytrack.model.License.class);
    }

    @Test
    public void testGetFieldMappingsForLicenseGroupProjection() {
        assertValidProtoFieldsAndColumns(LicenseGroupProjection.class, License.Group.getDescriptor(), org.dependencytrack.model.LicenseGroup.class);
    }

    @Test
    public void testGetFieldMappingsForProjectProjection() {
        assertValidProtoFieldsAndColumns(ProjectProjection.class, Project.getDescriptor(), org.dependencytrack.model.Project.class);
    }

    @Test
    public void testGetFieldMappingsForProjectPropertyProjection() {
        assertValidProtoFieldsAndColumns(ProjectPropertyProjection.class, Project.Property.getDescriptor(), org.dependencytrack.model.ProjectProperty.class);
    }

    @Test
    public void testGetFieldMappingsForVulnerabilityProjection() {
        assertValidProtoFieldsAndColumns(VulnerabilityProjection.class, Vulnerability.getDescriptor(), org.dependencytrack.model.Vulnerability.class);
    }

    private void assertValidProtoFieldsAndColumns(final Class<?> projectionClazz,
                                                  final Descriptor protoDescriptor,
                                                  final Class<?> persistenceClass) {
        assertThat(FieldMappingUtil.getFieldMappings(projectionClazz)).allSatisfy(
                fieldMapping -> {
                    assertHasProtoField(protoDescriptor, fieldMapping.protoFieldName());
                    assertHasSqlColumn(persistenceClass, fieldMapping.sqlColumnName());

                }
        );
    }

    private void assertHasProtoField(final Descriptor protoDescriptor, final String fieldName) {
        assertThat(protoDescriptor.findFieldByName(fieldName)).isNotNull();
    }

    private void assertHasSqlColumn(final Class<?> clazz, final String columnName) {
        final PersistenceManagerFactory pmf = qm.getPersistenceManager().getPersistenceManagerFactory();

        final TypeMetadata typeMetadata = pmf.getMetadata(clazz.getName());
        assertThat(typeMetadata).isNotNull();

        var found = false;
        for (final MemberMetadata memberMetadata : typeMetadata.getMembers()) {
            if (memberMetadata.getColumns() == null) {
                continue;
            }

            for (final ColumnMetadata columnMetadata : memberMetadata.getColumns()) {
                if (columnName.equals(columnMetadata.getName())) {
                    found = true;
                    break;
                }
            }
        }

        assertThat(found).isTrue();
    }

}
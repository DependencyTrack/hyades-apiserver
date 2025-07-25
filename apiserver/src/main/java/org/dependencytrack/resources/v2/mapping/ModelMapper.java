package org.dependencytrack.resources.v2.mapping;

import org.dependencytrack.api.v2.model.ExternalReference;
import org.dependencytrack.api.v2.model.License;
import org.dependencytrack.api.v2.model.OrganizationalContact;
import org.dependencytrack.api.v2.model.OrganizationalEntity;

import java.util.Arrays;
import java.util.List;

public class ModelMapper {

    public static OrganizationalEntity mapOrganizationEntity(org.dependencytrack.model.OrganizationalEntity entity) {
        return OrganizationalEntity.builder()
                .name(entity.getName())
                .urls(Arrays.stream(entity.getUrls()).toList())
                .contacts(mapOrganizationContacts(entity.getContacts()))
                .build();
    }

    public static List<OrganizationalContact> mapOrganizationContacts(List<org.dependencytrack.model.OrganizationalContact> contacts) {
        return contacts.stream()
                .<OrganizationalContact>map(authorRow -> OrganizationalContact.builder()
                        .name(authorRow.getName())
                        .email(authorRow.getEmail())
                        .phone(authorRow.getPhone())
                        .build()).toList();
    }

    public static List<ExternalReference> mapExternalReferences(List<org.dependencytrack.model.ExternalReference> externalReferences) {
        return externalReferences.stream()
                .<ExternalReference>map(externalReference -> ExternalReference.builder()
                        .type(ExternalReference.TypeEnum.valueOf(externalReference.getType().name()))
                        .comment(externalReference.getComment())
                        .url(externalReference.getUrl())
                        .build()).toList();
    }

    public static License mapLicense(org.dependencytrack.model.License license) {
        return License.builder()
                .name(license.getName())
                .customLicense(license.isCustomLicense())
                .fsfLibre(license.isFsfLibre())
                .licenseId(license.getLicenseId())
                .osiApproved(license.isOsiApproved())
                .uuid(license.getUuid())
                .build();
    }
}

package org.dependencytrack.util;

import alpine.common.logging.Logger;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentMetaInformation;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.IntegrityMatchStatus;
import org.dependencytrack.model.License;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.sqlMapping.ComponentProjection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

public class ComponentUtil {

    private static final Logger LOGGER = Logger.getLogger(ComponentUtil.class);

    public static final Component mapToComponent(ComponentProjection result) {
        Component componentPersistent = new Component();
        componentPersistent.setAuthor(result.author);
        componentPersistent.setBlake2b_256(result.blake2b_256);
        componentPersistent.setBlake2b_384(result.blake2b_384);
        componentPersistent.setBlake2b_512(result.blake2b_512);
        componentPersistent.setBlake3(result.blake3);
        if (result.classifier != null) {
            componentPersistent.setClassifier(Classifier.valueOf(result.classifier));
        }
        componentPersistent.setCopyright(result.copyright);
        componentPersistent.setCpe(result.cpe);
        componentPersistent.setDescription(result.description);
        componentPersistent.setDirectDependencies(result.directDependencies);
        componentPersistent.setExtension(result.extension);
        componentPersistent.setGroup(result.group);
        componentPersistent.setId(result.id);
        if (result.internal != null) {
            componentPersistent.setInternal(result.internal);
        }
        componentPersistent.setSwidTagId(result.swidTagId);
        componentPersistent.setLastInheritedRiskScore(result.lastInheritedRiskscore);
        componentPersistent.setLicense(result.licenseName);
        componentPersistent.setLicenseUrl(result.licenseUrl);
        componentPersistent.setLicenseExpression(result.licenseExpression);
        componentPersistent.setName(result.name);
        if (result.uuid != null) {
            componentPersistent.setUuid(UUID.fromString(result.uuid));
        }
        componentPersistent.setExternalReferences(readByteArray(result.externalReferences));
        componentPersistent.setPurl(result.purl);
        componentPersistent.setPurlCoordinates(result.purlCoordinates);
        componentPersistent.setVersion(result.version);
        componentPersistent.setMd5(result.md5);
        componentPersistent.setSha1(result.sha1);
        componentPersistent.setSha256(result.sha256);
        componentPersistent.setSha384(result.sha384);
        componentPersistent.setSha512(result.sha512);
        componentPersistent.setSha3_256(result.sha3_256);
        componentPersistent.setSha3_384(result.sha3_384);
        componentPersistent.setSha3_512(result.sha3_512);

        var project = new Project();
        if (result.projectId != null) {
            project.setId(result.projectId);
        }
        project.setAuthor(result.projectAuthor);
        if (result.projectActive != null) {
            project.setActive(result.projectActive);
        }
        project.setDescription(result.projectDescription);
        project.setCpe(result.projectCpe);
        project.setPurl(result.projectPurl);
        project.setSwidTagId(result.projectSwidTagId);
        project.setPublisher(result.projectPublisher);
        project.setExternalReferences(readByteArray(result.projectExternalReferences));
        project.setLastInheritedRiskScore(result.projectLastInheritedRiskScore);
        if (result.projectClassifier != null) {
            project.setClassifier(Classifier.valueOf(result.projectClassifier));
        }
        project.setDirectDependencies(result.projectDirectDependencies);
        project.setLastBomImport(result.lastBomImport);
        project.setLastBomImportFormat(result.lastBomImportFormat);
        project.setName(result.projectName);
        if (result.projectUuid != null) {
            project.setUuid(UUID.fromString(result.projectUuid));
        }
        project.setVersion(result.projectVersion);
        componentPersistent.setProject(project);

        var license = new License();
        if (result.licenseUuid != null) {
            license.setUuid(UUID.fromString(result.licenseUuid));
        }
        if (result.isCustomLicense != null) {
            license.setCustomLicense(result.isCustomLicense);
        }
        if (result.isFsfLibre != null) {
            license.setFsfLibre(result.isFsfLibre);
        }
        license.setLicenseId(result.licenseId);
        if (result.isOsiApproved != null) {
            license.setOsiApproved(result.isOsiApproved);
        }
        license.setName(result.licenseName);
        componentPersistent.setResolvedLicense(license);

        var componentMetaInformation = new ComponentMetaInformation(result.publishedAt,
                result.integrityCheckStatus != null ? IntegrityMatchStatus.valueOf(result.integrityCheckStatus) : null,
                result.lastFetch, result.integrityRepoUrl);
        componentPersistent.setComponentMetaInformation(componentMetaInformation);

        return componentPersistent;
    }

    private static List<ExternalReference> readByteArray(byte[] byteArrayInput) {
        if (byteArrayInput != null) {
            try {
                ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(byteArrayInput));
                return (List<ExternalReference>) ois.readObject();
            } catch (IOException | ClassNotFoundException e) {
                LOGGER.debug("Exception while parsing component external references.", e);
            }
        }
        return Collections.emptyList();
    }
}

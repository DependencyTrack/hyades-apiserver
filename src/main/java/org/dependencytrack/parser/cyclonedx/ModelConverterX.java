package org.dependencytrack.parser.cyclonedx;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ExternalReference;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.ServiceComponent;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;

import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.util.PurlUtil.silentPurlCoordinatesOnly;

public final class ModelConverterX {

    private static final Logger LOGGER = Logger.getLogger(ModelConverterX.class);

    private ModelConverterX() {
    }

    public static Project convertToProject(final org.cyclonedx.model.Component cdxComponent) {
        final var project = new Project();
        project.setAuthor(trimToNull(cdxComponent.getAuthor()));
        project.setPublisher(trimToNull(cdxComponent.getPublisher()));
        project.setClassifier(convert(cdxComponent.getType()));
        project.setGroup(trimToNull(cdxComponent.getGroup()));
        project.setName(trimToNull(cdxComponent.getName()));
        project.setVersion(trimToNull(cdxComponent.getVersion()));
        project.setDescription(trimToNull(cdxComponent.getDescription()));
        project.setExternalReferences(convert(cdxComponent.getExternalReferences()));

        if (cdxComponent.getPurl() != null) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                project.setPurl(purl);
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.getSwid() != null) {
            project.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        return project;
    }

    public static List<Component> flattenComponents(final Collection<Component> components) {
        final var result = new ArrayList<Component>();

        for (final Component component : components) {
            if (component.getChildren() != null) {
                result.addAll(flattenComponents(component.getChildren()));
                component.setChildren(null);
            }

            result.add(component);
        }

        return result;
    }

    public static List<Component> convertComponents(final List<org.cyclonedx.model.Component> cdxComponents) {
        if (cdxComponents == null || cdxComponents.isEmpty()) {
            return null;
        }

        return cdxComponents.stream().map(ModelConverterX::convertComponent).toList();
    }

    public static Component convertComponent(final org.cyclonedx.model.Component cdxComponent) {
        final var component = new Component();
        component.setAuthor(trimToNull(cdxComponent.getAuthor()));
        component.setPublisher(trimToNull(cdxComponent.getPublisher()));
        component.setBomRef(trimToNull(cdxComponent.getBomRef()));
        component.setClassifier(convert(cdxComponent.getType()));
        component.setGroup(trimToNull(cdxComponent.getGroup()));
        component.setName(trimToNull(cdxComponent.getName()));
        component.setVersion(trimToNull(cdxComponent.getVersion()));
        component.setDescription(trimToNull(cdxComponent.getDescription()));
        component.setCopyright(trimToNull(cdxComponent.getCopyright()));
        component.setCpe(trimToNull(cdxComponent.getCpe()));
        component.setExternalReferences(convert(cdxComponent.getExternalReferences()));

        if (cdxComponent.getPurl() != null) {
            try {
                final var purl = new PackageURL(cdxComponent.getPurl());
                component.setPurl(purl);
                component.setPurlCoordinates(silentPurlCoordinatesOnly(purl));
            } catch (MalformedPackageURLException e) {
                LOGGER.warn("Encountered invalid PURL", e);
            }
        }

        if (cdxComponent.getSwid() != null) {
            component.setSwidTagId(trimToNull(cdxComponent.getSwid().getTagId()));
        }

        if (cdxComponent.getHashes() != null && !cdxComponent.getHashes().isEmpty()) {
            for (final org.cyclonedx.model.Hash cdxHash : cdxComponent.getHashes()) {
                final Consumer<String> hashSetter = switch (cdxHash.getAlgorithm().toLowerCase()) {
                    case "md5" -> component::setMd5;
                    case "sha1" -> component::setSha1;
                    case "sha256" -> component::setSha256;
                    case "sha384" -> component::setSha384;
                    case "sha512" -> component::setSha512;
                    case "sha3_256" -> component::setSha3_256;
                    case "sha3_384" -> component::setSha3_384;
                    case "sha3_512" -> component::setSha3_512;
                    case "blake2b_256" -> component::setBlake2b_256;
                    case "blake2b_384" -> component::setBlake2b_384;
                    case "blake2b_512" -> component::setBlake2b_512;
                    case "blake3" -> component::setBlake3;
                    default -> null;
                };
                if (hashSetter != null) {
                    hashSetter.accept(cdxHash.getValue());
                }
            }
        }

        if (cdxComponent.getLicenseChoice() != null
                && cdxComponent.getLicenseChoice().getLicenses() != null
                && !cdxComponent.getLicenseChoice().getLicenses().isEmpty()) {
            for (final org.cyclonedx.model.License cdxLicense : cdxComponent.getLicenseChoice().getLicenses()) {
                if (cdxLicense != null) {
                    component.setLicenseId(trimToNull(cdxLicense.getId()));
                    component.setLicense(trimToNull(cdxLicense.getName()));
                    component.setLicenseUrl(trimToNull(cdxLicense.getUrl()));
                    break; // Components in CDX can have multiple licenses, but DT supports only one
                }
            }
        }

        if (cdxComponent.getComponents() != null && !cdxComponent.getComponents().isEmpty()) {
            final var children = new ArrayList<Component>();

            for (final org.cyclonedx.model.Component cdxChildComponent : cdxComponent.getComponents()) {
                children.add(convertComponent(cdxChildComponent));
            }

            component.setChildren(children);
        }

        return component;
    }

    public static List<ServiceComponent> flattenServices(final Collection<ServiceComponent> services) {
        final var result = new ArrayList<ServiceComponent>();

        for (final ServiceComponent service : services) {
            if (service.getChildren() != null) {
                result.addAll(flattenServices(service.getChildren()));
                service.setChildren(null);
            }

            result.add(service);
        }

        return result;
    }

    public static List<ServiceComponent> convertServices(final List<org.cyclonedx.model.Service> cdxServices) {
        if (cdxServices == null || cdxServices.isEmpty()) {
            return null;
        }

        return cdxServices.stream().map(ModelConverterX::convertService).toList();
    }

    public static ServiceComponent convertService(final org.cyclonedx.model.Service cdxService) {
        final var service = new ServiceComponent();
        service.setBomRef(trimToNull(cdxService.getBomRef()));
        service.setGroup(trimToNull(cdxService.getGroup()));
        service.setName(trimToNull(cdxService.getName()));
        service.setVersion(trimToNull(cdxService.getVersion()));
        service.setDescription(trimToNull(cdxService.getDescription()));
        service.setAuthenticated(cdxService.getAuthenticated());
        service.setCrossesTrustBoundary(cdxService.getxTrustBoundary());
        service.setExternalReferences(convert(cdxService.getExternalReferences()));

        if (cdxService.getServices() != null && !cdxService.getServices().isEmpty()) {
            final var children = new ArrayList<ServiceComponent>();

            for (final org.cyclonedx.model.Service cdxChildService : cdxService.getServices()) {
                children.add(convertService(cdxChildService));
            }

            service.setChildren(children);
        }

        return service;
    }

    private static Classifier convert(final org.cyclonedx.model.Component.Type cdxComponentType) {
        if (cdxComponentType != null) {
            return Classifier.valueOf(cdxComponentType.name());
        }

        return Classifier.LIBRARY;
    }

    private static List<ExternalReference> convert(final List<org.cyclonedx.model.ExternalReference> cdxExternalReferences) {
        if (cdxExternalReferences == null || cdxExternalReferences.isEmpty()) {
            return null;
        }

        return cdxExternalReferences.stream()
                .map(cdxExternalReference -> {
                    final var externalReference = new ExternalReference();
                    externalReference.setType(cdxExternalReference.getType());
                    externalReference.setUrl(cdxExternalReference.getUrl());
                    externalReference.setComment(cdxExternalReference.getComment());
                    return externalReference;
                })
                .toList();
    }

}

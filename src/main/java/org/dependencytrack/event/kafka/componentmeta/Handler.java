package org.dependencytrack.event.kafka.componentmeta;

import com.github.packageurl.MalformedPackageURLException;
import org.dependencytrack.model.IntegrityMetaComponent;

public interface Handler {
    IntegrityMetaComponent handle() throws MalformedPackageURLException;
}
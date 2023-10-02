package org.dependencytrack.event.kafka.componentmeta;

import alpine.common.logging.Logger;
import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.event.kafka.KafkaEventDispatcher;
import org.dependencytrack.util.PurlUtil;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

public class HandlerFactoryTest extends PersistenceCapableTest {

    private static final Logger LOGGER = Logger.getLogger(HandlerFactoryTest.class);

    @Test
    public void createHandlerForSupportedPackageTest() {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        try {
            PackageURL packageUrl = new PackageURL("pkg:maven/org.http4s/blaze-core_2.12");
            ComponentProjection componentProjection = new ComponentProjection(PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl.toString());
            handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, false);
            assertTrue(handler instanceof SupportedMetaHandler);
        } catch (MalformedPackageURLException e) {
            LOGGER.warn("Package url not formed correctly");
        }

    }

    @Test
    public void createHandlerForUnSupportedPackageTest() {
        Handler handler;
        KafkaEventDispatcher kafkaEventDispatcher = new KafkaEventDispatcher();
        try {
            PackageURL packageUrl = new PackageURL("pkg:golang/github.com/foo/bar@1.2.3");
            ComponentProjection componentProjection = new ComponentProjection(PurlUtil.silentPurlCoordinatesOnly(packageUrl).toString(), false, packageUrl.toString());
            handler = HandlerFactory.createHandler(componentProjection, qm, kafkaEventDispatcher, false);
            assertTrue(handler instanceof UnSupportedMetaHandler);
        } catch (MalformedPackageURLException e) {
            throw new RuntimeException(e);
        }

    }
}

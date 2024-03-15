package org.dependencytrack.parser.dependencytrack;

import org.dependencytrack.model.Epss;
import org.dependencytrack.proto.mirror.v1.EpssItem;

import java.math.BigDecimal;

public final class EpssModelConverter {

    public static Epss convert(final EpssItem epssItem) {
        final Epss epss = new Epss();
        epss.setCve(epssItem.getCve());
        epss.setEpss(new BigDecimal(epssItem.getEpss()));
        epss.setPercentile(new BigDecimal(epssItem.getPercentile()));
        return epss;
    }
}

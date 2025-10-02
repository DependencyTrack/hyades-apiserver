package org.dependencytrack.util;

import org.apache.commons.validator.routines.DomainValidator;
import org.apache.commons.validator.routines.UrlValidator;

public final class CsafUtil {
    private CsafUtil() {}

    public static boolean validateUrl(String url) {
        return UrlValidator.getInstance().isValid(url);
    }

    public static boolean validateDomain(String domain) {
        return DomainValidator.getInstance().isValid(domain);
    }

    public static boolean validateUrlOrDomain(String candidate) {
        return validateUrl(candidate) || validateDomain(candidate);
    }
}

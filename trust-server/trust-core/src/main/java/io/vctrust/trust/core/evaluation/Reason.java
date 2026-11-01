package io.vctrust.trust.core.evaluation;

import io.vctrust.trust.core.x509.ValidationIssue;

/** One explanation line of a decision. */
public record Reason(String code, String message, ValidationIssue.Severity severity) {

    public static Reason error(String code, String message) {
        return new Reason(code, message, ValidationIssue.Severity.ERROR);
    }

    public static Reason warning(String code, String message) {
        return new Reason(code, message, ValidationIssue.Severity.WARNING);
    }

    public static Reason info(String code, String message) {
        return new Reason(code, message, ValidationIssue.Severity.INFO);
    }

    public static Reason of(ValidationIssue i) {
        return new Reason(i.code(), i.message(), i.severity());
    }

    public boolean isError() {
        return severity == ValidationIssue.Severity.ERROR;
    }
}

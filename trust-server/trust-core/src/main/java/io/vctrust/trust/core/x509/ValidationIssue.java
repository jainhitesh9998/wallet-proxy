package io.vctrust.trust.core.x509;

/** A machine-readable finding raised during validation. */
public record ValidationIssue(String code, String message, Severity severity) {

    public enum Severity { ERROR, WARNING, INFO }

    public static ValidationIssue error(String code, String message) {
        return new ValidationIssue(code, message, Severity.ERROR);
    }

    public static ValidationIssue warning(String code, String message) {
        return new ValidationIssue(code, message, Severity.WARNING);
    }

    public static ValidationIssue info(String code, String message) {
        return new ValidationIssue(code, message, Severity.INFO);
    }

    public boolean isError() {
        return severity == Severity.ERROR;
    }
}

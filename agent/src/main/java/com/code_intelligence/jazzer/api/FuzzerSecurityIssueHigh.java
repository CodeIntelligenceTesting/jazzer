package com.code_intelligence.jazzer.api;

/**
 * Thrown to indicate that a fuzz target has detected a high severity security issue rather than a normal bug.
 *
 * There is only a semantical but no functional difference between throwing exceptions of this type
 * or any other. However, automated fuzzing platforms can use the extra information to handle the
 * detected issues appropriately.
 */
public class FuzzerSecurityIssueHigh extends RuntimeException {
    public FuzzerSecurityIssueHigh() {}

    public FuzzerSecurityIssueHigh(String message) {
        super(message);
    }

    public FuzzerSecurityIssueHigh(String message, Throwable cause) {
        super(message, cause);
    }

    public FuzzerSecurityIssueHigh(Throwable cause) {
        super(cause);
    }
}

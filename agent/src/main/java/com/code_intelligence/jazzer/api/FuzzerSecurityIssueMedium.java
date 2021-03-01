package com.code_intelligence.jazzer.api;

/**
 * Thrown to indicate that a fuzz target has detected a medium severity security issue rather than a normal bug.
 *
 * There is only a semantical but no functional difference between throwing exceptions of this type
 * or any other. However, automated fuzzing platforms can use the extra information to handle the
 * detected issues appropriately.
 */
public class FuzzerSecurityIssueMedium extends RuntimeException {
    public FuzzerSecurityIssueMedium() {}

    public FuzzerSecurityIssueMedium(String message) {
        super(message);
    }

    public FuzzerSecurityIssueMedium(String message, Throwable cause) {
        super(message, cause);
    }

    public FuzzerSecurityIssueMedium(Throwable cause) {
        super(cause);
    }
}

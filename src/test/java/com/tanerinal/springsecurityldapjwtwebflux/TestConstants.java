package com.tanerinal.springsecurityldapjwtwebflux;

public class TestConstants {
    public static final String TEST_AUTH_USERNAME = "DUMMY";
    public static final String TEST_AUTH_PASSWORD = "1234";

    public static final String COMMON_STRING = "test";
    public static final int COMMON_INT = 23;

    public static final String JWT_SECRET = "JWT_SECRET";
    public static final String JWT_TOKEN = "JWT_TOKEN";
    public static final String MESSAGE_EXCEPTION_CUSTOM = "Test Exception Message";

    private TestConstants() {
        //Hidden from external initializations.
    }
}
package com.tanerinal.springsecurityldapjwtwebflux.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class BaseException extends RuntimeException {
	static final long serialVersionUID = -7034897190745766933L;
	public static final String EXCEPTION_CODE_DEFAULT = "EXC-1";
	public static final String EXCEPTION_CODE_UNHANDLED = "EXC-500";

	private final String code;
    private final String message;

    public BaseException (String exceptionMessage, Throwable cause) {
    	super (exceptionMessage, cause);
		code = EXCEPTION_CODE_DEFAULT;
		message = exceptionMessage;
	}

	public BaseException (String exceptionMessage) {
		super (exceptionMessage);
		code = EXCEPTION_CODE_DEFAULT;
		message = exceptionMessage;
	}
}

package com.tanerinal.springsecurityldapjwtwebflux.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class UnauthenticatedException extends BaseException {
	private static final long serialVersionUID = -8268186537558019479L;

	public UnauthenticatedException(String message, Throwable cause) {
		super( message, cause);
	}

	public UnauthenticatedException(String message) {
		super( message);
	}
}

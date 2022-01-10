package com.tanerinal.springsecurityldapjwtwebflux.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorizedException extends BaseException{
	private static final long serialVersionUID = -5676887003138852441L;

	public UnauthorizedException(String message) {
		super(message);
	}
}

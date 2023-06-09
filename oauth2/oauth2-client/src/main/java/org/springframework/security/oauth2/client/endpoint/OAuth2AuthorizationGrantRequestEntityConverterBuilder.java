/*
 * Copyright 2002-2023 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth2.client.endpoint;

import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Steve Riesenberg
 */
public interface OAuth2AuthorizationGrantRequestEntityConverterBuilder<T extends AbstractOAuth2AuthorizationGrantRequest> {

	OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> headersConverter(
			Converter<T, HttpHeaders> headersConverter);

	OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> addHeadersConverter(
			Converter<T, HttpHeaders> headersConverter);

	default OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> defaultHeaders(HttpHeaders headers) {
		return addHeadersConverter((grantRequest) -> headers);
	}

	default OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> defaultHeaders(Consumer<HttpHeaders> consumer) {
		HttpHeaders headers = new HttpHeaders();
		consumer.accept(headers);
		return addHeadersConverter((grantRequest) -> headers);
	}

	OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> parametersConverter(
			Converter<T, MultiValueMap<String, String>> parametersConverter);

	OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> addParametersConverter(
			Converter<T, MultiValueMap<String, String>> parametersConverter);

	default OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> defaultParameters(
			MultiValueMap<String, String> parameters) {
		return addParametersConverter((grantRequest) -> parameters);
	}

	default OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> defaultParameters(
			Consumer<MultiValueMap<String, String>> consumer) {
		MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
		consumer.accept(parameters);
		return addParametersConverter((grantRequest) -> parameters);
	}

	Converter<T, RequestEntity<?>> build();

}

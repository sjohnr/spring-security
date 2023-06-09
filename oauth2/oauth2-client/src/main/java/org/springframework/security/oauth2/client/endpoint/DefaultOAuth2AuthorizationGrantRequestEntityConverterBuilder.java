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

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.RequestEntity;
import org.springframework.util.MultiValueMap;

/**
 * @author Steve Riesenberg
 */
final class DefaultOAuth2AuthorizationGrantRequestEntityConverterBuilder<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> {

	private final AbstractOAuth2AuthorizationGrantRequestEntityConverter<T> requestEntityConverter;

	DefaultOAuth2AuthorizationGrantRequestEntityConverterBuilder(
			AbstractOAuth2AuthorizationGrantRequestEntityConverter<T> requestEntityConverter) {
		this.requestEntityConverter = requestEntityConverter;
	}

	@Override
	public OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> headersConverter(
			Converter<T, HttpHeaders> headersConverter) {
		this.requestEntityConverter.setHeadersConverter(headersConverter);
		return this;
	}

	@Override
	public OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> addHeadersConverter(
			Converter<T, HttpHeaders> headersConverter) {
		this.requestEntityConverter.addHeadersConverter(headersConverter);
		return this;
	}

	@Override
	public OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> parametersConverter(
			Converter<T, MultiValueMap<String, String>> parametersConverter) {
		this.requestEntityConverter.setParametersConverter(parametersConverter);
		return this;
	}

	@Override
	public OAuth2AuthorizationGrantRequestEntityConverterBuilder<T> addParametersConverter(
			Converter<T, MultiValueMap<String, String>> parametersConverter) {
		this.requestEntityConverter.addParametersConverter(parametersConverter);
		return this;
	}

	@Override
	public Converter<T, RequestEntity<?>> build() {
		return this.requestEntityConverter;
	}

}

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
import org.springframework.http.RequestEntity;
import org.springframework.web.client.RestOperations;

/**
 * @author Steve Riesenberg
 */
final class DefaultOAuth2AccessTokenResponseClientBuilder<T extends AbstractOAuth2AuthorizationGrantRequest>
		implements OAuth2AccessTokenResponseClient.Builder<T> {

	private final OAuth2AccessTokenResponseClient<T> accessTokenResponseClient;

	private final Consumer<Converter<T, RequestEntity<?>>> requestEntityConverterSetter;

	private final Consumer<RestOperations> restOperationsSetter;

	DefaultOAuth2AccessTokenResponseClientBuilder(OAuth2AccessTokenResponseClient<T> accessTokenResponseClient,
			Consumer<Converter<T, RequestEntity<?>>> requestEntityConverterSetter,
			Consumer<RestOperations> restOperationsSetter) {
		this.accessTokenResponseClient = accessTokenResponseClient;
		this.requestEntityConverterSetter = requestEntityConverterSetter;
		this.restOperationsSetter = restOperationsSetter;
	}

	@Override
	public OAuth2AccessTokenResponseClient.Builder<T> requestEntityConverter(Converter<T, RequestEntity<?>> requestEntityConverter) {
		this.requestEntityConverterSetter.accept(requestEntityConverter);
		return this;
	}

	@Override
	public OAuth2AccessTokenResponseClient.Builder<T> restOperations(RestOperations restOperations) {
		this.restOperationsSetter.accept(restOperations);
		return this;
	}

	@Override
	public OAuth2AccessTokenResponseClient<T> build() {
		return this.accessTokenResponseClient;
	}
}

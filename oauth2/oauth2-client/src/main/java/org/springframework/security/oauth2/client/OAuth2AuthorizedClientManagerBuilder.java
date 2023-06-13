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

package org.springframework.security.oauth2.client;

import java.util.Map;
import java.util.function.Consumer;
import java.util.function.Function;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.oauth2.client.endpoint.DefaultClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultPasswordTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.DefaultRefreshTokenTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.util.Assert;
import org.springframework.web.client.RestOperations;

/**
 * @author Steve Riesenberg
 */
public final class OAuth2AuthorizedClientManagerBuilder implements FactoryBean<OAuth2AuthorizedClientManager> {

	private final ClientRegistrationRepository clientRegistrationRepository;

	private final OAuth2AuthorizedClientRepository authorizedClientRepository;

	// @formatter:off
	private OAuth2AuthorizedClientProviderBuilder authorizedClientProviderBuilder =
			OAuth2AuthorizedClientProviderBuilder.builder()
					.authorizationCode()
					.refreshToken()
					.clientCredentials()
					.password();
	// @formatter:on

	private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper;

	private OAuth2AuthorizationSuccessHandler authorizationSuccessHandler;

	private OAuth2AuthorizationFailureHandler authorizationFailureHandler;

	private OAuth2AuthorizedClientManagerBuilder(ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizedClientRepository = authorizedClientRepository;
	}

	public OAuth2AuthorizedClientManagerBuilder providers(
			OAuth2AuthorizedClientProviderBuilder authorizedClientProviderBuilder) {
		Assert.notNull(authorizedClientProviderBuilder, "authorizedClientProviderBuilder cannot be null");
		this.authorizedClientProviderBuilder = authorizedClientProviderBuilder;
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder providers(
			Consumer<OAuth2AuthorizedClientProviderBuilder> builderConsumer) {
		Assert.notNull(builderConsumer, "consumer cannot be null");
		builderConsumer.accept(this.authorizedClientProviderBuilder);
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder provider(OAuth2AuthorizedClientProvider authorizedClientProvider) {
		Assert.notNull(authorizedClientProvider, "authorizedClientProvider cannot be null");
		this.authorizedClientProviderBuilder.provider(authorizedClientProvider);
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder provider(OAuth2AuthorizedClientProviderBuilder.Builder builder) {
		Assert.notNull(builder, "builder cannot be null");
		this.authorizedClientProviderBuilder.provider(builder.build());
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder restOperations(RestOperations restOperations) {
		Assert.notNull(restOperations, "restOperations cannot be null");
		// @formatter:off
		this.authorizedClientProviderBuilder
				.refreshToken((configurer) -> configurer.accessTokenResponseClient(
						DefaultRefreshTokenTokenResponseClient.builder()
								.restOperations(restOperations)))
				.clientCredentials((configurer) -> configurer.accessTokenResponseClient(
						DefaultClientCredentialsTokenResponseClient.builder()
								.restOperations(restOperations)))
				.password((configurer) -> configurer.accessTokenResponseClient(
						DefaultPasswordTokenResponseClient.builder()
								.restOperations(restOperations)));
		// @formatter:on
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder contextAttributesMapper(
			Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper) {
		this.contextAttributesMapper = contextAttributesMapper;
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder authorizationSuccessHandler(
			OAuth2AuthorizationSuccessHandler authorizationSuccessHandler) {
		this.authorizationSuccessHandler = authorizationSuccessHandler;
		return this;
	}

	public OAuth2AuthorizedClientManagerBuilder authorizationFailureHandler(
			OAuth2AuthorizationFailureHandler authorizationFailureHandler) {
		this.authorizationFailureHandler = authorizationFailureHandler;
		return this;
	}

	public DefaultOAuth2AuthorizedClientManager build() {
		DefaultOAuth2AuthorizedClientManager authorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				this.clientRegistrationRepository, this.authorizedClientRepository);
		authorizedClientManager.setAuthorizedClientProvider(authorizedClientProviderBuilder.build());
		if (this.contextAttributesMapper != null) {
			authorizedClientManager.setContextAttributesMapper(this.contextAttributesMapper);
		}
		if (this.authorizationSuccessHandler != null) {
			authorizedClientManager.setAuthorizationSuccessHandler(this.authorizationSuccessHandler);
		}
		if (this.authorizationFailureHandler != null) {
			authorizedClientManager.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		}
		return authorizedClientManager;
	}

	@Override
	public OAuth2AuthorizedClientManager getObject() {
		return build();
	}

	@Override
	public Class<?> getObjectType() {
		return OAuth2AuthorizedClientManager.class;
	}

	public static OAuth2AuthorizedClientManagerBuilder builder(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository authorizedClientRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notNull(authorizedClientRepository, "authorizedClientRepository cannot be null");
		return new OAuth2AuthorizedClientManagerBuilder(clientRegistrationRepository, authorizedClientRepository);
	}

}

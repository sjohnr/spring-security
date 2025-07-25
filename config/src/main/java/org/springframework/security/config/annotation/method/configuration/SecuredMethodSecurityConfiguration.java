/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.springframework.aop.Pointcut;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.ImportAware;
import org.springframework.context.annotation.Role;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.authorization.AuthoritiesAuthorizationManager;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.authorization.method.SecuredAuthorizationManager;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * {@link Configuration} for enabling {@link Secured} Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 * @see EnableMethodSecurity
 */
@Configuration(value = "_securedMethodSecurityConfiguration", proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class SecuredMethodSecurityConfiguration implements ImportAware, AopInfrastructureBean {

	private static final Pointcut pointcut = AuthorizationManagerBeforeMethodInterceptor.secured().getPointcut();

	private final SecuredAuthorizationManager authorizationManager = new SecuredAuthorizationManager();

	private final AuthorizationManagerBeforeMethodInterceptor methodInterceptor;

	SecuredMethodSecurityConfiguration(
			ObjectProvider<ObjectPostProcessor<AuthorizationManager<MethodInvocation>>> postProcessors) {
		ObjectPostProcessor<AuthorizationManager<MethodInvocation>> postProcessor = postProcessors
			.getIfUnique(ObjectPostProcessor::identity);
		AuthorizationManager<MethodInvocation> manager = postProcessor.postProcess(this.authorizationManager);
		this.methodInterceptor = AuthorizationManagerBeforeMethodInterceptor.secured(manager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	static MethodInterceptor securedAuthorizationMethodInterceptor(
			ObjectProvider<SecuredMethodSecurityConfiguration> securedMethodSecurityConfiguration) {
		Supplier<AuthorizationManagerBeforeMethodInterceptor> supplier = () -> {
			SecuredMethodSecurityConfiguration configuration = securedMethodSecurityConfiguration.getObject();
			return configuration.methodInterceptor;
		};
		return new DeferringMethodInterceptor<>(pointcut, supplier);
	}

	@Override
	public void setImportMetadata(AnnotationMetadata importMetadata) {
		EnableMethodSecurity annotation = importMetadata.getAnnotations().get(EnableMethodSecurity.class).synthesize();
		this.methodInterceptor.setOrder(this.methodInterceptor.getOrder() + annotation.offset());
	}

	@Autowired(required = false)
	void setRoleHierarchy(RoleHierarchy roleHierarchy) {
		AuthoritiesAuthorizationManager authoritiesAuthorizationManager = new AuthoritiesAuthorizationManager();
		authoritiesAuthorizationManager.setRoleHierarchy(roleHierarchy);
		this.authorizationManager.setAuthoritiesAuthorizationManager(authoritiesAuthorizationManager);
	}

	@Autowired(required = false)
	void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.methodInterceptor.setSecurityContextHolderStrategy(securityContextHolderStrategy);
	}

	@Autowired(required = false)
	void setEventPublisher(AuthorizationEventPublisher eventPublisher) {
		this.methodInterceptor.setAuthorizationEventPublisher(eventPublisher);
	}

	@Autowired(required = false)
	void setAuthorizationManagerFactory(AuthorizationManagerFactory<Collection<String>> authorizationManagerFactory) {
		this.authorizationManager.setAuthoritiesAuthorizationManager(
				new DelegatingAuthoritiesAuthorizationManager(authorizationManagerFactory));
	}

	private static final class DelegatingAuthoritiesAuthorizationManager
			implements AuthorizationManager<Collection<String>> {

		private static final String[] STRING_ARRAY = new String[0];

		private final AuthorizationManagerFactory<Collection<String>> authorizationManagerFactory;

		private final Map<Collection<String>, AuthorizationManager<Collection<String>>> cachedAuthorizationManagers = new ConcurrentHashMap<>();

		private DelegatingAuthoritiesAuthorizationManager(
				AuthorizationManagerFactory<Collection<String>> authorizationManagerFactory) {
			this.authorizationManagerFactory = authorizationManagerFactory;
		}

		@Override
		public @Nullable AuthorizationResult authorize(Supplier<Authentication> authentication,
				Collection<String> authorities) {
			AuthorizationManager<Collection<String>> delegate = getAuthorizationManager(authorities);
			return delegate.authorize(authentication, authorities);
		}

		private AuthorizationManager<Collection<String>> getAuthorizationManager(Collection<String> authorities) {
			return this.cachedAuthorizationManagers.computeIfAbsent(authorities,
					(k) -> this.authorizationManagerFactory.hasAnyAuthority(authorities.toArray(STRING_ARRAY)));
		}

	}

}

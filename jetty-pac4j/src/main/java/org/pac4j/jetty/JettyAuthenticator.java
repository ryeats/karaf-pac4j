/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.pac4j.jetty;

import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.stream.Collectors;
import javax.security.auth.Subject;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.eclipse.jetty.security.ConstraintSecurityHandler;
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.ServerAuthException;
import org.eclipse.jetty.security.authentication.LoginAuthenticator;
import org.eclipse.jetty.server.Authentication;
import org.eclipse.jetty.server.UserIdentity;
import org.osgi.framework.Bundle;
import org.osgi.framework.BundleContext;
import org.osgi.framework.FrameworkUtil;
import org.pac4j.core.client.Client;
import org.pac4j.core.config.Config;
import org.pac4j.core.config.ConfigSingleton;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.engine.SecurityLogic;
import org.pac4j.core.profile.CommonProfile;
import org.slf4j.LoggerFactory;

public class JettyAuthenticator extends LoginAuthenticator {

  public static final String DDF_AUTH_METHOD = "DDF";
  private static final org.slf4j.Logger LOGGER = LoggerFactory.getLogger(JettyAuthenticator.class);
  private CopyOnWriteArraySet<String> keysOfInitializedSecurityFilters;
  private Config config = new DemoConfigFactory().build();

  public JettyAuthenticator() {
    super();
    keysOfInitializedSecurityFilters = new CopyOnWriteArraySet<>();
    _loginService = new DummyLoginService();
    _identityService = _loginService.getIdentityService();
  }

  @Override
  public void setConfiguration(AuthConfiguration configuration) {
    keysOfInitializedSecurityFilters.clear();
    if (configuration instanceof ConstraintSecurityHandler) {
      ((ConstraintSecurityHandler) configuration).setLoginService(_loginService);
      ((ConstraintSecurityHandler) configuration).setIdentityService(_identityService);
    }
  }

  @Override
  public String getAuthMethod() {
    return DDF_AUTH_METHOD;
  }

  @Override
  public Authentication validateRequest(
      ServletRequest servletRequest, ServletResponse servletResponse, boolean mandatory)
      throws ServerAuthException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    final J2EContext context = new J2EContext(request, response, getConfig().getSessionStore());

    final Collection<CommonProfile>[] profileCollection;
    SecurityLogic<Authentication, J2EContext> securityLogic = getConfig().getSecurityLogic();
    String clients = getConfig().getClients().getClients().stream().map(Client::getName)
        .collect(Collectors.joining(", "));
    String authorizers = String.join(",", getConfig().getAuthorizers().keySet());
    String matchers = String
        .join(",", getConfig().getMatchers().keySet());
    return securityLogic.perform(context, getConfig(), (ctx, profiles, parameters) -> {
          if (profiles.isEmpty()) {
            return null;
          } else {
            Set<Principal> principals = profiles.stream().map(CommonProfile::asPrincipal).collect(
                Collectors.toCollection(
                    HashSet::new));
            UserIdentity userIdentity = new JettyUserIdentity(new Subject(true, principals,
                Collections.emptySet(), Collections.emptySet()));
            return new JettyAuthenticatedUser(userIdentity);
          }
        }, (code, j2EContext) -> null, clients, authorizers
        , matchers, true);
  }

  protected BundleContext getContext() {
    final Bundle cxfBundle = FrameworkUtil.getBundle(JettyAuthenticator.class);
    if (cxfBundle != null) {
      return cxfBundle.getBundleContext();
    }
    return null;
  }

  @Override
  public boolean secureResponse(
      ServletRequest req,
      ServletResponse res,
      boolean mandatory,
      Authentication.User validatedUser) {
    return true;
  }

  public Config getConfig() {
    if (this.config == null) {
      return ConfigSingleton.getConfig();
    }
    return this.config;
  }

  public void setConfig(final Config config) {
    this.config = config;
    ConfigSingleton.setConfig(config);
  }


  private class DummyLoginService implements org.eclipse.jetty.security.LoginService {

    private final JettyIdentityService jettyIdentityService = new JettyIdentityService();

    @Override
    public String getName() {
      return null;
    }

    @Override
    public UserIdentity login(String username, Object credentials, ServletRequest request) {
      return null;
    }

    @Override
    public boolean validate(UserIdentity user) {
      return false;
    }

    @Override
    public IdentityService getIdentityService() {
      return jettyIdentityService;
    }

    @Override
    public void setIdentityService(IdentityService service) {
      // not needed
    }

    @Override
    public void logout(UserIdentity user) {
      // not needed
    }

  }
}

/**
 * Copyright 2016 Connexta, LLC
 *
 * <p>Unlimited Government Rights (FAR Subpart 27.4) Government right to use, disclose, reproduce,
 * prepare derivative works, distribute copies to the public, and perform and display publicly, in
 * any manner and for any purpose, and to have or permit others to do so.
 */

package org.pac4j.demo.j2e;

import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Hashtable;
import javax.servlet.Filter;
import org.ops4j.pax.web.service.WebContainer;
import org.osgi.framework.BundleActivator;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceReference;
import org.osgi.service.http.whiteboard.HttpWhiteboardConstants;
import org.pac4j.j2e.filter.CallbackFilter;
import org.pac4j.j2e.filter.SecurityFilter;

/**
 * Example using the whiteboard pattern to configure pac4j and register security filters
 */
public class Activator implements BundleActivator {

  public Activator() {
  }

  public void start(BundleContext bundleContext) throws Exception {

    // create and register filters
    WhiteBoardFilterFactory factory = new WhiteBoardFilterFactory(bundleContext);

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("indexFilter").addInitParam("clients", "AnonymousClient")
        .addInitParam("authorizers", "securityHeaders,csrfToken").addPattern("/")
        .addPattern("/index.jsp").register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("mustBeAnonFilter").addInitParam("clients", "AnonymousClient")
        .addInitParam("authorizers", "mustBeAnon").addPattern("/").addPattern("/loginForm.jsp")
        .register();

    factory.getInstance(new CallbackFilter()).setAsyncSupported(true)
        .setName("callbackFilter").addInitParam("defaultUrl", "/")
        .addInitParam("renewSession", "true").addInitParam("multiProfile", "true")
        .addPattern("/callback")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("JwtParameterFilter")
        .addInitParam("configFactory", "org.pac4j.demo.j2e.DemoConfigFactory")
        .addInitParam("clients", "ParameterClient").addInitParam("authorizers", "securityHeaders")
        .addPattern("/rest-jwt/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("DirectBasicAuthFilter")
        .addInitParam("clients", "DirectBasicAuthClient,ParameterClient")
        .addInitParam("multiProfile", "true").addInitParam("authorizers", "securityHeaders")
        .addPattern("/dba/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("OidcFilter").addInitParam("clients", "GoogleOidcClient")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/oidc/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("Saml2Filter").addInitParam("clients", "SAML2Client")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/saml2/*")
        .register();

//    factory.getInstance( new Saml2MetadataFilter()).setAsyncSupported(true)
//        .setName("Saml2MetadataFilter")
//        .addPattern("/saml2-metadata")
//        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("FacebookFilter").addInitParam("clients", "FacebookClient")
        .addInitParam("authorizers", "securityHeaders")
        .addInitParam("matchers", "excludedPath")
        .addPattern("/facebook/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("ProtectedFilter")
        .addInitParam("authorizers", "securityHeaders")
        .addInitParam("matchers", "excludedPath")
        .addPattern("/protected/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("FacebookAdminFilter")
        .addInitParam("clients", "FacebookClient")
        .addInitParam("authorizers", "admin,securityHeaders")
        .addInitParam("matchers", "excludedPath")
        .addPattern("/facebookadmin/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("facebookCustomFilter")
        .addInitParam("clients", "FacebookClient")
        .addInitParam("authorizers", "custom,securityHeaders")
        .addPattern("/facebookcustom/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("TwitterFilter")
        .addInitParam("clients", "TwitterClient,FacebookClient")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/twitter/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("FormFilter")
        .addInitParam("clients", "FormClient")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/form/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("IndirectBasicAuthFilter")
        .addInitParam("clients", "IndirectBasicAuthClient")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/basicauth/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("CasFilter")
        .addInitParam("clients", "CasClient")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/cas/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("StravaFilter")
        .addInitParam("clients", "StravaClient")
        .addInitParam("authorizers", "securityHeaders")
        .addPattern("/strava/*")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("mustBeAuthFilter")
        .addInitParam("clients", "AnonymousClient")
        .addInitParam("authorizers", "mustBeAuth")
        .addPattern("/logout")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("logoutFilter")
        .addInitParam("defaultUrl", "/?defaulturlafterlogout")
        .addInitParam("destroySession", "true")
        .addPattern("/logout")
        .register();

    factory.getInstance(new SecurityFilter()).setAsyncSupported(true)
        .setName("centralLogoutFilter")
        .addInitParam("defaultUrl", "http://localhost:8080/?defaulturlafterlogoutafteridp")
        .addInitParam("localLogout", "false")
        .addInitParam("centralLogout", "true")
        .addInitParam("logoutUrlPattern", "http://localhost:8080/.*")
        .addPattern("/centralLogout")
        .register();

  }

  public static class WhiteBoardFilterFactory {

    private final BundleContext bundleContext;
    private final WebContainer webContainer;

    WhiteBoardFilterFactory(BundleContext bundleContext) {
      ServiceReference<WebContainer> sr = bundleContext
          .getServiceReference(org.ops4j.pax.web.service.WebContainer.class);
      this.webContainer = bundleContext.getService(sr);
      this.bundleContext = bundleContext;
    }

    public WhiteBoardFilter getInstance(Filter filter) {
      return new WhiteBoardFilter(webContainer, filter);
    }
  }

  public static class WhiteBoardFilter {

    private final Dictionary<String, Object> filterProps = new Hashtable<>();
    private final Filter filter;
    private WebContainer webContainer;
    private ArrayList<String> dispatcher = new ArrayList<>();
    private ArrayList<String> pattern = new ArrayList<>();
    private ArrayList<String> regex = new ArrayList<>();
    private ArrayList<String> servlet = new ArrayList<>();
    private Dictionary<String, String> initParams = new Hashtable<>();

    public WhiteBoardFilter(WebContainer webContainer, Filter filter) {
      this.filter = filter;
      this.webContainer = webContainer;
    }

    WhiteBoardFilter setAsyncSupported(boolean asyncSupported) {
      filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_ASYNC_SUPPORTED,
          Boolean.toString(asyncSupported));
      return this;
    }

    WhiteBoardFilter setName(String name) {
      filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_NAME, name);
      return this;
    }

    WhiteBoardFilter addDispatcher(String dispatcher) {
      if (null == filterProps.get(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_DISPATCHER)) {
        filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_DISPATCHER, this.dispatcher);
      }
      this.dispatcher.add(dispatcher);
      return this;
    }

    WhiteBoardFilter addPattern(String pattern) {
      if (null == filterProps.get(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_PATTERN)) {
        filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_PATTERN, this.pattern);
      }
      this.pattern.add(pattern);
      return this;
    }

    WhiteBoardFilter addRegex(String regex) {
      if (null == filterProps.get(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_REGEX)) {
        filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_REGEX, this.regex);
      }
      this.regex.add(regex);
      return this;
    }

    WhiteBoardFilter addServlet(String servlet) {
      if (null == filterProps.get(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_SERVLET)) {
        filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_SERVLET, this.servlet);
      }
      this.servlet.add(servlet);
      return this;
    }

    WhiteBoardFilter addInitParam(String paramName, String paramValue) {
      filterProps.put(HttpWhiteboardConstants.HTTP_WHITEBOARD_FILTER_INIT_PARAM_PREFIX + paramName,
          paramValue);
      initParams.put(paramName, paramValue);
      return this;
    }

    void register() {
//      bundleContext.registerService(Filter.class, filter, filterProps);
      webContainer.registerFilter(filter, this.pattern.toArray(new String[0]),
          this.servlet.toArray(new String[0]), initParams, true,
          null);
    }
  }

  public void stop(BundleContext bundleContext) throws Exception {

  }
/*



    <!--filter>
        <filter-name>callbackFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter-->
    <filter>
        <filter-name>callbackFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.CallbackFilter</filter-class>
        <init-param>
            <param-name>defaultUrl</param-name>
            <param-value>/</param-value>
        </init-param>
        <init-param>
            <param-name>renewSession</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>multiProfile</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>callbackFilter</filter-name>
        <url-pattern>/callback</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>JwtParameterFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>configFactory</param-name>
            <param-value>org.pac4j.demo.j2e.DemoConfigFactory</param-value>
        </init-param>
        <init-param>
            <param-name>clients</param-name>
            <param-value>ParameterClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>JwtParameterFilter</filter-name>
        <url-pattern>/rest-jwt/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>DirectBasicAuthFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>clients</param-name>
            <param-value>DirectBasicAuthClient,ParameterClient</param-value>
        </init-param>
        <init-param>
            <param-name>multiProfile</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>DirectBasicAuthFilter</filter-name>
        <url-pattern>/dba/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>OidcFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>GoogleOidcClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>OidcFilter</filter-name>
        <url-pattern>/oidc/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>ForceLoginFilter</filter-name>
        <filter-class>org.pac4j.demo.j2e.ForceLoginFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>ForceLoginFilter</filter-name>
        <url-pattern>/forceLogin</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>Saml2Filter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>SAML2Client</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>Saml2Filter</filter-name>
        <url-pattern>/saml2/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>
    <filter>
        <filter-name>Saml2MetadataFilter</filter-name>
        <filter-class>org.pac4j.demo.j2e.Saml2MetadataFilter</filter-class>
    </filter>
    <filter-mapping>
        <filter-name>Saml2MetadataFilter</filter-name>
        <url-pattern>/saml2-metadata</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>FacebookFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>FacebookClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
        <init-param>
            <param-name>matchers</param-name>
            <param-value>excludedPath</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>FacebookFilter</filter-name>
        <url-pattern>/facebook/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>ProtectedFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>ProtectedFilter</filter-name>
        <url-pattern>/protected/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>FacebookAdminFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>clients</param-name>
            <param-value>FacebookClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>admin,securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>FacebookAdminFilter</filter-name>
        <url-pattern>/facebookadmin/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <!--filter>
        <filter-name>facebookCustomFilter</filter-name>
        <filter-class>org.springframework.web.filter.DelegatingFilterProxy</filter-class>
    </filter-->
    <filter>
        <filter-name>facebookCustomFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>clients</param-name>
            <param-value>FacebookClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>custom,securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>facebookCustomFilter</filter-name>
        <url-pattern>/facebookcustom/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>TwitterFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>TwitterClient,FacebookClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>TwitterFilter</filter-name>
        <url-pattern>/twitter/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>FormFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>FormClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>FormFilter</filter-name>
        <url-pattern>/form/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>IndirectBasicAuthFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>IndirectBasicAuthClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>IndirectBasicAuthFilter</filter-name>
        <url-pattern>/basicauth/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>CasFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
        	<param-name>clients</param-name>
        	<param-value>CasClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>CasFilter</filter-name>
        <url-pattern>/cas/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>StravaFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>clients</param-name>
            <param-value>StravaClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>securityHeaders</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>StravaFilter</filter-name>
        <url-pattern>/strava/*</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>mustBeAuthFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.SecurityFilter</filter-class>
        <init-param>
            <param-name>clients</param-name>
            <param-value>AnonymousClient</param-value>
        </init-param>
        <init-param>
            <param-name>authorizers</param-name>
            <param-value>mustBeAuth</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>mustBeAuthFilter</filter-name>
        <url-pattern>/logout</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>logoutFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.LogoutFilter</filter-class>
        <init-param>
            <param-name>defaultUrl</param-name>
            <param-value>/?defaulturlafterlogout</param-value>
        </init-param>
        <init-param>
            <param-name>destroySession</param-name>
            <param-value>true</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>logoutFilter</filter-name>
        <url-pattern>/logout</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

    <filter>
        <filter-name>centralLogoutFilter</filter-name>
        <filter-class>org.pac4j.j2e.filter.LogoutFilter</filter-class>
        <init-param>
            <param-name>defaultUrl</param-name>
            <param-value>http://localhost:8080/?defaulturlafterlogoutafteridp</param-value>
        </init-param>
        <init-param>
            <param-name>localLogout</param-name>
            <param-value>false</param-value>
        </init-param>
        <init-param>
            <param-name>centralLogout</param-name>
            <param-value>true</param-value>
        </init-param>
        <init-param>
            <param-name>logoutUrlPattern</param-name>
            <param-value>http://localhost:8080/.*</param-value>
        </init-param>
    </filter>
    <filter-mapping>
        <filter-name>centralLogoutFilter</filter-name>
        <url-pattern>/centralLogout</url-pattern>
        <dispatcher>REQUEST</dispatcher>
    </filter-mapping>

   */

}

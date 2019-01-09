/**
 * Licensed to The Apereo Foundation under one or more contributor license
 * agreements. See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 *
 * The Apereo Foundation licenses this file to you under the Educational
 * Community License, Version 2.0 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of the License
 * at:
 *
 *   http://opensource.org/licenses/ecl2.txt
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 */

package org.opencastproject.runtimeinfo;

import static org.opencastproject.rest.RestConstants.SERVICES_FILTER;

import org.opencastproject.rest.RestConstants;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.Role;
import org.opencastproject.security.api.SecurityService;
import org.opencastproject.security.api.User;
import org.opencastproject.systems.OpencastConstants;
import org.opencastproject.userdirectory.UserIdRoleProvider;
import org.opencastproject.util.UrlSupport;
import org.opencastproject.util.doc.rest.RestQuery;
import org.opencastproject.util.doc.rest.RestResponse;
import org.opencastproject.util.doc.rest.RestService;

import com.google.gson.Gson;

import org.apache.commons.lang3.StringUtils;
import org.osgi.framework.BundleContext;
import org.osgi.framework.Constants;
import org.osgi.framework.InvalidSyntaxException;
import org.osgi.framework.ServiceReference;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.stream.Collectors;

import javax.servlet.Servlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;

/**
 * This REST endpoint provides information about the runtime environment, including the services and user interfaces
 * deployed and the current login context.
 *
 * If the 'org.opencastproject.anonymous.feedback.url' is set in config.properties, this service will also update the
 * opencast project with the contents of the getRuntimeInfo() json feed.
 */
@Path("/")
@RestService(
  name = "RuntimeInfo",
  title = "Runtime Information",
  abstractText = "This service provides information about the runtime environment, including the services that are "
    + "deployed and the current user context.",
  notes = {})
public class RuntimeInfo {

  private static final Logger logger = LoggerFactory.getLogger(RuntimeInfo.class);

  /** Configuration properties id */
  private static final String ADMIN_URL_PROPERTY = "org.opencastproject.admin.ui.url";
  private static final String ENGAGE_URL_PROPERTY = "org.opencastproject.engage.ui.url";

  private static final Gson gson = new Gson();

  /**
   * The rest publisher looks for any non-servlet with the 'opencast.service.path' property
   */
  public static final String SERVICE_FILTER = "(&(!(objectClass=javax.servlet.Servlet))("
          + RestConstants.SERVICE_PATH_PROPERTY + "=*))";

  private UserIdRoleProvider userIdRoleProvider;
  private SecurityService securityService;
  private BundleContext bundleContext;
  private URL serverUrl;

  protected void setUserIdRoleProvider(UserIdRoleProvider userIdRoleProvider) {
    this.userIdRoleProvider = userIdRoleProvider;
  }

  protected void setSecurityService(SecurityService securityService) {
    this.securityService = securityService;
  }

  private ServiceReference[] getRestServiceReferences() throws InvalidSyntaxException {
    return bundleContext.getAllServiceReferences(null, SERVICES_FILTER);
  }

  private ServiceReference[] getUserInterfaceServiceReferences() throws InvalidSyntaxException {
    return bundleContext.getAllServiceReferences(Servlet.class.getName(), "(&(alias=*)(classpath=*))");
  }

  public void activate(ComponentContext cc) throws MalformedURLException {
    logger.debug("start()");
    this.bundleContext = cc.getBundleContext();
    serverUrl = new URL(bundleContext.getProperty(OpencastConstants.SERVER_URL_PROPERTY));
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Path("components.json")
  @RestQuery(name = "services", description = "List the REST services and user interfaces running on this host", reponses = { @RestResponse(description = "The components running on this host", responseCode = HttpServletResponse.SC_OK) }, returnDescription = "")
  public String getRuntimeInfo(@Context HttpServletRequest request) throws MalformedURLException,
          InvalidSyntaxException {
    final Organization organization = securityService.getOrganization();

    // Get request protocol and port
    final String targetScheme = request.getScheme();

    // Create the engage target URL
    URL targetEngageBaseUrl = null;
    final String orgEngageBaseUrl = organization.getProperties().get(ENGAGE_URL_PROPERTY);
    if (StringUtils.isNotBlank(orgEngageBaseUrl)) {
      try {
        targetEngageBaseUrl = new URL(orgEngageBaseUrl);
      } catch (MalformedURLException e) {
        logger.warn("Engage url '{}' of organization '{}' is malformed", orgEngageBaseUrl, organization.getId());
      }
    }

    if (targetEngageBaseUrl == null) {
      logger.debug(
              "Using 'org.opencastproject.server.url' as a fallback for the non-existing organization level key '{}' for the components.json response",
              ENGAGE_URL_PROPERTY);
      targetEngageBaseUrl = new URL(targetScheme, serverUrl.getHost(), serverUrl.getPort(), serverUrl.getFile());
    }

    // Create the admin target URL
    URL targetAdminBaseUrl = null;
    final String orgAdminBaseUrl = organization.getProperties().get(ADMIN_URL_PROPERTY);
    if (StringUtils.isNotBlank(orgAdminBaseUrl)) {
      try {
        targetAdminBaseUrl = new URL(orgAdminBaseUrl);
      } catch (MalformedURLException e) {
        logger.warn("Admin url '{}' of organization '{}' is malformed", orgAdminBaseUrl, organization.getId());
      }
    }

    if (targetAdminBaseUrl == null) {
      logger.debug(
              "Using 'org.opencastproject.server.url' as a fallback for the non-existing organization level key '{}' for the components.json response",
              ADMIN_URL_PROPERTY);
      targetAdminBaseUrl = new URL(targetScheme, serverUrl.getHost(), serverUrl.getPort(), serverUrl.getFile());
    }


    Map<String, Object> json = new HashMap<>();
    json.put("engage", targetEngageBaseUrl.toString());
    json.put("admin", targetAdminBaseUrl.toString());
    json.put("rest", getRestEndpointsAsJson(request));
    json.put("ui", getUserInterfacesAsJson());

    return gson.toJson(json);
  }

  @GET
  @Path("me.json")
  @Produces(MediaType.APPLICATION_JSON)
  @RestQuery(name = "me", description = "Information about the curent user", reponses = { @RestResponse(description = "Returns information about the current user", responseCode = HttpServletResponse.SC_OK) }, returnDescription = "")
  public String getMyInfo() {
    Map<String, Object> result = new HashMap<>();

    User user = securityService.getUser();
    Map<String, String> jsonUser = new HashMap<>();
    jsonUser.put("username", user.getUsername());
    jsonUser.put("name", user.getName());
    jsonUser.put("email", user.getEmail());
    jsonUser.put("provider", user.getProvider());
    result.put("user", jsonUser);
    if (userIdRoleProvider != null) {
      result.put("userRole", UserIdRoleProvider.getUserIdRole(user.getUsername()));
    }

    // Add the current user's roles
    result.put("roles", user.getRoles().stream()
            .map(Role::getName)
            .collect(Collectors.toList()));

    // Add the current user's organizational information
    Organization org = securityService.getOrganization();

    Map<String, Object> jsonOrg = new HashMap<>();
    jsonOrg.put("id", org.getId());
    jsonOrg.put("name", org.getName());
    jsonOrg.put("adminRole", org.getAdminRole());
    jsonOrg.put("anonymousRole", org.getAnonymousRole());
    jsonOrg.put("properties", org.getProperties());
    result.put("org", jsonOrg);

    return gson.toJson(result);
  }

  private List<Map<String, String>> getRestEndpointsAsJson(HttpServletRequest request)
          throws MalformedURLException, InvalidSyntaxException {
    List<Map<String, String>> result = new ArrayList<>();
    ServiceReference[] serviceRefs = getRestServiceReferences();
    if (serviceRefs == null)
      return result;
    for (ServiceReference servletRef : sort(serviceRefs)) {
      final String servletContextPath = (String) servletRef.getProperty(RestConstants.SERVICE_PATH_PROPERTY);
      final Map<String, String> endpoint = new HashMap<>();
      endpoint.put("description", (String) servletRef.getProperty(Constants.SERVICE_DESCRIPTION));
      endpoint.put("version", servletRef.getBundle().getVersion().toString());
      endpoint.put("type", (String) servletRef.getProperty(RestConstants.SERVICE_TYPE_PROPERTY));
      URL url = new URL(request.getScheme(), request.getServerName(), request.getServerPort(), servletContextPath);
      endpoint.put("path", servletContextPath);
      endpoint.put("docs", UrlSupport.concat(url.toExternalForm(), "/docs")); // This is a Opencast convention
      result.add(endpoint);
    }
    return result;
  }

  private List<Map<String, String>> getUserInterfacesAsJson() throws InvalidSyntaxException {
    List<Map<String, String>> result = new ArrayList<>();
    ServiceReference[] serviceRefs = getUserInterfaceServiceReferences();
    if (serviceRefs == null)
      return result;
    for (ServiceReference ref : sort(serviceRefs)) {
      String description = (String) ref.getProperty(Constants.SERVICE_DESCRIPTION);
      String version = ref.getBundle().getVersion().toString();
      String alias = (String) ref.getProperty("alias");
      String welcomeFile = (String) ref.getProperty("welcome.file");
      String welcomePath = "/".equals(alias) ? alias + welcomeFile : alias + "/" + welcomeFile;
      Map<String, String> endpoint = new HashMap<>();
      endpoint.put("description", description);
      endpoint.put("version", version);
      endpoint.put("welcomepage", serverUrl + welcomePath);
      result.add(endpoint);
    }
    return result;
  }

  /**
   * Returns the array of references sorted by their Constants.SERVICE_DESCRIPTION property.
   *
   * @param references
   *          the referencens
   * @return the sorted set of references
   */
  private static SortedSet<ServiceReference> sort(ServiceReference[] references) {
    SortedSet<ServiceReference> sortedServiceRefs = new TreeSet<>((o1, o2) -> {
      final String o1Description = Objects.toString(o1.getProperty(Constants.SERVICE_DESCRIPTION), o1.toString());
      final String o2Description = Objects.toString(o2.getProperty(Constants.SERVICE_DESCRIPTION), o2.toString());
      return o1Description.compareTo(o2Description);
    });
    sortedServiceRefs.addAll(Arrays.asList(references));
    return sortedServiceRefs;
  }
}
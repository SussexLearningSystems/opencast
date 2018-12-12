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

package org.opencastproject.userdirectory.canvas;

import org.opencastproject.security.api.CachingUserProviderMXBean;
import org.opencastproject.security.api.Group;
import org.opencastproject.security.api.JaxbOrganization;
import org.opencastproject.security.api.JaxbRole;
import org.opencastproject.security.api.JaxbUser;
import org.opencastproject.security.api.Organization;
import org.opencastproject.security.api.Role;
import org.opencastproject.security.api.RoleProvider;
import org.opencastproject.security.api.User;
import org.opencastproject.security.api.UserProvider;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.ExecutionError;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
//import com.google.gson.JsonSyntaxException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.BufferedInputStream;
import java.io.FileNotFoundException;
import java.lang.management.ManagementFactory;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServer;
import javax.management.ObjectName;

/**
 * A UserProvider that reads user roles from Canvas.
 */
public class CanvasUserProviderInstance implements UserProvider, RoleProvider, CachingUserProviderMXBean {

  private static final String LTI_LEARNER_ROLE = "Learner";

  private static final String LTI_INSTRUCTOR_ROLE = "Instructor";

  public static final String PROVIDER_NAME = "canvas";

  private static final String OC_USERAGENT = "Opencast";

  /** The logger */
  private static final Logger logger = LoggerFactory.getLogger(CanvasUserProviderInstance.class);

  /** The organization */
  private Organization organization = null;

  /** Total number of requests made to load users */
  private AtomicLong requests = null;

  /** The number of requests made to Canvas */
  private AtomicLong canvasLoads = null;

  /** A cache of users, which lightens the load on Canvas */
  private LoadingCache<String, Object> cache = null;

  /** A token to store in the miss cache */
  protected Object nullToken = new Object();

  /** The URL of the Canvas instance */
  private String canvasUrl = null;

  /** The token used to call Canvas REST webservices */
  private String canvasToken = null;

  /** Regular expression for matching valid courses */
  private String coursePattern;

  /** Regular expression for matching valid users */
  private String userPattern;

  /** A map of roles which are regarded as Instructor roles */
  private Set<String> instructorRoles;

  /**
   * Constructs an Canvas user provider with the needed settings.
   *
   * @param pid
   *          the pid of this service
   * @param organization
   *          the organization
   * @param url
   *          the url of the Canvas server
   * @param userName
   *          the user to authenticate as
   * @param password
   *          the user credentials
   * @param cacheSize
   *          the number of users to cache
   * @param cacheExpiration
   *          the number of minutes to cache users
   */
  public CanvasUserProviderInstance(String pid, Organization organization, String url, String token,
          String coursePattern, String userPattern, Set<String> instructorRoles, int cacheSize,
          int cacheExpiration) {

    this.organization = organization;
    this.canvasUrl = url;
    this.canvasToken = token;
    this.coursePattern = coursePattern;
    this.userPattern = userPattern;
    this.instructorRoles = instructorRoles;

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    logger.debug("Creating new CanvasUserProviderInstance(pid={}, url={}, cacheSize={}, cacheExpiration={})",
                 pid, url, cacheSize, cacheExpiration);

    // Setup the caches
    cache = CacheBuilder.newBuilder().maximumSize(cacheSize).expireAfterWrite(cacheExpiration, TimeUnit.MINUTES)
            .build(new CacheLoader<String, Object>() {
              @Override
              public Object load(String id) throws Exception {
                User user = loadUserFromCanvas(id);
                return user == null ? nullToken : user;
              }
            });

    registerMBean(pid);
  }

  @Override
  public String getName() {
    return PROVIDER_NAME;
  }

  /**
   * Registers an MXBean.
   */
  protected void registerMBean(String pid) {
    // register with jmx
    requests = new AtomicLong();
    canvasLoads = new AtomicLong();
    try {
      ObjectName name;
      name = CanvasUserProviderFactory.getObjectName(pid);
      Object mbean = this;
      MBeanServer mbs = ManagementFactory.getPlatformMBeanServer();
      try {
        mbs.unregisterMBean(name);
      } catch (InstanceNotFoundException e) {
        logger.debug(name + " was not registered");
      }
      mbs.registerMBean(mbean, name);
    } catch (Exception e) {
      logger.error("Unable to register {} as an mbean: {}", this, e);
    }
  }

  // UserProvider methods

  /**
   * {@inheritDoc}
   * 
   * @see org.opencastproject.security.api.UserProvider#getOrganization()
   */
  @Override
  public String getOrganization() {
    return organization.getId();
  }

  /**
   * {@inheritDoc}
   * 
   * @see org.opencastproject.security.api.UserProvider#loadUser(java.lang.String)
   */
  @Override
  public User loadUser(String userName) {
    logger.debug("loaduser({})", userName);
    requests.incrementAndGet();
    try {
      Object user = cache.getUnchecked(userName);
      if (user == nullToken) {
        logger.debug("Returning null user from cache");
        return null;
      } else {
        logger.debug("Returning user " + userName + " from cache");
        return (JaxbUser) user;
      }
    } catch (ExecutionError e) {
      logger.warn("Exception while loading user {}", userName, e);
      return null;
    } catch (UncheckedExecutionException e) {
      logger.warn("Exception while loading user {}", userName, e);
      return null;
    }
  }

  /**
   * Loads a user from Canvas.
   * 
   * @param userName
   *          the username
   * @return the user
   */
  protected User loadUserFromCanvas(String userName) {
    if (cache == null) {
      throw new IllegalStateException("The Canvas user detail service has not yet been configured");
    }

    // Don't answer for admin, anonymous or empty user
    if ("admin".equals(userName) || "".equals(userName) || "anonymous".equals(userName)) {
      cache.put(userName, nullToken);
      logger.debug("We don't answer for: " + userName);
      return null;
    }

    logger.debug("In loadUserFromCanvas, currently processing user : {}", userName);

    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

    // update cache statistics
    canvasLoads.incrementAndGet();

    Thread currentThread = Thread.currentThread();
    ClassLoader originalClassloader = currentThread.getContextClassLoader();
    try {

      // Canvas userId (internal id), email address and display name
      String[] canvasUser = getCanvasUser(userName);

      if (canvasUser == null) {
        // user not known to this provider
        logger.debug("User {} not found in Canvas system", userName);
        cache.put(userName, nullToken);
        return null;
      }

      String userId = canvasUser[0];
      String email = canvasUser[1];
      String displayName = canvasUser[2];

      // Get the set of Canvas roles for the user
      String[] canvasRoles = getRolesFromCanvas(userId);

      // if Canvas doesn't know about this user we need to return
      if (canvasRoles == null) {
        cache.put(userName, nullToken);
        return null;
      }

      logger.debug("Canvas roles for eid " + userName + " id " + userId + ": " + Arrays.toString(canvasRoles));

      Set<JaxbRole> roles = new HashSet<JaxbRole>();

      boolean isInstructor = false;

      for (String r : canvasRoles) {
        roles.add(new JaxbRole(r, jaxbOrganization, "Canvas external role", Role.Type.EXTERNAL));

        if (r.endsWith(LTI_INSTRUCTOR_ROLE))
          isInstructor = true;
      }

      // Group role for all Canvas users
      roles.add(new JaxbRole(Group.ROLE_PREFIX + "CANVAS", jaxbOrganization, "Canvas Users", Role.Type.EXTERNAL_GROUP));

      // Group role for Canvas users who are an instructor in one more courses
      if (isInstructor)
        roles.add(new JaxbRole(Group.ROLE_PREFIX + "CANVAS_INSTRUCTOR", jaxbOrganization, "Canvas Instructors", Role.Type.EXTERNAL_GROUP));

      logger.debug("Returning JaxbRoles: " + roles);

      // JaxbUser(String userName, String password, String name, String email, String provider, boolean canLogin, JaxbOrganization organization, Set<JaxbRole> roles)
      User user = new JaxbUser(userName, null, displayName, email, PROVIDER_NAME, true, jaxbOrganization, roles);

      cache.put(userName, user);
      logger.debug("Returning user {}", userName);

      return user;

    } finally {
      currentThread.setContextClassLoader(originalClassloader);
    }

  }

  /*
   ** Verify that the user exists
   ** Query with /api/v1/users/sis_user_id:{userId}
   */
  private boolean verifyCanvasUser(String userId) {
      logger.debug("verifyCanvasUser({})", userId);
      try {
        if ((userPattern != null) && !userId.matches(userPattern)) {
          logger.debug("Verify user {} failed regexp {}", userId, userPattern);
          return false;
        }
      } catch (PatternSyntaxException e) {
        logger.warn("Invalid regular expression for user pattern {} - disabling checks", userPattern);
        userPattern = null;
      }

      int code;
      try {
          URL url = new URL(canvasUrl + "/api/v1/users/sis_user_id:" + userId);
          logger.debug("Verifying user: {} using API: {}", url.toString());
          HttpURLConnection connection = (HttpURLConnection) url.openConnection();
          connection.setRequestMethod("GET");
          connection.setRequestProperty("Authorization", "Bearer " + canvasToken);
          connection.setRequestProperty("User-Agent", OC_USERAGENT);

          connection.connect();
          code = connection.getResponseCode();
      } catch (Exception e) {
          logger.warn("Exception verifying Canvas user " + userId + " at " + canvasUrl + ": " + e.getMessage());
          return false;
      }
      // HTTP OK 200 for course exists, return false for everything else (typically 404 not found)
      return (code == 200);
  }

  /*
   ** Verify that the course exists
   ** Query with /api/v1/courses/{courseId}
   */
  private boolean verifyCanvasCourse(String courseId) {
      // We could additionally cache positive and negative courseId lookup results here
      logger.debug("verifyCanvasCourse({})", courseId);
      try {
        if ((coursePattern != null) && !courseId.matches(coursePattern)) {
          logger.debug("Verify course {} failed regexp {}", courseId, coursePattern);
          return false;
        }
      } catch (PatternSyntaxException e) {
        logger.warn("Invalid regular expression for course pattern {} - disabling checks", coursePattern);
        coursePattern = null;
      }

      int code;
      try {
          URL url = new URL(canvasUrl + "/api/v1/courses/" + courseId);
          logger.debug("Verifying course: {} using API: {}", courseId, url.toString());
          HttpURLConnection connection = (HttpURLConnection) url.openConnection();
          connection.setRequestMethod("GET");
          connection.setRequestProperty("Authorization", "Bearer " + canvasToken);
          connection.setRequestProperty("User-Agent", OC_USERAGENT);

          connection.connect();
          code = connection.getResponseCode();
      } catch (Exception e) {
          logger.warn("Exception verifying Canvas course " + courseId + " at " + canvasUrl + ": " + e.getMessage());
          return false;
      }
      // HTTP OK 200 for course exists, return false for everything else (typically 404 not found)
      return (code == 200);
  }

  private String[] getRolesFromCanvas(String userId) {
    logger.debug("getRolesFromCanvas({})", userId);
    String nextLinkRegex = "(?:.*)<(.+)>; rel=\"next\"";
    Pattern pattern = Pattern.compile(nextLinkRegex);

    List<String> roleList = new ArrayList<String>();

    try {
      String nextPage = canvasUrl + "/api/v1/users/sis_user_id:" + userId + "/courses";
      while (StringUtils.isNotBlank(nextPage)) {
        URL url = new URL(nextPage);
        logger.debug("Requesting courses for user:{}, using API: {}", userId, url.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setDoOutput(true);
        connection.setRequestProperty("Authorization", "Bearer " + canvasToken);
        connection.setRequestProperty("User-Agent", OC_USERAGENT);

        String json = IOUtils.toString(new BufferedInputStream(connection.getInputStream()));
        logger.debug(json);

        logger.debug("Response code for API: {}, is: {}", url.toString(), connection.getResponseCode());
        JsonArray courses = new JsonParser().parse(json).getAsJsonArray();
        for (JsonElement courseElement : courses) {
          JsonObject course = courseElement.getAsJsonObject();
          JsonElement jsonCourseId = course.get("id");
          if (jsonCourseId.isJsonNull()) {
            continue;
          }
          String courseId = course.get("id").getAsString();
          if (StringUtils.isNotBlank(courseId)) {
            JsonArray enrollments = course.get("enrollments").getAsJsonArray();
            for (JsonElement enrollmentElement : enrollments) {
              JsonObject enrollment = enrollmentElement.getAsJsonObject();
              /*
              Canvas enrollment `type` is a parent/base type that roles are created from.
              We allow the specifying of parent types and/or a child roles in configuration
              (these are mutually exclusive in Canvas, you can't have a child role with the
              same name as any parent type).
              This provides the ability to use any parent type to grant the LTI
              instructor roles for any child role created from it now or in the future, and/or
              specific set of child roles.
              The can be multiple enrollments for a user for a given course, adding them all to
              the roleList is ok because the roleList is converted to a Set later on.
              */
              String type = enrollment.get("type").getAsString();
              String role = enrollment.get("role").getAsString();
              String opencastRoleFromCanvasType = buildOpencastRole(courseId, type);
              roleList.add(opencastRoleFromCanvasType);
              String opencastRoleFromCanvasRole = buildOpencastRole(courseId, role);
              roleList.add(opencastRoleFromCanvasRole);
            }
          }
        }

        String linkHeader = connection.getHeaderField("link");
        Matcher matcher = pattern.matcher(linkHeader);
        if (matcher.find()) {
          logger.debug("Link header contains a next page so there are more courses to fetch: {}", linkHeader);
          nextPage = matcher.group(1);
        } else {
          logger.debug("No more courses to find for user: {}", userId);
          nextPage = null;
        }
      }

      if (roleList.isEmpty()) {
        return null;
      }
      return roleList.toArray(new String[0]);

    } catch (FileNotFoundException fnf) {
      // if the return is 404 it means the user wasn't found
      logger.debug("User id " + userId + " not found on " + canvasUrl);
    } catch (Exception e) {
      logger.warn("Exception getting course/role membership for Canvas user {} at {}: {}", userId, canvasUrl, e.getMessage());
    }

    return null;
  }

  /**
   * Get the internal Canvas user Id for the supplied user. If the user exists, set the user's email address.
   * 
   * @param eid
   * @return
   */
  private String[] getCanvasUser(String eid) {
    logger.debug("getCanvasUser({})", eid);
    try {
      URL url = new URL(canvasUrl + "/api/v1/users/sis_user_id:" + eid + "/profile");
      logger.debug("Requesting user: {}, using API: {}", eid, url.toString());
      HttpURLConnection connection = (HttpURLConnection) url.openConnection();
      connection.setRequestMethod("GET");
      connection.setDoOutput(true);
      connection.setRequestProperty("Authorization", "Bearer " + canvasToken);
      connection.setRequestProperty("User-Agent", OC_USERAGENT);

      String json = IOUtils.toString(new BufferedInputStream(connection.getInputStream()));
      logger.debug(json);

      if (StringUtils.isBlank(json)) {
        return null;
      }
      JsonObject user = new JsonParser().parse(json).getAsJsonObject();

      String canvasID = eid;
      String canvasEmail = user.get("primary_email").getAsString();
      String canvasDisplayName = user.get("name").getAsString();

      return new String[]{canvasID, canvasEmail, canvasDisplayName};

    } catch (FileNotFoundException fnf) {
      logger.debug("User {} does not exist on Canvas system: {}", eid, fnf);
    } catch (Exception e) {
      logger.warn("Exception getting Canvas user information for user {} at {}: {}", eid, canvasUrl, e);
    }

    return null;
  }

  /**
   * {@inheritDoc}
   * 
   * @see org.opencastproject.security.api.CachingUserProviderMXBean#getCacheHitRatio()
   */
  @Override
  public float getCacheHitRatio() {
    if (requests.get() == 0) {
      return 0;
    }
    return (float) (requests.get() - canvasLoads.get()) / requests.get();
  }

  /**
   * Build a Opencast role "foo_user" from the given Canvas locations
   * 
   * @param canvasLocationReference
   * @param canvasRole
   * @return
   */
  private String buildOpencastRole(String courseId, String canvasRole) {

    // map Canvas role to LTI role
    String ltiRole = instructorRoles.contains(canvasRole) ? LTI_INSTRUCTOR_ROLE : LTI_LEARNER_ROLE;

    return courseId + "_" + ltiRole;
  }

  @Override
  public Iterator<User> findUsers(String query, int offset, int limit) {
    if (query == null) {
      logger.error("Query is null");
      throw new IllegalArgumentException("Query must be set");
    }

    if (query.endsWith("%")) {
      query = query.substring(0, query.length() - 1);
    }

    if (query.isEmpty()) {
      return Collections.emptyIterator();
    }

    // Verify if a user exists (non-wildcard searches only)
    if (!verifyCanvasUser(query)) {
      return Collections.emptyIterator();
    }

    List<User> users = new LinkedList<User>();
    JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);
    JaxbUser queryUser = new JaxbUser(query, PROVIDER_NAME, jaxbOrganization, new HashSet<JaxbRole>());
    users.add(queryUser);

    return users.iterator();
  }

  @Override
  public Iterator<User> getUsers() {
    // We never enumerate all users
    return Collections.emptyIterator();
  }

  @Override
  public void invalidate(String userName) {
    cache.invalidate(userName);
  }

  @Override
  public long countUsers() {
    // Not meaningful, as we never enumerate users
    return 0;
  }

  // RoleProvider methods

   @Override
   public Iterator<Role> getRoles() {

     // We won't ever enumerate all Canvas courses, so return an empty list here
     return Collections.emptyIterator();
   }

   @Override
   public List<Role> getRolesForUser(String userName) {
      logger.debug("getRolesForUser({})", userName);
      List<Role> roles = new LinkedList<Role>();
      // Don't answer for admin, anonymous or empty user
      if ("admin".equals(userName) || "".equals(userName) || "anonymous".equals(userName)) {
         logger.debug("We don't answer for: " + userName);
         return roles;
      }

      User user = loadUser(userName);
      if (user != null) {
        logger.debug("Returning cached roleset for {}", userName);
        return new ArrayList<Role>(user.getRoles());
      }

     // Not found
     logger.debug("Return empty roleset for {} - not found on Canvas");
     return new LinkedList<Role>();
   }

   @Override
   public Iterator<Role> findRoles(String query, Role.Target target, int offset, int limit) {
     // We search for COURSEID, COURSEID_Learner, COURSEID_Instructor
     logger.debug("findRoles(query=" + query + " offset=" + offset + " limit=" + limit + ")");

     // Don't return roles for users or groups
     if (target == Role.Target.USER) {
        return Collections.emptyIterator();
     }

     boolean exact = true;
     boolean ltirole = false;

     if (query.endsWith("%")) {
       exact = false;
       query = query.substring(0, query.length() - 1);
     }

     if (query.isEmpty()) {
        return Collections.emptyIterator();
     }

     // Verify that role name ends with LTI_LEARNER_ROLE or LTI_INSTRUCTOR_ROLE
     if (exact && !query.endsWith("_" + LTI_LEARNER_ROLE) && !query.endsWith("_" + LTI_INSTRUCTOR_ROLE)) {
        return Collections.emptyIterator();
     }

     String canvasCourse = null;

     if (query.endsWith("_" + LTI_LEARNER_ROLE)) {
       canvasCourse = query.substring(0, query.lastIndexOf("_" + LTI_LEARNER_ROLE));
       ltirole = true;
     } else if (query.endsWith("_" + LTI_INSTRUCTOR_ROLE)) {
       canvasCourse = query.substring(0, query.lastIndexOf("_" + LTI_INSTRUCTOR_ROLE));
       ltirole = true;
     }

     if (!ltirole) {
       canvasCourse = query;
     }

     if (!verifyCanvasCourse(canvasCourse)) {
        return Collections.emptyIterator();
     }

     // Roles list
     List<Role> roles = new LinkedList<Role>();

     JaxbOrganization jaxbOrganization = JaxbOrganization.fromOrganization(organization);

     if (ltirole) {
       // Query is for a Course ID and an LTI role (Instructor/Learner)
       roles.add(new JaxbRole(query, jaxbOrganization, "Canvas Course Role", Role.Type.EXTERNAL));
     } else {
       // Course ID - return both roles
       roles.add(new JaxbRole(canvasCourse + "_" + LTI_INSTRUCTOR_ROLE, jaxbOrganization, "Canvas Course Instructor Role", Role.Type.EXTERNAL));
       roles.add(new JaxbRole(canvasCourse + "_" + LTI_LEARNER_ROLE, jaxbOrganization, "Canvas Course Learner Role", Role.Type.EXTERNAL));
     }

     return roles.iterator();
   }

}

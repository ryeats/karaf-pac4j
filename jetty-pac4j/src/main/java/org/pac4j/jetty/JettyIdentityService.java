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
import org.eclipse.jetty.security.IdentityService;
import org.eclipse.jetty.security.RunAsToken;
import org.eclipse.jetty.server.UserIdentity;

public class JettyIdentityService implements IdentityService {

  @Override
  public Object associate(UserIdentity user) {

    return null;
  }

  @Override
  public void disassociate(Object previous) {
  }

  @Override
  public Object setRunAs(UserIdentity user, RunAsToken token) {
    return null;
  }

  @Override
  public void unsetRunAs(Object token) {
    // not needed
  }

  @Override
  public UserIdentity newUserIdentity(
      javax.security.auth.Subject subject, Principal userPrincipal, String[] roles) {
    return new JettyUserIdentity(subject);
  }

  @Override
  public RunAsToken newRunAsToken(String runAsName) {
    return null;
  }

  @Override
  public UserIdentity getSystemUserIdentity() {
    return null;
  }
}

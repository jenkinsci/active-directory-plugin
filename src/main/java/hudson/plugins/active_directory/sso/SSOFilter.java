/*
 * The MIT License
 *
 * Copyright (c) 2008-2015, Louis Lecaroz, and contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package hudson.plugins.active_directory.sso;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.acegisecurity.Authentication;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.GrantedAuthorityImpl;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.ui.WebAuthenticationDetails;
import org.acegisecurity.userdetails.User;
import org.acegisecurity.userdetails.UserDetails;

import hudson.plugins.active_directory.ActiveDirectorySecurityRealm;
import hudson.plugins.active_directory.ActiveDirectoryUserDetail;
import hudson.security.SecurityRealm;
import hudson.util.VersionNumber;
import jenkins.model.Jenkins;
import jenkins.security.SecurityListener;

public class SSOFilter implements Filter {
  static final Logger LOGGER = Logger.getLogger(SSOFilter.class.getName());

  /**
   * Tests if username is the one in the current authentication
   * 
   * @param a Authentication instance containing all current authentication data coming from context
   * @param   username username to be compared to
   * @return  true if equal otherwise false
   */
  private boolean isUsername(Authentication a, String username) {
    // Check first if current principal is a ActiveDirectoryUserDetail and compare to its username otherwise against the authentication getname()
    if( username!=null && a!=null) {
      final Object principal=a.getPrincipal();
      if(principal instanceof ActiveDirectoryUserDetail) return username.equals(((ActiveDirectoryUserDetail)principal).getUsername());
      else return username.equals(a.getName());
    }
    return false;
  }

  @Override
  public void destroy()
  {      
  }

  @Override
  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    final SecurityRealm realm = Jenkins.getInstance().getSecurityRealm();
    final X509Certificate[] certChain = (X509Certificate[])request.getAttribute("javax.servlet.request.X509Certificate");
    final Authentication oldAuthentication=SecurityContextHolder.getContext().getAuthentication();
    final Authentication a;
    
    if (
          (!(request instanceof HttpServletRequest) || !(response instanceof  HttpServletResponse)) || // Must be an HTTP Call
          !(certChain != null && certChain.length>0 && certChain[0] != null ) || // Must contain a certificate
          !(realm instanceof ActiveDirectorySecurityRealm  && ((ActiveDirectorySecurityRealm)realm).getSsoOptions()!=null && ((ActiveDirectorySecurityRealm)realm).getSsoOptions().getUserField()!=null) // SSO must be enabled and the user field must be not null
    ) {
      chain.doFilter(request, response);
      return;
    }
    
    final ActiveDirectorySecurityRealm activeDirectoryRealm = (ActiveDirectorySecurityRealm)realm;
    final String dn = certChain[0].getSubjectDN()!=null?certChain[0].getSubjectDN().getName():null;
    final String[] splittedDn = dn!=null?dn.split(activeDirectoryRealm.getSsoOptions().getUserField() + "="):null;
    
    String username = (splittedDn!=null && splittedDn.length>1)?splittedDn[1].split(",")[0]:null;
    
    if(username==null || username.isEmpty()) { // A username must be found in the certifcate regarding the userField X500 syntax
      LOGGER.warning("User authentication failed: No username found in certificate: "+dn);
      chain.doFilter(request, response);
      return;
    }

    final String group = activeDirectoryRealm.getSsoOptions().getDefaultGroup();    
    // Checking rules, no change, lower or upper case
    if(SSOOptions.SSO_MODE_LOWER.equalsIgnoreCase(activeDirectoryRealm.getSsoOptions().getCheckMode())) username=username.toLowerCase();
    else if(SSOOptions.SSO_MODE_UPPER.equalsIgnoreCase(activeDirectoryRealm.getSsoOptions().getCheckMode())) username=username.toUpperCase();
    
    if(!SSOOptions.SSO_MODE_NOCHECK.equalsIgnoreCase(activeDirectoryRealm.getSsoOptions().getCheckMode())) { // Client certificate must be checked against AD
      LOGGER.log(Level.FINE, "Checking against AD for: {0}", username);
      if(!isUsername(oldAuthentication,username)) { // The current authenticated user is not the one having the current client certificate
        UserDetails d=null;
        try { // To work correctly if an exception is generated by loadUserByUsername, it should not throw the exception and continue chaining to the original AD filter, otherwise it will be oddly logged with another account !
          d=activeDirectoryRealm.getAuthenticationProvider().loadUserByUsername(username);
        } catch(Exception e) {
          LOGGER.log(Level.SEVERE,e.getMessage(),e);
        }
        if(d!=null && username.equals(d.getUsername())) // Ensure that returned user details from AD is for the current one                                                   
          a = new UsernamePasswordAuthenticationToken(d, null, d.getAuthorities());
        else a=null; // an error ? force to be authenticated with the standard page                          
      } else a=oldAuthentication; 
    } else { // no_check against AD set, create the data users for allowing it
      username+=(activeDirectoryRealm.getSsoOptions().getJenkinsUsernameSuffix()!=null?activeDirectoryRealm.getSsoOptions().getJenkinsUsernameSuffix():"");
      LOGGER.log(Level.FINE, "Only certificate authentication for: {0}", username);
     if(!isUsername(oldAuthentication,username)) {
        final GrantedAuthority[] authorities = new GrantedAuthority[] {
            SecurityRealm.AUTHENTICATED_AUTHORITY,
            new GrantedAuthorityImpl(group!=null && !group.isEmpty()?group:"")
          };    
        a = new UsernamePasswordAuthenticationToken(new ActiveDirectoryUserDetail(username, null, true, true, true, true, authorities, username, null, null), null, authorities);
      }
      else a=null;
    }

    if(a!=null && a!=oldAuthentication) { // User authenticated with a certificate, set it and go to the next filter instead of using the original one used by AD (if secContext is null,a will be null also) 
      ((UsernamePasswordAuthenticationToken)a).setDetails(new WebAuthenticationDetails((HttpServletRequest) request)); 
      SecurityContextHolder.getContext().setAuthentication(a); // Set this authenticated in the newly created security context
      if(Jenkins.getVersion().isNewerThan(new VersionNumber("1.568"))) {
        try {
          Method fireLoggedIn = SecurityListener.class.getMethod("fireLoggedIn", String.class);
          if(fireLoggedIn!=null && a.getPrincipal() instanceof User) fireLoggedIn.invoke(null, ((User)a.getPrincipal()).getUsername());
        } catch(NoSuchMethodException e) {}
        catch (IllegalAccessException e) {
          LOGGER.log(Level.SEVERE,e.getMessage(),e);
        }
        catch (IllegalArgumentException e) {
          LOGGER.log(Level.SEVERE,e.getMessage(),e);
        }
        catch (InvocationTargetException e) {
          LOGGER.log(Level.SEVERE,e.getMessage(),e);
        }
      }
      LOGGER.log(Level.FINE, "Authenticated user {0}", ((User)a.getPrincipal()).getUsername());
    }
    chain.doFilter( request, response);
  }

  @Override
  public void init(FilterConfig arg0) throws ServletException
  {
    
  }
  
}
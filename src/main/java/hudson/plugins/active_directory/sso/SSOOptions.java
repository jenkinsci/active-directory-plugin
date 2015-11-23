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

import org.kohsuke.stapler.DataBoundConstructor;

public class SSOOptions {
  public final static String SSO_MODE_NOCHECK="no_check";
  public final static String SSO_MODE_LOWER="lower";
  public final static String SSO_MODE_UPPER="upper";
  
  private final String userField;
  private final String defaultGroup;
  private final String checkMode;
  private final String jenkinsUsernameSuffix;
  
  public String getJenkinsUsernameSuffix() {
    return jenkinsUsernameSuffix;
  }

  /**
   * Field of the DN to look at.
   */
  public String getUserField() {
      return this.userField;
  }

  /**
   * Field of the Sso Case mode to be converted in another case
   */
  public String getCheckMode() {
      return this.checkMode;
  }
  
  public String getDefaultGroup() {
    return this.defaultGroup;
  }
  

  @DataBoundConstructor
  public SSOOptions(final String userField, final String defaultGroup, final String checkMode,final String jenkinsUsernameSuffix) {
    this.userField=userField;
    this.checkMode=checkMode;
    this.jenkinsUsernameSuffix=jenkinsUsernameSuffix;
    this.defaultGroup=defaultGroup;
  }
}
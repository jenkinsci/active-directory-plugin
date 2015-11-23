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

import hudson.Extension;
import hudson.Plugin;
import hudson.tasks.PluginImpl;
import hudson.util.PluginServletFilter;
import jenkins.model.Jenkins;

import javax.servlet.ServletException;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.Filter;


@Extension 
public class SSOPluginImpl  extends Plugin 
{
  static final Logger LOGGER = Logger.getLogger(SSOPluginImpl.class.getName());

  Filter filter;
        /**
       * Fetches the singleton instance of this plugin.
       * @return the instance.
       */
      public static PluginImpl getInstance() {
          Jenkins jenkins = Jenkins.getInstance();
          if (jenkins != null) {
              return jenkins.getPlugin(PluginImpl.class);
          } else {
              return null;
          }
      }

      /**
       * Starts the plugin. Loads previous configuration if such exists.
       * @throws Exception if the Kerberos filter cannot be added to Jenkins.
       */
      @Override
      public void start() throws Exception {
          load();
          try {
              this.filter = new SSOFilter();
                  PluginServletFilter.addFilter(filter);
          } catch (ServletException e) {
              LOGGER.log(Level.SEVERE, "Failed initialize plugin due to faulty config.", e);
              removeFilter();
          }
      }

      /**
       * Stops this plugin and removes the filter from Jenkins.
       * @throws Exception if removing the filter fails.
       */
      @Override
      public void stop() throws Exception {
          removeFilter();
      }

      /**
       * Safe and complete removal of the filter from the system.
       * @throws ServletException if
       */
      private void removeFilter() throws ServletException {
          if (filter != null) {
              PluginServletFilter.removeFilter(filter);
              filter.destroy();
              filter = null;
          }
      }
}


/*
 * The MIT License
 *
 * Copyright (c) 2008-2014, Kohsuke Kawaguchi, CloudBees, Inc., and contributors
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
package hudson.plugins.active_directory;

import javax.annotation.CheckForNull;
import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Tuple of a socket endpoint. A pair of the host name and the TCP port number.
 *
 * @author Kohsuke Kawaguchi
 */
public class SocketInfo {
    private final String host;
    private final int port;

    public SocketInfo(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public SocketInfo(String hostAndPort) {
        int idx = hostAndPort.lastIndexOf(':');
        if (idx<0) {
            this.host = hostAndPort;
            this.port = 0;
        } else {
            this.host = hostAndPort.substring(0,idx);
            this.port = Integer.parseInt(hostAndPort.substring(idx+1));
        }
    }

    @Override
    public String toString() {
        return port==0 ? host : host+':'+port;
    }

    public String getHost() {
        return host;
    }

    public int getPort() {
        return port;
    }

    public Socket connect() throws IOException {
        return new Socket(host,port);
    }

    /**
     * Retrieve the IP address of the Server we are targeting
     *
     * @return the IP address of the host
     */
    @CheckForNull
    public String getIpAddress() {
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            return inetAddress.getHostAddress();
        } catch (UnknownHostException e) {
            LOGGER.log(Level.FINE, String.format("The Ip address for the host %s could not be retrieved", host), e);
        }
        return null;
    }

    private static final Logger LOGGER = Logger.getLogger(SocketInfo.class.getName());

}

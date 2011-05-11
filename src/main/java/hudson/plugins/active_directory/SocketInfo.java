package hudson.plugins.active_directory;

import java.io.IOException;
import java.net.Socket;

/**
 * Tuple of a socket endpoint. A pair of the host name and the TCP port number.
 *
 * @author Kohsuke Kawaguchi
 */
public class SocketInfo {
    public final String host;
    public final int port;

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

    public Socket connect() throws IOException {
        return new Socket(host,port);
    }
}

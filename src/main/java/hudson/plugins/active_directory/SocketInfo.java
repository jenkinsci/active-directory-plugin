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

    @Override
    public String toString() {
        return host+':'+port;
    }

    public Socket connect() throws IOException {
        return new Socket(host,port);
    }
}

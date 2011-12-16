package hudson.plugins.active_directory;

import com.google.common.collect.ImmutableList;
import hudson.util.FlushProofOutputStream;
import org.acegisecurity.AuthenticationException;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;

/**
 * {@link AuthenticationException} that supports multiple nested causes.
 *
 * @author Kohsuke Kawaguchi
 */
public class MultiCauseBadCredentialsException extends AuthenticationException {
    private final List<Throwable> causes;

    public MultiCauseBadCredentialsException(String msg, Collection<? extends Throwable> causes) {
        super(msg);
        this.causes = ImmutableList.copyOf(causes);
    }

    @Override
    public void printStackTrace(PrintStream s) {
        PrintWriter w = new PrintWriter(new FlushProofOutputStream(s));
        printStackTrace(w);
        w.flush();
    }

    @Override
    public void printStackTrace(PrintWriter s) {
        synchronized (s) {
            super.printStackTrace(s);

            for (int i = 0; i < causes.size(); i++) {
                Throwable cause = causes.get(i);
                s.format("Cause #%s: ", i + 1);
                cause.printStackTrace(s);
            }
        }
    }
}

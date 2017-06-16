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

import com.google.common.collect.ImmutableList;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.security.UserMayOrMayNotExistException;
import hudson.util.FlushProofOutputStream;

import javax.naming.NamingException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.List;

/**
 * @author Kohsuke Kawaguchi
 */
public class MultiCauseUserMayOrMayNotExistException extends UserMayOrMayNotExistException {
    private final List<Throwable> causes;

    public MultiCauseUserMayOrMayNotExistException(String msg, Collection<? extends Throwable> causes) {
        super(msg);
        this.causes = ImmutableList.copyOf(causes);
    }

    @Override
    @SuppressFBWarnings(value = "DM_DEFAULT_ENCODING", justification = "It seems that encoding selection is not supported.")
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


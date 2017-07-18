/*
 * The MIT License
 *
 * Copyright (c) 2008-2016, Kohsuke Kawaguchi, CloudBees, Inc., and contributors
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

import org.jvnet.localizer.Localizable;

/**
 * Hack to let people pick lesser of two evils: performance or completeness.
 *
 * See JENKINS-22830 for the context.
 *
 * Marking as package private because I hope to get rid of this switch one day by figuring out
 * "the right way".
 *
 * See help-groupLookupStrategy.html for the detailed discussion.
 *
 * @author Kohsuke Kawaguchi
 */
/*hidden*/ public enum GroupLookupStrategy {
    AUTO           (Messages._GroupLookupStrategy_Auto()),
    RECURSIVE      (Messages._GroupLookupStrategy_Recursive()),
    CHAIN          (Messages._GroupLookupStrategy_ChainMatch()),
    TOKENGROUPS    (Messages._GroupLookupStrategy_TokenGroups())
    ;

    public final Localizable msg;

    GroupLookupStrategy(Localizable msg) {
        this.msg = msg;
    }

    public String getDisplayName() {
        return msg.toString();
    }
}

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
/*hidden*/ enum GroupLookupStrategy {
    AUTO     (Messages._GroupLookupStrategy_Auto()),
    RECURSIVE(Messages._GroupLookupStrategy_Recursive()),
    CHAIN    (Messages._GroupLookupStrategy_ChainMatch()),
    ;

    public final Localizable msg;

    GroupLookupStrategy(Localizable msg) {
        this.msg = msg;
    }

    public String getDisplayName() {
        return msg.toString();
    }
}

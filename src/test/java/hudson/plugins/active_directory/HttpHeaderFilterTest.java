package hudson.plugins.active_directory;

import hudson.util.Secret;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;

import javax.servlet.http.HttpServletRequest;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@RunWith(PowerMockRunner.class)
@PrepareForTest({Secret.class})
public class HttpHeaderFilterTest {

    @Before
    public void setup() {
        PowerMockito.mockStatic(Secret.class);
        when(Secret.fromString(anyString())).thenReturn(mock(Secret.class));
    }

    @Test
    public void testNoRegex() {
        String headerField = "x-user-name";
        String username = "CN=abcde,OU=yes,C=no";

        HttpHeaderFilter filter = new HttpHeaderFilter(new TestRealm(headerField, ""));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(headerField)).thenReturn(username);

        String result = filter.getUserFromReverseProxyHeader(request);
        assertEquals("CN=abcde,OU=yes,C=no", result);
    }

    @Test
    public void testWithRegex() {
        String headerField = "x-user-name";
        String username = "CN=abcde,OU=yes,C=no";

        HttpHeaderFilter filter = new HttpHeaderFilter(new TestRealm(headerField, "^CN=([^,]*).*"));
        HttpServletRequest request = mock(HttpServletRequest.class);
        when(request.getHeader(headerField)).thenReturn(username);

        String result = filter.getUserFromReverseProxyHeader(request);
        assertEquals("abcde", result);
    }

    static class TestRealm extends ActiveDirectorySecurityRealm {
        TestRealm(String headerField, String regex) {
            super("", "", "", "", "");
            setUserFromHttpHeader(headerField);
            setUsernameExtractionExpression(regex);
        }
    }
}
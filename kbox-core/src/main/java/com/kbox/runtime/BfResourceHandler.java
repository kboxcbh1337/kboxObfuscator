package com.kbox.runtime;

import java.io.IOException;
import java.net.URL;
import java.net.URLStreamHandler;

/**
 * {@link URLStreamHandler} for the synthetic {@code kboxbf:} scheme handed out by
 * {@link BfSecureLoader#findResource(String)}.
 *
 * <p>This is a <b>separate top-level class</b> (not an anonymous handler inside
 * the loader): the BF bootstrap jar is assembled from an explicit list of plain
 * class files, so an anonymous {@code BfSecureLoader$1} would have to be injected
 * as an extra entry and kept in sync. Two tiny named classes are cheaper and
 * obvious.</p>
 *
 * <p>The URL carries the resource name as its path; the body is decoded from the
 * native blob on {@code getInputStream()} and wiped as soon as it is consumed.</p>
 */
public final class BfResourceHandler extends URLStreamHandler {

    @Override
    protected java.net.URLConnection openConnection(URL u) throws IOException {
        return new BfResourceConnection(u);
    }
}

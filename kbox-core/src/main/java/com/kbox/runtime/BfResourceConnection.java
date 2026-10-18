package com.kbox.runtime;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;

/**
 * {@link URLConnection} for {@code kboxbf:} URLs produced by
 * {@link BfResourceHandler} / {@link BfSecureLoader#findResource(String)}.
 *
 * <p>Keeping this as its own top-level class (instead of an anonymous
 * {@code URLConnection}) is required by the BF bootstrap layout: only explicitly
 * listed plain class files ship outside the blob.</p>
 */
public final class BfResourceConnection extends URLConnection {

    BfResourceConnection(URL url) {
        super(url);
    }

    @Override
    public void connect() {
        // Nothing to do: the payload is decoded on demand from native memory.
    }

    @Override
    public InputStream getInputStream() throws IOException {
        String path = getURL().getPath();
        if (path == null) throw new FileNotFoundException(getURL().toExternalForm());
        while (path.startsWith("/")) path = path.substring(1);
        InputStream in = BfSecureLoader.openBlobResource(path);
        if (in == null) throw new FileNotFoundException(getURL().toExternalForm());
        return in;
    }

    @Override
    public int getContentLength() {
        return -1;
    }

    @Override
    public long getContentLengthLong() {
        return -1L;
    }
}

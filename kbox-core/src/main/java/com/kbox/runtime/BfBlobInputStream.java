package com.kbox.runtime;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;

/**
 * {@link InputStream} over the OFF-HEAP direct buffer that
 * {@link BfSecureLoader#getResourceBytes(String)} returns.
 *
 * <p>Reads go straight out of the native (direct) buffer — the KBox runtime
 * never copies the resource's plaintext into a Java heap {@code byte[]} — and
 * the buffer is wiped + unmapped via {@link BfSecureLoader#wipeResource} the
 * moment the stream is exhausted or closed, whichever comes first. A caller
 * that fully reads the stream therefore never leaves the plaintext resting in
 * process memory once it has consumed it.
 *
 * <p>This class is injected into the protected jar as a plain runtime entry
 * (same family as {@link BfSecureLoader}); it references no class that is not
 * also injected, so it is safe to ship outside the Brainfuck payload.</p>
 */
public final class BfBlobInputStream extends InputStream {

    /** Remaining content, or null once exhausted/closed/wiped. */
    private ByteBuffer bb;
    private boolean wiped = false;

    /**
     * @param direct the direct ByteBuffer returned by
     *               {@code BfSecureLoader.getResourceBytes}; must not be null.
     */
    public BfBlobInputStream(ByteBuffer direct) {
        this.bb = direct;
    }

    @Override
    public int read() throws IOException {
        ByteBuffer b = bb;
        if (b == null) return -1;
        if (!b.hasRemaining()) {
            wipe();
            return -1;
        }
        return b.get() & 0xFF;
    }

    @Override
    public int read(byte[] out, int off, int len) throws IOException {
        if (out == null) throw new NullPointerException();
        if (off < 0 || len < 0 || len > out.length - off) {
            throw new IndexOutOfBoundsException();
        }
        ByteBuffer b = bb;
        if (b == null) return -1;
        if (len == 0) return 0;
        int n = Math.min(len, b.remaining());
        if (n <= 0) {
            wipe();
            return -1;
        }
        b.get(out, off, n);
        return n;
    }

    @Override
    public long skip(long n) throws IOException {
        ByteBuffer b = bb;
        if (b == null) return 0;
        int s = (int) Math.min(n, b.remaining());
        b.position(b.position() + s);
        if (!b.hasRemaining()) wipe();
        return s;
    }

    @Override
    public int available() throws IOException {
        ByteBuffer b = bb;
        return b == null ? 0 : b.remaining();
    }

    @Override
    public void close() throws IOException {
        wipe();
    }

    /** Wipes + unmaps the native buffer exactly once; idempotent. */
    private void wipe() {
        if (wiped) return;
        wiped = true;
        ByteBuffer b = bb;
        bb = null;
        if (b != null) {
            BfSecureLoader.wipeResource(b);
        }
    }
}

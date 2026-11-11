package io.vctrust.trust.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Bounds the body of every request, before anything parses it: a body that declares more than the limit is refused
 * with 413, and one that does not say how long it is (chunked) stops being read at the limit. Without this a single
 * request could hold as many certificates, or as large a document, as its sender likes.
 */
public class RequestSizeFilter extends OncePerRequestFilter {

    private final long maxBytes;

    public RequestSizeFilter(long maxBytes) {
        if (maxBytes <= 0) {
            throw new IllegalArgumentException("trust.service.max-request-bytes must be positive");
        }
        this.maxBytes = maxBytes;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (request.getContentLengthLong() > maxBytes) {
            ClientAuthenticationFilter.problem(response, 413, "request_too_large", "The request body exceeds " + maxBytes + " bytes", null);
            return;
        }
        chain.doFilter(new Limited(request, maxBytes), response);
    }

    /** The request, with a body that cannot be read past the limit. */
    private static final class Limited extends HttpServletRequestWrapper {
        private final long maxBytes;
        private ServletInputStream stream;

        Limited(HttpServletRequest request, long maxBytes) {
            super(request);
            this.maxBytes = maxBytes;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (stream == null) {
                stream = new Counting(super.getInputStream(), maxBytes);
            }
            return stream;
        }

        @Override
        public BufferedReader getReader() throws IOException {
            String encoding = getCharacterEncoding();
            Charset charset = encoding == null ? StandardCharsets.UTF_8 : Charset.forName(encoding);
            return new BufferedReader(new InputStreamReader(getInputStream(), charset));
        }
    }

    private static final class Counting extends ServletInputStream {
        private final ServletInputStream in;
        private final long maxBytes;
        private long read;

        Counting(ServletInputStream in, long maxBytes) {
            this.in = in;
            this.maxBytes = maxBytes;
        }

        private void count(long n) throws IOException {
            if (n > 0 && (read += n) > maxBytes) {
                throw new IOException("The request body exceeds " + maxBytes + " bytes");
            }
        }

        @Override
        public int read() throws IOException {
            int b = in.read();
            count(b < 0 ? 0 : 1);
            return b;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            int n = in.read(b, off, len);
            count(n);
            return n;
        }

        @Override
        public boolean isFinished() {
            return in.isFinished();
        }

        @Override
        public boolean isReady() {
            return in.isReady();
        }

        @Override
        public void setReadListener(ReadListener listener) {
            in.setReadListener(listener);
        }
    }
}

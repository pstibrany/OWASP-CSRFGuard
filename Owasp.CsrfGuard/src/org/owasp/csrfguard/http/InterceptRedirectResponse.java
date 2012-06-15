package org.owasp.csrfguard.http;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.owasp.csrfguard.CsrfGuard;

public class InterceptRedirectResponse extends HttpServletResponseWrapper {

	private HttpServletResponse response = null;

	private CsrfGuard csrfGuard;

	private HttpServletRequest request;

	public InterceptRedirectResponse(HttpServletResponse response, HttpServletRequest request, CsrfGuard csrfGuard) {
		super(response);
		this.response = response;
		this.request = request;
		this.csrfGuard = csrfGuard;
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		URI uri = null;
		try {
			uri = new URI(location);
		} catch (URISyntaxException e) {
			response.sendRedirect(location);
			return;
		}
		
		String path = uri.getPath();
		if (path == null) {
			response.sendRedirect(location);
			return;
		}
		
		/** ensure token included in redirects **/
		if ((csrfGuard.isProtectedPage(path) || !csrfGuard.isProtectedMethod("GET"))) {
			// Make sure that there is a session
			request.getSession(true);
			
			/** update tokens **/
			csrfGuard.updateTokens(request);
			
			if (!path.startsWith("/")) {
				path = request.getContextPath() + "/" + path;
			}

			StringBuilder q = new StringBuilder();
			q.append(csrfGuard.getTokenName());
			q.append('=');
			q.append(csrfGuard.getTokenValue(request, path));
			
			if (uri.getQuery() != null) {
				q.append("&");
				q.append(uri.getQuery());
			}
			
			URI targetURI = null;
			try {
				targetURI = new URI(uri.getScheme(), uri.getUserInfo(), uri.getHost(), uri.getPort(), path, q.toString(), null);
			} catch (URISyntaxException e) {
				response.sendRedirect(location);
				return;
			}
			
			response.sendRedirect(targetURI.toASCIIString());
		} else {
			response.sendRedirect(location);
		}
	}

}

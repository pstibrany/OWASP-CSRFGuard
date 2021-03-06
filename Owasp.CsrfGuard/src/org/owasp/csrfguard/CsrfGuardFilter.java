/**
 * The OWASP CSRFGuard Project, BSD License
 * Eric Sheridan (eric@infraredsecurity.com), Copyright (c) 2011 
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *    1. Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *    2. Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *    3. Neither the name of OWASP nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific
 *       prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package org.owasp.csrfguard;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.csrfguard.action.*;
import org.owasp.csrfguard.http.*;
import org.owasp.csrfguard.log.*;

public final class CsrfGuardFilter implements Filter {

	private FilterConfig filterConfig = null;

	@Override
	public void destroy() {
		filterConfig = null;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain) throws IOException, ServletException {
		/** only work with HttpServletRequest objects **/
		if (request instanceof HttpServletRequest && response instanceof HttpServletResponse) {
			HttpServletRequest httpRequest = (HttpServletRequest) request;
			HttpSession session = httpRequest.getSession(false);
			
			if (session == null) {
				// If there is no session, no harm can be done
				filterChain.doFilter(httpRequest, (HttpServletResponse) response);
				return;
			}

			CsrfGuard csrfGuard = CsrfGuard.getInstance();
			csrfGuard.getLogger().log(String.format("CsrfGuard analyzing request %s", httpRequest.getRequestURI()));

			InterceptRedirectResponse httpResponse = new InterceptRedirectResponse((HttpServletResponse) response, httpRequest, csrfGuard);

//			 if(MultipartHttpServletRequest.isMultipartRequest(httpRequest)) {
//				 httpRequest = new MultipartHttpServletRequest(httpRequest);
//			 }

			if (session.isNew() && csrfGuard.isUseNewTokenLandingPage()) {
				csrfGuard.writeLandingPage(httpRequest, httpResponse);
			} else {
				try {
					csrfGuard.checkRequest(httpRequest, httpResponse);
					
					filterChain.doFilter(httpRequest, httpResponse);
				} catch (CsrfGuardException csrfe) {
					for (IAction action : csrfGuard.getActions()) {
						try {
							if (action instanceof IAction2) {
								((IAction2) action).execute(httpRequest, httpResponse, csrfe, csrfGuard, filterChain);
							} else {
								action.execute(httpRequest, httpResponse, csrfe, csrfGuard);
							}
						} catch (CsrfGuardException exception) {
							csrfGuard.getLogger().log(LogLevel.Error, exception);
						}
					}
				}
			}

			/** rotate session and page tokens **/
			if (!csrfGuard.isAjaxRequest(httpRequest) && csrfGuard.isRotateEnabled()) {
				csrfGuard.rotateTokens(httpRequest);
			}
			
			/** update tokens **/
			csrfGuard.updateTokens(httpRequest);

		} else {
			filterConfig.getServletContext().log(String.format("[WARNING] CsrfGuard does not know how to work with requests of class %s ", request.getClass().getName()));

			filterChain.doFilter(request, response);
		}
	}

	@Override
	public void init(@SuppressWarnings("hiding") FilterConfig filterConfig) throws ServletException {
		this.filterConfig = filterConfig;
	}

}

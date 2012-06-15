package org.owasp.csrfguard.action;

import java.io.*;

import javax.servlet.*;
import javax.servlet.http.*;

import org.owasp.csrfguard.*;

public interface IAction2 extends IAction {

	public void execute(HttpServletRequest request, HttpServletResponse response, CsrfGuardException csrfe, CsrfGuard csrfGuard, FilterChain filterChain) throws CsrfGuardException, IOException, ServletException;

}

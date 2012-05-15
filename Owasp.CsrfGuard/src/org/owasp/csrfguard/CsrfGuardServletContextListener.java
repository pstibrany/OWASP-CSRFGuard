package org.owasp.csrfguard;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import java.util.Properties;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.owasp.csrfguard.util.Streams;

public class CsrfGuardServletContextListener implements ServletContextListener {

	private final static String CONFIG_PARAM = "Owasp.CsrfGuard.Config";

	private final static String CONFIG_PRINT_PARAM = "Owasp.CsrfGuard.Config.Print";

	@Override
	public void contextInitialized(ServletContextEvent event) {
		ServletContext context = event.getServletContext();
		String config = context.getInitParameter(CONFIG_PARAM);


		if (config == null) {
			throw new RuntimeException(String.format("failure to specify context init-param - %s", CONFIG_PARAM));
		}

		InputStream is = null;
		Properties properties = new Properties();

		try {
			is = getResourceStream(config, context);
			properties.load(is);
			CsrfGuard.load(properties);
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			Streams.close(is);
		}


		String printConfig = context.getInitParameter(CONFIG_PRINT_PARAM);

		if (printConfig != null && Boolean.parseBoolean(printConfig)) {
			context.log(CsrfGuard.getInstance().toString());
		}
	}

	@Override
	public void contextDestroyed(ServletContextEvent event) {
		/** nothing to do **/
	}

	private InputStream getResourceStream(String resourceName, ServletContext context) throws IOException {
		InputStream is = null;

		/** try classpath **/
		is = getClass().getClassLoader().getResourceAsStream(resourceName);

		/** try web context **/
		if (is == null) {
			String res = resourceName;
			if (!res.startsWith("/")) {
				res = "/" + res;
			}
			
			is = context.getResourceAsStream(res);
		}

		/** try current directory **/
		if (is == null) {
			File file = new File(resourceName);

			if (file.exists()) {
				is = new FileInputStream(resourceName);
			}
		}

		/** fail if still empty **/
		if (is == null) {
			throw new IOException(String.format("unable to locate resource - %s", resourceName));
		}

		return is;
	}

}

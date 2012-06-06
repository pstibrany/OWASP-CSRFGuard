package org.owasp.csrfguard;

import java.io.*;
import java.util.*;
import java.util.concurrent.*;

import javax.servlet.*;

import org.owasp.csrfguard.log.*;
import org.owasp.csrfguard.util.*;

public class CsrfGuardServletContextListener implements ServletContextListener {

	private final static String CONFIG_PARAM = "Owasp.CsrfGuard.Config";

	private final static String CONFIG_PRINT_PARAM = "Owasp.CsrfGuard.Config.Print";

	private final static String RELOAD_PROPERTIES = "Owasp.CsrfGuard.ReloadProperties";
	
	@Override
	public void contextInitialized(ServletContextEvent event) {
		final ServletContext context = event.getServletContext();
		final String config = context.getInitParameter(CONFIG_PARAM);

		if (config == null) {
			throw new RuntimeException(String.format("failure to specify context init-param - %s", CONFIG_PARAM));
		}
		
		Properties initialProperties = loadConfig(context, config);
		try {
			CsrfGuard.load(initialProperties);
		} catch (Exception e) {
			throw new RuntimeException(e);
		}

		if (Boolean.parseBoolean(context.getInitParameter(CONFIG_PRINT_PARAM))) {
			CsrfGuard guard = CsrfGuard.getInstance();
			guard.getLogger().log(guard.toString());
		}
		
		if (Boolean.parseBoolean(context.getInitParameter(RELOAD_PROPERTIES))) {
			startConfigReloader(context, config, initialProperties);
		}
	}

	private void startConfigReloader(final ServletContext context, final String config, final Properties initialProperties) {
		Runnable reloader = new Runnable() {
			@Override
			public void run() {
				Properties lastProps = initialProperties;
				
				while (true) {
					try {
						Thread.sleep(TimeUnit.SECONDS.toMillis(30));
					} catch (InterruptedException e) {
						Thread.currentThread().interrupt();
						return;
					}
					
					Properties newProps = loadConfig(context, config);
					if (!newProps.equals(lastProps)) {
						CsrfGuard.getInstance().getLogger().log("CSRFGuard properties has been changed, setting new properties");
						try {
							CsrfGuard.load(newProps);
							CsrfGuard.getInstance().getLogger().log("New CSRFGuard properties has been set");
						} catch (Exception e) {
							CsrfGuard.getInstance().getLogger().log(LogLevel.Error, e);
						}
					}
					
					lastProps = newProps;
				}
			}
		};
		
		Thread t = new Thread(reloader);
		t.setName("CSRFGuard config reloader");
		t.setDaemon(true);
		t.start();
	}

	private Properties loadConfig(ServletContext context, String config) {
		InputStream is = null;
		Properties properties = new Properties();
		try {
			is = getResourceStream(config, context);
			properties.load(is);
			return properties;
		} catch (Exception e) {
			throw new RuntimeException(e);
		} finally {
			Streams.close(is);
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

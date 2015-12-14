package org.security.web.filter;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.csrf.CsrfToken;

/**
 * Servlet Filter implementation class CsrfHeaderPublisher
 */
public class CsrfHeaderFilter implements Filter {

    private static final Logger LOGGER = LoggerFactory.getLogger(CsrfHeaderFilter.class);

    private static final String REQUEST_ATTRIBUTE_NAME = "_csrf";
    private static final String RESPONSE_HEADER_NAME = "X-CSRF-HEADER";
    private static final String RESPONSE_PARAM_NAME = "X-CSRF-PARAM";
    private static final String RESPONSE_TOKEN_NAME = "X-CSRF-TOKEN";

    /**
     * Default constructor.
     */
    public CsrfHeaderFilter() {
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
		// TODO Auto-generated method stub
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

	    final HttpServletRequest request = (HttpServletRequest) servletRequest;
	    final HttpServletResponse response = (HttpServletResponse) servletResponse;

	    LOGGER.debug(request.getRequestURI());

	    final CsrfToken token = (CsrfToken) request.getAttribute(REQUEST_ATTRIBUTE_NAME);

        if (token != null) {
            response.setHeader(RESPONSE_HEADER_NAME, token.getHeaderName());
            response.setHeader(RESPONSE_PARAM_NAME, token.getParameterName());
            response.setHeader(RESPONSE_TOKEN_NAME , token.getToken());
        }

        filterChain.doFilter(request, response);
	}

	/**
	 * @see Filter#init(FilterConfig)
	 */
	public void init(FilterConfig fConfig) throws ServletException {
		// TODO Auto-generated method stub
	}

}

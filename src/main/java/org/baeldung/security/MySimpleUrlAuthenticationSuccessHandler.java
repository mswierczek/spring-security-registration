package org.baeldung.security;

import org.baeldung.persistence.dao.RoleRepository;
import org.baeldung.persistence.model.User;
import org.baeldung.service.DeviceService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.security.Principal;
import java.util.Collection;

@Component("myAuthenticationSuccessHandler")
public class MySimpleUrlAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    private final ActiveUserStore activeUserStore;

    private final DeviceService deviceService;

    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

    public MySimpleUrlAuthenticationSuccessHandler(ActiveUserStore activeUserStore, DeviceService deviceService) {
        this.activeUserStore = activeUserStore;
        this.deviceService = deviceService;
    }

    @Override
    public void onAuthenticationSuccess(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {
        handle(request, response, authentication);
        final HttpSession session = request.getSession(false);
        if (session != null) {
            session.setMaxInactiveInterval(30 * 60);

            String username;
            if (authentication.getPrincipal() instanceof User) {
            	username = ((User)authentication.getPrincipal()).getEmail();
            }
            else {
            	username = authentication.getName();
            }
            LoggedUser user = new LoggedUser(username, activeUserStore);
            session.setAttribute("user", user);
        }
        clearAuthenticationAttributes(request);

        loginNotification(authentication, request);
    }

    private void loginNotification(Authentication authentication, HttpServletRequest request) {
        try {
            if (authentication.getPrincipal() instanceof User) {
                deviceService.verifyDevice(((User)authentication.getPrincipal()), request);
            }
        } catch (Exception e) {
            logger.error("An error occurred while verifying device or location", e);
            throw new RuntimeException(e);
        }

    }

    protected void handle(final HttpServletRequest request, final HttpServletResponse response, final Authentication authentication) throws IOException {
        final String targetUrl = determineTargetUrl(authentication);

        if (response.isCommitted()) {
            logger.debug("Response has already been committed. Unable to redirect to " + targetUrl);
            return;
        }
        redirectStrategy.sendRedirect(request, response, targetUrl);
    }

    private String determineTargetUrl(final Authentication authentication) {
        // TODO maybe we can check if we should handle any scenario when authentication.getPrincipal() is not
        //  an instance of User. If we don't need to, then instead of using authorities we could use
        //  ((User) authentication.getPrincipal()).getRoles() and have some mappings between roles and pages for redirections
        //  because keeping booleans below could be tricky when more roles appear
        boolean isAdmin = authentication.getAuthorities().stream()
            .anyMatch((GrantedAuthority authority) -> authority.getAuthority().equals(Privileges.WRITE_PRIVILEGE));
        boolean isManager = !isAdmin && authentication.getAuthorities().stream()
            .anyMatch((GrantedAuthority authority) -> authority.getAuthority().equals(Privileges.MANAGER_PRIVILEGE));
        boolean isUser = !isManager && !isAdmin;
        if (isUser) {
        	 String username;
             if (authentication.getPrincipal() instanceof User) {
             	username = ((User)authentication.getPrincipal()).getEmail();
             }
             else {
             	username = authentication.getName();
             }
            return "/homepage.html?user="+username;
        } else if (isAdmin) {
            return "/console.html";
        } else if (isManager) {
            return "/management.html";
        } else {
            throw new IllegalStateException();
        }
    }

    private void clearAuthenticationAttributes(final HttpServletRequest request) {
        final HttpSession session = request.getSession(false);
        if (session == null) {
            return;
        }
        session.removeAttribute(WebAttributes.AUTHENTICATION_EXCEPTION);
    }

    public void setRedirectStrategy(final RedirectStrategy redirectStrategy) {
        this.redirectStrategy = redirectStrategy;
    }

    protected RedirectStrategy getRedirectStrategy() {
        return redirectStrategy;
    }
}
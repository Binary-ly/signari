package dev.signari.quickstart;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.HtmlUtils;

@RestController
public class HomeController {

    @GetMapping("/")
    public String home() {
        return "<p><a href=\"/oauth2/authorization/signari\">Sign in with Signari</a></p>";
    }

    /** Reached only signed in: Spring has checked the ID token before anybody gets here. */
    @GetMapping("/me")
    public String me(@AuthenticationPrincipal OidcUser user) {
        String who = user.getEmail() != null ? user.getEmail() : user.getSubject();
        return "<p>Signed in as " + HtmlUtils.htmlEscape(who) + "</p>";
    }
}

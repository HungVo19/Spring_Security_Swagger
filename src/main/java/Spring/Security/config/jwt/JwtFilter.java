package Spring.Security.config.jwt;

import Spring.Security.config.CustomUserDetails;
import Spring.Security.config.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Kiểm tra jwt trong request có hợp lệ không
 */
@Slf4j
public class JwtFilter extends OncePerRequestFilter {
    @Autowired
    private JwtProvider tokenProvider;

    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        try {
            //Lấy jwt từ request
            String jwt = getJwtFromRequest(httpServletRequest);

            if(StringUtils.hasText(jwt) && tokenProvider.validateToken(jwt)) {
                //Lấy id từ jwt
                Long userId = tokenProvider.getUserIdFromJWT(jwt);
                //Lấy thông tin user
                UserDetails userDetails = userService.loadUserByUsername(String.valueOf(userId));
                if(userDetails != null) {
                    //Nếu user hợp lệ, set thông tin cho Security Context
                    UsernamePasswordAuthenticationToken
                            authentication = new UsernamePasswordAuthenticationToken(userDetails,null,
                            userDetails.getAuthorities());

                    authentication.setDetails(
                            new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (Exception ex) {
            log.error("failed on set user authentication", ex);
        }
        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }

    /**
     *Lấy chuỗi JWT từ request
     *
     * @param request
     * @return
     */
    private String getJwtFromRequest (HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        //Kiểm tra header Authorization có chứa thông tin jwt không
        if(StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer")) {
            //HTTP Header sẽ có dạng
            //Authorization: Bearer
            // eyJhbGciOiJIUzI1NiIXVCJ9...TJVA95OrM7E20RMHrHDcEfxjoYZgeFONFh7HgQ
            //Chuỗi JWT sẽ nằm sau 'Bearer'
            return bearerToken.substring(7);
        }
        return null;
    }
}

package pl.plenczewski.jwtasynckey.security;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.sun.org.apache.xerces.internal.impl.dv.util.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.filter.OncePerRequestFilter;
import sun.security.rsa.RSAPublicKeyImpl;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Collections;

public class JWTFilter extends OncePerRequestFilter {

    private String pub = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtd4iA+xZfFqDT255UwA7\n" +
            "1P0Qi7UAXfkQdxWOKuQvQuSXgRgxPV+HUwXP9DcLrMqtdFT/Wzaa53k2CdKje6se\n" +
            "GNfzbGm0pnYgUkUJM6YKkiWwD5Thr4qZrr2/3kkRWZ7IG5I4BI7qqmVADRLU7J+j\n" +
            "lgCRXIPE0Y1D3jWTtBz0Tqo0rs7O6kFOk1KycQQz3h4gpRwg6qq5rRDHHnww7CpG\n" +
            "e2ASjZVe+oR0PPzaMb/6fFHJQj/zkkQmZ9xBotsVAeFURKIrT7MDngee45fxBKOx\n" +
            "nG3s8f68iEWvwXjJ3Adj1kpm6Ih6TpWPTe8+Tum+xp4FHQarXgQ2cCUrjI0Wb8Hd\n" +
            "5R8cMFRcSIpRgoI7v2eFf2ghvjUWwx3I9XY7DD74Yeb7P1Eyu6bjxjFETB3EeKTe\n" +
            "1KHDnT7n40a93WQPEfgDsdPgOdg2DBk3CXFA/9oLwWGYimE06FvQ1DVCw2fIqc1h\n" +
            "nL7qa8R9m7aM7gk5EfJsJ2XjVmqutssvxPOw2Q2BZ3DaGUJmvfwgxzjOL/3gEZR1\n" +
            "VXxKUQQB2wf2UB36F8OF/njTRvMeVdMptfVy/xG1nW7rkudO7fcAfUU/tlxXxOea\n" +
            "iX01Gn2D75Zg1+OgiQWBGxSA54cw27uq1DUhQyhcMz2rKxJIS1pWpmOmIX7n9xhk\n" +
            "JPVnavqpc+lZxDWtjpl/LzsCAwEAAQ==";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorization = request.getHeader("Authorization");
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = null;
        try {
            usernamePasswordAuthenticationToken = getInfo(authorization);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        filterChain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken getInfo(String authorization) throws NoSuchAlgorithmException, InvalidKeySpecException {
        RSAPublicKey publicKey = getRsaPublicKey();
        JWTVerifier jwtVerifier1 = JWT.require(Algorithm.RSA512(publicKey,null)).build();
        DecodedJWT decodedJWT = jwtVerifier1.verify(authorization.substring(7));
        Claim name = decodedJWT.getClaim("name");
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(name.asString(), null, Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));
        return token;
    }

    private RSAPublicKey getRsaPublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory kf = KeyFactory.getInstance("RSA");
        Base64 b64 = new Base64();
        byte [] decoded = b64.decode(pub);
        return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));
    }
}

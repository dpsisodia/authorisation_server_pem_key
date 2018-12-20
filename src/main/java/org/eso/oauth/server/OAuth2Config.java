package org.eso.oauth.server;

import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
@EnableAuthorizationServer
public class OAuth2Config extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private AuthenticationManager authenticationManager;

	@Value("${public_key}")
	private String publicKey;

	@Value("${private_key}")
	private String privateKey;

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints.authenticationManager(authenticationManager).tokenStore(tokenStore()).tokenEnhancer(tokenEnhancer());
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
	}

	@Bean
	public TokenStore tokenStore() throws Exception {
		return new JwtTokenStore(tokenEnhancer());
	}

	@Bean
	public JwtAccessTokenConverter tokenEnhancer() throws Exception {
		JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
		//since default alg is "SHA256withRSA" but we need different alg "SHA512withRSA" therefore have set custom signer/verfier
		//converter.setSigningKey(privateKey);
		//converter.setVerifierKey(publicKey);
		converter.setSigner(new RsaSigner(loadRSAPrivateKey(privateKey), "SHA512withRSA"));
		converter.setVerifier(new RsaVerifier(loadRSAPublicKey(publicKey), "SHA512withRSA"));
		return converter;
	}

	@Bean
	public static NoOpPasswordEncoder passwordEncoder() {
		return (NoOpPasswordEncoder) NoOpPasswordEncoder.getInstance();
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.inMemory().withClient("test").secret("Gtest").authorizedGrantTypes("client_credentials")
				.scopes("read", "write").accessTokenValiditySeconds(3000);
	}
	// https://stackoverflow.com/questions/6559272/algid-parse-error-not-a-sequence
	// For error: "Algid parse error, not a sequence" => It means your key is not in PKCS#8 format.
	// Convert private key in PKCS#8 format using command: 
	// openssl pkcs8 -topk8 -nocrypt -in myrsakey.pem -out myrsakey_pcks8
	public RSAPrivateKey loadRSAPrivateKey(String privateKeyPEM) throws Exception {
		// decode to its constituent bytes
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("-----END PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN RSA PRIVATE KEY-----", "");
		privateKeyPEM = privateKeyPEM.replace("-----END RSA PRIVATE KEY-----", "");
		byte[] privateKeyBytes = Base64.decodeBase64(privateKeyPEM);

		// create a key object from the bytes
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory;
		try {
			
			keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (Exception e) {
			throw new Exception("Fail to create RSAPrivateKey", e);
		}
	}

	public RSAPublicKey loadRSAPublicKey(String publicKeyPEM) throws Exception {
		// decode to its constituent bytes
		publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "");
		publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
		byte[] publicKeyBytes = Base64.decodeBase64(publicKeyPEM);

		// create a key object from the bytes
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new Exception("Fail to create RSAPublicKey", e);
		}
	}
}
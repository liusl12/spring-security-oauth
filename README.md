#概述

使用oauth2保护你的应用，可以分为简易的分为三个步骤

- 配置资源服务器
- 配置认证服务器
- 配置spring security

前两点是oauth2的主体内容，但前面我已经描述过了，spring security oauth2是建立在spring security基础之上的，所以有一些体系是公用的。

oauth2根据使用场景不同，分成了4种模式

- 授权码模式（authorization code）
- 简化模式（implicit）
- 密码模式（resource owner password credentials）
- 客户端模式（client credentials）

本文重点讲解接口对接中常使用的密码模式（以下简称password模式）和客户端模式（以下简称client模式）。授权码模式使用到了回调地址，是最为复杂的方式，通常网站中经常出现的微博，qq第三方登录，都会采用这个形式。简化模式不常用。

#小试牛刀

##项目准备

主要的maven依赖如下

**一下是基于springboot2.0的配置**

```xml
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-security</artifactId>
</dependency>
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-web</artifactId>
</dependency>
<!-- https://mvnrepository.com/artifact/org.springframework.security.oauth/spring-security-oauth2 -->
<dependency>
   <groupId>org.springframework.security.oauth</groupId>
   <artifactId>spring-security-oauth2</artifactId>
   <version>2.3.3.RELEASE</version>
</dependency>
```

我们给自己先定个目标，要干什么事？既然说到保护应用，那必须得先有一些资源，我们创建一个endpoint作为提供给外部的接口： 

```java
@RestController
public class TestEndpoints {

    @GetMapping("/product/{id}")
    public String getProduct(@PathVariable String id) {
        //for debug
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "product id : " + id;
    }

    @GetMapping("/order/{id}")
    public String getOrder(@PathVariable String id) {
	    //for debug
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "order id : " + id;
    }

}
```

暴露一个商品查询接口，后续不做安全限制，一个订单查询接口，后续添加访问控制。 

##配置资源服务器和授权服务器

由于是两个oauth2的核心配置，我们放到一个配置类中。
为了方便下载代码直接运行，我这里将客户端信息放到了内存中，生产中可以配置到数据库中。token的存储一般选择使用redis，一是性能比较好，二是自动过期的机制，符合token的特性。

```java
@Configuration
public class OAuth2ServerConfig {

    private static final String DEMO_RESOURCE_ID = "order";

    @Configuration
    @EnableResourceServer
    protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

        @Override
        public void configure(ResourceServerSecurityConfigurer resources) {
            resources.resourceId(DEMO_RESOURCE_ID).stateless(true);
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            // @formatter:off
            http
                    // Since we want the protected resources to be accessible in the UI as well we need
                    // session creation to be allowed (it's disabled by default in 2.0.6)
                    .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .and()
                    .requestMatchers().anyRequest()
                    .and()
                    .anonymous()
                    .and()
                    .authorizeRequests()
//                    .antMatchers("/product/**").access("#oauth2.hasScope('select') and hasRole('ROLE_USER')")
                    .antMatchers("/order/**").authenticated();//配置order访问控制，必须认证过后才可以访问
            // @formatter:on
        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

        /**
         * 如果WebSecurityConfig中没有@Bean暴露AuthenticationManager，这个地方会报错，springboot2.0发生了略微改动
         */
        @Autowired
        AuthenticationManager authenticationManager;

        @Autowired
        RedisConnectionFactory redisConnectionFactory;

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            //        password 方案一：明文存储，用于测试，不能用于生产
//        String finalSecret = "123456";
//        password 方案二：用 BCrypt 对密码编码
//        String finalSecret = new BCryptPasswordEncoder().encode("123456");
            // password 方案三：支持多种编码，通过密码的前缀区分编码方式
            String finalSecret = "{bcrypt}"+new BCryptPasswordEncoder().encode("123456");
            //配置两个客户端,一个用于password认证一个用于client认证
            clients.inMemory().withClient("client_1")
                    .resourceIds(DEMO_RESOURCE_ID)
                    .authorizedGrantTypes("client_credentials", "refresh_token")
                    .scopes("select")
                    .authorities("client")
                    .secret(finalSecret)
                    .and().withClient("client_2")
                    .resourceIds(DEMO_RESOURCE_ID)
                    .authorizedGrantTypes("password", "refresh_token")
                    .scopes("select")
                    .authorities("client")
                    .secret(finalSecret);
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                    .tokenStore(new RedisTokenStore(redisConnectionFactory))
                    .authenticationManager(authenticationManager);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
            //允许表单认证
            oauthServer.allowFormAuthenticationForClients();
        }

    }

}
```

- client模式，没有用户的概念，直接与认证服务器交互，用配置中的客户端信息去申请accessToken，客户端有自己的client_id,client_secret对应于用户的username,password，而客户端也拥有自己的authorities，当采取client模式认证时，对应的权限也就是客户端自己的authorities。
- password模式，自己本身有一套用户体系，在认证时需要带上自己的用户名和密码，以及客户端的client_id,client_secret。此时，accessToken所包含的权限是用户本身的权限，而不是客户端的权限。

*我对于两种模式的理解便是，如果你的系统已经有了一套用户体系，每个用户也有了一定的权限，可以采用password模式；如果仅仅是接口的对接，不考虑用户，则可以使用client模式。*

##配置spring security

在spring security的版本迭代中，产生了多种配置方式，建造者模式，适配器模式等等设计模式的使用，spring security内部的认证flow也是错综复杂，在我一开始学习ss也产生了不少困惑，总结了一下配置经验：使用了springboot之后，spring security其实是有不少自动配置的，我们可以仅仅修改自己需要的那一部分，并且遵循一个原则，直接覆盖最需要的那一部分。这一说法比较抽象，举个例子。比如配置内存中的用户认证器。有两种配置方式 

PlanA

```java
@Bean
protected UserDetailsService userDetailsService(){
    InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
    manager.createUser(User.withUsername("user_1").password("123456").authorities("USER").build());
    manager.createUser(User.withUsername("user_2").password("123456").authorities("USER").build());
    return manager;
}
```

PlanB

```java
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("user_1").password("123456").authorities("USER")
                .and()
                .withUser("user_2").password("123456").authorities("USER");
   }

   @Bean
   @Override
   public AuthenticationManager authenticationManagerBean() throws Exception {
       AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }
}
```

你最终都能得到配置在内存中的两个用户，前者是直接替换掉了容器中的UserDetailsService，这么做比较直观；后者是替换了AuthenticationManager，当然你还会在SecurityConfiguration 复写其他配置，这么配置最终会由一个委托者去认证。如果你熟悉spring security，会知道AuthenticationManager和AuthenticationProvider以及UserDetailsService的关系，他们都是顶级的接口，实现类之间错综复杂的聚合关系…配置方式千差万别，但理解清楚认证流程，知道各个实现类对应的职责才是掌握spring security的关键。 

下面给出我最终的配置： 

```java
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    @Override
    protected UserDetailsService userDetailsService(){
        BCryptPasswordEncoder bCryptPasswordEncoder = new BCryptPasswordEncoder();
//        password 方案一：明文存储，用于测试，不能用于生产
//        String finalPassword = "123456";
//        password 方案二：用 BCrypt 对密码编码
//        String finalPassword = bCryptPasswordEncoder.encode("123456");
        // password 方案三：支持多种编码，通过密码的前缀区分编码方式
        String finalPassword = "{bcrypt}"+bCryptPasswordEncoder.encode("123456");
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user_1").password(finalPassword).authorities("USER").build());
        manager.createUser(User.withUsername("user_2").password(finalPassword).authorities("USER").build());
        return manager;
    }
    @Bean
    PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
    /**
     * 这一步的配置是必不可少的，否则SpringBoot会自动配置一个AuthenticationManager,覆盖掉内存中的用户
     * springboot2.0 的自动配置发生略微的变更，原先的自动配置现在需要通过@Bean暴露，否则你会得到AuthenticationManager找不到的异常
     */
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        AuthenticationManager manager = super.authenticationManagerBean();
        return manager;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
                .requestMatchers().anyRequest()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth/*").permitAll();
        // @formatter:on
    }
}
```

重点就是配置了一个UserDetailsService，和ClientDetailsService一样，为了方便运行，使用内存中的用户，实际项目中，一般使用的是数据库保存用户，具体的实现类可以使用JdbcDaoImpl或者JdbcUserDetailsManager。 

##获取token

此时启动应用，发现会多了一些自动创建的endpoints

![1526277174698](C:\Users\liusl12\AppData\Local\Temp\1526277174698.png)

重点关注一下/oauth/token，它是获取的token的endpoint。启动springboot应用之后，使用http工具访问 password模式： 

http://localhost:8082/oauth/token?username=user_1&password=123456&grant_type=password&scope=select&client_id=client_2&client_secret=123456 

响应如下：

{
    "access_token": "3e432e32-9cfe-4ca5-9bee-421a6afbce99",
    "token_type": "bearer",
    "refresh_token": "2df4a300-230d-439b-924c-f76007947af4",
    "expires_in": 43199,
    "scope": "select"
}

client模式：

http://localhost:8082/oauth/token?grant_type=client_credentials&scope=select&client_id=client_1&client_secret=123456 

{
    "access_token": "47dbc823-9925-4280-a269-48aac2175835",
    "token_type": "bearer",
    "expires_in": 43199,
    "scope": "select"
}

在配置中，我们已经配置了对order资源的保护，如果直接访问:`http://localhost:8080/order/1`会得到这样的响应:`{"error":"unauthorized","error_description":"Full authentication is required to access this resource"}`
（这样的错误响应可以通过重写配置来修改）

而对于未受保护的product资源`http://localhost:8080/product/1`则可以直接访问，得到响应`product id : 1`

携带accessToken参数访问受保护的资源：

使用password模式获得的token:`http://localhost:8080/order/1?access_token=950a7cc9-5a8a-42c9-a693-40e817b1a4b0`，得到了之前匿名访问无法获取的资源：`order id : 1`

使用client模式获得的token:`http://localhost:8080/order/1?access_token=56465b41-429d-436c-ad8d-613d476ff322`，同上的响应`order id : 1`

我们重点关注一下debug后，对资源访问时系统记录的用户认证信息，可以看到如下的debug信息 

![password模式](http://img.blog.csdn.net/20170808145230975?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMzgxNTU0Ng==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast) 

client模式

![client模式](http://img.blog.csdn.net/20170808145304794?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMzgxNTU0Ng==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast) 

和我们的配置是一致的，仔细看可以发现两者的身份有些许的不同。想要查看更多的debug信息，可以选择下载demo代码自己查看，为了方便读者调试和验证，我去除了很多复杂的特性，基本实现了一个最简配置，涉及到数据库的地方也尽量配置到了内存中，这点记住在实际使用时一定要修改。

到这儿，一个简单的oauth2入门示例就完成了，一个简单的配置教程。token的工作原理是什么，它包含了哪些信息？spring内部如何对身份信息进行验证？以及上述的配置到底影响了什么？这些内容会放到后面的文章中去分析。

#详解

首先开启debug信息：

```yaml
logging:
  level:
    org.springframework: DEBUG
```

可以完整的看到内部的运转流程。

client模式稍微简单一些，使用client模式获取token
`http://localhost:8080/oauth/token?client_id=client_1&client_secret=123456&scope=select&grant_type=client_credentials`

由于debug信息太多了，我简单按照顺序列了一下关键的几个类：

```
ClientCredentialsTokenEndpointFilter
DaoAuthenticationProvider
TokenEndpoint
TokenGranter
```

## @EnableAuthorizationServer

上一篇博客中我们尝试使用了password模式和client模式，有一个比较关键的endpoint：/oauth/token。从这个入口开始分析，spring security oauth2内部是如何生成token的。获取token，与第一篇文章中的两个重要概念之一有关，也就是AuthorizationServer与ResourceServer中的AuthorizationServer。

在之前的配置中

```java
@Configuration
@EnableAuthorizationServer
protected static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {}
```

出现了AuthorizationServerConfigurerAdapter 关键类，他关联了三个重要的配置类，分别是 

```java
public class AuthorizationServerConfigurerAdapter implements AuthorizationServerConfigurer {
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security <1>) throws Exception{
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients <2>) throws Exception {
	}

	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints <3>) throws Exception {
	}

}
```

<1> 配置AuthorizationServer安全认证的相关信息，创建ClientCredentialsTokenEndpointFilter核心过滤器

<2> 配置OAuth2的客户端相关信息

<3> 配置AuthorizationServerEndpointsConfigurer众多相关类，包括配置身份认证器，配置认证方式，TokenStore，TokenGranter，OAuth2RequestFactory

我们逐步分析其中关键的类

## 客户端身份认证核心过滤器ClientCredentialsTokenEndpointFilter（掌握）

截取关键的代码，可以分析出大概的流程 在请求到达/oauth/token之前经过了ClientCredentialsTokenEndpointFilter这个过滤器，关键方法如下 

```java
@Override
public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
      throws AuthenticationException, IOException, ServletException {

   if (allowOnlyPost && !"POST".equalsIgnoreCase(request.getMethod())) {
      throw new HttpRequestMethodNotSupportedException(request.getMethod(), new String[] { "POST" });
   }

   String clientId = request.getParameter("client_id");
   String clientSecret = request.getParameter("client_secret");

   // If the request is already authenticated we can assume that this
   // filter is not needed
   Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
   if (authentication != null && authentication.isAuthenticated()) {
      return authentication;
   }

   if (clientId == null) {
      throw new BadCredentialsException("No client credentials presented");
   }

   if (clientSecret == null) {
      clientSecret = "";
   }

   clientId = clientId.trim();
   UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(clientId,
         clientSecret);

   return this.getAuthenticationManager().authenticate(authRequest);

}
```

##TokenEndpoint

经过ClientCredentialsTokenEndpointFilter之后，身份信息已经得到了AuthenticationManager的验证。接着便到达了 TokenEndpoint。  ## Token处理端点TokenEndpoint（掌握）  前面的两个ClientCredentialsTokenEndpointFilter和AuthenticationManager可以理解为一些前置校验，和身份封装，而这个类一看名字就知道和我们的token是密切相关的。 

```java
@FrameworkEndpoint
public class TokenEndpoint extends AbstractEndpoint {

	@RequestMapping(value = "/oauth/token", method=RequestMethod.POST)
	public ResponseEntity<OAuth2AccessToken> postAccessToken(Principal principal, @RequestParam
	Map<String, String> parameters) throws HttpRequestMethodNotSupportedException {
		 ...
		String clientId = getClientId(principal);
		ClientDetails authenticatedClient = getClientDetailsService().loadClientByClientId(clientId);//<1>
		...
		TokenRequest tokenRequest = getOAuth2RequestFactory().createTokenRequest(parameters, authenticatedClient);//<2>
		...
		OAuth2AccessToken token = getTokenGranter().grant(tokenRequest.getGrantType(), tokenRequest);//<3>
		...
		return getResponse(token);
	
	}
	
	private TokenGranter tokenGranter;
}
```

<1> 加载客户端信息  <2> 结合请求信息，创建TokenRequest  <3> 将TokenRequest传递给TokenGranter颁发token  省略了一些校验代码之后，真正的/oauth/token端点暴露在了我们眼前，其中方法参数中的Principal经过之前的过滤器，已经被填充了相关的信息，而方法的内部则是依赖了一个TokenGranter 来颁发token。其中OAuth2AccessToken的实现类DefaultOAuth2AccessToken就是最终在控制台得到的token序列化之前的原始类: 

```java
public class DefaultOAuth2AccessToken implements Serializable, OAuth2AccessToken {
  private static final long serialVersionUID = 914967629530462926L;
  private String value;
  private Date expiration;
  private String tokenType = BEARER_TYPE.toLowerCase();
  private OAuth2RefreshToken refreshToken;
  private Set<String> scope;
  private Map<String, Object> additionalInformation = Collections.emptyMap();
  //getter,setter
}
```

```java
@org.codehaus.jackson.map.annotate.JsonSerialize(using = OAuth2AccessTokenJackson1Serializer.class)
@org.codehaus.jackson.map.annotate.JsonDeserialize(using = OAuth2AccessTokenJackson1Deserializer.class)
@com.fasterxml.jackson.databind.annotation.JsonSerialize(using = OAuth2AccessTokenJackson2Serializer.class)
@com.fasterxml.jackson.databind.annotation.JsonDeserialize(using = OAuth2AccessTokenJackson2Deserializer.class)
public interface OAuth2AccessToken {
	public static String BEARER_TYPE = "Bearer";
	public static String OAUTH2_TYPE = "OAuth2";
	public static String ACCESS_TOKEN = "access_token";
	public static String TOKEN_TYPE = "token_type";
	public static String EXPIRES_IN = "expires_in";
	public static String REFRESH_TOKEN = "refresh_token";
	public static String SCOPE = "scope";
	...
}
```

一个典型的样例token响应,如下所示，就是上述类序列化后的结果： 

```json
{ 
	"access_token":"950a7cc9-5a8a-42c9-a693-40e817b1a4b0", 
	"token_type":"bearer", 
	"refresh_token":"773a0fcd-6023-45f8-8848-e141296cb3cb", 
	"expires_in":27036, 
	"scope":"select" 
}
```

##TokenGranter（掌握） 

![这里写图片描述](http://img.blog.csdn.net/20170809134129753?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMzgxNTU0Ng==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast) 

TokenGranter的设计思路是使用CompositeTokenGranter管理一个List列表，每一种grantType对应一个具体的真正授权者，在debug过程中可以发现CompositeTokenGranter 内部就是在循环调用五种TokenGranter实现类的grant方法，而granter内部则是通过grantType来区分是否是各自的授权类型。 

```java
public class CompositeTokenGranter implements TokenGranter {
	
	private final List<TokenGranter> tokenGranters;
	
	public CompositeTokenGranter(List<TokenGranter> tokenGranters) {
		this.tokenGranters = new ArrayList<TokenGranter>(tokenGranters);
	}
	
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
		for (TokenGranter granter : tokenGranters) {
			OAuth2AccessToken grant = granter.grant(grantType, tokenRequest);
			if (grant!=null) {
				return grant;
			}
		}
		return null;
	}
}
```

五种类型分别是：

- ResourceOwnerPasswordTokenGranter ==> password密码模式
- AuthorizationCodeTokenGranter ==> authorization_code授权码模式
- ClientCredentialsTokenGranter ==> client_credentials客户端模式
- ImplicitTokenGranter ==> implicit简化模式
- RefreshTokenGranter ==>refresh_token 刷新token专用

以客户端模式为例，思考如何产生token的，则需要继续研究5种授权者的抽象类：AbstractTokenGranter

```java
public abstract class AbstractTokenGranter implements TokenGranter {
	protected final Log logger = LogFactory.getLog(getClass());
	//与token相关的service，重点
	private final AuthorizationServerTokenServices tokenServices;
	//与clientDetails相关的service，重点
	private final ClientDetailsService clientDetailsService;
	//创建oauth2Request的工厂，重点
	private final OAuth2RequestFactory requestFactory;
	
	private final String grantType;
	...
	
	public OAuth2AccessToken grant(String grantType, TokenRequest tokenRequest) {
	
		...
		String clientId = tokenRequest.getClientId();
		ClientDetails client = clientDetailsService.loadClientByClientId(clientId);
		validateGrantType(grantType, client);
		
		logger.debug("Getting access token for: " + clientId);
	
		return getAccessToken(client, tokenRequest);
	
	}
	
	protected OAuth2AccessToken getAccessToken(ClientDetails client, TokenRequest tokenRequest) {
		return tokenServices.createAccessToken(getOAuth2Authentication(client, tokenRequest));
	}
	
	protected OAuth2Authentication getOAuth2Authentication(ClientDetails client, TokenRequest tokenRequest) {
		OAuth2Request storedOAuth2Request = requestFactory.createOAuth2Request(client, tokenRequest);
		return new OAuth2Authentication(storedOAuth2Request, null);
	}
	
	...
}
```

回过头去看TokenEndpoint中，正是调用了这里的三个重要的类变量的相关方法。由于篇幅限制，不能延展太多，不然没完没了，所以重点分析下AuthorizationServerTokenServices是何方神圣。 

## AuthorizationServerTokenServices（了解）

AuthorizationServer端的token操作service，接口设计如下： 

```java

public interface AuthorizationServerTokenServices {
	//创建token
	OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException;
	//刷新token
	OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest)
			throws AuthenticationException;
	//获取token
	OAuth2AccessToken getAccessToken(OAuth2Authentication authentication);

}
```

在默认的实现类DefaultTokenServices中，可以看到token是如何产生的，并且了解了框架对token进行哪些信息的关联。 

```java
@Transactional
public OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException {

	OAuth2AccessToken existingAccessToken = tokenStore.getAccessToken(authentication);
	OAuth2RefreshToken refreshToken = null;
	if (existingAccessToken != null) {
		if (existingAccessToken.isExpired()) {
			if (existingAccessToken.getRefreshToken() != null) {
				refreshToken = existingAccessToken.getRefreshToken();
				// The token store could remove the refresh token when the
				// access token is removed, but we want to
				// be sure...
				tokenStore.removeRefreshToken(refreshToken);
			}
			tokenStore.removeAccessToken(existingAccessToken);
		}
		else {
			// Re-store the access token in case the authentication has changed
			tokenStore.storeAccessToken(existingAccessToken, authentication);
			return existingAccessToken;
		}
	}

	// Only create a new refresh token if there wasn't an existing one
	// associated with an expired access token.
	// Clients might be holding existing refresh tokens, so we re-use it in
	// the case that the old access token
	// expired.
	if (refreshToken == null) {
		refreshToken = createRefreshToken(authentication);
	}
	// But the refresh token itself might need to be re-issued if it has
	// expired.
	else if (refreshToken instanceof ExpiringOAuth2RefreshToken) {
		ExpiringOAuth2RefreshToken expiring = (ExpiringOAuth2RefreshToken) refreshToken;
		if (System.currentTimeMillis() > expiring.getExpiration().getTime()) {
			refreshToken = createRefreshToken(authentication);
		}
	}

	OAuth2AccessToken accessToken = createAccessToken(authentication, refreshToken);
	tokenStore.storeAccessToken(accessToken, authentication);
	// In case it was modified
	refreshToken = accessToken.getRefreshToken();
	if (refreshToken != null) {
		tokenStore.storeRefreshToken(refreshToken, authentication);
	}
	return accessToken;

}
```

简单总结一下AuthorizationServerTokenServices的作用，他提供了创建token，刷新token，获取token的实现。在创建token时，他会调用tokenStore对产生的token和相关信息存储到对应的实现类中，可以是redis，数据库，内存，jwt。 

## @EnableResourceServer与@EnableAuthorizationServer

还记得我们在第一节中就介绍过了OAuth2的两个核心概念，资源服务器与身份认证服务器。我们对两个注解进行配置的同时，到底触发了内部的什么相关配置呢？

上一篇文章重点介绍的其实是与身份认证相关的流程，即如果获取token，而本节要分析的携带token访问受限资源，自然便是与@EnableResourceServer相关的资源服务器配置了。

我们注意到其相关配置类是ResourceServerConfigurer，内部关联了ResourceServerSecurityConfigurer和HttpSecurity。前者与资源安全配置相关，后者与http安全配置相关。（类名比较类似，注意区分，以Adapter结尾的是适配器，以Configurer结尾的是配置器，以Builder结尾的是建造器，他们分别代表不同的设计模式，对设计模式有所了解可以更加方便理解其设计思路） 

```java
public class ResourceServerConfigurerAdapter implements ResourceServerConfigurer {

   @Override
   public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
   }

   @Override
   public void configure(HttpSecurity http) throws Exception {
      http.authorizeRequests().anyRequest().authenticated();
   }

}
```

## ResourceServerSecurityConfigurer（了解）

核心配置如下：

```java
public void configure(HttpSecurity http) throws Exception {
	AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
	resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();//<1>
	resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
	resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);//<2>
	if (eventPublisher != null) {
		resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
	}
	if (tokenExtractor != null) {
		resourcesServerFilter.setTokenExtractor(tokenExtractor);//<3>
	}
	resourcesServerFilter = postProcess(resourcesServerFilter);
	resourcesServerFilter.setStateless(stateless);

	// @formatter:off
	http
		.authorizeRequests().expressionHandler(expressionHandler)
	.and()
		.addFilterBefore(resourcesServerFilter, AbstractPreAuthenticatedProcessingFilter.class)
		.exceptionHandling()
			.accessDeniedHandler(accessDeniedHandler)//<4>
			.authenticationEntryPoint(authenticationEntryPoint);
	// @formatter:on
}
```

这段是整个oauth2与HttpSecurity相关的核心配置，其中有非常多的注意点，顺带的都强调一下：

<1> 创建OAuth2AuthenticationProcessingFilter，即下一节所要介绍的OAuth2核心过滤器。

<2> 为OAuth2AuthenticationProcessingFilter提供固定的AuthenticationManager即OAuth2AuthenticationManager，它并没有将OAuth2AuthenticationManager添加到spring的容器中，不然可能会影响spring security的普通认证流程（非oauth2请求），只有被OAuth2AuthenticationProcessingFilter拦截到的oauth2相关请求才被特殊的身份认证器处理。

<3> 设置了TokenExtractor默认的实现—-BearerTokenExtractor，这个类在下一节介绍。

<4> 相关的异常处理器，可以重写相关实现，达到自定义异常的目的。

还记得我们在一开始的配置中配置了资源服务器，是它触发了相关的配置。

```java
@Configuration
@EnableResourceServer
protected static class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {}
```

## 核心过滤器 OAuth2AuthenticationProcessingFilter（掌握）

回顾一下我们之前是如何携带token访问受限资源的： `http://localhost:8080/order/1?access_token=950a7cc9-5a8a-42c9-a693-40e817b1a4b0` 唯一的身份凭证，便是这个access_token，携带它进行访问，会进入OAuth2AuthenticationProcessingFilter之中，其核心代码如下： 

```java
public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain){
	final HttpServletRequest request = (HttpServletRequest) req;
	final HttpServletResponse response = (HttpServletResponse) res;

	try {
		//从请求中取出身份信息，即access_token
		Authentication authentication = tokenExtractor.extract(request);
		
		if (authentication == null) {
			...
		}
		else {
			request.setAttribute(OAuth2AuthenticationDetails.ACCESS_TOKEN_VALUE, authentication.getPrincipal());
			if (authentication instanceof AbstractAuthenticationToken) {
				AbstractAuthenticationToken needsDetails = (AbstractAuthenticationToken) authentication;
				needsDetails.setDetails(authenticationDetailsSource.buildDetails(request));
			}
			//认证身份
			Authentication authResult = authenticationManager.authenticate(authentication);
			...
			eventPublisher.publishAuthenticationSuccess(authResult);
			//将身份信息绑定到SecurityContextHolder中
			SecurityContextHolder.getContext().setAuthentication(authResult);
		}
	}
	catch (OAuth2Exception failed) {
		...
		return;
	}

	chain.doFilter(request, response);
}
```

整个过滤器便是oauth2身份鉴定的关键，在源码中，对这个类有一段如下的描述 

> A pre-authentication filter for OAuth2 protected resources. Extracts an OAuth2 token from the incoming request and uses it to populate the Spring Security context with an {@link OAuth2Authentication} (if used in conjunction with an {@link OAuth2AuthenticationManager}). OAuth2保护资源的预先认证过滤器。如果与OAuth2AuthenticationManager结合使用，则会从到来的请求之中提取一个OAuth2 token，之后使用OAuth2Authentication来填充Spring Security上下文。

其中涉及到了两个关键的类TokenExtractor，AuthenticationManager。相信后者这个接口大家已经不陌生，但前面这个类之前还未出现在我们的视野中。

## OAuth2的身份管理器–OAuth2AuthenticationManager（掌握）

在之前的OAuth2核心过滤器中出现的AuthenticationManager其实在我们意料之中，携带access_token必定得经过身份认证，但是在我们debug进入其中后，发现了一个出乎意料的事，AuthenticationManager的实现类并不是我们在前面文章中聊到的常用实现类ProviderManager，而是OAuth2AuthenticationManager。 

![OAuth2AuthenticationManager](http://img.blog.csdn.net/20170810122532720?watermark/2/text/aHR0cDovL2Jsb2cuY3Nkbi5uZXQvdTAxMzgxNTU0Ng==/font/5a6L5L2T/fontsize/400/fill/I0JBQkFCMA==/dissolve/70/gravity/SouthEast) 

这里要强调的是OAuth2AuthenticationManager是密切与token认证相关的，而不是与获取token密切相关的。 

其判别身份的关键代码如下： 

```java
public Authentication authenticate(Authentication authentication) throws AuthenticationException {
	...
	String token = (String) authentication.getPrincipal();
	//最终还是借助tokenServices根据token加载身份信息
	OAuth2Authentication auth = tokenServices.loadAuthentication(token);
	...

	checkClientDetails(auth);

	if (authentication.getDetails() instanceof OAuth2AuthenticationDetails) {
		OAuth2AuthenticationDetails details = (OAuth2AuthenticationDetails) authentication.getDetails();
		...
	}
	auth.setDetails(authentication.getDetails());
	auth.setAuthenticated(true);
	return auth;

}
```

说到tokenServices这个密切与token相关的接口，这里要强调下，避免产生误解。tokenServices分为两类，一个是用在AuthenticationServer端 

```java
public interface AuthorizationServerTokenServices {
    //创建token
    OAuth2AccessToken createAccessToken(OAuth2Authentication authentication) throws AuthenticationException;
    //刷新token
    OAuth2AccessToken refreshAccessToken(String refreshToken, TokenRequest tokenRequest)
            throws AuthenticationException;
    //获取token
    OAuth2AccessToken getAccessToken(OAuth2Authentication authentication);
}
```

而在ResourceServer端有自己的tokenServices接口： 

```java
public interface ResourceServerTokenServices {
	//根据accessToken加载客户端信息
	OAuth2Authentication loadAuthentication(String accessToken) throws AuthenticationException, InvalidTokenException;

	//根据accessToken获取完整的访问令牌详细信息。
	OAuth2AccessToken readAccessToken(String accessToken);

}
```

具体内部如何加载，和AuthorizationServer大同小异，只是从tokenStore中取出相应身份的流程有点区别，不再详细看实现类了。 

## TokenExtractor（了解）

这个接口只有一个实现类，而且代码非常简单 

```java
public class BearerTokenExtractor implements TokenExtractor {
	private final static Log logger = LogFactory.getLog(BearerTokenExtractor.class);
	@Override
	public Authentication extract(HttpServletRequest request) {
		String tokenValue = extractToken(request);
		if (tokenValue != null) {
			PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(tokenValue, "");
			return authentication;
		}
		return null;
	}

	protected String extractToken(HttpServletRequest request) {
		// first check the header...
		String token = extractHeaderToken(request);

		// bearer type allows a request parameter as well
		if (token == null) {
			...
			//从requestParameter中获取token
		}

		return token;
	}

/**
	 * Extract the OAuth bearer token from a header.
	 */
	protected String extractHeaderToken(HttpServletRequest request) {
		Enumeration<String> headers = request.getHeaders("Authorization");
		while (headers.hasMoreElements()) { // typically there is only one (most servers enforce that)
			...
			//从Header中获取token
		}
		return null;
	}

}
```

它的作用在于分离出请求中包含的token。也启示了我们可以使用多种方式携带token。 

1. 在Header中携带 

   http://localhost:8080/order/1 Header： Authentication：Bearer f732723d-af7f-41bb-bd06-2636ab2be135  

2. 拼接在url中作为requestParam 

   http://localhost:8080/order/1?access_token=f732723d-af7f-41bb-bd06-2636ab2be135

3. 在form表单中携带 

   ```
   http://localhost:8080/order/1
   form param：
   access_token=f732723d-af7f-41bb-bd06-2636ab2be135
   ```

## 异常处理

OAuth2在资源服务器端的异常处理不算特别完善，但基本够用，如果想要重写异常机制，可以直接替换掉相关的Handler，如权限相关的AccessDeniedHandler。具体的配置应该在@EnableResourceServer中被覆盖，这是适配器+配置器的好处。
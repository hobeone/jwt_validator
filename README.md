Simple Cloudflare Access JWT validation microservice.

Used by Nginx to validate Cloudflare JWT and extract the claim email from them.  Can be used to pass authentication information to proxied services (Grafana in my original use case).

Grab your Cloudflare Access information and dump them in `.env`.  Then `docker compose up` should get things going.

```
  # Define the upstream for the JWT validation service.
  # NGINX Open Source cannot validate JWTs natively. It needs to make a
  # subrequest to a small, fast internal service that can.
  # This service should return a 200 OK status for a valid token
  # and a 401 Unauthorized status for an invalid or missing token.
  upstream jwt_validator_service {
    server 127.0.0.1:9001;
  }

 location / {
    auth_request /check_jwt;
    auth_request_set $x_authentication_id $sent_http_x_authentication_id;
    error_page 401 = @do_basic_auth;
    include            proxy_params;
    proxy_set_header X-WEBAUTH-USER $x_authentication_id;
    proxy_pass         http://grafana;
  }
 
  # --- Internal subrequest handler for JWT check ---
  location = /check_jwt {
    internal;
 
    # If the auth cookie is missing, deny access immediately.
    # This triggers the 401 error_page in the parent location.
    if ($cookie_CF_Authorization = "") {
      return 401;
    }
 
    # If cookie exists, proxy to validator service.
    proxy_pass http://jwt_validator_service/validate;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
  }

 
  # --- Internal fallback handler for Basic Auth ---
  location @do_basic_auth {
    # Perform basic authentication.
    auth_basic "Restricted Content";
    auth_basic_user_file /etc/nginx/htpasswd;
 
    # If basic auth succeeds, we must proxy from here.
    # The original location's proxy_pass is not executed.
    # We use the map to send the request to the correct backend.
    include proxy_params;
    proxy_set_header X-WEBAUTH-USER $remote_user;
    proxy_pass http://grafana;
  }
```

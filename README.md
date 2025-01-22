# Traefik Plugin Safeline

This plugin is a middleware for Traefik that can be used to detect and block malicious requests which base on the [Safeline](https://waf.chaitin.com/) engine.

## Safeline Prepare
The detection engine of the SafeLine provides services by default via Unix socket. We need to modify it to use TCP, so it can be called by the t1k plugin.

1.Navigate to the configuration directory of the SafeLine detection engine:
```shell
cd /data/safeline/resources/detector/
```
2.Open the `detector.yml` file in a text editor. Modify the bind configuration from Unix socket to TCP by adding the following settings:
```yaml
bind_addr: 0.0.0.0
listen_port: 8000
```
These configuration values will override the default settings in the container, making the SafeLine engine listen on port 8000.

3.Next, map the container’s port 8000 to the host machine. First, navigate to the SafeLine installation directory:
```shell
cd /data/safeline
```

4.Open the compose.yaml file in a text editor and add the ports field to the detector container to expose port 8000:
```yaml
...
detect:
  ports:
    - 8000:8000
...
```

5.Save the changes and restart SafeLine with the following commands:
```shell
docker-compose down
docker-compose up -d
```
This will apply the changes and activate the new configuration.

## Plugin Usage

For a plugin to be active for a given Traefik instance, it must be declared in the static configuration.

Plugins are parsed and loaded exclusively during startup, which allows Traefik to check the integrity of the code and catch errors early on.
If an error occurs during loading, the plugin is disabled.

For security reasons, it is not possible to start a new plugin or modify an existing one while Traefik is running.

Once loaded, middleware plugins behave exactly like statically compiled middlewares.
Their instantiation and behavior are driven by the dynamic configuration.

Plugin dependencies must be [vendored](https://golang.org/ref/mod#vendoring) for each plugin.
Vendored packages should be included in the plugin's GitHub repository. ([Go modules](https://blog.golang.org/using-go-modules) are not supported.)

### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

```yaml
# Static configuration

experimental:
  plugins:
    safeline:
      moduleName: github.com/chaitin/traefik-safeline
      version: v1.0.0
```

Here is an example of a file provider dynamic configuration (given here in YAML), where the interesting part is the `http.middlewares` section:

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`demo.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - chaitin

  services:
   service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
  
  middlewares:
    chaitin:
      plugin:
        safeline:
          addr: safeline-detector.safeline:8000 # Safeline detection engine address
```

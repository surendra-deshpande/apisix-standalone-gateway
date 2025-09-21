FROM apache/apisix:3.11.0-debian

#adding custom plugins. Make sure to configure the same in the routes.
COPY --chown=apisix ./plugins/datadome-protect.lua /usr/local/apisix/apisix/plugins/datadome-protect.lua
COPY --chown=apisix ./plugins/jwt-header-plugin.lua /usr/local/apisix/apisix/plugins/jwt-header-plugin.lua

#Update default config.
#Note, different versions may have fewer plugins. Accordingly adjust the config file.
COPY --chown=apisix ./conf/config.yaml /usr/local/apisix/conf/config.yaml
COPY --chown=apisix ./conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml

# Ensure read and write permissions for all users
RUN chmod -R 777 /usr/local/apisix/conf/config.yaml

RUN ls -ltr /usr/local/apisix/conf

# RUN cat /usr/local/apisix/conf/config.yaml
## Repo to setup APISIX standalone gateway ( without ETCD )

Build the docker image using 
`docker build -t apisix-gateway`

Run the docker image built using above step
`docker run -p 80:9080 api-gateway`

Access the gateway using the browser: `http://localhost/hello`

The routes are mentioned in `conf/apisix.yaml`
## Internet Compliance Scanning


Before running the script, you need to create/run following docker container:
```bash
# RPKI server docker start:
# https://routinator.docs.nlnetlabs.nl/en/stable/installation.html

# To persist the RPKI cache data you can create a separate Docker volume and mount it into the container like so:
# sudo docker volume create rpki-cache
docker run -d --restart=unless-stopped --name routinator -p 3323:3323  -p 8323:8323  -v rpki-cache:/home/routinator/.rpki-cache nlnetlabs/routinator


# To run Routinator as a background daemon with the default settings (RTR server on port 3323 and HTTP server on port 8323) can be done like so:
docker run -d --restart=unless-stopped --name routinator \
    -p 3323:3323 \
    -p 8323:8323 \
    nlnetlabs/routinator
    

# To update the docker container:
sudo docker pull nlnetlabs/routinator
sudo docker rm --force routinator
sudo docker run <your usual arguments> nlnetlabs/routinator
```


### Troubleshooting
In some networks, the routinator container can't connect to the known RPKI repositories on port 873 (`rsync error: error in socket IO (code 10) at clientserver.c(139) [Receiver=3.4.0]`) . In this case, you can try to use a different DNS server. For example, you can use Google's DNS server by adding the following argument to the docker run command:
1. First you need to update the `/etc/docker/daemon.json` file. In case that it hasn't been created yet, you need to create it by following content:
```json
{
    "dns": ["8.8.8.8", "8.8.4.4"]
}
```
2. Then you need to restart the docker service:
```bash
sudo systemctl restart docker
```

3. Finally:
```bash
# Stop and remove the current container
docker stop routinator
docker rm routinator

# Start a new container with the new DNS server
docker run -d --restart=unless-stopped --name routinator \
    -p 3323:3323 \
    -p 8323:8323 \
    --dns 8.8.8.8
    --dns 8.8.4.4
    nlnetlabs/routinator
```
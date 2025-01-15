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

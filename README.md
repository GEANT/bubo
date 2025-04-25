# Internet and Email Compliance Checker
A tool for validating domains against various internet standards, including RPKI, DANE, DNSSEC, Email Security (SPF, DKIM, DMARC), and Web Security (Certificate, Protocol & Ciphers, and HTTP headers).

## What it does
This tool helps you check whether domains comply with important internet security standards:

- **RPKI**: Resource Public Key Infrastructure validation
- **DANE**: DNS-based Authentication of Named Entities
- **DNSSEC**: Domain Name System Security Extensions
- **Email Security**: Checks for SPF, DKIM, and DMARC
- **Web Security**: Validates HTTPS implementation and other web security measures

The results are compiled into an HTML report that makes it easy to assess compliance.
___

## Requirements
- Python 3.10+
- OpenSSL (installed on your system) (`apt install openssl`)
- Routinator (RPKI validator) container.

___

## Setup
### 1. Install Python dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set up Routinator for RPKI checks

Routinator runs as a Docker container and validates Resource Public Key Infrastructure (RPKI).
If you already have Routinator running, you can skip this step and look at the program usage to see how you can specify the routinator url.

```bash
# To persist the RPKI cache data you can create a Docker volume and mount it into the container like so:
docker volume create rpki-cache
docker run -d --restart=unless-stopped --name routinator \
    -p 3323:3323 \
    -p 8323:8323 \
    -v rpki-cache:/home/routinator/.rpki-cache \
    nlnetlabs/routinator
   

# In future, to update the routinator docker container, you can run the following commands:
sudo docker pull nlnetlabs/routinator
sudo docker rm --force routinator
sudo docker run <your usual arguments> nlnetlabs/routinator

# Routinator installation page: 
# https://routinator.docs.nlnetlabs.nl/en/stable/installation.html
```
___

## Usage
You can run the tool in two modes:

1. ### Single domain check
```bash
python main.py --single example.com
```

2. ### Batch domain check
Create a CSV file with the domains you want to check. The file should have at least a "Domain" column, and can optionally include "Country" and "Institution" columns:
```
Domain,Country,Institution
example.nl,NL,Example Organization
example.uk,UK,Example Foundation
```

Then run:
```bash
python main.py --batch path/to/domains.csv
```

### Additional options
```
--batch [-b] FILE               Path to CSV file with domains to check
--single [-d] DOMAIN            Domain to check
--max-concurrent INTEGER        Maximum concurrent validations (default: 48)
--ignore-cache                  Force fresh validation instead of using cached results (the cache is valid for 24 hours).
--routinator-url or -ru URL     URL of the Routinator RPKI validator service (default: http://localhost:8323)
# You can also have an environment variable called ROUTINATOR_URL=http://localhost:8323
```

___

## Output
The tool generates two types of reports:
- **Detailed HTML report** with validation results for each domain
- **Statistics report** summarizing the overall compliance status and scores.

Both reports are saved in the results/ directory with timestamped directory and filenames.\
The HTML report provides a user-friendly visualization of the results, while the JSON file contains the same data in a machine-readable format for further processing.

___

## Cache
Results are cached for 24 hours by default to speed up repeated checks. Use the `--ignore-cache` flag to force new validations.

___

## Docker quick reference
<details>
<summary>Click to expand</summary>

### Build
```bash
docker build -t compliance-checker .
```

### Single Domain Check
```bash
# Basic usage (results in container only)
docker run --rm compliance-checker --single example.com

# With results saved to host
docker run --rm -v "$(pwd)/results:/app/results-docker" compliance-checker --single example.com

# Using named volume
docker volume create compliance_data
docker run --rm -v compliance_data:/app/results-docker compliance-checker --single example.com
```

### Batch Processing
```bash
# Mount CSV file and save results
docker run --rm \
  -v "$(pwd)/domains.csv:/app/domains.csv" \
  -v "$(pwd)/results:/app/results-docker" \
  compliance-checker --batch domains.csv
```

### Common Options
```bash
# Ignore cache
docker run --rm -v "$(pwd)/results:/app/results-docker" compliance-checker --single example.com --ignore-cache

# Custom output directory
docker run --rm -v "$(pwd)/custom-dir:/app/custom-dir" compliance-checker --single example.com -o custom-dir

# Custom Routinator URL
docker run --rm compliance-checker --single example.com -ru http://routinator-host:8323
```

### Extract Results from Volume
```bash
docker run --rm \
  -v compliance_data:/source \
  -v "$(pwd)/extracted:/destination" \
  alpine sh -c "cp -R /source/* /destination/"
```

</details>


___

## Troubleshooting Routinator
<details>
<summary>Click to expand</summary>

In some networks, the routinator container can't connect to the known RPKI repositories on port 873 (`rsync error: error in socket IO (code 10) at clientserver.c(139) [Receiver=3.4.0]`) . In this case, you can try to use a different DNS server. For example, you can use Google's DNS server by adding the following argument to the docker run command:

1. Update Docker's DNS settings by creating or modifying `/etc/docker/daemon.json`:

```json
{
    "dns": ["8.8.8.8", "8.8.4.4"]
}
```

2. Restart the Docker service:

```bash
sudo systemctl restart docker
```

3. Restart Routinator with explicit DNS settings:

```bash
# Stop and remove the current container
docker stop routinator
docker rm routinator

# Start a new container with Google DNS servers
docker run -d --restart=unless-stopped --name routinator \
    -p 3323:3323 \
    -p 8323:8323 \
    --dns 8.8.8.8 \
    --dns 8.8.4.4 \
    -v rpki-cache:/home/routinator/.rpki-cache \
    nlnetlabs/routinator
```
</details>

___

## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.
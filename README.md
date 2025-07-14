# Bubo

This tool helps you check whether domains comply with important internet standards, including RPKI, DANE, DNSSEC, Email
Security (SPF,
DKIM, DMARC), Web Security (Certificate, Protocol & Ciphers, and HTTP headers), etc.

___

## License

This project and its dependencies use the following licenses:

| Component    | License                                                                   | Notes                             |
|--------------|---------------------------------------------------------------------------|-----------------------------------|
| This project | MIT                                                                       |                                   |
| OpenSSL 3.0+ | [Apache-2.0](https://github.com/openssl/openssl/blob/master/LICENSE.txt)  | Required system dependency        |
| Routinator   | [BSD-3-Clause](https://github.com/NLnetLabs/routinator/blob/main/LICENSE) | RPKI validator (Docker container) |

---

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
If you already have Routinator running, you can skip this step and look at the program usage to see how you can specify
the routinator url.

```bash
# To persist the RPKI cache data you can create a Docker volume and mount it into the container like so:
docker volume create rpki-cache
docker run -d --restart=unless-stopped --name routinator \
    -p 3323:3323 \
    -p 8323:8323 \
    -v rpki-cache:/home/routinator/.rpki-cache \
    nlnetlabs/routinator
```

___

## Usage

You can run the tool in two modes:

1. ### Single domain check

```bash
python bubo.py --single example.com
```

2. ### Batch domain check

Create a CSV file with the domains you want to check. The file should have at least a "Domain" column, and can
optionally include "Country" and "Institution" columns:

```
Domain,Country,Institution
example.nl,NL,Example Organization
example.uk,UK,Example Foundation
```

Then run:

```bash
python bubo.py --batch path/to/domains.csv
```

### Additional options

```
--batch [-b] FILE                 Path to CSV file with domains to check
--single [-d] DOMAIN              Domain to check
--output-dir [-o] DIR             Directory to save results (default: results/)
--max-concurrent [-mc] INTEGER    Maximum concurrent validations (default: 48)
--ignore-cache [-ic]              Force fresh validation instead of using cached results (the cache is valid for 24 hours).
--routinator-url [-ru] URL        URL of the Routinator RPKI validator service (default: http://localhost:8323)
# You can also have an environment variable called ROUTINATOR_URL=http://localhost:8323
```

___

## Output

The tool generates two types of reports:

- **Detailed HTML report** with validation results for each domain
- **Statistics report** summarizing the overall compliance status and scores.
- **Scoreboard report** with a list of domains and their scores. (Hall of Fame)

Both reports are saved in the results/ directory with timestamped directory and filenames.\
The HTML report provides a user-friendly visualization of the results, while the JSON file contains the same data in a
machine-readable format for further processing.

### Note:

- **To make it easy to access (or for automation), you can also find the last generated report in `results/index.html`,
  `results/statistics.html`, and `results/scoreboard.html` files.**
- **If you want to sent the report somewhere else, remember to contain `results/css`, `results/js`, and `results/img`
  directories.**

___

## Cache

<details>
<summary>Click to expand</summary>
By default, results are cached for 24 hours to speed up repeated checks. Use the `--ignore-cache` flag to force fresh
validation.
When using the Docker image, you can create a persistent volume to retain cached data (see the Docker quick reference).
Without a persistent volume, the cache is cleared between runs, so validations are always fresh and `--ignore-cache` is
unnecessary.

- For cipher suites, we use IANA TLS cipher suite recommendations. The cache is valid for 30 days by default. You can
  change this by setting the `IANA_UPDATE_CACHE_DAYS` environment variable in `.env` file or in the shell:
    ```bash
    export IANA_UPDATE_CACHE_DAYS=7
    ```

</details>

___

## Docker quick reference

<details>
<summary>Click to expand</summary>

### Build

```bash
docker build -t bubo .
```

### Single Domain Check

```bash
# Basic usage with persistent cache
docker compose run --rm bubo -d example.com 
```

### Batch Processing

```bash
# For domains file in the project directory
docker compose run --rm bubo --batch /bubo/input/domains.csv

# For files from external paths
docker compose run --rm -v "/path/to/file/directory:/bubo/input" bubo --batch /bubo/input/domains.csv

# Example with absolute path
docker compose run --rm -v "/home/user/data:/bubo/input" bubo --batch /bubo/input/domains.csv
```

### Common Options

```bash
# Ignore cache
docker compose run --rm bubo -d example.com --ignore-cache
  
# Custom output directory
# (modify docker-compose.yml volumes: ./custom-dir:/bubo/custom-dir)
docker compose run --rm bubo -d example.com -o custom-dir

# Custom Routinator URL
docker compose run --rm bubo -d example.com -ru http://routinator-host:8323
```

### Alternative: One-time runs without docker-compose.yml

If you prefer not to use a compose file:

```bash
docker volume create bubo_cache
docker run --rm --network host \
  -v "$(pwd)/results:/results" \
  -v bubo_cache:/bubo/cache \
  bubo -d example.com
```

</details>


___

## Troubleshooting Routinator

<details>
<summary>Click to expand</summary>

In some networks, the routinator container can't connect to the known RPKI repositories on port 873 (
`rsync error: error in socket IO (code 10) at clientserver.c(139) [Receiver=3.4.0]`) . In this case, you can try to use
a different DNS server. For example, you can use Google's DNS server by adding the following argument to the docker run
command:

1. Update Docker's DNS settings by creating or modifying `/etc/docker/daemon.json`:

```json
{
  "dns": [
    "8.8.8.8",
    "8.8.4.4"
  ]
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
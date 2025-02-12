# Running Integration Tests

## Prerequisites

1. **Docker**
   - Must be installed and running
   - Installation: [Get Docker](https://docs.docker.com/get-docker/)
   - Verify with: `docker ps`

2. **Nigiri**
   - Install: `curl https://getnigiri.vulpem.com | bash`
   - Verify with: `nigiri --version`

## Running the Test

```bash
cd adaptor
cargo test test_bisq_musig -- --nocapture
```

Expected duration: ~15-20 seconds

## Troubleshooting

If the test fails:
1. Verify Docker is running: `docker ps`
2. Try restarting Nigiri: `nigiri stop && nigiri start`
3. Review test logs for specific error messages 
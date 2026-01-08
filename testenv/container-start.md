btc

```bash
podman run -it --rm \
    -p 3002:3002 \ 
    --add-host=host.containers.internal:host-gateway \
    -e BTCEXP_BITCOIND_HOST=host.containers.internal  \
    -e BTCEXP_BITCOIND_PORT=44825 \
    -e BTCEXP_BITCOIND_USER=bitcoin \
    -e BTCEXP_BITCOIND_PASS=bitcoin \
    -e BTCEXP_HOST=0.0.0.0 \
    docker.io/getumbrel/btc-rpc-explorer:v3.5.1
```

fd
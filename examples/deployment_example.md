# Deezel Docker Deployment Example

This example demonstrates how to use the new Docker deployment functionality in deezel CLI.

## Prerequisites

1. Docker installed and running
2. deezel CLI built with deployment features

## Basic Usage

### 1. Create a new deployment

```bash
# Create a regtest deployment (default)
deezel deploy create --name my-regtest --network regtest

# Create a mainnet deployment
deezel deploy create --name my-mainnet --network mainnet

# Create with custom data directory
deezel deploy create --name custom --network regtest --data-dir /custom/path
```

### 2. List deployments

```bash
# List all deployments
deezel deploy list

# List deployments for specific network
deezel deploy list --network regtest
```

### 3. Check deployment status

```bash
deezel deploy status --name my-regtest --network regtest
```

### 4. Start/Stop deployments

```bash
# Start a deployment
deezel deploy start --name my-regtest --network regtest

# Stop a deployment
deezel deploy stop --name my-regtest --network regtest
```

### 5. View logs

```bash
# View Bitcoin Core logs
deezel deploy logs --name my-regtest --network regtest --service bitcoin --tail 50

# View Metashrew logs
deezel deploy logs --name my-regtest --network regtest --service metashrew --tail 100
```

### 6. Set active deployment

```bash
# Set a deployment as active for automatic RPC URL resolution
deezel deploy set-active --name my-regtest --network regtest
```

### 7. Use with existing commands

Once a deployment is active, other deezel commands will automatically use its RPC endpoints:

```bash
# These will use the active deployment's RPC URLs
deezel bitcoind getblockcount
deezel metashrew height
deezel wallet info
```

### 8. Remove deployment

```bash
# Remove with confirmation
deezel deploy remove --name my-regtest --network regtest

# Force remove without confirmation
deezel deploy remove --name my-regtest --network regtest --force
```

## Network Types

- **regtest**: Local testing network (default)
- **signet**: Bitcoin signet test network
- **mainnet**: Bitcoin main network

## Services Deployed

Each deployment includes:

1. **Bitcoin Core** - Full Bitcoin node
2. **Metashrew** - Indexer for alkanes protocol
3. **Alkanes JSON-RPC** - JSON-RPC interface for alkanes
4. **Esplora** - Block explorer API
5. **Ord** - Ordinals indexer

## Port Mappings

Default ports by network:

### Regtest
- Bitcoin RPC: 18332
- Metashrew RPC: 8082
- Esplora: 3002
- Ord: 82
- Alkanes JSON-RPC: 18890

### Signet
- Bitcoin RPC: 38332
- Metashrew RPC: 8081
- Esplora: 3001
- Ord: 81
- Alkanes JSON-RPC: 18889

### Mainnet
- Bitcoin RPC: 8332
- Metashrew RPC: 8080
- Esplora: 3000
- Ord: 80
- Alkanes JSON-RPC: 18888

## Data Storage

Deployment data is stored in:
```
~/.deezel/deployments/networks/{network}/{name}/
```

This includes:
- Bitcoin blockchain data
- Metashrew index data
- Configuration files
- Deployment metadata

## Advanced Usage

### Custom Configuration

You can modify the deployment configuration by editing:
```
~/.deezel/deployments/networks/{network}/{name}/deployment.json
```

### Building Custom Images

```bash
# Build images for specific network
deezel deploy build --network regtest

# Force rebuild
deezel deploy build --network regtest --force
```

## Troubleshooting

1. **Docker not running**: Ensure Docker daemon is running
2. **Port conflicts**: Check if ports are already in use
3. **Permission issues**: Ensure user has Docker permissions
4. **Image build failures**: Check Docker logs and network connectivity

## Integration with Existing Workflows

The deployment system integrates seamlessly with existing deezel commands. When you have an active deployment, all RPC operations will automatically use the deployment's services instead of external endpoints.
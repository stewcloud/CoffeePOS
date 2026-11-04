# CoffeePOS

Self-hosted home coffee ordering system for Unraid.

Development status: v0.3.0. Includes blind unique-PIN login, section browsing, configurable
modifier groups, ordering, order status management, menu and user administration, and a durable
print queue. Chits print to an ESC/POS network printer and to-go labels print through
`brother-ql-web`. Use `PRINT_MODE=mock` for testing or `PRINT_MODE=live` with `EPSON_HOST`,
`EPSON_PORT`, `BROTHER_URL`, and `BROTHER_LABEL_SIZE` configured for hardware output.

For internet access, place the app behind an authenticated reverse proxy such as Cloudflare
Tunnel + Access. Do not publish port 8541 directly to the internet.

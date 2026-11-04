# CoffeePOS

Self-hosted home coffee ordering system for Unraid.

Development status: v0.3.0. Includes blind unique-PIN login, section browsing, configurable
modifier groups, ordering, order status management, menu and user administration, and a durable
print queue. Chits print to an ESC/POS network printer and portrait to-go labels print directly
to a Brother QL network printer using its raster protocol. Use `PRINT_MODE=mock` for testing or
`PRINT_MODE=live` with the Epson and Brother host/port variables configured for hardware output.

For internet access, place the app behind an HTTPS reverse proxy such as Cloudflare Tunnel.
Do not forward port 8541 directly from the router.

## Unraid updates

GitHub Actions publishes `ghcr.io/stewcloud/coffeepos:latest`. Install with
`unraid/CoffeePOS.xml`; Unraid can then detect and apply image updates normally while preserving
the `/data` mapping. Printer endpoints and modes are editable template variables.

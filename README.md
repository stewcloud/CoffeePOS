# CoffeePOS

Self-hosted home coffee ordering system for Unraid.

Development status: v0.2.0. Includes ordering, order status management, menu/category management,
full user administration, PIN changes, CSRF protection, login throttling, and hardened browser
headers. Printing is queued but not yet dispatched.

For internet access, place the app behind an authenticated reverse proxy such as Cloudflare
Tunnel + Access. Do not publish port 8541 directly to the internet.

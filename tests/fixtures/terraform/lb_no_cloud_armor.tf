resource "google_compute_backend_service" "api_backend" {
  name        = "genai-api-backend"
  port_name   = "http"
  protocol    = "HTTP"
  timeout_sec = 30
}

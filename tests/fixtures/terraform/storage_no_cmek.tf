resource "google_storage_bucket" "unencrypted_bucket" {
  name     = "customer-sensitive-data"
  location = "US"
  uniform_bucket_level_access = true
}

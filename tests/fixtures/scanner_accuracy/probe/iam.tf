resource "google_storage_bucket_iam_binding" "public" {
  bucket  = "rag-corpus"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

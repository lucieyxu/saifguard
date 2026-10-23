# Regression fixture for TF_IAM_PUBLIC_ACCESS: plural `members`, multi-line lists and the
# old alternation-precedence bug (any quoted "allAuthenticatedUsers" used to match).
resource "google_storage_bucket_iam_binding" "public_single_line" {
  bucket  = "rag-corpus"
  role    = "roles/storage.objectViewer"
  members = ["allUsers"]
}

resource "google_cloud_run_service_iam_binding" "public_mixed" {
  location = "us-central1"
  service  = "chat-api"
  role     = "roles/run.invoker"
  members  = ["serviceAccount:ci@example-project.iam.gserviceaccount.com", "allAuthenticatedUsers"]
}

resource "google_project_iam_binding" "public_multi_line" {
  project = "example-project"
  role    = "roles/aiplatform.user"
  members = [
    "group:ml-team@example.com",
    "allUsers",
  ]
}

resource "google_project_iam_member" "public_member" {
  project = "example-project"
  role    = "roles/viewer"
  member  = "allAuthenticatedUsers"
}

resource "google_cloud_run_v2_service_iam_binding" "public_toset" {
  name    = "chat-api"
  role    = "roles/run.invoker"
  members = toset(["allUsers"])
}

resource "google_cloud_run_v2_service_iam_binding" "public_toset_multi_line" {
  name    = "chat-api"
  role    = "roles/run.invoker"
  members = toset([
    "allAuthenticatedUsers",
  ])
}

resource "google_project_iam_binding" "private_only" {
  project = "example-project"
  role    = "roles/aiplatform.user"
  members = [
    "group:ml-team@example.com",
  ]
}

# members = ["allUsers"]

locals {
  forbidden_principals = ["allUsers", "allAuthenticatedUsers"]
}

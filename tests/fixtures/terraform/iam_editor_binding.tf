resource "google_project_iam_member" "broad_access" {
  project = "my-ai-project"
  role    = "roles/editor"
  member  = "serviceAccount:ai-app@my-ai-project.iam.gserviceaccount.com"
}

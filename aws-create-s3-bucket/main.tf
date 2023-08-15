resource "aws_s3_bucket" "demo" {
  bucket = "jtan-tfdemo"
}

resource "aws_s3_bucket_public_access_block" "demo" {
  bucket = aws_s3_bucket.demo.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "demo" {
  bucket = aws_s3_bucket.demo.id
  key    = "demo.txt"
  source = "demo.txt"
  etag = filemd5("demo.txt")
}

output "id" {
    value = aws_s3_bucket.demo.id
}

output "arn" {
    value = aws_s3_bucket.demo.arn
}
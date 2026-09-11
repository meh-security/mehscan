import type { S3Event } from 'aws-lambda'

export function handler (event: S3Event) {
  return eval(event.Records[0].s3.object.key)
}

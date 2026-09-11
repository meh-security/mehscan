const AWS = require('aws-sdk')

exports.handler = async (event) => {
  const value = event.queryStringParameters.value
  const url = new URL(value)
  if (url.hostname !== 'documents.example.test') {
    return { statusCode: 400, body: 'invalid destination' }
  }
  const s3 = new AWS.S3()
  await s3.putObject({
    Bucket: process.env.BUCKET,
    Key: 'audit',
    Body: url.href,
    ACL: 'private'
  }).promise()
  return { statusCode: 204 }
}

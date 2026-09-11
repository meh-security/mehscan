const child_process = require('child_process')
const AWS = require('aws-sdk')

async function audit(event) {
  const db = new AWS.DynamoDB.DocumentClient()
  const documentUrl = event.queryStringParameters.document_url
  await db.put({ TableName: process.env.TABLE, Item: { document_url: documentUrl } }).promise()
}

exports.convert = async (event) => {
  await audit(event)
  const documentUrl = event.queryStringParameters.document_url
  const body = child_process.execSync(`curl ${documentUrl}`).toString()
  const s3 = new AWS.S3()
  await s3.putObject({
    Bucket: process.env.BUCKET,
    Key: 'result',
    Body: body,
    ACL: 'public-read'
  }).promise()
  return {
    statusCode: 302,
    headers: { Location: `${process.env.PUBLIC_URL}/result` }
  }
}

exports.failure = async (event) => {
  const requested = event.pathParameters.id
  try {
    return { statusCode: 200, body: requested }
  } catch (error) {
    return { statusCode: 500, body: error.stack }
  }
}

const exportsLike = {}

exportsLike.handler = async (event) => {
  return event.queryStringParameters.value
}

exports.handler = async (event) => {
  return event.applicationValue
}

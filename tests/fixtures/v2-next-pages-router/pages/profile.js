export async function getServerSideProps(context) {
  const tab = context.query.tab
  const session = context.req.cookies.session
  return { props: { tab, sessionPresent: Boolean(session) } }
}

export default function Profile() {
  return null
}

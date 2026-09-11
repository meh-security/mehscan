use warp::Filter;

fn route() {
    let _route = warp::path::param().map(|name: String| {
        format!("<h1>Hello, {name}</h1>")
    });
}

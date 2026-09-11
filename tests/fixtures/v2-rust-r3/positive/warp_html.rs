use warp::Filter;

fn route() {
    let _route = warp::path::param().map(|name: String| {
        warp::reply::html(format!("<h1>Hello, {name}</h1>"))
    });
}

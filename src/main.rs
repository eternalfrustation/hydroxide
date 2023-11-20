use axum_typed_multipart::{TryFromMultipart, TypedMultipart};
use base64::{engine::general_purpose, Engine as _};
use comrak::{plugins::syntect, Plugins};
use rand::random;
use std::{
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use upon::value;

use tower_http::services::ServeDir;

use tokio_stream::StreamExt;

use axum::{
    async_trait,
    extract::{FromRequestParts, Path, Query, State},
    http::{request::Parts, StatusCode},
    response::{Html, Redirect},
    routing::{get, post},
    Form, Router,
};
use axum_extra::extract::{
    cookie::{Cookie, SameSite},
    CookieJar,
};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation};
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_512};
use sqlx::{query_as, Encode, FromRow, Pool, Sqlite};

#[derive(Serialize, Deserialize)]
struct Page<'a> {
    link: &'a str,
    name: &'a str,
}

struct Keys {
    encoding: EncodingKey,
    decoding: DecodingKey,
}

// Keys for encoding JWTs
impl Keys {
    fn new(secret: &[u8]) -> Keys {
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
        }
    }
}

static KEYS: Lazy<Keys> = Lazy::new(|| {
    let secret = std::env::var("JWT_SECRET")
        .expect("JWT_SCRET Environment Vaiable not set, it must be set.");
    Keys::new(secret.as_bytes())
});

// Templates for the static pages
static TEMPLATES: Lazy<upon::Engine<'static>> = Lazy::new(|| {
    let mut templates = upon::Engine::new();
    templates
        .add_template("index", include_str!("index.html"))
        .unwrap();
    templates
        .add_template("sign_up", include_str!("sign_up.html"))
        .unwrap();
    templates
        .add_template("sign_in", include_str!("sign_in.html"))
        .unwrap();
    templates
        .add_template("blogs", include_str!("blogs.html"))
        .unwrap();
    templates
        .add_template("create_post", include_str!("create_post.html"))
        .unwrap();
    templates.add_filter("brief", |s: String| {
        let mut s1 = s.clone();
        s1.truncate(100);
        s1 + "..."
    });
    templates
});

// User struct, maps to the database
#[derive(Deserialize, Serialize, Clone, Debug, Default)]
struct User {
    name: String,
    username: String,
    profile_pic: Option<String>,
    salt: Vec<u8>,
    sh_pass: Vec<u8>,
    email: String,
}

enum PostInsertError {
    DatabaseError(String),
}

impl User {
    async fn insert_post(&self, blog: Blog, state: &AppState) -> Result<(), PostInsertError> {
        let time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        match sqlx::query!(
            "insert into posts (title, body, writer_username, post_time) values($1, $2, $3, $4)",
            blog.title,
            blog.body,
            self.username,
            time
        )
        .execute(&state.db)
        .await
        {
            Err(e) => {
                return Err(PostInsertError::DatabaseError(e.to_string()));
            }
            Ok(r) => Ok(()),
        }
    }
}

// implementing the "Auto Auth thing", slap a User in the arguments to a handler
// and BAM, you get Auth
#[async_trait]
impl FromRequestParts<AppState> for User {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        // Grab the Cookies, if not found, send back error
        match parts.headers.get("Cookie") {
            Some(cookie_string) => match Cookie::split_parse(match cookie_string.to_str() {
                Ok(s) => s,
                Err(e) => return Err((StatusCode::BAD_REQUEST, "Invalid Cookies")),
            })
            .map(|cookie| match cookie {
                Ok(c) => Some(c),
                Err(e) => None,
            })
            .filter(|c| c.is_some())
            .map(|c| c.unwrap())
            // Check if any of them is a "jwt-token"
            .filter(|c| c.name() == "jwt-token")
            .next()
            {
                // Check id the jwt-token cookie is actually a jsonwebtoken,
                // and decode it
                Some(c) => match jsonwebtoken::decode::<UserToken>(
                    c.value(),
                    &KEYS.decoding,
                    &Validation::new(jsonwebtoken::Algorithm::HS256),
                ) {
                    // If it is a valid JWT, grab the User struct from the database
                    // and match its creds with the token, then, if they match,
                    // return the User struct
                    Ok(token) => {
                        // The database query
                        let user = match query_as!(
                            User,
                            "select * from users where username = ?",
                            token.claims.username
                        )
                        .fetch_one(&state.db)
                        .await
                        {
                            // If found return the user
                            Ok(user) => user,
                            // If not, Yell through HTTP
                            Err(e) => {
                                log::error!("{}", e);
                                return Err((
                                    StatusCode::UNAUTHORIZED,
                                    "Incorrent Username or Password",
                                ));
                            }
                        };

                        // Hash the password to prepare for matching with the password in the db
                        let mut hasher = Sha3_512::new();

                        hasher.update(user.sh_pass.clone());

                        // read hash digest
                        let result: Vec<u8> = hasher.finalize()[..].into();

                        // Check the new password with the password in the db
                        // If both are the same, return the user
                        let resp_hash = match general_purpose::STANDARD.decode(token.claims.sh_pass)
                        {
                            Ok(h) => h,
                            Err(e) => {
                                log::error!("{}", e);
                                return Err((
                                    StatusCode::BAD_REQUEST,
                                    "Incorrect username or password",
                                ));
                            }
                        };
                        if result == resp_hash {
                            return Ok(user);
                        }
                        // else, Yell through HTTP
                        return Err((StatusCode::UNAUTHORIZED, "Incorrect username or password"));
                    }
                    Err(e) => {
                        log::error!("At line {}, {}", line!(), e);
                        return Err((StatusCode::BAD_REQUEST, "Could not parse the JWT"));
                    }
                },
                None => {
                    return Err((StatusCode::UNAUTHORIZED, "JWT Cookie not found"));
                }
            },
            None => return Err((StatusCode::UNAUTHORIZED, "JWT Cookie not found")).into(),
        };
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
enum UserSignUpError {
    FailedHashing,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
enum UserSignInError {
    FailedHashing,
}

#[derive(Deserialize, Serialize, Clone, Debug)]
struct UserToken {
    username: String,
    sh_pass: String,
    exp: u64,
}

impl From<User> for UserToken {
    fn from(user: User) -> Self {
        let mut hasher = Sha3_512::new();
        hasher.update(user.sh_pass);
        let shh_pass: Vec<u8> = hasher.finalize()[..].into();
        let exp_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            + Duration::from_secs(60 * 60 * 24);

        UserToken {
            username: user.username,
            sh_pass: general_purpose::STANDARD.encode(shh_pass),
            exp: exp_time.as_secs(),
        }
    }
}

impl TryFrom<UserSignUp> for User {
    type Error = UserSignUpError;

    fn try_from(value: UserSignUp) -> Result<Self, Self::Error> {
        let mut salt: [u8; 64] = [0; 64];
        for b in salt.iter_mut() {
            *b = random();
        }
        let mut hasher = Sha3_512::new();
        hasher.update(salt);
        hasher.update(value.pass);
        let salted_hash: Vec<u8> = hasher.finalize()[..].into();
        Ok(User {
            name: value.name,
            username: value.username,
            profile_pic: None,
            salt: Vec::from(salt),
            sh_pass: salted_hash,
            email: value.email,
        })
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
struct Claims {
    username: String,
    sh_pass: Vec<u8>,
    exp: usize,
}

#[derive(Clone)]
struct AppState {
    top_posters: [User; 10],
    db: Pool<Sqlite>,
}

unsafe impl Send for AppState {}
unsafe impl Sync for AppState {}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct HomePageContext {
    user: Option<User>,
    is_user_logged_in: bool,
    posts: Vec<Blog>,
}

impl AppState {
    async fn get_page_state(&self, user: Option<User>) -> HomePageContext {
        let is_user_logged_in = user.is_some();
        let latest_posts = match self.get_latest_posts().await {
            Ok(v) => v,
            Err(e) => {
                log::error!("{}", e);
                Vec::new()
            }
        };
        HomePageContext {
            user,
            is_user_logged_in,
            posts: latest_posts,
        }
    }
    // get latest 10 posts
    async fn get_latest_posts(&self) -> Result<Vec<Blog>, &'static str> {
        let a = query_as!(
            Blog,
            "select title, body, post_time, writer_username, id from posts order by id desc limit 10"
        )
        .fetch(&self.db);
        tokio::pin!(a);
        let mut posts = Vec::new();
        while let Some(blog) = a.next().await {
            match blog {
                Ok(blog) => posts.push(blog),
                Err(_) => return Err("FUCKING DATABASE IS ON FIREEEE!!!!!!!"),
            }
        }
        Ok(posts)
    }
}

fn setup_routes() -> Router<AppState> {
    Router::new()
        .route("/:page", axum::routing::get(template_handler))
        .route("/", get(index_serve))
        .route("/posts/:postid", get(get_post))
        .nest(
            "/api",
            Router::new()
                .route("/sign_up", post(sign_up))
                .route("/sign_in", post(sign_in))
                .route("/create_post", post(create_post)),
        )
        .nest_service("/static", ServeDir::new("static"))
        .nest_service("/assets", ServeDir::new("assets"))
}

async fn get_post(
    State(state): State<AppState>,
    id: Path<u32>,
) -> Result<Html<String>, (StatusCode, String)> {
    match query_as!(Blog, "select * from posts where id = ?", id.0)
        .fetch_one(&state.db)
        .await
    {
        Ok(blog) => match TEMPLATES.get_template("blogs") {
            Some(blog_template) => match blog_template
                .render(
                    value! {title: blog.title.clone(), body: blog.body.clone(), posts: state.get_latest_posts().await.unwrap()},
                )
                .to_string()
            {
                Ok(rendered_blog) => {
                    log::info!("{:#?}", blog);
                    Ok(Html(rendered_blog))
                }
                Err(e) => {
                    log::error!("{}", e);
                    Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
                }
            },
            None => {
                log::error!("Could not find the given post");
                Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Post template not found".to_string(),
                ))
            }
        },
        Err(e) => {
            log::error!("{}", e.to_string());
            Err((
                StatusCode::NOT_FOUND,
                "Could not find the given post".to_string(),
            ))
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, TryFromMultipart)]
#[try_from_multipart(strict)]
struct Blog {
    title: String,
    body: String,
    post_time: Option<i64>,
    writer_username: Option<String>,
    id: Option<i64>,
}

impl Blog {
    fn parse(self) -> Blog {
        let mut plugins = Plugins::default();
        let syntect_adapter = syntect::SyntectAdapter::new("base16-ocean.dark");
        plugins.render.codefence_syntax_highlighter = Some(&syntect_adapter);
        Blog {
            title: comrak::markdown_to_html(self.title.as_str(), &comrak::Options::default()),
            body: comrak::markdown_to_html_with_plugins(
                self.body.as_str(),
                &comrak::Options::default(),
                &plugins,
            ),
            writer_username: self.writer_username,
            post_time: self.post_time,
            id: self.id,
        }
    }
}

#[axum::debug_handler]
async fn create_post(
    user: User,
    State(state): State<AppState>,
    TypedMultipart(blog): TypedMultipart<Blog>,
) -> Result<Redirect, (StatusCode, String)> {
    let mut blog = blog.parse();
    blog.writer_username = Some(user.username.clone());
    match user.insert_post(blog, &state).await {
        Ok(()) => Ok(Redirect::to("/")),
        Err(_) => Err((StatusCode::BAD_REQUEST, "Unable to save post".to_string())),
    }
}

#[derive(Deserialize, Serialize, Encode, FromRow)]
struct UserSignIn {
    username: String,
    pass: String,
}

#[axum::debug_handler]
async fn sign_in(
    cookie_jar: CookieJar,
    State(state): State<AppState>,
    Form(user_resp): Form<UserSignIn>,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    let user = match query_as!(
        User,
        "select * from users where username = ?",
        user_resp.username
    )
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => user,
        Err(e) => {
            log::error!("{}", e);
            return Err((StatusCode::UNAUTHORIZED, e.to_string()));
        }
    };
    let mut hasher = Sha3_512::new();
    hasher.update(user.salt.clone());
    hasher.update(user_resp.pass.as_bytes());
    let salted_hash: Vec<u8> = hasher.finalize()[..].into();
    if Vec::from(salted_hash) == user.sh_pass {
        let user_token: UserToken = user.into();
        match jsonwebtoken::encode(&Header::default(), &user_token, &KEYS.encoding) {
            Err(e) => {
                log::error!("{}", e);
                return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
            }
            Ok(s) => {
                return Ok((
                    cookie_jar.add(
                        Cookie::build("jwt-token", s)
                            .http_only(true)
                            .secure(true)
                            .same_site(SameSite::None)
                            .max_age(Duration::from_secs(60 * 60 * 12).try_into().unwrap())
                            .path("/")
                            .finish(),
                    ),
                    Redirect::to("/"),
                ));
            }
        };
    }
    Err((
        StatusCode::UNAUTHORIZED,
        "Incorrect Username or password".to_string(),
    ))
}
#[derive(Deserialize, Serialize, Encode, FromRow)]
struct UserSignUp {
    name: String,
    username: String,
    pass: String,
    email: String,
}

struct Num {
    count: i64,
}

#[axum::debug_handler]
async fn sign_up(
    cookie_jar: CookieJar,
    State(state): State<AppState>,
    Form(user_resp): Form<UserSignUp>,
) -> Result<(CookieJar, Redirect), (StatusCode, String)> {
    let user: User = user_resp.try_into().unwrap();
    match sqlx::query!("insert into users (name, username, profile_pic, salt, sh_pass, email) values($1, $2, $3, $4, $5, $6)", user.name, user.username, user.profile_pic, user.salt, user.sh_pass, user.email).execute(&state.db).await {
        Err(e) => {
            log::error!("{:?}", e);
            return Err((StatusCode::INTERNAL_SERVER_ERROR, String::from("Could not Sign Up")));
        }
        Ok(r) => {
            log::info!("{:?}", r);
            let user_token: UserToken = user.into();
            match jsonwebtoken::encode(&Header::default(), &user_token, &KEYS.encoding) {
                Err(e) => {
                    return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
                }
                Ok(s) => {
                    return Ok((cookie_jar
                        .add(Cookie::build("jwt-token", s)
                            .http_only(true)
                            .secure(true)
                            .same_site(SameSite::None)
                            .max_age(Duration::from_secs(60 * 60 * 12).try_into().unwrap())
                            .path("/")
                        .finish()), Redirect::to("/" )));
                }
            };
        }
    };
}

#[axum::debug_handler]
async fn index_serve(
    State(state): State<AppState>,
    cookie_jar: CookieJar,
    user: Option<User>,
) -> Result<Html<String>, (StatusCode, Html<String>)> {
    let token = cookie_jar.get("jwt-token");
    match TEMPLATES
        .template("index")
        .render(&state.get_page_state(user).await)
        .to_string()
    {
        Ok(t) => Ok(Html(t)),
        Err(e) => {
            log::error!("{}", e);
            Err((
                StatusCode::NOT_FOUND,
                Html("<h1>Not Found<Internal Server Error/h1>".to_string()),
            ))
        }
    }
}

async fn template_handler(
    State(state): State<AppState>,
    path: Path<String>,
    user: Option<User>,
) -> (StatusCode, Html<String>) {
    match TEMPLATES.get_template(path.as_str()) {
        Some(template) => match template
            .render(&state.get_page_state(user).await)
            .to_string()
        {
            Ok(t) => (StatusCode::OK, Html(t)),
            Err(e) => {
                log::error!("{}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html("<h1>Internal Server Error</h1>".to_string()),
                )
            }
        },
        None => (
            StatusCode::NOT_FOUND,
            Html("<h1>Not Found</h1>".to_string()),
        ),
    }
}
#[tokio::main]
async fn main() {
    femme::start();
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect("sqlite:data.db")
        .await
        .unwrap();
    sqlx::query(
        "
CREATE TABLE if not exists users (
	salt blob unique not null,
	name text not null,
	username text unique not null primary key,
	profile_pic text,
	sh_pass blob not null,
	email text not null unique
) STRICT)",
    )
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query(
        "CREATE TABLE if not exists posts (
id integer primary key autoincrement,
title text not null,
body text not null,
writer_username text not null,
post_time integer not null,
FOREIGN KEY(writer_username) REFERENCES users(username)
) STRICT",
    )
    .execute(&pool)
    .await
    .unwrap();
    let state = AppState {
        top_posters: <[User; 10]>::default(),
        db: pool,
    };
    let app = setup_routes().with_state(state);
    let addr = SocketAddr::from(([127, 0, 0, 1], 9070));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap()
}

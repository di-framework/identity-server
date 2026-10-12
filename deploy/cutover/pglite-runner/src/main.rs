//! The importer's view of `di-framework:pglite/database`: a wasip2 command that reads one JSON
//! request per line on stdin, calls the provider and writes one JSON response per line on stdout,
//! each prefixed with `@pglite ` so engine output on stdout can never be mistaken for a reply.
//!
//! Requests: `{"op": "open", "path": "/data/pglite"}`, `{"op": "exec", "sql": "..."}`,
//! `{"op": "query" | "run" | "first", "sql": "...", "params": [value, ...]}`, `{"op": "begin"}`,
//! `commit`, `rollback`, `savepoint` / `release-savepoint` / `rollback-to-savepoint` with
//! `"name"`, and `close`. Values are `{"tag": ..., "val": ...}` as in the WIT, except that
//! `integer` travels as a decimal string (s64 does not fit a JSON number) and `blob` as hex.
//! Replies are `{"ok": ...}` or `{"err": {"tag": ..., "val": ...}}`.
//!
//! Nothing here prints SQL, parameters or rows anywhere but the reply stream, which the importer
//! reads and never logs.

wit_bindgen::generate!({
    path: "wit",
    world: "imports",
});

use di_framework::pglite::database::{open, Connection};
use di_framework::pglite::types::{Error, Value};
use serde_json::{json, Map, Value as Json};
use std::io::{BufRead, Write};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

fn to_json(value: &Value) -> Json {
    match value {
        Value::Null => json!({"tag": "null"}),
        Value::Integer(v) => json!({"tag": "integer", "val": v.to_string()}),
        Value::Real(v) => json!({"tag": "real", "val": v.to_string()}),
        Value::Text(v) => json!({"tag": "text", "val": v}),
        Value::Blob(v) => json!({"tag": "blob", "val": hex(v)}),
        Value::Boolean(v) => json!({"tag": "boolean", "val": v}),
        Value::Json(v) => json!({"tag": "json", "val": v}),
        Value::Timestamp(v) => json!({"tag": "timestamp", "val": v}),
    }
}

fn from_json(value: &Json) -> Result<Value, String> {
    let tag = value
        .get("tag")
        .and_then(Json::as_str)
        .ok_or("value without tag")?;
    let val = value.get("val");
    let text = || -> Result<String, String> {
        val.and_then(Json::as_str)
            .map(str::to_owned)
            .ok_or_else(|| format!("{tag} value must be a string"))
    };
    Ok(match tag {
        "null" => Value::Null,
        "integer" => Value::Integer(text()?.parse().map_err(|_| "invalid integer")?),
        "real" => Value::Real(text()?.parse().map_err(|_| "invalid real")?),
        "text" => Value::Text(text()?),
        "blob" => Value::Blob(unhex(&text()?)?),
        "boolean" => Value::Boolean(val.and_then(Json::as_bool).ok_or("invalid boolean")?),
        "json" => Value::Json(text()?),
        "timestamp" => Value::Timestamp(text()?),
        other => return Err(format!("unknown value tag {other}")),
    })
}

fn error_json(error: &Error) -> Json {
    let (tag, val) = match error {
        Error::OpenFailed(m) => ("open-failed", json!(m)),
        Error::Closed => ("closed", Json::Null),
        Error::InvalidSql(m) => ("invalid-sql", json!(m)),
        Error::InvalidParams(m) => ("invalid-params", json!(m)),
        Error::ExecutionFailed(e) => (
            "execution-failed",
            json!({"code": e.code, "message": e.message}),
        ),
        Error::ValueConversionFailed(m) => ("value-conversion-failed", json!(m)),
        Error::ConnectionLost(m) => ("connection-lost", json!(m)),
        Error::InvalidTransactionState(m) => ("invalid-transaction-state", json!(m)),
        Error::Other(m) => ("other", json!(m)),
    };
    json!({"tag": tag, "val": val})
}

fn row_json(row: &[(String, Value)]) -> Json {
    Json::Array(
        row.iter()
            .map(|(name, value)| json!([name, to_json(value)]))
            .collect(),
    )
}

fn field<'a>(request: &'a Map<String, Json>, name: &str) -> Result<&'a str, String> {
    request
        .get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| format!("missing {name}"))
}

fn params(request: &Map<String, Json>) -> Result<Vec<Value>, String> {
    match request.get("params") {
        None => Ok(Vec::new()),
        Some(Json::Array(items)) => items.iter().map(from_json).collect(),
        Some(_) => Err("params must be an array".into()),
    }
}

/// One request against the connection; the outer `Err` is a malformed request.
fn serve(
    connection: &mut Option<Connection>,
    request: &Map<String, Json>,
) -> Result<Result<Json, Error>, String> {
    let op = field(request, "op")?;
    if op == "open" {
        if connection.is_some() {
            return Err("already open".into());
        }
        return Ok(open(field(request, "path")?, None).map(|opened| {
            *connection = Some(opened);
            Json::Null
        }));
    }
    let db = connection.as_ref().ok_or("not open")?;
    let unit = |result: Result<(), Error>| result.map(|()| Json::Null);
    Ok(match op {
        "exec" => unit(db.exec(field(request, "sql")?)),
        "run" => db
            .run(field(request, "sql")?, &params(request)?)
            .map(|count| json!(count.to_string())),
        "query" => db
            .query(field(request, "sql")?, &params(request)?)
            .map(|rows| Json::Array(rows.iter().map(|row| row_json(row)).collect())),
        "first" => db
            .first(field(request, "sql")?, &params(request)?)
            .map(|row| row.map_or(Json::Null, |row| row_json(&row))),
        "begin" => unit(db.begin()),
        "commit" => unit(db.commit()),
        "rollback" => unit(db.rollback()),
        "savepoint" => unit(db.savepoint(field(request, "name")?)),
        "release-savepoint" => unit(db.release_savepoint(field(request, "name")?)),
        "rollback-to-savepoint" => unit(db.rollback_to_savepoint(field(request, "name")?)),
        "close" => {
            let result = unit(db.close());
            *connection = None;
            result
        }
        other => return Err(format!("unknown op {other}")),
    })
}

fn main() {
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    let mut connection: Option<Connection> = None;
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(_) => break,
        };
        if line.trim().is_empty() {
            continue;
        }
        let reply = match serde_json::from_str::<Json>(&line) {
            Ok(Json::Object(request)) => match serve(&mut connection, &request) {
                Ok(Ok(value)) => json!({"ok": value}),
                Ok(Err(error)) => json!({"err": error_json(&error)}),
                Err(message) => json!({"err": {"tag": "other", "val": message}}),
            },
            _ => json!({"err": {"tag": "other", "val": "request must be a JSON object"}}),
        };
        let _ = writeln!(stdout, "@pglite {reply}");
        let _ = stdout.flush();
    }
    if let Some(db) = connection.take() {
        let _ = db.close();
    }
}

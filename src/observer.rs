use crate::trace::{Finding, TraceEvent};
use rhai::{AST, Array, Dynamic, Engine, EvalAltResult, Map, Scope};
use std::path::Path;

pub struct Observer {
    engine: Engine,
    ast: AST,
}

impl Observer {
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let source = std::fs::read_to_string(path.as_ref())?;
        Self::from_source(&source)
    }

    pub fn from_source(source: &str) -> anyhow::Result<Self> {
        let mut engine = Engine::new();
        engine.set_max_operations(100_000);
        engine.set_max_call_levels(32);
        let ast = engine.compile(source)?;
        Ok(Self { engine, ast })
    }

    pub fn on_event(&mut self, event: &TraceEvent) -> anyhow::Result<Vec<Finding>> {
        let event = event_to_map(event);
        let mut scope = Scope::new();
        match self
            .engine
            .call_fn::<Dynamic>(&mut scope, &self.ast, "on_event", (event,))
        {
            Ok(result) => Ok(findings_from_dynamic(result)),
            Err(err) if is_missing_on_event(&err) => Ok(Vec::new()),
            Err(err) => Err(anyhow::anyhow!("observer script failed: {err}")),
        }
    }
}

fn event_to_map(event: &TraceEvent) -> Map {
    let mut map = Map::new();
    map.insert("ts".into(), Dynamic::from(event.ts.to_string()));
    map.insert("seq".into(), Dynamic::from(event.seq as i64));
    map.insert("run_id".into(), Dynamic::from(event.run_id.to_string()));
    map.insert("kind".into(), Dynamic::from(event.kind.clone()));
    map.insert("level".into(), Dynamic::from(event.level.clone()));
    if let Some(pid) = event.pid {
        map.insert("pid".into(), Dynamic::from(pid as i64));
    } else {
        map.insert("pid".into(), Dynamic::UNIT);
    }
    map.insert("data_json".into(), Dynamic::from(event.data.to_string()));
    map
}

fn findings_from_dynamic(result: Dynamic) -> Vec<Finding> {
    if result.is_unit() {
        return Vec::new();
    }

    if let Some(message) = result.clone().try_cast::<String>() {
        if message.trim().is_empty() {
            return Vec::new();
        }
        return vec![Finding {
            message,
            severity: "info".to_string(),
            tags: Vec::new(),
        }];
    }

    if let Some(map) = result.clone().try_cast::<Map>() {
        return finding_from_map(map).into_iter().collect();
    }

    if let Some(array) = result.try_cast::<Array>() {
        return array.into_iter().flat_map(findings_from_dynamic).collect();
    }

    Vec::new()
}

fn finding_from_map(mut map: Map) -> Option<Finding> {
    let message = map.remove("message")?.try_cast::<String>()?;
    let severity = map
        .remove("severity")
        .and_then(|value| value.try_cast::<String>())
        .unwrap_or_else(|| "info".to_string());
    let tags = map
        .remove("tags")
        .and_then(|value| value.try_cast::<Array>())
        .map(|items| {
            items
                .into_iter()
                .filter_map(|item| item.try_cast::<String>())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(Finding {
        message,
        severity,
        tags,
    })
}

fn is_missing_on_event(err: &EvalAltResult) -> bool {
    err.to_string().contains("Function not found") && err.to_string().contains("on_event")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use uuid::Uuid;

    #[test]
    fn observer_can_emit_finding_from_string() {
        let mut observer = Observer::from_source(
            "fn on_event(event) { if event.kind == \"stderr.chunk\" { return \"stderr seen\"; } }",
        )
        .unwrap();
        let event = TraceEvent::new(1, Uuid::nil(), "stderr.chunk", Some(42), "info", json!({}));
        let findings = observer.on_event(&event).unwrap();
        assert_eq!(findings[0].message, "stderr seen");
    }
}

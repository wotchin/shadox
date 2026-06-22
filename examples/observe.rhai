fn on_event(event) {
    if event.kind == "stderr.chunk" {
        return #{
            message: "process wrote to stderr",
            severity: "warn",
            tags: ["stderr", "agent"]
        };
    }

    if event.kind == "sandbox.denied" {
        return #{
            message: "sandbox denied or stopped an operation",
            severity: "error",
            tags: ["sandbox", "policy"]
        };
    }
}

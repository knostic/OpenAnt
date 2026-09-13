# The browser-smoke canary markdown — exercises every MD_SANITIZE class.
# Rendered by the REAL vendored marked + DOMPurify in a real browser; the
# sanitized #content innerHTML is compared against golden_expected.html
# (full equality) plus hard canary assertions the --update-golden path can
# never touch.

# Security Analysis: openant

**Repository:** https://example.com/org/repo
**Language:** go
**Commit:** abc123

## Summary

A **bold** claim, *emphasis*, ~~strikethrough~~, and `inline code`.

### The hostile shapes (must all be stripped by the sanitizer)

- an image: <img src=x onerror=alert(1)>
- a form: <form action=/evil><input name=q value=steal>
- a style block: <style>body{background:url(javascript:alert(1))}</style>
- a raw script: <script>alert(1)</script>
- a scheme link: [click](javascript:alert(1)) and [data](data:text/html,<b>x</b>)
- a data attribute: <div data-payload="x">tagged</div>

### A code fence

```go
func main() { fmt.Println("hello") }
```

Raw script inside a fence (must survive as literal text, not execute):

    <script>alert("fenced")</script>

### A table

| Verdict | Count |
|---------|-------|
| vulnerable | 2 |
| not_vulnerable | 3 |

### A task list

- [ ] unchecked task
- [x] completed task

### A link that must survive

[safe link](https://example.com/docs)

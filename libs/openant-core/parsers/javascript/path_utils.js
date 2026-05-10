"use strict";

/**
 * Convert a filesystem path to forward slashes.
 *
 * ts-morph stores source-file paths internally with forward slashes and
 * also treats backslashes as escape characters when matching paths it
 * has already added. On Windows, Node's `path.relative()` and
 * `path.resolve()` return backslash-separated paths, which causes
 * ts-morph to silently fail to find any files (resulting in 0 functions
 * extracted). Always normalise to forward slashes before handing paths
 * to ts-morph or storing them as functionId components.
 *
 * UNC paths (`\\server\share\...`) are correctly converted to
 * `//server/share/...`, which TypeScript understands on Windows.
 *
 * CONTRACT FOR CONTRIBUTORS: every path that will be passed to ts-morph
 * (addSourceFileAtPath, getSourceFile, etc.) or stored as a functionId
 * component MUST go through toPosixPath() first. This applies to the
 * result of any path.resolve(), path.relative(), or path.join() call.
 * Skipping this step silently breaks Windows: ts-morph finds zero files
 * and the analyzer emits an empty result without an error.
 */
function toPosixPath(p) {
  return p.replace(/\\/g, "/");
}

module.exports = { toPosixPath };

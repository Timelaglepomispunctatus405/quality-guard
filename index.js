/**
 * quality-guard — OpenClaw Safety Plugin
 *
 * Hooks into OpenClaw's plugin lifecycle to provide two layers of protection:
 *
 * 1. before_tool_call  → Block dangerous shell commands before they execute
 * 2. tool_result_persist → Analyze tool output for errors, warnings, and bloat
 *
 * Detection engine (5 layers):
 *   L1  Full-command regex match
 *   L2  Split on |, &&, ||, ; — check each segment
 *   L3  Shell-wrapper extraction (eval, bash -c, sh -c, xargs)
 *   L4  $(...) subcommand recursion
 *   L5  Backtick subcommand recursion
 *
 * @license MIT
 */

// ---------------------------------------------------------------------------
// Read-only prefixes — commands that only *read* data; SQL keywords after
// these are part of a search pattern, not an actual destructive statement.
// ---------------------------------------------------------------------------
const READ_ONLY_PREFIXES =
  /^\s*(echo|grep|cat|head|tail|less|more|awk|sed\s+-n|find|ag|rg|wc|printf)\b/;

// ---------------------------------------------------------------------------
// Compound-command separators used to split a one-liner into segments.
// ---------------------------------------------------------------------------
const CMD_SEPARATORS = /\s*(?:\|{1,2}|&&|;)\s*/;

// ---------------------------------------------------------------------------
// Extract the inner command from common shell wrappers.
// ---------------------------------------------------------------------------
function extractWrappedCommand(command) {
  // eval "cmd" / eval 'cmd'
  const evalMatch = command.match(/^\s*eval\s+["'](.+)["']\s*$/);
  if (evalMatch) return evalMatch[1];

  // bash -c "cmd" / sh -c "cmd" (optional env/sudo/nohup prefix)
  const shMatch = command.match(
    /^\s*(?:(?:env|sudo|nohup)\s+)*(?:bash|sh|zsh|dash)\s+-c\s+["'](.+)["']\s*$/,
  );
  if (shMatch) return shMatch[1];

  // xargs <destructive-cmd> — stdin supplies targets, can't statically verify
  const xargsMatch = command.match(/^\s*xargs\s+(.+)$/);
  if (xargsMatch) return xargsMatch[1];

  return null;
}

// ---------------------------------------------------------------------------
// Dangerous-command patterns.
//
// Each entry:
//   pattern     — RegExp to test against a command segment
//   desc        — human-readable label (used in logs / block messages)
//   skipReadOnly — if true, skip when the segment starts with a read-only cmd
// ---------------------------------------------------------------------------
const DANGEROUS_PATTERNS = [
  // -- rm root (multi-slash & dot-path variants) --
  { pattern: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?\/+\s*$/, desc: "rm root" },
  {
    pattern: /\brm\s+(-[a-zA-Z]*f[a-zA-Z]*\s+)?\/+\.?\/?\s*$/,
    desc: "rm root variant",
  },
  {
    pattern: /\brm\s+.*(?:^|\s)\/+(?:\s|$)/,
    desc: "rm includes root",
  },

  // -- SQL destructive ops (skipped for read-only commands) --
  {
    pattern: /\bDROP\s+(TABLE|DATABASE)\b/i,
    desc: "DROP TABLE/DATABASE",
    skipReadOnly: true,
  },
  {
    pattern: /\bTRUNCATE\s+TABLE\b/i,
    desc: "TRUNCATE TABLE",
    skipReadOnly: true,
  },
  {
    pattern: /\bDELETE\s+FROM\s+\w+\s*[;"']*\s*$/i,
    desc: "DELETE without WHERE",
    skipReadOnly: true,
  },
  {
    pattern: /\bUPDATE\s+\w+\s+SET\s+(?!.*\bWHERE\b)/i,
    desc: "UPDATE without WHERE",
    skipReadOnly: true,
  },

  // -- Git destructive ops --
  {
    pattern: /\bgit\s+push\s+.*(?:--force|-f)\b/,
    desc: "git push --force/-f",
  },
  { pattern: /\bgit\s+reset\s+--hard\b/, desc: "git reset --hard" },

  // -- Disk operations --
  { pattern: /\bdd\s+.*of=\/dev\/[sh]d/, desc: "dd to disk" },
  { pattern: /\bmkfs\b/, desc: "mkfs" },
  { pattern: /\b>\s*\/dev\/[sh]d/, desc: "redirect to disk" },

  // -- Remote code execution --
  {
    pattern: /\bcurl\b.*\|\s*(?:bash|sh|zsh)\b/,
    desc: "curl pipe to shell",
  },
  {
    pattern: /\bwget\b.*\|\s*(?:bash|sh|zsh)\b/,
    desc: "wget pipe to shell",
  },

  // -- xargs + destructive command --
  { pattern: /\bxargs\s+rm\b/, desc: "xargs rm" },

  // -- System-file overwrites --
  {
    pattern: />\s*\/etc\/(?:passwd|shadow|sudoers|hosts|fstab)\b/,
    desc: "overwrite system file",
  },
  {
    pattern: /\btee\s+\/etc\/(?:passwd|shadow|sudoers)\b/,
    desc: "tee to system file",
  },
];

// ---------------------------------------------------------------------------
// Core detection functions
// ---------------------------------------------------------------------------

/** Check whether a single command segment matches any dangerous pattern. */
function isSegmentDangerous(segment) {
  if (!segment || typeof segment !== "string") return false;
  const trimmed = segment.trim();
  if (!trimmed) return false;
  const isReadOnly = READ_ONLY_PREFIXES.test(trimmed);
  return DANGEROUS_PATTERNS.some(({ pattern, skipReadOnly }) => {
    if (skipReadOnly && isReadOnly) return false;
    return pattern.test(trimmed);
  });
}

/**
 * Determine whether a full command string is dangerous.
 *
 * Runs 5 detection layers:
 *   1. Full-string match
 *   2. Split on separators, check each segment
 *   3. Extract inner commands from shell wrappers
 *   4. Recurse into $(...) subcommands
 *   5. Recurse into `...` (backtick) subcommands
 */
function isDangerousCommand(command) {
  if (!command || typeof command !== "string") return false;

  // L1 — full command
  if (isSegmentDangerous(command)) return true;

  // L2 — split compound commands
  const segments = command.split(CMD_SEPARATORS);
  for (const seg of segments) {
    if (isSegmentDangerous(seg)) return true;

    // L3 — shell wrappers
    const wrapped = extractWrappedCommand(seg.trim());
    if (wrapped && isDangerousCommand(wrapped)) return true;
  }

  // L4 — $(...) subcommands
  const subshellMatches = command.match(/\$\(([^)]+)\)/g);
  if (subshellMatches) {
    for (const match of subshellMatches) {
      if (isDangerousCommand(match.slice(2, -1))) return true;
    }
  }

  // L5 — backtick subcommands
  const backtickMatches = command.match(/`([^`]+)`/g);
  if (backtickMatches) {
    for (const match of backtickMatches) {
      if (isDangerousCommand(match.slice(1, -1))) return true;
    }
  }

  return false;
}

// ---------------------------------------------------------------------------
// Output-analysis helpers
// ---------------------------------------------------------------------------

function countPatterns(text, patterns) {
  let count = 0;
  for (const p of patterns) {
    const matches = text.match(p);
    if (matches) count += matches.length;
  }
  return count;
}

const ERROR_PATTERNS = [
  /\bERROR[:\s]/gi,
  /\bError:/g,
  /\bFAILED\b/gi,
  /\bFATAL\b/gi,
  /\bPANIC\b/gi,
  /\bSegmentation fault\b/gi,
  /\bcommand not found\b/gi,
  /\bPermission denied\b/gi,
  /\bNo such file or directory\b/gi,
];

const WARN_PATTERNS = [
  /\bWARN(?:ING)?[:\s]/gi,
  /\bDeprecated\b/gi,
  /\bDeprecationWarning\b/gi,
];

// ---------------------------------------------------------------------------
// Plugin entry point
// ---------------------------------------------------------------------------

const plugin = {
  id: "quality-guard",
  name: "Quality Guard",
  description:
    "Automatic safety guard for AI agents — dangerous command blocking + tool output quality analysis",

  register(api) {
    const log = (...args) => {
      if (typeof api.log === "function") api.log(...args);
    };

    // ── Hook 1: before_tool_call — block dangerous commands ──────────
    api.registerHook("before_tool_call", (event, _ctx) => {
      if (event.toolName !== "exec") return;

      const command = event.params?.command;
      if (isDangerousCommand(command)) {
        log(`[quality-guard] BLOCKED: ${command}`);
        return {
          block: true,
          blockReason: `⛔ Quality Guard blocked a dangerous command:\n\n  ${command}\n\nPlease verify the command is safe and run it manually if needed.`,
        };
      }
    });

    // ── Hook 2: tool_result_persist — analyze tool output ────────────
    api.registerHook("tool_result_persist", (event, _ctx) => {
      if (!event.message) return;

      const { toolName } = event;
      const msg = event.message;

      // Extract text from the tool result (handles string & array content)
      let resultText = "";
      if (msg.content) {
        if (typeof msg.content === "string") {
          resultText = msg.content;
        } else if (Array.isArray(msg.content)) {
          for (const block of msg.content) {
            if (block?.type === "text") {
              resultText += (block.text || "") + "\n";
            } else if (block?.type === "tool_result") {
              if (typeof block.content === "string") {
                resultText += block.content + "\n";
              } else if (Array.isArray(block.content)) {
                for (const sub of block.content) {
                  if (sub?.type === "text") resultText += (sub.text || "") + "\n";
                }
              }
            }
          }
        }
      }

      if (!resultText) return;

      const warnings = [];

      // — exec output analysis —
      if (toolName === "exec") {
        const lineCount = resultText.split("\n").length;
        if (lineCount > 100) {
          warnings.push(
            `📏 Output is ${lineCount} lines (>100). Consider using grep/head/tail to extract key info.`,
          );
        }

        const errorCount = countPatterns(resultText, ERROR_PATTERNS);
        const warnCount = countPatterns(resultText, WARN_PATTERNS);
        if (errorCount > 0) warnings.push(`🔴 Detected ${errorCount} ERROR(s) in output`);
        if (warnCount > 0) warnings.push(`🟡 Detected ${warnCount} WARNING(s) in output`);
      }

      // — write/edit file-size analysis —
      if (toolName === "write" || toolName === "edit") {
        const lineMatch = resultText.match(/(\d+)\s*(?:lines?|行)/i);
        if (lineMatch) {
          const fileLines = parseInt(lineMatch[1], 10);
          if (fileLines > 400) {
            warnings.push(
              `📐 File is ${fileLines} lines (>400). Consider splitting into smaller modules.`,
            );
          }
        }
      }

      // Append warnings to the tool result message
      if (warnings.length > 0) {
        const warningText = "\n\n⚡ Quality Guard:\n" + warnings.join("\n");
        const modified = { ...msg };
        if (typeof modified.content === "string") {
          modified.content += warningText;
        } else if (Array.isArray(modified.content)) {
          modified.content = [...modified.content, { type: "text", text: warningText }];
        }
        return { message: modified };
      }
    });

    log("[quality-guard] registered — dangerous command blocking + output analysis active");
  },
};

export default plugin;

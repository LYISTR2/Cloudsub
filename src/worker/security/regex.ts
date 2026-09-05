/**
 * Safe, linear-time regular expressions for subscription name filtering.
 *
 * The Workers runtime's native RegExp is a backtracking engine: untrusted
 * patterns such as `(a+)+$` can stall a request for seconds on a long input
 * (ReDoS). Length caps and "nested quantifier" heuristics are not sufficient
 * to close that gap, so CloudSub compiles patterns to a Thompson NFA and runs
 * them with a Pike VM — the same technique used by RE2. Execution time is
 * O(pattern * input) with no backtracking, so even pathological patterns are
 * linear in the node-name length.
 *
 * Supported syntax (documented in docs/security.md):
 *   - literals and escaped metacharacters: `a`, `\.`, `\*`, ...
 *   - dot `.` (any single character)
 *   - character classes: `[abc]`, `[a-z0-9_]`, `[^...]`, `[\u4e00-\u9fff]`
 *   - shorthand classes: `\d \w \s` and their negations `\D \W \S`
 *   - unicode properties: `\p{L} \p{N} \p{Lu} \p{P}` ... (whitelisted)
 *   - anchors: `^` `$`, word boundaries `\b` `\B`
 *   - groups: `(...)` (capturing) and `(?:...)` (non-capturing)
 *   - alternation: `a|b`
 *   - quantifiers: `*` `+` `?` `{m}` `{m,}` `{m,n}` plus lazy `*?` `+?` `??`
 *     `{m,n}?`; bounded repetition is capped at 500
 *   - case-insensitive matching is the default (mirrors the previous "iu")
 *
 * Rejected constructs (would require backtracking or are ambiguous):
 *   - backreferences `\1` and named groups `(?<name>...)`
 *   - lookahead / lookbehind `(?=...)` `(?!...)` `(?<=...)` `(?<!...)`
 *   - atomic groups `(?>...)`, inline flags `(?i)`, comments `(?#...)`
 *   - bounded repetition beyond the 500 cap
 *
 * The engine operates on Unicode code points, so surrogate pairs and CJK
 * characters are handled correctly by classes, `\p{L}` and `.`. Input text is
 * capped at 50_000 code points for matching (node names are far shorter).
 */

export const SAFE_PATTERN_MAX_LENGTH = 200;
export const SAFE_PATTERN_MAX_REPEAT = 500;
const SAFE_TEXT_MAX_CODEPOINTS = 50_000;

// ─── AST ─────────────────────────────────────────────────────────────

interface Quantifier { min: number; max: number | null; lazy: boolean }

type Node =
  | { type: "char"; value: string }
  | { type: "class"; test: (char: string) => boolean }
  | { type: "any" }
  | { type: "assert"; test: (prev: string | undefined, next: string | undefined) => boolean }
  | { type: "group"; children: Node[]; capture: boolean }
  | { type: "alt"; branches: Node[][] }
  | { type: "quant"; child: Node; quantifier: Quantifier };

// ─── Shorthand / property predicates ─────────────────────────────────

const PROPERTY_WHITELIST = new Set([
  "L", "Lu", "Ll", "Lt", "Lm", "Lo",
  "N", "Nd", "Nl", "No",
  "P", "Pd", "Ps", "Pe", "Pi", "Pf", "Po",
  "S", "Sm", "Sc", "Sk", "So",
  "Z", "Zs", "Zl", "Zp",
  "M", "Mn", "Mc", "Me",
  "C", "Cc", "Cf", "Co", "Cn",
]);

function isWordChar(char: string): boolean {
  return /[A-Za-z0-9_]/u.test(char);
}

function shorthandTest(name: string, negate: boolean): (char: string) => boolean {
  const matcher = (char: string): boolean => {
    switch (name) {
      case "d": return /[0-9]/u.test(char);
      case "w": return isWordChar(char);
      case "s": return /[\t\n\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]/u.test(char);
      default: return false;
    }
  };
  return negate ? (char) => !matcher(char) : matcher;
}

function propertyTest(name: string, negate: boolean): ((char: string) => boolean) | undefined {
  if (!PROPERTY_WHITELIST.has(name)) return undefined;
  const expression = new RegExp("\\p{" + name + "}", "u");
  return negate ? (char) => !expression.test(char) : (char) => expression.test(char);
}

const ESCAPE_SINGLE: Record<string, string> = {
  n: "\n", t: "\t", r: "\r", f: "\f", v: "\v", "0": "\u0000",
};

// ─── Parser ──────────────────────────────────────────────────────────

class PatternError extends Error {}

class Parser {
  private readonly input: string;
  private index = 0;
  private groupCount = 0;

  constructor(input: string) {
    this.input = input;
  }

  parse(): { node: Node; groups: number } {
    const node = this.parseAlternation();
    if (this.index !== this.input.length) {
      const rest = this.input.slice(this.index);
      if (rest.startsWith(")")) throw new PatternError("unmatched closing parenthesis");
      throw new PatternError("unexpected character '" + rest[0] + "'");
    }
    return { node, groups: this.groupCount };
  }

  private peek(): string | undefined {
    return this.input[this.index];
  }

  private next(): string {
    const char = this.input[this.index];
    if (char === undefined) throw new PatternError("unexpected end of pattern");
    this.index += 1;
    return char;
  }

  private parseAlternation(): Node {
    const branches: Node[][] = [this.parseSequence()];
    while (this.peek() === "|") {
      this.next();
      branches.push(this.parseSequence());
    }
    if (branches.length === 1) {
      return branches[0].length === 1 ? branches[0][0] : { type: "group", children: branches[0], capture: false };
    }
    return { type: "alt", branches };
  }

  private parseSequence(): Node[] {
    const nodes: Node[] = [];
    while (this.index < this.input.length) {
      const char = this.peek();
      if (char === "|" || char === ")") break;
      nodes.push(this.parseAtom());
    }
    return nodes;
  }

  private parseAtom(): Node {
    const char = this.next();
    let atom: Node;
    if (char === "(") {
      atom = this.parseGroup();
    } else if (char === "[") {
      atom = this.parseClass();
    } else if (char === ".") {
      atom = { type: "any" };
    } else if (char === "^") {
      atom = { type: "assert", test: (prev) => prev === undefined };
    } else if (char === "$") {
      atom = { type: "assert", test: (_prev, next) => next === undefined };
    } else if (char === "\\") {
      atom = this.parseEscape();
    } else if (char === "*" || char === "+" || char === "?") {
      throw new PatternError("nothing to repeat");
    } else {
      atom = { type: "char", value: char };
    }
    return this.parseQuantifier(atom);
  }

  private parseGroup(): Node {
    if (this.peek() === "?") {
      this.next();
      if (this.peek() === ":") {
        this.next();
        // Groups contain full alternations, not bare sequences.
        const children = [this.parseAlternation()];
        this.expectClose();
        return { type: "group", children, capture: false };
      }
      throw new PatternError("unsupported group construct (lookaround / atomic / flags are not supported)");
    }
    if (this.groupCount >= 19) throw new PatternError("too many capture groups (max 19)");
    this.groupCount += 1;
    const children = [this.parseAlternation()];
    this.expectClose();
    return { type: "group", children, capture: true };
  }

  private expectClose(): void {
    if (this.next() !== ")") throw new PatternError("unclosed group");
  }

  private parseEscape(): Node {
    const escaped = this.next();
    if (/[0-9]/u.test(escaped)) throw new PatternError("backreferences are not supported");
    if (escaped === "p" || escaped === "P") {
      const name = this.parsePropertyName();
      const test = propertyTest(name, escaped === "P");
      if (!test) throw new PatternError("unsupported unicode property \\" + escaped + "{" + name + "}");
      return { type: "class", test };
    }
    if (escaped === "x") return { type: "char", value: this.parseHex(2, "\\x") };
    if (escaped === "u") return { type: "char", value: this.parseHex(4, "\\u") };
    if (escaped === "b" || escaped === "B") {
      const boundary = escaped === "b";
      return {
        type: "assert",
        test: (prev, next) => boundary !== (isWordChar(prev ?? "") === isWordChar(next ?? "")),
      };
    }
    if (escaped === "d" || escaped === "D" || escaped === "w" || escaped === "W" || escaped === "s" || escaped === "S") {
      return { type: "class", test: shorthandTest(escaped.toLowerCase(), escaped === escaped.toUpperCase()) };
    }
    if (ESCAPE_SINGLE[escaped] !== undefined) return { type: "char", value: ESCAPE_SINGLE[escaped] };
    return { type: "char", value: escaped };
  }

  private parsePropertyName(): string {
    if (this.next() !== "{") throw new PatternError("expected { after \\p");
    const start = this.index;
    while (this.index < this.input.length && this.input[this.index] !== "}") this.index += 1;
    if (this.index >= this.input.length) throw new PatternError("unclosed unicode property");
    const name = this.input.slice(start, this.index);
    this.next();
    return name;
  }

  private parseHex(length: number, prefix: string): string {
    let value = "";
    for (let i = 0; i < length; i += 1) {
      const char = this.next();
      if (!/[0-9a-fA-F]/u.test(char)) throw new PatternError("invalid " + prefix + " escape");
      value += char;
    }
    return String.fromCodePoint(Number.parseInt(value, 16));
  }

  private parseClass(): Node {
    let negate = false;
    if (this.peek() === "^") {
      negate = true;
      this.next();
    }
    const matchers: Array<(char: string) => boolean> = [];
    let first = true;
    while (true) {
      const char = this.peek();
      if (char === undefined) throw new PatternError("unclosed character class");
      if (char === "]" && !first) {
        this.next();
        break;
      }
      first = false;
      let lo: string;
      if (char === "\\") {
        this.next();
        const escaped = this.next();
        if (/[0-9]/u.test(escaped)) throw new PatternError("backreferences are not supported");
        if (escaped === "p" || escaped === "P") {
          const name = this.parsePropertyName();
          const test = propertyTest(name, escaped === "P");
          if (!test) throw new PatternError("unsupported unicode property");
          matchers.push(test);
          continue;
        }
        if (escaped === "x") { lo = this.parseHex(2, "\\x"); }
        else if (escaped === "u") { lo = this.parseHex(4, "\\u"); }
        else if (escaped === "d" || escaped === "D" || escaped === "w" || escaped === "W" || escaped === "s" || escaped === "S") {
          matchers.push(shorthandTest(escaped.toLowerCase(), escaped === escaped.toUpperCase()));
          continue;
        }
        else if (ESCAPE_SINGLE[escaped] !== undefined) { lo = ESCAPE_SINGLE[escaped]; }
        else { lo = escaped; }
      } else {
        this.next();
        lo = char;
      }
      if (this.peek() === "-" && this.input[this.index + 1] !== undefined && this.input[this.index + 1] !== "]") {
        this.next();
        const hi = this.parseRangeEnd();
        matchers.push(this.rangeMatcher(lo, hi));
      } else {
        matchers.push(this.singleMatcher(lo));
      }
    }
    const matchAny = (char: string): boolean => matchers.some((matcher) => matcher(char));
    return { type: "class", test: negate ? (char) => !matchAny(char) : matchAny };
  }

  private parseRangeEnd(): string {
    const char = this.peek();
    if (char === undefined) throw new PatternError("unclosed character class");
    if (char !== "\\") {
      this.next();
      return char;
    }
    this.next();
    const escaped = this.next();
    if (escaped === "x") return this.parseHex(2, "\\x");
    if (escaped === "u") return this.parseHex(4, "\\u");
    if (ESCAPE_SINGLE[escaped] !== undefined) return ESCAPE_SINGLE[escaped];
    return escaped;
  }

  private singleMatcher(char: string): (char: string) => boolean {
    const lowered = char.toLowerCase();
    return (candidate) => candidate.toLowerCase() === lowered;
  }

  private rangeMatcher(lo: string, hi: string): (char: string) => boolean {
    const loCode = lo.toLowerCase().codePointAt(0)!;
    const hiCode = hi.toLowerCase().codePointAt(0)!;
    if (loCode > hiCode) throw new PatternError("invalid character range");
    return (candidate) => {
      const code = candidate.toLowerCase().codePointAt(0)!;
      return code >= loCode && code <= hiCode;
    };
  }

  private parseQuantifier(atom: Node): Node {
    if (atom.type === "assert") return atom;
    const char = this.peek();
    let quantifier: Quantifier | undefined;
    if (char === "*") {
      this.next();
      quantifier = { min: 0, max: null, lazy: false };
    } else if (char === "+") {
      this.next();
      quantifier = { min: 1, max: null, lazy: false };
    } else if (char === "?") {
      this.next();
      quantifier = { min: 0, max: 1, lazy: false };
    } else if (char === "{") {
      quantifier = this.tryParseBraceQuantifier();
    }
    if (!quantifier) return atom;
    if (this.peek() === "?") {
      this.next();
      quantifier = { ...quantifier, lazy: true };
    }
    return { type: "quant", child: atom, quantifier };
  }

  private tryParseBraceQuantifier(): Quantifier | undefined {
    const start = this.index;
    this.next();
    const minDigits = /^[0-9]+/u.exec(this.input.slice(this.index));
    if (!minDigits) return undefined;
    this.index += minDigits[0].length;
    const min = Number(minDigits[0]);
    let max: number | null = min;
    if (this.peek() === ",") {
      this.next();
      const maxDigits = /^[0-9]+/u.exec(this.input.slice(this.index));
      if (maxDigits) {
        this.index += maxDigits[0].length;
        max = Number(maxDigits[0]);
      } else {
        max = null;
      }
    }
    if (this.peek() !== "}") {
      this.index = start;
      return undefined; // malformed brace — treated as a literal per JS semantics
    }
    this.next();
    if (min > SAFE_PATTERN_MAX_REPEAT || (max !== null && max > SAFE_PATTERN_MAX_REPEAT)) {
      throw new PatternError("bounded repetition exceeds the limit of " + SAFE_PATTERN_MAX_REPEAT);
    }
    if (max !== null && max < min) throw new PatternError("invalid quantifier range");
    return { min, max, lazy: false };
  }
}

// ─── Compilation to a Thompson NFA program ───────────────────────────

type Instruction =
  | { op: "char"; char: string }
  | { op: "class"; test: (char: string) => boolean }
  | { op: "any" }
  | { op: "assert"; test: (prev: string | undefined, next: string | undefined) => boolean }
  | { op: "save"; slot: number }
  | { op: "split"; x: number; y: number; greedy: boolean }
  | { op: "jmp"; x: number }
  | { op: "match" };

export interface CompiledPattern {
  program: Instruction[];
  captureSlots: number;
}

interface CompiledNode {
  start: number;
  patch: number[];
}

class Compiler {
  private readonly program: Instruction[] = [];
  private slotCounter = 2; // slots 0/1 = whole match

  emitSave0(): void {
    this.emit({ op: "save", slot: 0 });
  }

  /** Emit save(1) + match, wire the compiled patch list into save(1). */
  finish(patch: number[]): { program: Instruction[]; captureSlots: number } {
    const save1 = this.emit({ op: "save", slot: 1 });
    this.patch(patch, save1);
    const matchIndex = this.program.length;
    this.emit({ op: "match" });
    for (let i = 0; i < this.program.length; i += 1) {
      const instruction = this.program[i];
      if (instruction.op === "split" && instruction.y === 0) {
        this.program[i] = { ...instruction, y: matchIndex };
      } else if (instruction.op === "jmp" && instruction.x === 0) {
        this.program[i] = { ...instruction, x: matchIndex };
      }
    }
    return { program: this.program, captureSlots: this.slotCounter };
  }

  compile(node: Node): CompiledNode {
    switch (node.type) {
      case "char": return this.single(this.emit({ op: "char", char: node.value }));
      case "class": return this.single(this.emit({ op: "class", test: node.test }));
      case "any": return this.single(this.emit({ op: "any" }));
      case "assert": return this.single(this.emit({ op: "assert", test: node.test }));
      case "group": {
        if (!node.capture) return this.sequence(node.children);
        const open = this.emit({ op: "save", slot: this.slotCounter });
        this.slotCounter += 1;
        const inner = this.sequence(node.children);
        const close = this.emit({ op: "save", slot: this.slotCounter });
        this.slotCounter += 1;
        this.patch(inner.patch, close);
        return { start: open, patch: [close] };
      }
      case "alt": return this.alternation(node.branches);
      case "quant": return this.repeat(node);
    }
  }

  private single(index: number): CompiledNode {
    // Every atom is followed by a redirectable jump so that any enclosing
    // construct (sequence, loop, alternation, group) can rewire this atom's
    // continuation without relying on linear fall-through.
    const jmp = this.emit({ op: "jmp", x: 0 });
    return { start: index, patch: [jmp] };
  }

  private sequence(nodes: Node[]): CompiledNode {
    if (nodes.length === 0) {
      const index = this.emit({ op: "jmp", x: 0 });
      return { start: index, patch: [index] };
    }
    const compiled = nodes.map((node) => this.compile(node));
    for (let i = 0; i < compiled.length - 1; i += 1) {
      this.patch(compiled[i].patch, compiled[i + 1].start);
    }
    return { start: compiled[0].start, patch: compiled.at(-1)!.patch };
  }

  private alternation(branches: Node[][]): CompiledNode {
    if (branches.length === 1) return this.sequence(branches[0]);
    // Binary-split chain (classic Thompson construction). There is NO
    // "skip everything" path: every split target is a real branch, so an
    // alternation of non-empty branches never matches the empty string.
    //
    //   split(b0, split1)  b0 ...; jmp(merge)  split1(b1, split2)  b1 ...; jmp(merge)  ...
    //
    // Entry splits are emitted first (the VM enters the program linearly
    // from save(0)) and wired once every branch body is compiled.
    const splits: number[] = [];
    for (let i = 0; i < branches.length - 1; i += 1) {
      splits.push(this.emit({ op: "split", x: 0, y: 0, greedy: true }));
    }
    const compiled = branches.map((branch) => this.sequence(branch));
    for (let i = 0; i < splits.length; i += 1) {
      this.patch([splits[i]], compiled[i].start);
      this.patch([splits[i]], i < splits.length - 1 ? splits[i + 1] : compiled[i + 1].start);
    }
    const mergePatches: number[] = [];
    for (let i = 0; i < branches.length - 1; i += 1) {
      const jmp = this.emit({ op: "jmp", x: 0 });
      mergePatches.push(jmp);
      this.patch(compiled[i].patch, jmp);
    }
    return { start: splits[0], patch: [...mergePatches, ...compiled.at(-1)!.patch] };
  }

  private repeat(node: { type: "quant"; child: Node; quantifier: Quantifier }): CompiledNode {
    const { min, max, lazy } = node.quantifier;
    const greedy = !lazy;
    if (min === 0 && max === 0) {
      const index = this.emit({ op: "jmp", x: 0 });
      return { start: index, patch: [index] };
    }

    if (max === null) {
      if (min === 0) {
        // (child)* — the split is the entry so the zero-match path is
        // reachable immediately; the loop-back is wired through the body's
        // redirectable patch.
        const split = this.emit({ op: "split", x: 0, y: 0, greedy });
        const body = this.compile(node.child);
        this.patch([split], body.start);
        this.patch(body.patch, split);
        return { start: split, patch: [split] };
      }
      // (child){min,} — `min` mandatory copies in a linear chain, then a
      // split that loops back to the last copy.
      const first = this.compile(node.child);
      let previous = first;
      for (let i = 1; i < min; i += 1) {
        const copy = this.compile(node.child);
        this.patch(previous.patch, copy.start);
        previous = copy;
      }
      const split = this.emit({ op: "split", x: previous.start, y: 0, greedy });
      this.patch(previous.patch, split);
      return { start: first.start, patch: [split] };
    }

    // Bounded {m,n}
    const patchList: number[] = [];
    if (min === 0) {
      // {0,n}: each optional copy has an entry split that either runs the
      // copy (x) or skips straight to the continuation (y). The first split
      // is emitted before any copy so it is the entry instruction.
      const first = this.emit({ op: "split", x: 0, y: 0, greedy });
      patchList.push(first);
      let splitIndex = first;
      for (let i = 0; i < max; i += 1) {
        const copy = this.compile(node.child);
        this.patch([splitIndex], copy.start);
        if (i < max - 1) {
          const next = this.emit({ op: "split", x: 0, y: 0, greedy });
          this.patch([splitIndex], next);
          this.patch(copy.patch, next);
          splitIndex = next;
          patchList.push(splitIndex);
        } else {
          patchList.push(...copy.patch);
        }
      }
      return { start: first, patch: patchList };
    }

    const mandatory: CompiledNode[] = [];
    for (let i = 0; i < min; i += 1) mandatory.push(this.compile(node.child));
    const start = mandatory[0].start;
    for (let i = 0; i < mandatory.length - 1; i += 1) {
      this.patch(mandatory[i].patch, mandatory[i + 1].start);
    }
    let previous = mandatory.at(-1)!;
    for (let i = min; i < max; i += 1) {
      const copy = this.compile(node.child);
      const split = this.emit({ op: "split", x: copy.start, y: 0, greedy });
      this.patch(previous.patch, split);
      previous = copy;
      patchList.push(split, ...copy.patch);
    }
    return { start, patch: patchList.length ? patchList : previous.patch };
  }

  private emit(instruction: Instruction): number {
    this.program.push(instruction);
    return this.program.length - 1;
  }

  private patch(list: number[], target: number): void {
    for (const index of list) {
      const instruction = this.program[index];
      if (instruction.op === "jmp") {
        this.program[index] = { op: "jmp", x: target };
      } else if (instruction.op === "split") {
        // Fill the first unresolved target (x before y).
        this.program[index] = instruction.x === 0 ? { ...instruction, x: target } : { ...instruction, y: target };
      }
    }
  }
}

export function compileSafePattern(pattern: string): CompiledPattern | null {
  if (pattern.length > SAFE_PATTERN_MAX_LENGTH) return null;
  try {
    const parser = new Parser(pattern);
    const { node } = parser.parse();
    const compiler = new Compiler();
    compiler.emitSave0();
    const compiled = compiler.compile(node);
    return compiler.finish(compiled.patch);
  } catch {
    return null;
  }
}

// ─── Pike VM runner ──────────────────────────────────────────────────

export interface MatchResult {
  start: number;
  end: number;
  captures: Array<string | undefined>;
}

interface Thread {
  pc: number;
  saves: Array<number | undefined>;
}

export interface SafeRegex {
  /** True when the pattern matches anywhere in the text. */
  test(text: string): boolean;
  /** Non-overlapping matches with capture groups (0 = whole match). */
  matchAll(text: string): MatchResult[];
  /** JavaScript-style replacement supporting `$$`, `$&`, `$1`..`$9`. */
  replace(text: string, replacement: string): string;
}

class Vm {
  private readonly program: Instruction[];
  private readonly captureSlots: number;
  private readonly chars: string[];
  private readonly visited: Uint8Array;

  constructor(pattern: CompiledPattern, text: string) {
    this.program = pattern.program;
    this.captureSlots = pattern.captureSlots;
    this.chars = Array.from(text.slice(0, SAFE_TEXT_MAX_CODEPOINTS));
    this.visited = new Uint8Array(pattern.program.length);
  }

  private addThread(
    pc: number,
    saves: Array<number | undefined>,
    position: number,
    prev: string | undefined,
    next: string | undefined,
    add: (thread: Thread) => void,
  ): void {
    while (true) {
      const instruction = this.program[pc];
      if (!instruction) return;
      switch (instruction.op) {
        case "save": {
          const copy = saves.slice();
          copy[instruction.slot] = position;
          saves = copy;
          pc += 1;
          continue;
        }
        case "split": {
          const priority = instruction.greedy ? [instruction.x, instruction.y] : [instruction.y, instruction.x];
          this.addThread(priority[0], saves.slice(), position, prev, next, add);
          pc = priority[1];
          continue;
        }
        case "jmp": {
          pc = instruction.x;
          continue;
        }
        case "assert": {
          if (instruction.test(prev, next)) {
            pc += 1;
            continue;
          }
          return;
        }
        default: {
          if (this.visited[pc]) return;
          this.visited[pc] = 1;
          add({ pc, saves });
          return;
        }
      }
    }
  }

  private result(thread: Thread, position: number): MatchResult {
    const start = thread.saves[0] ?? position;
    const end = thread.saves[1] ?? position;
    const captures: Array<string | undefined> = [];
    for (let group = 0; group < this.captureSlots / 2; group += 1) {
      const groupStart = thread.saves[group * 2];
      const groupEnd = thread.saves[group * 2 + 1];
      captures.push(groupStart !== undefined && groupEnd !== undefined ? this.chars.slice(groupStart, groupEnd).join("") : undefined);
    }
    return { start, end, captures };
  }

  /** Leftmost match at or after startPosition (unanchored search). */
  run(startPosition: number): MatchResult | undefined {
    const { chars, program } = this;
    const length = chars.length;
    let current: Thread[] = [];

    for (let i = startPosition; i <= length; i += 1) {
      // 1) Threads that already consumed characters ending at position i.
      //    Greedy leftmost-first semantics: a match is accepted immediately
      //    when no higher-priority consuming thread precedes it (a
      //    consuming thread may still lead to a longer match), or at the
      //    very end of the text where nothing can be consumed anymore.
      //    A match that IS preceded by a consuming thread is remembered as
      //    pendingMatch: if the consuming threads die on char i, that
      //    greedy match (e.g. `\p{L}+` stopping at a digit) is the answer.
      let pendingMatch: Thread | undefined;
      if (current.length > 0) {
        let sawConsuming = false;
        for (const thread of current) {
          const instruction = program[thread.pc];
          if (!instruction) continue;
          if (instruction.op === "match") {
            if (!sawConsuming || i >= length) return this.result(thread, i);
            // Defer result materialization (it is O(match length)).
            if (!pendingMatch) pendingMatch = thread;
          } else if (instruction.op === "char" || instruction.op === "class" || instruction.op === "any") {
            sawConsuming = true;
          }
        }
      }

      // 2) Add threads starting at position i (zero-width entry paths,
      //    including quantifier exits such as a* matching nothing).
      this.visited.fill(0);
      let pendingEmpty: MatchResult | undefined;
      const addEmpty = (thread: Thread) => {
        if (!pendingEmpty && program[thread.pc]?.op === "match") pendingEmpty = this.result(thread, i);
        current.push(thread);
      };
      this.addThread(0, new Array(this.captureSlots), i, i > 0 ? chars[i - 1] : undefined, chars[i], addEmpty);

      if (i >= length) {
        // End of text: the greedy paths found nothing, so the zero-width
        // match (if any) is the match.
        return pendingEmpty;
      }

      // 3) Consume char i.
      const char = chars[i];
      const next: Thread[] = [];
      const nextAdd = (thread: Thread) => { next.push(thread); };
      this.visited.fill(0);
      for (const thread of current) {
        const instruction = program[thread.pc];
        if (!instruction) continue;
        const matches = instruction.op === "char"
          ? char.toLowerCase() === instruction.char.toLowerCase()
          : instruction.op === "class"
            ? instruction.test(char)
            : instruction.op === "any";
        if (!matches) continue;
        this.addThread(thread.pc + 1, thread.saves.slice(), i + 1, char, chars[i + 1], nextAdd);
      }
      if (next.length === 0) {
        // Every greedy path died on char i: the remembered greedy match
        // (consumed up to i) wins over a zero-width match at i.
        if (pendingMatch) return this.result(pendingMatch, i);
        if (pendingEmpty) return pendingEmpty;
      }
      current = next;
    }
    return undefined;
  }
}

function expandReplacement(replacement: string, wholeMatch: string, captures: Array<string | undefined>): string {
  let output = "";
  for (let i = 0; i < replacement.length; i += 1) {
    const char = replacement[i];
    if (char !== "$") {
      output += char;
      continue;
    }
    const next = replacement[i + 1];
    if (next === "$") {
      output += "$";
      i += 1;
    } else if (next === "&") {
      output += wholeMatch;
      i += 1;
    } else if (next !== undefined && /[0-9]/u.test(next)) {
      output += captures[Number(next)] ?? "";
      i += 1;
    } else {
      output += char;
    }
  }
  return output;
}

export function runSafePattern(pattern: CompiledPattern): SafeRegex {
  return {
    test(value: string): boolean {
      return new Vm(pattern, value).run(0) !== undefined;
    },
    matchAll(value: string): MatchResult[] {
      const vm = new Vm(pattern, value);
      const matches: MatchResult[] = [];
      let position = 0;
      while (true) {
        const match = vm.run(position);
        if (!match) break;
        matches.push(match);
        position = match.end > match.start ? match.end : match.end + 1;
      }
      return matches;
    },
    replace(value: string, replacement: string): string {
      const matches = this.matchAll(value);
      if (matches.length === 0) return value;
      const chars = Array.from(value.slice(0, SAFE_TEXT_MAX_CODEPOINTS));
      const parts: string[] = [];
      let cursor = 0;
      for (const match of matches) {
        parts.push(chars.slice(cursor, match.start).join(""));
        parts.push(expandReplacement(replacement, chars.slice(match.start, match.end).join(""), match.captures));
        cursor = match.end;
      }
      parts.push(chars.slice(cursor).join(""));
      return parts.join("");
    },
  };
}

/**
 * Validate a name-filter pattern against the safe subset.
 * Returns null when the pattern is valid, otherwise a human-readable error.
 */
export function validateSafePattern(pattern: string): string | null {
  if (pattern.length > SAFE_PATTERN_MAX_LENGTH) {
    return "正则表达式长度不能超过 " + SAFE_PATTERN_MAX_LENGTH + " 个字符";
  }
  if (compileSafePattern(pattern) === null) {
    return "不支持的表达式语法（不支持环视/反向引用/原子组/命名组；重复上限 " + SAFE_PATTERN_MAX_REPEAT + "）";
  }
  return null;
}

/** Compile a pattern; returns undefined for invalid patterns (legacy data). */
export function safeRegex(pattern: string): SafeRegex | undefined {
  const compiled = compileSafePattern(pattern);
  if (!compiled) return undefined;
  return runSafePattern(compiled);
}

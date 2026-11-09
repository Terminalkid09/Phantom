module.exports = {
  root: true,
  parser: "@typescript-eslint/parser",
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: "module",
    ecmaFeatures: { jsx: true },
  },
  plugins: ["@typescript-eslint", "react-hooks"],
  extends: ["eslint:recommended", "plugin:@typescript-eslint/recommended"],
  env: { browser: true, node: true, es2022: true },
  ignorePatterns: ["dist/", "dist-electron/", "dist-release/", "node_modules/"],
  rules: {
    // The renderer talks to a typed preload bridge; `any` is used at the
    // boundary where the IPC payload is validated again in Python.
    "@typescript-eslint/no-explicit-any": "off",
    // The tree predates this config and carries unused imports inherited from
    // larger components; tsc is the authority on the type surface, so the
    // linter reports real syntax/semantic problems without blocking on that
    // backlog.
    "@typescript-eslint/no-unused-vars": "off",
    "react-hooks/exhaustive-deps": "off",
  },
};

module.exports = {
  root: true,
  env: {
    node: true,
  },
  extends: ["plugin:vue/essential", "@vue/prettier", "@vue/typescript"],
  plugins: ["simple-import-sort"],
  rules: {
    "no-console": process.env.NODE_ENV === "production" ? "error" : "off",
    "no-debugger": process.env.NODE_ENV === "production" ? "error" : "off",
    "simple-import-sort/sort": "error",
  },
  parserOptions: {
    parser: "@typescript-eslint/parser",
  },
  overrides: [
    {
      files: [
        "**/__tests__/*.{j,t}s?(x)",
        "**/tests/unit/**/*.spec.{j,t}s?(x)",
      ],
      env: {
        jest: true,
      },
    },
  ],
};

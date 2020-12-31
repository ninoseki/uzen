module.exports = {
  root: true,
  env: {
    node: true,
  },
  extends: [
    "@vue/prettier",
    "@vue/prettier/@typescript-eslint",
    "@vue/typescript",
    "@vue/typescript/recommended",
    "eslint:recommended",
    "plugin:vue/essential",
  ],
  plugins: ["simple-import-sort"],
  rules: {
    "no-console": process.env.NODE_ENV === "production" ? "error" : "off",
    "no-debugger": process.env.NODE_ENV === "production" ? "error" : "off",
    "simple-import-sort/exports": "error",
    "simple-import-sort/imports": "error",
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

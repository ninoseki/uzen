const { defineConfig } = require("@vue/cli-service");

const target = process.env.BACKEND_URL || "http://localhost:8000/";

module.exports = defineConfig({
  transpileDependencies: true,
  outputDir: "dist",
  assetsDir: "static",
  devServer: {
    proxy: {
      "/api/*": {
        target,
      },
      "/docs": {
        target,
      },
      "/openapi.json": {
        target,
      },
    },
  },
});

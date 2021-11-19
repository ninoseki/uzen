const target = process.env.BACKEND_URL || "http://localhost:8000/";

module.exports = {
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
};

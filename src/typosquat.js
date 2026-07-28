// Typosquat detection: flag names within edit distance 1-2 of a very popular
// package (but not the popular package itself). The list is embedded so the
// check works offline and can't be tampered with over the network.

export const POPULAR = [
  "react", "react-dom", "next", "vue", "svelte", "angular", "express",
  "fastify", "koa", "hono", "lodash", "underscore", "axios", "node-fetch",
  "got", "chalk", "picocolors", "commander", "yargs", "minimist", "inquirer",
  "prompts", "dotenv", "cross-env", "rimraf", "glob", "fs-extra", "mkdirp",
  "typescript", "ts-node", "tsx", "esbuild", "vite", "webpack", "rollup",
  "parcel", "babel", "eslint", "prettier", "jest", "vitest", "mocha", "chai",
  "supertest", "playwright", "cypress", "puppeteer", "moment", "dayjs",
  "date-fns", "luxon", "uuid", "nanoid", "zod", "yup", "joi", "ajv",
  "classnames", "clsx", "styled-components", "tailwindcss", "postcss",
  "autoprefixer", "sass", "less", "jquery", "d3", "three", "chart.js",
  "socket.io", "ws", "cors", "helmet", "morgan", "body-parser", "multer",
  "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "mongoose", "mongodb",
  "pg", "mysql2", "sqlite3", "better-sqlite3", "redis", "ioredis", "prisma",
  "sequelize", "knex", "drizzle-orm", "graphql", "apollo-server", "trpc",
  "rxjs", "ramda", "immer", "zustand", "redux", "mobx", "react-router-dom",
  "react-query", "swr", "formik", "react-hook-form", "framer-motion",
  "lucide-react", "openai", "anthropic", "langchain", "sharp", "jimp",
  "cheerio", "jsdom", "marked", "markdown-it", "highlight.js", "shiki",
  "semver", "debug", "winston", "pino", "npm", "yarn", "pnpm", "nodemon",
  "concurrently", "husky", "lint-staged", "serve", "http-server",
];

/** Damerau-Levenshtein distance (with adjacent transpositions). */
export function editDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const d = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 0; i <= m; i++) d[i][0] = i;
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(
        d[i - 1][j] + 1,
        d[i][j - 1] + 1,
        d[i - 1][j - 1] + cost,
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

/** Returns the popular package this name is squatting on, or null. */
export function typosquatTarget(name) {
  const bare = name.startsWith("@") ? name.split("/")[1] ?? name : name;
  if (POPULAR.includes(bare)) return null;
  const maxDist = bare.length <= 4 ? 1 : 2;
  let best = null;
  for (const popular of POPULAR) {
    const dist = editDistance(bare, popular);
    if (dist <= maxDist && (best === null || dist < best.dist)) {
      best = { target: popular, dist };
    }
  }
  return best?.target ?? null;
}

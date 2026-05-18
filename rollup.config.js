import typescript from "@rollup/plugin-typescript";

const tsPlugin = () =>
  typescript({ tsconfig: "./tsconfig.json", declaration: false, outDir: undefined });

export default [
  {
    input: "src/index.ts",
    output: { file: "dist/index.esm.js", format: "es", sourcemap: true },
    plugins: [tsPlugin()],
    external: ["node:crypto"],
  },
  {
    input: "src/index.ts",
    output: { file: "dist/index.cjs.js", format: "cjs", exports: "named", sourcemap: true },
    plugins: [tsPlugin()],
    external: ["node:crypto"],
  },
];

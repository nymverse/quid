import resolve from '@rollup/plugin-node-resolve';
import commonjs from '@rollup/plugin-commonjs';
import typescript from '@rollup/plugin-typescript';
import terser from '@rollup/plugin-terser';
import dts from 'rollup-plugin-dts';
import pkg from './package.json' with { type: 'json' };

const banner = `/*!
 * QuID JavaScript SDK v${pkg.version}
 * ${pkg.homepage}
 * 
 * Copyright ${new Date().getFullYear()} QuID Team
 * Licensed under ${pkg.license}
 */`;

const external = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.peerDependencies || {})
];

export default [
  // ES Module build
  {
    input: 'src/index.ts',
    external,
    output: {
      file: pkg.module,
      format: 'es',
      banner,
      sourcemap: true
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false
      })
    ]
  },

  // CommonJS build
  {
    input: 'src/index.ts',
    external,
    output: {
      file: pkg.main,
      format: 'cjs',
      banner,
      sourcemap: true,
      exports: 'named'
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false
      })
    ]
  },

  // UMD build for browsers
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/quid-sdk.umd.js',
      format: 'umd',
      name: 'QuIDSDK',
      banner,
      sourcemap: true,
      globals: {
        'react': 'React',
        'vue': 'Vue'
      }
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false
      })
    ]
  },

  // Minified UMD build
  {
    input: 'src/index.ts',
    output: {
      file: 'dist/quid-sdk.umd.min.js',
      format: 'umd',
      name: 'QuIDSDK',
      banner,
      sourcemap: true,
      globals: {
        'react': 'React',
        'vue': 'Vue'
      }
    },
    plugins: [
      resolve({
        browser: true,
        preferBuiltins: false
      }),
      commonjs(),
      typescript({
        tsconfig: './tsconfig.json',
        declaration: false
      }),
      terser({
        format: {
          comments: /^!/
        }
      })
    ]
  },

  // Type definitions
  {
    input: 'dist/index.d.ts',
    output: {
      file: 'dist/index.d.ts',
      format: 'es'
    },
    plugins: [dts()],
    external: [/\.css$/]
  }
];
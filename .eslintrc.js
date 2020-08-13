module.exports = {
    root: true,
    parser: '@typescript-eslint/parser',
    parserOptions: {
        project: './tsconfig.json',
    },
    plugins: [
        '@typescript-eslint',
    ],
    extends: [
        'eslint:recommended',
        'plugin:@typescript-eslint/eslint-recommended',
        'plugin:@typescript-eslint/recommended',
    ],
    rules: {
        "quotes": ["warn", "double", {"avoidEscape": false, "allowTemplateLiterals": true}],
        // Make it an error if we forget to 'await' a promise
        "@typescript-eslint/no-floating-promises": "error",
        "@typescript-eslint/no-explicit-any": "off",
        "@typescript-eslint/no-unused-vars": "off",
        "@typescript-eslint/explicit-function-return-type": ["warn", {
            "allowExpressions": true,
        }],
        "@typescript-eslint/explicit-module-boundary-types": "off",
        "no-empty": "off",
    },
};

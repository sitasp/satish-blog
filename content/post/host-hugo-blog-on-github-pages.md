+++
title = "Hosting Hugo Site on GitHub Pages"
date = '2025-01-05T23:31:30+05:30'
description = "A step-by-step guide to deploying Hugo website on GitHub Pages using GitHub Actions"
draft = false
+++

GitHub Pages provides an excellent free hosting solution for Hugo website. In this guide, We will walk through the process of setting up continuous deployment using GitHub Actions.

## Prerequisites
- A Hugo website ready to deploy
- A GitHub account
- Git installed on local machine
- Basic familiarity with Git commands

## Step 1: Prepare Repository

1. Create a new repository on GitHub named `foo.github.io`

2. Initialize Hugo project as a Git repository:
```bash
cd my-hugo
git init
git add .
git commit -m "Initial commit"
```

3. Add GitHub repository as the remote origin:
```bash
git remote add origin https://github.com/foo/foo.github.io.git
```

## Step 2: Configure Hugo

1. Update `config.toml` (or `config.yaml`) file. Make sure baseURL matches GitHub Pages URL:
```toml
baseURL = "https://foo.github.io/"
```

2. Commit these changes:
```bash
git add config.toml
git commit -m "Update baseURL for GitHub Pages"
```

## Step 3: Set Up GitHub Actions

1. Create a new directory structure in the repository:
```bash
mkdir -p .github/workflows
```

2. Create a new file named `.github/workflows/hugo.yaml` with the following content:
```yaml
name: Deploy Hugo site to Pages

on:
  push:
    branches: ["main"]
  workflow_dispatch:

permissions:
  contents: read
  pages: write
  id-token: write

concurrency:
  group: "pages"
  cancel-in-progress: false

defaults:
  run:
    shell: bash

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      HUGO_VERSION: 0.121.0
    steps:
      - name: Install Hugo CLI
        run: |
          wget -O ${{ runner.temp }}/hugo.deb https://github.com/gohugoio/hugo/releases/download/v${HUGO_VERSION}/hugo_extended_${HUGO_VERSION}_linux-amd64.deb \
          && sudo dpkg -i ${{ runner.temp }}/hugo.deb
      - name: Install Dart Sass
        run: sudo snap install dart-sass
      - name: Checkout
        uses: actions/checkout@v4
        with:
          submodules: recursive
          fetch-depth: 0
      - name: Setup Pages
        id: pages
        uses: actions/configure-pages@v4
      - name: Build with Hugo
        env:
          HUGO_ENVIRONMENT: production
          HUGO_ENV: production
        run: |
          hugo \
            --gc \
            --minify \
            --baseURL "${{ steps.pages.outputs.base_url }}/"
      - name: Upload artifact
        uses: actions/upload-pages-artifact@v2
        with:
          path: ./public

  deploy:
    environment:
      name: github-pages
      url: ${{ steps.deployment.outputs.page_url }}
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: Deploy to GitHub Pages
        id: deployment
        uses: actions/deploy-pages@v3
```

## Step 4: Enable GitHub Pages

1. Go to the repository settings on GitHub
2. Navigate to "Pages" in the sidebar
3. Under "Build and deployment":
   - Source: Select "GitHub Actions"
   - Branch: main

## Step 5: Push the Changes

Push all the changes to GitHub:
```bash
git add .
git commit -m "Add GitHub Actions workflow"
git push -u origin main
```

## Step 6: Verify Deployment

1. Go to the repository's "Actions" tab on GitHub
2. We should see our workflow running
3. Once completed, visit `https://foo.github.io` to see our site live

## Troubleshooting

If our site isn't displaying correctly:

1. Check the GitHub Actions logs for any errors
2. Verify our baseURL in the Hugo configuration
3. Make sure our repository name exactly matches `foo.github.io`
4. Confirm that GitHub Pages is enabled and using GitHub Actions

## Maintaining Site
1. Make changes to the content locally
2. Commit the changes
3. Push to GitHub

The GitHub Action will automatically build and deploy the updates.

## Best Practices

1. Always test changes locally using `hugo server` before pushing
2. Use branch-based workflow for major changes
3. Keep our Hugo version in the workflow file up to date
4. Remember to push the theme submodules if we're using them

## That’s It!

We now have a fully automated deployment pipeline for our Hugo site using GitHub Pages and GitHub Actions. Any changes we push to our main branch will automatically trigger a new build and deployment.

Please refer to the [official Hugo documentation](https://gohugo.io/documentation/) and [GitHub Pages documentation](https://docs.github.com/en/pages) for more detailed information.
+++
date = '2025-01-05T20:09:18+05:30'
draft = false
title = 'Create Personal Blog Using Hugo'
+++


## What is Hugo?
1. Hugo is a fast and flexible **static site generator**.
2. Offers a wide range of **cool themes** to customize your site.
3. **Write in Markdown** and see your content rendered beautifully on your website.


## Steps to Build Your Blog

### 1. Install Hugo

Install Hugo on your system:

- **Linux/macOS**: 

```bash 
brew install hugo
```

- **Windows**: Download the executable from Hugo's GitHub releases. (need to add the link here)


### 2. Create a New Website Project

Run the following command to create your project:

```bash 
hugo new site my-blog 
```

Navigate into the project folder:
```bash 
cd my-blog
```

Setup `hugo.toml` file:
```toml
baseURL = 'https://example.org/'
languageCode = 'en-us'
title = 'My Blogs'
```

### 3. Install a theme; Let's install `xmin` theme

The `xmin` theme is a minimalist theme with essential features. Add it to your project:

```bash 
git init
git submodule add https://github.com/yihui/hugo-xmin themes/xmin
```

Update the `hugo.toml` file to use the theme:
```toml
theme = "xmin"
```


### 4. Create Posts in Markdown

Create your first post:

```bash 
hugo new posts/first-post.md
```

Edit the file in `content/posts/first-post.md`:

```markdown
---
title: "First Post"
date: 2025-01-01
draft: false
---

Welcome to my blog! This is my first post using Hugo.
```


### 5. Build and Run Your Blog

Run a local server to preview your blog (in development mode):

```bash
hugo server -D
```

Run a local server to preview your blog (in production mode):

```bash
hugo server
```

Access it in your browser at http://localhost:1313.

## That’s It!
Minimalist blog using the xmin theme is ready to go. 
Start writing, customize, and share your stories with the world. 🚀



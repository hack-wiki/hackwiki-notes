---
title: Contribute to HackWiki
---

# Contribute to HackWiki

HackWiki is a community-driven project and we welcome contributions from security professionals of all experience levels. Whether you want to fix a typo, improve an existing article, or write new content, your help makes this resource better for everyone.

## Ways to Contribute

### Content Contributions

- **New articles** — Write about techniques, tools, or concepts not yet covered
- **Improvements** — Expand existing articles with more detail or examples
- **Corrections** — Fix technical errors, typos, or outdated information
- **Code examples** — Add practical code snippets and demonstrations

### Bug Reports

Found something broken? Open an issue describing:
- What you expected to happen
- What actually happened
- Steps to reproduce the problem

## Contribution Guidelines

### Content Standards

1. **Accuracy** — Verify technical information before submitting
2. **Clarity** — Write for your peers; be clear and concise
3. **Practical** — Include real-world examples and use cases
4. **Ethical** — Focus on defensive knowledge and authorized testing scenarios

### Article Format

Articles should use Markdown with optional YAML frontmatter:

````markdown
---
title: Your Article Title
---

# Your Article Title

Brief introduction explaining what this article covers.

## Section Heading

Content organized into logical sections...

## Practical Example

Include code examples where relevant:

```python
# Example code with comments
```

## References

- Link to official documentation
- Related resources
````

### Writing Tips

- Start with a clear introduction
- Use headings to organize content logically
- Include code examples with syntax highlighting
- Add context for when/why techniques are used
- Link to related articles when relevant

## How to Submit

We use GitHub for all contributions:

### Quick Edits

1. Navigate to the article on GitHub
2. Click the edit button
3. Make your changes
4. Submit a pull request

### New Articles or Major Changes

1. **Fork** the repository
2. **Clone** your fork locally
3. **Create a branch** for your changes
4. **Write or edit** content in the `notes/` folder
5. **Test** by running `python3 grimoire.py`
6. **Commit** with a clear message
7. **Push** to your fork
8. **Open a pull request** with a description of your changes

### GitHub Repository

Visit our repository to get started:

**[HackWiki on GitHub](https://github.com/hack-wiki/hackwiki-notes)**

## Questions?

If you're unsure about anything or want to discuss a potential contribution before starting, open an issue on GitHub. We're happy to help guide you through the process.

---

Thank you for helping make HackWiki a better resource for the security community!

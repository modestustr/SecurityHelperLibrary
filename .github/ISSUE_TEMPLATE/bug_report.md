name: 🐛 Bug Report
description: Report a security issue, crash, or unexpected behavior
title: "[BUG] "
labels: ["bug", "needs-triage"]

body:
  - type: markdown
    attributes:
      value: |
        ## 🔒 Security Issue?
        **If this is a security vulnerability**, please follow our [Security Policy](SECURITY.md) instead of using this form. Report security issues confidentially via security@modestustr.com.

  - type: checkboxes
    id: prerequisites
    attributes:
      label: Prerequisites
      options:
        - label: I've searched for similar issues
          required: true
        - label: I've tested with the latest version
          required: true
        - label: This is a bug, not a feature request
          required: true

  - type: dropdown
    id: version
    attributes:
      label: Version
      description: Which version of SecurityHelperLibrary are you using?
      options:
        - 2.1.0 (latest)
        - 2.0.3
        - 2.0.2
        - 2.0.1
        - 2.0.0
        - Other (specify below)

  - type: dropdown
    id: framework
    attributes:
      label: .NET Target Framework
      options:
        - net481 (.NET Framework 4.8.1)
        - net6.0
        - net8.0 (latest)
        - Other (specify below)

  - type: textarea
    id: description
    attributes:
      label: Description
      description: Clearly describe the bug
      placeholder: "The Hash operation crashes when..."

  - type: textarea
    id: steps
    attributes:
      label: Steps to Reproduce
      description: Provide code snippets or steps
      placeholder: |
        1. Call `HashPasswordWithPBKDF2(...)`
        2. With input `...`
        3. Observe crash/unexpected result

  - type: textarea
    id: expected
    attributes:
      label: Expected Behavior
      description: What should happen?

  - type: textarea
    id: actual
    attributes:
      label: Actual Behavior
      description: What actually happened?
      placeholder: "Exception: InvalidOperationException..."

  - type: textarea
    id: repro
    attributes:
      label: Minimal Reproducible Example (MRE)
      description: Paste a complete code snippet that reproduces the issue
      render: csharp

  - type: textarea
    id: logs
    attributes:
      label: Error Logs / Stack Trace
      description: Full exception stack trace if applicable
      render: csharp

  - type: checkboxes
    id: impact
    attributes:
      label: Impact Assessment
      options:
        - label: Affects security (authentication, encryption, memory handling)
        - label: Affects performance
        - label: Affects API compatibility
        - label: Blocking (prevents normal use)

  - type: textarea
    id: extra
    attributes:
      label: Additional Context
      description: Anything else relevant?

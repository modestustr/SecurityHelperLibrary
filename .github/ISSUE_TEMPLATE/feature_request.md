name: ✨ Feature Request
description: Propose a new feature or enhancement
title: "[FEATURE] "
labels: ["enhancement", "needs-triage"]

body:
  - type: checkboxes
    id: prerequisites
    attributes:
      label: Prerequisites
      options:
        - label: I've searched for similar requests
          required: true
        - label: This feature fits SecurityHelperLibrary's scope
          required: true

  - type: textarea
    id: problem
    attributes:
      label: Problem Statement
      description: What problem does this solve?
      placeholder: "Users need a way to..."

  - type: textarea
    id: solution
    attributes:
      label: Proposed Solution
      description: How should this be implemented?
      placeholder: "Add a new method like..."

  - type: textarea
    id: api
    attributes:
      label: Proposed API (if applicable)
      render: csharp
      placeholder: |
        public string EncryptWithXChaCha20(...) { }

  - type: textarea
    id: alternatives
    attributes:
      label: Alternatives Considered
      description: Any other approaches?

  - type: checkboxes
    id: security
    attributes:
      label: Security Considerations
      options:
        - label: This feature requires new security scrutiny
        - label: This affects cryptographic operations
        - label: This changes memory handling
        - label: No security impact (e.g., documentation-only)

  - type: textarea
    id: security_notes
    attributes:
      label: Security Analysis
      description: If security-related, explain the threat model and mitigation

  - type: checkboxes
    id: impact
    attributes:
      label: Impact Assessment
      options:
        - label: Backward compatible (PATCH/MINOR version)
        - label: Breaking change (MAJOR version bump needed)
        - label: New dependency required
        - label: Increases binary size significantly

  - type: textarea
    id: extra
    attributes:
      label: Additional Context
      description: Links, examples, references?

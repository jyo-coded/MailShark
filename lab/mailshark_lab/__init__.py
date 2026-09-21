"""MailShark Lab: phishing campaign tracing for email forensics.

Pipeline (the course's deliverable structure):

    acquire   → evidence intake with chain-of-custody hashes            (acquire.py)
    extract   → headers, route, auth, URLs, attachment hashes            (extract.py)
    normalize → pandas tables, registrable domains, templates, sketches  (normalize.py)
    cluster   → campaign correlation: similarity over equality          (cluster.py)
    trace     → shared indicators, invariants vs. rotated, origin        (trace.py)
    validate  → IOC baseline vs. campaign correlation under rotation     (evaluate.py, synth.py)
    report    → self-contained HTML + CSV evidence tables                (report.py)
"""

__version__ = "1.0.0"

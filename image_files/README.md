# Example Image Inputs

Place image definition files for `harbor_sbom_report.py` in this directory.

By default, the script reads files whose names start with `images_`.
Each non-empty, non-comment line should contain one container image reference:

```text
harbor.example.com/project/repository:tag
```

Use `images_example.txt` as a neutral template and replace the image
references with images from your own Harbor instance.

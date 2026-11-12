# Fuzz Platform Open Science Materials

This repository contains the supporting artifacts for our ICSE submission on the Fuzz Platform. The materials are organized to support inspection and replication of the user study, statistical analyses, coverage measurements, and platform configuration.

The repository contains four main directories:

- `Analysis/`
- `Platform/`
- `Projects/`
- `Study Materials/`

## Analysis

The `Analysis/` directory contains anonymized study data, participant-created fuzz drivers, code coverage reports, survey responses, statistical analysis scripts, and data used to generate figures and tables in the paper.

All participant-identifying information has been removed from the released artifacts.

### `Code Coverage - Base Drivers only - 24-hr and 30 sec/`

Contains the raw code coverage measurements for the baseline fuzz drivers at both the 30-second and 24-hour measurement points.

These data support the code coverage results reported in the paper.

### `Statistics - Completion Time Analysis/`

Contains the R scripts and associated statistical data used for the completion-time analysis.

This includes the analysis for the primary statistical model and the corresponding sensitivity analyses reported in the paper.

### `Pilot Study anonymized activity logs/`

Contains anonymized artifacts collected during the pilot study, including:

- participant-created fuzz drivers;
- activity logs; and
- logs and reports generated during code coverage measurement.

### `Main Study anonymized activity logs/`

Contains the corresponding anonymized artifacts collected during Study 2, including:

- participant-created fuzz drivers;
- activity logs; and
- logs and reports generated during code coverage measurement.

### `paper tables and figures/`

Contains the spreadsheet data used to generate tables and figures reported in the paper.

## Platform

The `Platform/` directory contains the custom Docker configuration, build scripts, command wrappers, and reporting utilities used to extend OSS-Fuzz for the Fuzz Platform workflow.

These files provide the infrastructure used by the study environment, including simplified interfaces for building fuzz drivers, executing fuzzing tasks, and collecting coverage information.

### Installation

The released platform depends on the supporting `anoncollege` infrastructure.

1. Install `anoncollege` using the instructions available at:

   `<redacted>`

2. Copy the files from the `Platform/` directory into the `Fuzz-Infrastructure` directory of the `anoncollege` installation.

3. Build the base Docker image:

   ```bash
   docker exec -it $(docker ps -q) docker build -t fuzz-base:latest Fuzz-Infrastructure
   ```

4. Host the contents of the `Projects/` directory in a GitHub repository and configure it as a custom project source following the instructions at:

   `<redacted>`

   This provides access to the 59 OSS-Fuzz projects adapted for use with the Fuzz Platform.

5. Host the contents of `Study Materials/fuzz-platform-study/` in a GitHub repository and configure it as a custom project source following the same instructions.

   These materials provide the training modules, practice challenges, study challenges, survey instruments, and consent materials used during the two phases of the user study.

## Projects

The `Projects/` directory contains the 59 OSS-Fuzz projects adapted for execution within the Fuzz Platform.

For each project, the repository includes the relevant project configuration, build scripts, and baseline fuzz drivers required by the study infrastructure.

The collection includes the 14 projects used in the user study and reported in Table 3 of the paper.

## Study Materials

The `Study Materials/` directory contains the materials used to conduct the user study, including:

- platform training modules;
- training slides;
- practice challenges;
- study challenges;
- survey instruments; and
- study-related supporting materials.

These materials correspond to the study procedures described in the paper.

## Artifact Scope

The repository is intended to provide the artifacts necessary to inspect the reported analyses and reproduce the principal experimental workflow. Participant materials have been anonymized before release.

Some external infrastructure references have been replaced with `<redacted>` for anonymous review. These references can be restored in the archival version of the artifact after the review process.
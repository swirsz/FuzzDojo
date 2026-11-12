# ============================================================
# Completion-time analysis
# Revised primary model without INC-24hr
#
# Model:
# TIME ~ PLATFORM + PROJECT + FUZZEXP + ORDER + (1 | USER)
#
# Estimation:
# REML
# Satterthwaite denominator degrees of freedom
# ============================================================

library(lme4)
library(lmerTest)
library(dplyr)
library(knitr)

# ------------------------------------------------------------
# Full revised dataset: 34 observations
# ------------------------------------------------------------

df <- data.frame(

  PROJECT = c(
    "Snappy",
    "Guetzli",
    "Openjpeg",
    "Snappy",
    "Casync",
    "Openjpeg",
    "Guetzli",
    "Snappy",
    "Openjpeg",
    "Unrar",
    "Guetzli",
    "Snappy",
    "Openjpeg",
    "Unrar",
    "Casync",
    "Openjpeg",
    "Openjpeg",
    "Casync",
    "Snappy",
    "Guetzli",
    "Guetzli",
    "Casync",
    "Casync",
    "Openjpeg",
    "Unrar",
    "Openjpeg",
    "Guetzli",
    "Snappy",
    "Guetzli",
    "Snappy",
    "Snappy",
    "Openjpeg",
    "Casync",
    "Guetzli"
  ),

  ORDER = c(
    1,2,1,2,1,2,1,2,
    1,2,1,2,1,2,1,2,
    1,2,1,2,1,2,1,2,
    1,2,1,2,1,2,1,2,
    1,2
  ),

  PLATFORM = c(
    "OSS",
    "FD",
    "FD",
    "OSS",
    "OSS",
    "FD",
    "FD",
    "OSS",
    "FD",
    "OSS",
    "FD",
    "OSS",
    "OSS",
    "FD",
    "FD",
    "OSS",
    "OSS",
    "FD",
    "FD",
    "OSS",
    "OSS",
    "FD",
    "FD",
    "OSS",
    "FD",
    "OSS",
    "OSS",
    "FD",
    "FD",
    "OSS",
    "OSS",
    "FD",
    "FD",
    "OSS"
  ),

  USER = c(
    "AR",
    "AR",
    "BE",
    "BE",
    "CO",
    "CO",
    "ER",
    "ER",
    "GA",
    "GA",
    "GL",
    "GL",
    "HE",
    "HE",
    "KY",
    "KY",
    "MI",
    "MI",
    "MO",
    "MO",
    "NE",
    "NE",
    "PE",
    "PE",
    "RS",
    "RS",
    "RE",
    "RE",
    "SY",
    "SY",
    "US",
    "US",
    "PC",
    "PC"
  ),

  INC24 = c(
    0.1309,
    0.0623,
    0.1273,
    0.1107,
    0.0461,
    0.1272,
    0.0304,
    0.0646,
    0.1398,
    0.1458,
    0.0977,
    0.1915,
    0.0543,
    0.0857,
    0.0459,
    0.0186,
    0.0222,
    0.0478,
    0.1072,
    0.0601,
    0.0621,
    0.0751,
    0.0483,
    0.0036,
    0.0800,
    0.0186,
    0.0563,
    0.0543,
    0.0689,
    0.0975,
    0.0727,
    0.0057,
    0.0600,
    0.0600
  ),

  TIME = c(
    0.633333333,
    1.6633,
    1.8211,
    3.3731,
    4.4,
    0.39,
    1.56,
    1.7,
    2.27,
    4.13,
    0.28,
    3.04,
    3.00,
    1.51,
    0.89,
    9.68,
    5.77,
    1.22,
    2.64,
    3.22,
    3.65,
    1.22,
    0.38,
    3.71,
    2.47,
    6.36,
    1.23,
    1.80,
    5.51,
    4.90,
    1.76,
    4.66,
    0.16,
    9.43
  ),

  FUZZEXP = c(
    2,
    2,
    0,
    0,
    1,
    1,
    0,
    0,
    2,
    2,
    0,
    0,
    1,
    1,
    0,
    0,
    2,
    2,
    1,
    1,
    1,
    1,
    NA,
    NA,
    0,
    0,
    0,
    0,
    0,
    0,
    1,
    1,
    NA,
    NA
  ),

  stringsAsFactors = FALSE
)

# Preserve the original 34 observations for raw means
df_original <- df

# ------------------------------------------------------------
# Recode model variables
# ------------------------------------------------------------

# OSS is the reference platform
df$PLATFORM <- factor(
  df$PLATFORM,
  levels = c("OSS", "FD")
)

# Project is a categorical fixed effect
# Casync is explicitly used as the reference project
df$PROJECT <- factor(df$PROJECT)
df$PROJECT <- relevel(
  df$PROJECT,
  ref = "Casync"
)

# Participant grouping variable
df$USER <- factor(df$USER)

# ORDER is numeric
df$ORDER <- as.numeric(df$ORDER)

# FUZZEXP is numeric.
# Apply the specified +1 recoding.
df$FUZZEXP <- as.numeric(df$FUZZEXP)
df$FUZZEXP <- df$FUZZEXP + 1

# ------------------------------------------------------------
# Raw means from ALL 34 observations
# ------------------------------------------------------------

raw_summary <- df_original %>%
  group_by(PLATFORM) %>%
  summarise(
    n = n(),
    mean_TIME = mean(TIME),
    .groups = "drop"
  )

mean_fd <- mean(
  df_original$TIME[
    df_original$PLATFORM == "FD"
  ]
)

mean_oss <- mean(
  df_original$TIME[
    df_original$PLATFORM == "OSS"
  ]
)

raw_difference <- mean_fd - mean_oss

cat("\n")
cat("========================================\n")
cat("RAW PLATFORM MEANS: ALL 34 OBSERVATIONS\n")
cat("========================================\n")

print(raw_summary)

cat("\nMean FD  =", mean_fd, "\n")
cat("Mean OSS =", mean_oss, "\n")
cat("FD - OSS =", raw_difference, "\n")

# ------------------------------------------------------------
# Complete-case filtering
#
# IMPORTANT:
# INC24 is NOT part of the new primary model.
#
# Therefore missingness is checked only for variables actually
# used in the fitted model.
# ------------------------------------------------------------

model_variables <- c(
  "TIME",
  "PLATFORM",
  "PROJECT",
  "FUZZEXP",
  "ORDER",
  "USER"
)

complete_rows <- complete.cases(
  df[, model_variables]
)

df_model <- df[
  complete_rows,
]

# Drop unused levels after exclusions
df_model$PLATFORM <- droplevels(
  df_model$PLATFORM
)

df_model$PROJECT <- droplevels(
  df_model$PROJECT
)

df_model$USER <- droplevels(
  df_model$USER
)

# ------------------------------------------------------------
# Data summary
# ------------------------------------------------------------

cat("\n")
cat("========================================\n")
cat("MODEL DATA SUMMARY\n")
cat("========================================\n")

cat(
  "Total CSV observations:",
  nrow(df),
  "\n"
)

cat(
  "Observations excluded:",
  sum(!complete_rows),
  "\n"
)

cat(
  "Observations used:",
  nrow(df_model),
  "\n"
)

cat(
  "USER levels:",
  nlevels(df_model$USER),
  "\n"
)

cat(
  "PROJECT levels:",
  nlevels(df_model$PROJECT),
  "\n"
)

cat(
  "PLATFORM reference:",
  levels(df_model$PLATFORM)[1],
  "\n"
)

cat(
  "PROJECT reference:",
  levels(df_model$PROJECT)[1],
  "\n"
)

cat("\nExcluded observations:\n")

print(
  df[
    !complete_rows,
    c(
      "PROJECT",
      "ORDER",
      "PLATFORM",
      "USER",
      "TIME",
      "FUZZEXP"
    )
  ]
)

# ------------------------------------------------------------
# Revised primary mixed-effects model
#
# INC24 IS INTENTIONALLY OMITTED
# ------------------------------------------------------------

model <- lmer(
  TIME ~ PLATFORM +
         PROJECT +
         FUZZEXP +
         ORDER +
         (1 | USER),
  data = df_model,
  REML = TRUE
)

# ------------------------------------------------------------
# lmerTest summary
# Satterthwaite denominator degrees of freedom
# ------------------------------------------------------------

model_summary <- summary(
  model,
  ddf = "Satterthwaite"
)

cat("\n")
cat("========================================\n")
cat("FULL LMERTEST MODEL SUMMARY\n")
cat("========================================\n")

print(model_summary)

# ------------------------------------------------------------
# Fixed effects
# ------------------------------------------------------------

fix <- as.data.frame(
  model_summary$coefficients
)

fixed_table <- data.frame(
  Fixed_Effect = rownames(fix),
  Estimate     = fix$Estimate,
  SE           = fix$`Std. Error`,
  df           = fix$df,
  t            = fix$`t value`,
  p            = fix$`Pr(>|t|)`,
  row.names = NULL
)

cat("\n")
cat("========================================\n")
cat("FIXED EFFECTS\n")
cat("========================================\n")

print(
  fixed_table,
  digits = 8
)

# ------------------------------------------------------------
# Publication-friendly names
# ------------------------------------------------------------

publication_table <- fixed_table

publication_table$Fixed_Effect <- c(
  "Intercept",
  "Platform: FD vs. OSS",
  "Project: Guetzli vs. Casync",
  "Project: Openjpeg vs. Casync",
  "Project: Snappy vs. Casync",
  "Project: Unrar vs. Casync",
  "Fuzzing Experience",
  "Order"
)

cat("\n")
cat("========================================\n")
cat("PUBLICATION-READY FIXED EFFECT TABLE\n")
cat("========================================\n")

print(
  publication_table,
  digits = 8
)

# Optional formatted table
kable(
  publication_table,
  digits = c(
    NA,
    3,
    3,
    2,
    3,
    4
  ),
  align = c(
    "l",
    "r",
    "r",
    "r",
    "r",
    "r"
  )
)

# ------------------------------------------------------------
# Random effects
# ------------------------------------------------------------

rand <- as.data.frame(
  VarCorr(model)
)

random_table <- rand %>%
  select(
    Group = grp,
    Variance = vcov,
    SD = sdcor
  )

cat("\n")
cat("========================================\n")
cat("RANDOM EFFECTS\n")
cat("========================================\n")

print(
  random_table,
  digits = 8
)

# ------------------------------------------------------------
# Singularity and convergence diagnostics
# ------------------------------------------------------------

singular_fit <- isSingular(
  model,
  tol = 1e-4
)

cat("\n")
cat("========================================\n")
cat("MODEL DIAGNOSTICS\n")
cat("========================================\n")

cat(
  "REML used:",
  isREML(model),
  "\n"
)

cat(
  "Singular fit:",
  singular_fit,
  "\n"
)

convergence_messages <-
  model@optinfo$conv$lme4$messages

if (is.null(convergence_messages)) {

  cat(
    "Convergence warnings: none\n"
  )

} else {

  cat(
    "Convergence warnings:\n"
  )

  print(
    convergence_messages
  )
}

# ------------------------------------------------------------
# Extract primary PLATFORM result
# ------------------------------------------------------------

platform_row <- publication_table[
  publication_table$Fixed_Effect ==
    "Platform: FD vs. OSS",
]

cat("\n")
cat("========================================\n")
cat("PRIMARY PLATFORM EFFECT\n")
cat("========================================\n")

cat(
  "Estimate:",
  platform_row$Estimate,
  "\n"
)

cat(
  "SE:",
  platform_row$SE,
  "\n"
)

cat(
  "Satterthwaite df:",
  platform_row$df,
  "\n"
)

cat(
  "t:",
  platform_row$t,
  "\n"
)

cat(
  "Two-sided p:",
  platform_row$p,
  "\n"
)

cat("\n")

cat(
  "Raw mean FD:",
  mean_fd,
  "\n"
)

cat(
  "Raw mean OSS:",
  mean_oss,
  "\n"
)

cat(
  "Raw FD - OSS difference:",
  raw_difference,
  "\n"
)

# ------------------------------------------------------------
# Rounded values for manuscript / LaTeX
# ------------------------------------------------------------

latex_fixed <- publication_table %>%
  mutate(
    Estimate = sprintf("%.2f", Estimate),
    SE       = sprintf("%.2f", SE),
    df       = sprintf("%.2f", df),
    t        = sprintf("%.2f", t),
    p        = sprintf("%.3f", p)
  )

cat("\n")
cat("========================================\n")
cat("ROUNDED FIXED EFFECTS FOR LATEX\n")
cat("========================================\n")

print(
  latex_fixed,
  row.names = FALSE
)

latex_random <- random_table %>%
  mutate(
    Variance = sprintf("%.2f", Variance),
    SD       = sprintf("%.2f", SD)
  )

cat("\n")
cat("========================================\n")
cat("ROUNDED RANDOM EFFECTS FOR LATEX\n")
cat("========================================\n")

print(
  latex_random,
  row.names = FALSE
)

# ------------------------------------------------------------
# Expected primary model specification:
#
# TIME ~ PLATFORM + PROJECT + FUZZEXP + ORDER + (1 | USER)
#
# Note:
# INC24 remains stored in the dataset for reference but is
# intentionally excluded from the primary statistical model.
# ------------------------------------------------------------
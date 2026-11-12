# ============================================================
# Completion-time sensitivity model without fuzzing experience
#
# Model:
# TIME ~ PLATFORM + PROJECT + ORDER + (1 | USER)
#
# Dataset:
# Corrected 34-row highest-coverage completion-time dataset
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
# Full corrected dataset: 34 observations
# ------------------------------------------------------------

df <- data.frame(
  
  PROJECT = c(
    "Snappy","Guetzli","Openjpeg","Snappy","Casync","Openjpeg","Guetzli","Snappy",
    "Openjpeg","Unrar","Guetzli","Snappy","Openjpeg","Unrar","Casync","Openjpeg",
    "Openjpeg","Casync","Snappy","Guetzli","Guetzli","Casync","Casync","Openjpeg",
    "Unrar","Openjpeg","Guetzli","Snappy","Guetzli","Snappy","Snappy","Openjpeg",
    "Casync","Guetzli"
  ),
  
  ORDER = c(
    1,2,1,2,1,2,1,2,
    1,2,1,2,1,2,1,2,
    1,2,1,2,1,2,1,2,
    1,2,1,2,1,2,1,2,
    1,2
  ),
  
  PLATFORM = c(
    "OSS","FD","FD","OSS","OSS","FD","FD","OSS",
    "FD","OSS","FD","OSS","OSS","FD","FD","OSS",
    "OSS","FD","FD","OSS","OSS","FD","FD","OSS",
    "FD","OSS","OSS","FD","FD","OSS","OSS","FD",
    "FD","OSS"
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
  
  QUALITY = c(
    20,15,18,15,16,8,11,17,
    13,11,18,19,19,11,10,7,
    11,8,16,6,4,11,7,5,
    9,11,6,3,10,11,13,10,
    1,1
  ),
  
  INC30 = c(
    13.08,6.23,12.73,11.07,4.61,12.72,4.52,7.13,
    13.98,14.58,9.66,19.15,5.43,8.57,5.03,1.86,
    2.22,4.78,10.72,6.68,6.21,7.35,4.77,0.36,
    7.66,1.86,5.73,5.43,7.91,9.75,7.27,0.57,
    1.00,1.00
  ),
  
  PROD30 = c(
    0.048,0.268,0.143,0.194,0.947,0.030,0.347,0.238,
    0.162,0.283,0.043,0.264,0.522,0.185,0.215,5.869,
    2.485,0.746,0.210,0.469,0.577,0.195,0.087,10.278,
    0.483,6.622,0.215,0.331,0.293,0.318,0.245,8.158,
    1,1
  ),
  
  INC24 = c(
    13.06,6.02,12.87,11.06,6.97,12.38,2.68,5.98,
    14.68,13.59,9.79,19.13,5.26,4.57,4.59,1.82,
    0.87,4.78,10.69,8.80,6.23,7.51,4.83,1.28,
    12.34,2.88,5.47,5.40,6.59,9.72,7.24,-0.06,
    0.06,0.06
  ),
  
  PROD24 = c(
    0.048,0.277,0.141,0.194,0.626,0.031,0.585,0.284,
    0.154,0.304,0.043,0.264,0.539,0.346,0.236,5.998,
    6.341,0.746,0.210,0.356,0.575,0.191,0.086,2.891,
    0.300,4.277,0.225,0.333,0.352,0.319,0.246,-77.500,
    1,1
  ),
  
  DIFF24VS30 = c(
    -0.02,-0.21,0.14,-0.01,2.36,-0.34,-1.84,-1.15,
    0.70,-0.99,0.13,-0.02,-0.17,-4.00,-0.44,-0.04,
    -1.35,0.00,-0.03,2.12,0.02,0.16,0.06,0.92,
    4.68,1.02,-0.26,-0.03,-1.32,-0.03,-0.03,-0.63,
    1.00,1.00
  ),
  
  TIME = c(
    0.72, 1.66, 1.82, 3.37, 4.4, 0.39, 1.64, 1.7, 2.27, 4.13, 1.32, 5.14, 2.99, 1.51, 1.08, 10.93, 5.85, 1.61, 2.24, 3.22, 3.65, 1.31, 0.38, 3.71, 2.01, 6.36, 1.23, 1.8, 5.61, 5.44, 1.76, 4.66,
    0.16, 9.43
  
  ),
  
  FUZZEXP = c(
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    1, 1
  
  ),
  
  stringsAsFactors = FALSE
)

# ------------------------------------------------------------
# Preserve original data
# ------------------------------------------------------------

df_original <- df

# ------------------------------------------------------------
# Recode variables
# ------------------------------------------------------------

# OSS is the platform reference
df$PLATFORM <- factor(
  df$PLATFORM,
  levels = c("OSS", "FD")
)

# Casync is the project reference
df$PROJECT <- factor(df$PROJECT)
df$PROJECT <- relevel(
  df$PROJECT,
  ref = "Casync"
)

# USER grouping variable
df$USER <- factor(df$USER)

# ORDER remains numeric
df$ORDER <- as.numeric(df$ORDER)

# ------------------------------------------------------------
# Complete-case filtering
#
# INC24 and FUZZEXP are intentionally NOT part of this model.
# ------------------------------------------------------------

model_variables <- c(
  "TIME",
  "PLATFORM",
  "PROJECT",
  "ORDER",
  "USER"
)

complete_rows <- complete.cases(
  df[, model_variables]
)

df_model <- df[complete_rows, ]

df_model$PLATFORM <- droplevels(df_model$PLATFORM)
df_model$PROJECT  <- droplevels(df_model$PROJECT)
df_model$USER     <- droplevels(df_model$USER)

# ------------------------------------------------------------
# Data summary
# ------------------------------------------------------------

cat("\n========================================\n")
cat("MODEL DATA SUMMARY\n")
cat("========================================\n")

cat("Total observations:", nrow(df), "\n")
cat("Excluded observations:", sum(!complete_rows), "\n")
cat("Observations used:", nrow(df_model), "\n")
cat("USER levels:", nlevels(df_model$USER), "\n")
cat("PROJECT levels:", nlevels(df_model$PROJECT), "\n")
cat("PLATFORM reference:", levels(df_model$PLATFORM)[1], "\n")
cat("PROJECT reference:", levels(df_model$PROJECT)[1], "\n")

cat("\nExcluded observations:\n")

print(
  df[
    !complete_rows,
    c("PROJECT", "ORDER", "PLATFORM",
      "USER", "TIME")
  ]
)

# ------------------------------------------------------------
# Model
# ------------------------------------------------------------

model <- lmer(
  TIME ~ PLATFORM +
    PROJECT +
    ORDER +
    (1 | USER),
  data = df_model,
  REML = TRUE
)

model_summary <- summary(
  model,
  ddf = "Satterthwaite"
)

cat("\n========================================\n")
cat("PRIMARY MODEL\n")
cat("========================================\n")

print(model_summary)

model_coef <- as.data.frame(
  model_summary$coefficients
)

platform_result <- model_coef[
  "PLATFORMFD",
]

cat("\nPlatform result:\n")

cat("Estimate =", platform_result$Estimate, "\n")
cat("SE =", platform_result$`Std. Error`, "\n")
cat("df =", platform_result$df, "\n")
cat("t =", platform_result$`t value`, "\n")
cat("p =", platform_result$`Pr(>|t|)`, "\n")

cat(
  "Singular fit =",
  isSingular(model, tol = 1e-4),
  "\n"
)

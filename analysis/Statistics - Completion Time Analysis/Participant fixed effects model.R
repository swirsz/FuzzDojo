# Participant fixed-effects sensitivity analysis for completion time
# Model: TIME ~ PLATFORM + PROJECT + ORDER + USER
# Uses all 32 observations, including the participant with missing FUZZ-EXP.
# FUZZ-EXP is intentionally omitted because participant fixed effects absorb
# participant-level characteristics that are constant across tasks.

csv_text <- 'PROJECT,ORDER,PLATFORM,USER,QUALITY,INC-30sec,PROD-30,INC-24hr,PROD-24 hr, 24vs30 ,TIME,FUZZ-EXP,JOB,COUNTRY
Snappy,1,OSS,4rbit3r,20,13.08%,0.048,13.06%,0.048,-0.02%,0.72,2,Researcher / Academics,United States
Guetzli,2,FD,4rbit3r,15,6.23%,0.268,6.02%,0.277,-0.21%,1.66,2,Researcher / Academics,United States
Openjpeg,1,FD,bena,18,12.73%,0.143,12.87%,0.141,0.14%,1.82,0,Researcher / Academics,United States
Snappy,2,OSS,bena,15,11.07%,0.194,11.06%,0.194,-0.01%,3.37,0,Researcher / Academics,United States
Casync,1,OSS,costomato,16,4.61%,0.947,6.97%,0.626,2.36%,4.40,1,Student,United States (F1)
Openjpeg,2,FD,costomato,8,12.72%,0.030,12.38%,0.031,-0.34%,0.39,1,Student,United States (F1)
Guetzli,1,FD,erge,11,4.52%,0.347,2.68%,0.585,-1.84%,1.64,0,Student,n/a
Snappy,2,OSS,erge,17,7.13%,0.238,5.98%,0.284,-1.15%,1.70,0,Student,n/a
Openjpeg,1,FD,gabesharm,13,13.98%,0.162,14.68%,0.154,0.70%,2.27,2,Student,United States of America
Unrar,2,OSS,gabesharm,11,14.58%,0.283,13.59%,0.304,-0.99%,4.13,2,Student,United States of America
Guetzli,1,FD,glueless,18,9.66%,0.043,9.79%,0.043,0.13%,1.32,0,"unemployed / not in education, disabled",AMERICA
Snappy,2,OSS,glueless,19,19.15%,0.264,19.13%,0.264,-0.02%,5.14,0,"unemployed / not in education, disabled",AMERICA
Openjpeg,1,OSS,hextechblade / 0xsegfault,19,5.43%,0.522,5.26%,0.539,-0.17%,2.99,1,Researcher / Academics,US
Unrar,2,FD,hextechblade / 0xsegfault,11,8.57%,0.185,4.57%,0.346,-4.00%,1.51,1,Researcher / Academics,US
Casync,1,FD,kylma,10,5.03%,0.215,4.59%,0.236,-0.44%,1.08,0,Security Expert,Italy
Openjpeg,2,OSS,kylma,7,1.86%,5.869,1.82%,5.998,-0.04%,10.93,0,Security Expert,Italy
Openjpeg,1,OSS,midnighttracer,11,2.22%,2.485,0.87%,6.341,-1.35%,5.85,2,Developer,United Kingdom
Casync,2,FD,midnighttracer,8,4.78%,0.746,4.78%,0.746,0.00%,1.61,2,Developer,United Kingdom
Snappy,1,FD,mowteam,16,10.72%,0.210,10.69%,0.210,-0.03%,2.24,1,Researcher / Academics,United States of America
Guetzli,2,OSS,mowteam,6,6.68%,0.469,8.80%,0.356,2.12%,3.22,1,Researcher / Academics,United States of America
Guetzli,1,OSS,nendo,4,6.21%,0.577,6.23%,0.575,0.02%,3.65,1,Hobbyist,n/a
Casync,2,FD,nendo,11,7.35%,0.195,7.51%,0.191,0.16%,1.31,1,Hobbyist,n/a
Casync,1,FD,pepito,7,4.77%,0.087,4.83%,0.086,0.06%,0.38,n/a,n/a,n/a
Openjpeg,2,OSS,pepito,5,0.36%,10.278,1.28%,2.891,0.92%,3.71,n/a,n/a,n/a
Unrar,1,FD,r3st / m0rpheus,9,7.66%,0.483,12.34%,0.300,4.68%,2.01,0,Developer,United States of America
Openjpeg,2,OSS,r3st / m0rpheus,11,1.86%,6.622,2.88%,4.277,1.02%,6.36,0,Developer,United States of America
Guetzli,1,OSS,return42,6,5.73%,0.215,5.47%,0.225,-0.26%,1.23,0,Student,n/a
Snappy,2,FD,return42,3,5.43%,0.331,5.40%,0.333,-0.03%,1.80,0,Student,n/a
Guetzli,1,FD,SYS_exit,10,7.91%,0.293,6.59%,0.352,-1.32%,5.61,0,Developer,Canada
Snappy,2,OSS,SYS_exit,11,9.75%,0.318,9.72%,0.319,-0.03%,5.44,0,Developer,Canada
Snappy,1,OSS,usdk,13,7.27%,0.245,7.24%,0.246,-0.03%,1.76,1,Researcher / Academics,Italy
Openjpeg,2,FD,usdk,10,0.57%,8.158,-0.06%,-77.500,-0.63%,4.66,1,Researcher / Academics,Italy'

# Read exactly the supplied values. check.names = FALSE preserves the original
# column names, including FUZZ-EXP and the columns containing spaces.
dat <- read.csv(text = csv_text,
                stringsAsFactors = FALSE,
                check.names = FALSE,
                na.strings = c("n/a", "NA", ""))

# Confirm that all 32 observations are available for this model.
model_vars <- c("TIME", "PLATFORM", "PROJECT", "ORDER", "USER")
complete_rows <- complete.cases(dat[, model_vars])
dat_model <- dat[complete_rows, , drop = FALSE]

# Explicit reference levels.
dat_model$PLATFORM <- factor(dat_model$PLATFORM, levels = c("OSS", "FD"))
dat_model$PROJECT  <- relevel(factor(dat_model$PROJECT), ref = "Casync")
dat_model$USER     <- factor(dat_model$USER)
dat_model$ORDER    <- as.numeric(dat_model$ORDER)
dat_model$TIME     <- as.numeric(dat_model$TIME)

# Participant fixed-effects sensitivity model.
# FUZZ-EXP is intentionally excluded: it is constant within participant and
# is therefore absorbed by the USER fixed effects.
fit <- lm(TIME ~ PLATFORM + PROJECT + ORDER + USER, data = dat_model)

# Basic accounting.
cat("Participant fixed-effects sensitivity analysis\n")
cat("==============================================\n")
cat("Total CSV observations:", nrow(dat), "\n")
cat("Excluded for missing model variables:", sum(!complete_rows), "\n")
cat("Observations used:", nrow(dat_model), "\n")
cat("USER levels:", nlevels(dat_model$USER), "\n")
cat("PROJECT levels:", nlevels(dat_model$PROJECT), "\n")
cat("PLATFORM reference: OSS\n")
cat("PROJECT reference: Casync\n")
cat("Model: TIME ~ PLATFORM + PROJECT + ORDER + USER\n\n")

# Full model summary.
print(summary(fit))

# Full coefficient table with conventional two-sided t tests from lm().
coef_table <- coef(summary(fit))
cat("\nFull coefficient table:\n")
print(coef_table)

# Extract the FD vs OSS coefficient explicitly.
platform_row <- coef_table["PLATFORMFD", , drop = FALSE]
cat("\nFD vs OSS platform effect:\n")
cat(sprintf("Estimate = %.10f hours\n", platform_row[1, "Estimate"]))
cat(sprintf("SE       = %.10f\n", platform_row[1, "Std. Error"]))
cat(sprintf("df       = %d\n", df.residual(fit)))
cat(sprintf("t        = %.10f\n", platform_row[1, "t value"]))
cat(sprintf("p        = %.10f (two-sided)\n", platform_row[1, "Pr(>|t|)"]))

# Additional diagnostics.
cat("\nModel diagnostics:\n")
cat(sprintf("Residual standard error = %.10f\n", sigma(fit)))
cat(sprintf("Residual variance       = %.10f\n", sigma(fit)^2))
cat(sprintf("R-squared               = %.10f\n", summary(fit)$r.squared))
cat(sprintf("Adjusted R-squared      = %.10f\n", summary(fit)$adj.r.squared))

# Optional 95% confidence interval for the platform coefficient.
cat("\n95% confidence interval for FD vs OSS:\n")
print(confint(fit, "PLATFORMFD", level = 0.95))

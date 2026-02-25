df <- data.frame(
PROJECT=c(
"Snappy","Guetzli","Openjpeg","Snappy","Casync","Openjpeg","Guetzli","Snappy",
"Openjpeg","Unrar","Guetzli","Snappy","Openjpeg","Unrar","Casync","Openjpeg",
"Openjpeg","Casync","Snappy","Guetzli","Guetzli","Casync","Casync","Openjpeg",
"Unrar","Openjpeg","Guetzli","Snappy","Guetzli","Snappy","Snappy","Openjpeg"
),

ORDER=c(
1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2,1,2
),

PLATFORM=c(
"OSS","FD","FD","OSS","OSS","FD","FD","OSS","FD","OSS","FD","OSS",
"OSS","FD","FD","OSS","OSS","FD","FD","OSS","OSS","FD","FD","OSS",
"FD","OSS","OSS","FD","FD","OSS","OSS","FD"
),

QUALITY=c(
20,15,18,15,16,8,11,17,13,11,18,19,19,11,10,7,11,8,16,6,4,11,7,5,9,11,6,3,10,11,13,10
),

INC24=c(
13.06,6.02,12.87,11.06,6.97,12.38,2.68,5.98,14.68,13.59,9.79,19.13,
5.26,4.57,4.59,1.82,0.87,4.78,10.69,8.80,6.23,7.51,4.83,1.28,
12.34,2.88,5.47,5.40,6.59,9.72,7.24,-0.06
),

TIME=c(
0.633333333,1.666666667,1.816666667,2.15,4.366666667,0.383333333,
1.566666667,1.7,2.266666667,4.133333333,0.416666667,5.05,
2.833333333,1.583333333,1.083333333,10.91666667,5.516666667,
3.566666667,2.25,3.133333333,3.583333333,1.433333333,
0.416666667,3.7,3.7,12.31666667,1.233333333,1.8,
2.316666667,3.1,1.783333333,4.65
),

FUZZEXP=c(
3,3,1,1,2,2,1,1,3,3,1,1,2,2,1,1,3,3,2,2,2,2,NA,NA,1,1,1,1,1,1,2,2
)
)

library(lme4)
library(lmerTest)   # gives p-values
library(dplyr)

df$PROJECT <- factor(df$PROJECT)
df$PLATFORM <- factor(df$PLATFORM, levels=c("OSS","FD"))
df$ORDER <- as.numeric(df$ORDER)

# optional: remove rows with missing fuzz experience
df_model <- df

df_model <- na.omit(df)

df_model$PROJECT <- factor(df_model$PROJECT)
df_model$PLATFORM <- factor(df_model$PLATFORM, levels=c("OSS","FD"))
df_model$ORDER <- as.numeric(df_model$ORDER)

df_model$INC24_c <- scale(df_model$INC24, scale=FALSE)
df_model$FUZZEXP_c <- scale(df_model$FUZZEXP, scale=FALSE)

model <- lmer(
  TIME ~ PLATFORM + INC24 + FUZZEXP + ORDER + (1|PROJECT),
  data = df_model,
  REML = TRUE   # change from FALSE to TRUE
)

fix <- summary(model)$coefficients

fix_tab <- data.frame(
  Effect = rownames(fix),
  Estimate = fix[,"Estimate"],
  StdError = fix[,"Std. Error"],
  t = fix[,"t value"],
  p = fix[,"Pr(>|t|)"]
)

rand_tab <- as.data.frame(VarCorr(model)) |>
  dplyr::select(
    Effect = grp,
    Variance = vcov,
    SD = sdcor
  )

print(rand_tab)

library(knitr)

kable(fix_tab, digits=3)
kable(rand_tab, digits=2)

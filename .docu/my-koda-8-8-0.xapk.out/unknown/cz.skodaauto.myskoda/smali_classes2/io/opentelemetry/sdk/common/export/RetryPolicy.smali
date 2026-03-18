.class public abstract Lio/opentelemetry/sdk/common/export/RetryPolicy;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    }
.end annotation


# static fields
.field private static final DEFAULT:Lio/opentelemetry/sdk/common/export/RetryPolicy;

.field private static final DEFAULT_BACKOFF_MULTIPLIER:D = 1.5

.field private static final DEFAULT_INITIAL_BACKOFF_SECONDS:I = 0x1

.field private static final DEFAULT_MAX_ATTEMPTS:I = 0x5

.field private static final DEFAULT_MAX_BACKOFF_SECONDS:I = 0x5


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->builder()Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;->build()Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sput-object v0, Lio/opentelemetry/sdk/common/export/RetryPolicy;->DEFAULT:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 10
    .line 11
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder()Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x5

    .line 7
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->setMaxAttempts(I)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const-wide/16 v1, 0x1

    .line 12
    .line 13
    invoke-static {v1, v2}, Ljava/time/Duration;->ofSeconds(J)Ljava/time/Duration;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;->setInitialBackoff(Ljava/time/Duration;)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const-wide/16 v1, 0x5

    .line 22
    .line 23
    invoke-static {v1, v2}, Ljava/time/Duration;->ofSeconds(J)Ljava/time/Duration;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-virtual {v0, v1}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;->setMaxBackoff(Ljava/time/Duration;)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    const-wide/high16 v1, 0x3ff8000000000000L    # 1.5

    .line 32
    .line 33
    invoke-virtual {v0, v1, v2}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;->setBackoffMultiplier(D)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    return-object v0
.end method

.method public static getDefault()Lio/opentelemetry/sdk/common/export/RetryPolicy;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/common/export/RetryPolicy;->DEFAULT:Lio/opentelemetry/sdk/common/export/RetryPolicy;

    .line 2
    .line 3
    return-object v0
.end method


# virtual methods
.method public abstract getBackoffMultiplier()D
.end method

.method public abstract getInitialBackoff()Ljava/time/Duration;
.end method

.method public abstract getMaxAttempts()I
.end method

.method public abstract getMaxBackoff()Ljava/time/Duration;
.end method

.method public abstract getRetryExceptionPredicate()Ljava/util/function/Predicate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/function/Predicate<",
            "Ljava/io/IOException;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract toBuilder()Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
.end method

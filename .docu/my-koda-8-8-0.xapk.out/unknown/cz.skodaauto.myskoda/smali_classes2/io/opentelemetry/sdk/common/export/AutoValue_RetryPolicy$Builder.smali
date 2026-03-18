.class final Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;
.super Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation


# instance fields
.field private backoffMultiplier:D

.field private initialBackoff:Ljava/time/Duration;

.field private maxAttempts:I

.field private maxBackoff:Ljava/time/Duration;

.field private retryExceptionPredicate:Ljava/util/function/Predicate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Predicate<",
            "Ljava/io/IOException;",
            ">;"
        }
    .end annotation
.end field

.field private set$0:B


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;-><init>()V

    return-void
.end method

.method public constructor <init>(Lio/opentelemetry/sdk/common/export/RetryPolicy;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;-><init>()V

    .line 3
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getMaxAttempts()I

    move-result v0

    iput v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxAttempts:I

    .line 4
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getInitialBackoff()Ljava/time/Duration;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->initialBackoff:Ljava/time/Duration;

    .line 5
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getMaxBackoff()Ljava/time/Duration;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxBackoff:Ljava/time/Duration;

    .line 6
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getBackoffMultiplier()D

    move-result-wide v0

    iput-wide v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->backoffMultiplier:D

    .line 7
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/export/RetryPolicy;->getRetryExceptionPredicate()Ljava/util/function/Predicate;

    move-result-object p1

    iput-object p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->retryExceptionPredicate:Ljava/util/function/Predicate;

    const/4 p1, 0x3

    .line 8
    iput-byte p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    return-void
.end method


# virtual methods
.method public autoBuild()Lio/opentelemetry/sdk/common/export/RetryPolicy;
    .locals 9

    .line 1
    iget-byte v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    if-ne v0, v1, :cond_1

    .line 5
    .line 6
    iget-object v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->initialBackoff:Ljava/time/Duration;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    iget-object v0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxBackoff:Ljava/time/Duration;

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    new-instance v1, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy;

    .line 16
    .line 17
    iget v2, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxAttempts:I

    .line 18
    .line 19
    iget-object v3, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->initialBackoff:Ljava/time/Duration;

    .line 20
    .line 21
    iget-object v4, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxBackoff:Ljava/time/Duration;

    .line 22
    .line 23
    iget-wide v5, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->backoffMultiplier:D

    .line 24
    .line 25
    iget-object v7, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->retryExceptionPredicate:Ljava/util/function/Predicate;

    .line 26
    .line 27
    const/4 v8, 0x0

    .line 28
    invoke-direct/range {v1 .. v8}, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy;-><init>(ILjava/time/Duration;Ljava/time/Duration;DLjava/util/function/Predicate;Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$1;)V

    .line 29
    .line 30
    .line 31
    return-object v1

    .line 32
    :cond_1
    :goto_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 35
    .line 36
    .line 37
    iget-byte v1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 38
    .line 39
    and-int/lit8 v1, v1, 0x1

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    const-string v1, " maxAttempts"

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    :cond_2
    iget-object v1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->initialBackoff:Ljava/time/Duration;

    .line 49
    .line 50
    if-nez v1, :cond_3

    .line 51
    .line 52
    const-string v1, " initialBackoff"

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    :cond_3
    iget-object v1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxBackoff:Ljava/time/Duration;

    .line 58
    .line 59
    if-nez v1, :cond_4

    .line 60
    .line 61
    const-string v1, " maxBackoff"

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    :cond_4
    iget-byte p0, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 67
    .line 68
    and-int/lit8 p0, p0, 0x2

    .line 69
    .line 70
    if-nez p0, :cond_5

    .line 71
    .line 72
    const-string p0, " backoffMultiplier"

    .line 73
    .line 74
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 75
    .line 76
    .line 77
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 78
    .line 79
    const-string v1, "Missing required properties:"

    .line 80
    .line 81
    invoke-static {v1, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v0

    .line 85
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    throw p0
.end method

.method public setBackoffMultiplier(D)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    .locals 0

    .line 1
    iput-wide p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->backoffMultiplier:D

    .line 2
    .line 3
    iget-byte p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x2

    .line 6
    .line 7
    int-to-byte p1, p1

    .line 8
    iput-byte p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 9
    .line 10
    return-object p0
.end method

.method public setInitialBackoff(Ljava/time/Duration;)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->initialBackoff:Ljava/time/Duration;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 7
    .line 8
    const-string p1, "Null initialBackoff"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public setMaxAttempts(I)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    .locals 0

    .line 1
    iput p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxAttempts:I

    .line 2
    .line 3
    iget-byte p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 4
    .line 5
    or-int/lit8 p1, p1, 0x1

    .line 6
    .line 7
    int-to-byte p1, p1

    .line 8
    iput-byte p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->set$0:B

    .line 9
    .line 10
    return-object p0
.end method

.method public setMaxBackoff(Ljava/time/Duration;)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    .locals 0

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->maxBackoff:Ljava/time/Duration;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 7
    .line 8
    const-string p1, "Null maxBackoff"

    .line 9
    .line 10
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public setRetryExceptionPredicate(Ljava/util/function/Predicate;)Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Predicate<",
            "Ljava/io/IOException;",
            ">;)",
            "Lio/opentelemetry/sdk/common/export/RetryPolicy$RetryPolicyBuilder;"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/common/export/AutoValue_RetryPolicy$Builder;->retryExceptionPredicate:Ljava/util/function/Predicate;

    .line 2
    .line 3
    return-object p0
.end method

.class final Lio/opentelemetry/sdk/logs/internal/AutoValue_LoggerConfig;
.super Lio/opentelemetry/sdk/logs/internal/LoggerConfig;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final enabled:Z


# direct methods
.method public constructor <init>(Z)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-boolean p1, p0, Lio/opentelemetry/sdk/logs/internal/AutoValue_LoggerConfig;->enabled:Z

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;

    .line 11
    .line 12
    iget-boolean p0, p0, Lio/opentelemetry/sdk/logs/internal/AutoValue_LoggerConfig;->enabled:Z

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/sdk/logs/internal/LoggerConfig;->isEnabled()Z

    .line 15
    .line 16
    .line 17
    move-result p1

    .line 18
    if-ne p0, p1, :cond_1

    .line 19
    .line 20
    return v0

    .line 21
    :cond_1
    return v2
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/logs/internal/AutoValue_LoggerConfig;->enabled:Z

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/16 p0, 0x4cf

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/16 p0, 0x4d5

    .line 9
    .line 10
    :goto_0
    const v0, 0xf4243

    .line 11
    .line 12
    .line 13
    xor-int/2addr p0, v0

    .line 14
    return p0
.end method

.method public isEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/logs/internal/AutoValue_LoggerConfig;->enabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "LoggerConfig{enabled="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-boolean p0, p0, Lio/opentelemetry/sdk/logs/internal/AutoValue_LoggerConfig;->enabled:Z

    .line 9
    .line 10
    const-string v1, "}"

    .line 11
    .line 12
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

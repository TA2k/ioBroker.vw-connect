.class final Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;
.super Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final clock:Lio/opentelemetry/sdk/common/Clock;

.field private final exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

.field private final resource:Lio/opentelemetry/sdk/resources/Resource;

.field private final startEpochNanos:J


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/common/Clock;Lio/opentelemetry/sdk/resources/Resource;JLio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_2

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 7
    .line 8
    if-eqz p2, :cond_1

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 11
    .line 12
    iput-wide p3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->startEpochNanos:J

    .line 13
    .line 14
    if-eqz p5, :cond_0

    .line 15
    .line 16
    iput-object p5, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 20
    .line 21
    const-string p1, "Null exemplarFilter"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 28
    .line 29
    const-string p1, "Null resource"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 36
    .line 37
    const-string p1, "Null clock"

    .line 38
    .line 39
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getClock()Lio/opentelemetry/sdk/common/Clock;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->startEpochNanos:J

    .line 37
    .line 38
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getStartEpochNanos()J

    .line 39
    .line 40
    .line 41
    move-result-wide v5

    .line 42
    cmp-long v1, v3, v5

    .line 43
    .line 44
    if-nez v1, :cond_1

    .line 45
    .line 46
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 47
    .line 48
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getExemplarFilter()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-eqz p0, :cond_1

    .line 57
    .line 58
    return v0

    .line 59
    :cond_1
    return v2
.end method

.method public getClock()Lio/opentelemetry/sdk/common/Clock;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    return-object p0
.end method

.method public getExemplarFilter()Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 2
    .line 3
    return-object p0
.end method

.method public getResource()Lio/opentelemetry/sdk/resources/Resource;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStartEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->startEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const v1, 0xf4243

    .line 8
    .line 9
    .line 10
    xor-int/2addr v0, v1

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-wide v2, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->startEpochNanos:J

    .line 21
    .line 22
    const/16 v4, 0x20

    .line 23
    .line 24
    ushr-long v4, v2, v4

    .line 25
    .line 26
    xor-long/2addr v2, v4

    .line 27
    long-to-int v2, v2

    .line 28
    xor-int/2addr v0, v2

    .line 29
    mul-int/2addr v0, v1

    .line 30
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 31
    .line 32
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    xor-int/2addr p0, v0

    .line 37
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MeterProviderSharedState{clock="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->clock:Lio/opentelemetry/sdk/common/Clock;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", resource="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->resource:Lio/opentelemetry/sdk/resources/Resource;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", startEpochNanos="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->startEpochNanos:J

    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", exemplarFilter="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/AutoValue_MeterProviderSharedState;->exemplarFilter:Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, "}"

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

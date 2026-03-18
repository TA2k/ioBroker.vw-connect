.class final Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;
.super Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T::",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">",
        "Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData<",
        "TT;>;"
    }
.end annotation


# instance fields
.field private final aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

.field private final monotonic:Z

.field private final points:Ljava/util/Collection;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Collection<",
            "TT;>;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/util/Collection;ZLio/opentelemetry/sdk/metrics/data/AggregationTemporality;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "TT;>;Z",
            "Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->points:Ljava/util/Collection;

    .line 7
    .line 8
    iput-boolean p2, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->monotonic:Z

    .line 9
    .line 10
    if-eqz p3, :cond_0

    .line 11
    .line 12
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 16
    .line 17
    const-string p1, "Null aggregationTemporality"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    throw p0

    .line 23
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 24
    .line 25
    const-string p1, "Null points"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableSumData;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->points:Ljava/util/Collection;

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/Data;->getPoints()Ljava/util/Collection;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-interface {v1, v3}, Ljava/util/Collection;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->monotonic:Z

    .line 25
    .line 26
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/SumData;->isMonotonic()Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-ne v1, v3, :cond_1

    .line 31
    .line 32
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 33
    .line 34
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/SumData;->getAggregationTemporality()Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    return v0

    .line 45
    :cond_1
    return v2
.end method

.method public getAggregationTemporality()Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPoints()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->points:Ljava/util/Collection;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->points:Ljava/util/Collection;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/Collection;->hashCode()I

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
    iget-boolean v2, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->monotonic:Z

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    const/16 v2, 0x4cf

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/16 v2, 0x4d5

    .line 20
    .line 21
    :goto_0
    xor-int/2addr v0, v2

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    xor-int/2addr p0, v0

    .line 30
    return p0
.end method

.method public isMonotonic()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->monotonic:Z

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
    const-string v1, "ImmutableSumData{points="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->points:Ljava/util/Collection;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", monotonic="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-boolean v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->monotonic:Z

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", aggregationTemporality="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableSumData;->aggregationTemporality:Lio/opentelemetry/sdk/metrics/data/AggregationTemporality;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string p0, "}"

    .line 34
    .line 35
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0
.end method

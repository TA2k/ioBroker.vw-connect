.class public Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/LongPointData;


# instance fields
.field private attributes:Lio/opentelemetry/api/common/Attributes;

.field private epochNanos:J

.field private exemplars:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
            ">;"
        }
    .end annotation
.end field

.field private startEpochNanos:J

.field private value:J


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 11
    .line 12
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->exemplars:Ljava/util/List;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lio/opentelemetry/sdk/metrics/data/LongPointData;

    .line 12
    .line 13
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->value:J

    .line 14
    .line 15
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    .line 16
    .line 17
    .line 18
    move-result-wide v5

    .line 19
    cmp-long v1, v3, v5

    .line 20
    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->startEpochNanos:J

    .line 24
    .line 25
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    .line 26
    .line 27
    .line 28
    move-result-wide v5

    .line 29
    cmp-long v1, v3, v5

    .line 30
    .line 31
    if-nez v1, :cond_2

    .line 32
    .line 33
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->epochNanos:J

    .line 34
    .line 35
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    .line 36
    .line 37
    .line 38
    move-result-wide v5

    .line 39
    cmp-long v1, v3, v5

    .line 40
    .line 41
    if-nez v1, :cond_2

    .line 42
    .line 43
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 44
    .line 45
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    .line 46
    .line 47
    .line 48
    move-result-object v3

    .line 49
    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-eqz v1, :cond_2

    .line 54
    .line 55
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->exemplars:Ljava/util/List;

    .line 56
    .line 57
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getExemplars()Ljava/util/List;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    if-eqz p0, :cond_2

    .line 66
    .line 67
    return v0

    .line 68
    :cond_2
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->epochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getExemplars()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->exemplars:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public getStartEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->startEpochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getValue()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->value:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public hashCode()I
    .locals 7

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->startEpochNanos:J

    .line 2
    .line 3
    const/16 v2, 0x20

    .line 4
    .line 5
    ushr-long v3, v0, v2

    .line 6
    .line 7
    xor-long/2addr v0, v3

    .line 8
    long-to-int v0, v0

    .line 9
    const v1, 0xf4243

    .line 10
    .line 11
    .line 12
    xor-int/2addr v0, v1

    .line 13
    mul-int/2addr v0, v1

    .line 14
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->epochNanos:J

    .line 15
    .line 16
    ushr-long v5, v3, v2

    .line 17
    .line 18
    xor-long/2addr v3, v5

    .line 19
    long-to-int v3, v3

    .line 20
    xor-int/2addr v0, v3

    .line 21
    mul-int/2addr v0, v1

    .line 22
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 23
    .line 24
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    xor-int/2addr v0, v3

    .line 29
    mul-int/2addr v0, v1

    .line 30
    iget-wide v3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->value:J

    .line 31
    .line 32
    ushr-long v5, v3, v2

    .line 33
    .line 34
    xor-long v2, v5, v3

    .line 35
    .line 36
    long-to-int v2, v2

    .line 37
    xor-int/2addr v0, v2

    .line 38
    mul-int/2addr v0, v1

    .line 39
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->exemplars:Ljava/util/List;

    .line 40
    .line 41
    invoke-interface {p0}, Ljava/util/List;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    xor-int/2addr p0, v0

    .line 46
    return p0
.end method

.method public set(JJLio/opentelemetry/api/common/Attributes;J)V
    .locals 9

    .line 7
    sget-object v8, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    move-object v0, p0

    move-wide v1, p1

    move-wide v3, p3

    move-object v5, p5

    move-wide v6, p6

    invoke-virtual/range {v0 .. v8}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->set(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)V

    return-void
.end method

.method public set(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "J",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/LongExemplarData;",
            ">;)V"
        }
    .end annotation

    .line 8
    iput-wide p1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->startEpochNanos:J

    .line 9
    iput-wide p3, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->epochNanos:J

    .line 10
    iput-object p5, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 11
    iput-wide p6, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->value:J

    .line 12
    iput-object p8, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->exemplars:Ljava/util/List;

    return-void
.end method

.method public set(Lio/opentelemetry/sdk/metrics/data/LongPointData;)V
    .locals 9

    .line 1
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getStartEpochNanos()J

    move-result-wide v1

    .line 2
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getEpochNanos()J

    move-result-wide v3

    .line 3
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/PointData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

    move-result-object v5

    .line 4
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getValue()J

    move-result-wide v6

    .line 5
    invoke-interface {p1}, Lio/opentelemetry/sdk/metrics/data/LongPointData;->getExemplars()Ljava/util/List;

    move-result-object v8

    move-object v0, p0

    .line 6
    invoke-virtual/range {v0 .. v8}, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->set(JJLio/opentelemetry/api/common/Attributes;JLjava/util/List;)V

    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "MutableLongPointData{value="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->value:J

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", startEpochNanos="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->startEpochNanos:J

    .line 19
    .line 20
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", epochNanos="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-wide v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->epochNanos:J

    .line 29
    .line 30
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", attributes="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", exemplars="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/data/MutableLongPointData;->exemplars:Ljava/util/List;

    .line 49
    .line 50
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const/16 p0, 0x7d

    .line 54
    .line 55
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p0

    .line 62
    return-object p0
.end method

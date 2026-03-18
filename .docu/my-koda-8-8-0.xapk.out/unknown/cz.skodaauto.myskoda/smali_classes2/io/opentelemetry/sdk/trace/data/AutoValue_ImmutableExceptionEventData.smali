.class final Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;
.super Lio/opentelemetry/sdk/trace/data/ImmutableExceptionEventData;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final attributes:Lio/opentelemetry/api/common/Attributes;

.field private final epochNanos:J

.field private final exception:Ljava/lang/Throwable;

.field private final totalAttributeCount:I


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/common/Attributes;JILjava/lang/Throwable;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/data/ImmutableExceptionEventData;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 7
    .line 8
    iput-wide p2, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->epochNanos:J

    .line 9
    .line 10
    iput p4, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->totalAttributeCount:I

    .line 11
    .line 12
    if-eqz p5, :cond_0

    .line 13
    .line 14
    iput-object p5, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->exception:Ljava/lang/Throwable;

    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 18
    .line 19
    const-string p1, "Null exception"

    .line 20
    .line 21
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    throw p0

    .line 25
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 26
    .line 27
    const-string p1, "Null attributes"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
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
    instance-of v1, p1, Lio/opentelemetry/sdk/trace/data/ImmutableExceptionEventData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/trace/data/ImmutableExceptionEventData;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/EventData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

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
    iget-wide v3, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->epochNanos:J

    .line 25
    .line 26
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/EventData;->getEpochNanos()J

    .line 27
    .line 28
    .line 29
    move-result-wide v5

    .line 30
    cmp-long v1, v3, v5

    .line 31
    .line 32
    if-nez v1, :cond_1

    .line 33
    .line 34
    iget v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->totalAttributeCount:I

    .line 35
    .line 36
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/EventData;->getTotalAttributeCount()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-ne v1, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->exception:Ljava/lang/Throwable;

    .line 43
    .line 44
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/ExceptionEventData;->getException()Ljava/lang/Throwable;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    if-eqz p0, :cond_1

    .line 53
    .line 54
    return v0

    .line 55
    :cond_1
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEpochNanos()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->epochNanos:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getException()Ljava/lang/Throwable;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->exception:Ljava/lang/Throwable;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTotalAttributeCount()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->totalAttributeCount:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->attributes:Lio/opentelemetry/api/common/Attributes;

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
    iget-wide v2, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->epochNanos:J

    .line 13
    .line 14
    const/16 v4, 0x20

    .line 15
    .line 16
    ushr-long v4, v2, v4

    .line 17
    .line 18
    xor-long/2addr v2, v4

    .line 19
    long-to-int v2, v2

    .line 20
    xor-int/2addr v0, v2

    .line 21
    mul-int/2addr v0, v1

    .line 22
    iget v2, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->totalAttributeCount:I

    .line 23
    .line 24
    xor-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->exception:Ljava/lang/Throwable;

    .line 27
    .line 28
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    xor-int/2addr p0, v0

    .line 33
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ImmutableExceptionEventData{attributes="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", epochNanos="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-wide v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->epochNanos:J

    .line 19
    .line 20
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", totalAttributeCount="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->totalAttributeCount:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", exception="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;->exception:Ljava/lang/Throwable;

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

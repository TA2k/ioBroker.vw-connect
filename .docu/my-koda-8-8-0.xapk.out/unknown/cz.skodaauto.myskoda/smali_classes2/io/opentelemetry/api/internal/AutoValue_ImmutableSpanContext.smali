.class final Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;
.super Lio/opentelemetry/api/internal/ImmutableSpanContext;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final remote:Z

.field private final spanId:Ljava/lang/String;

.field private final traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

.field private final traceId:Ljava/lang/String;

.field private final traceState:Lio/opentelemetry/api/trace/TraceState;

.field private final valid:Z


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/TraceFlags;Lio/opentelemetry/api/trace/TraceState;ZZ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/api/internal/ImmutableSpanContext;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_3

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceId:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p2, :cond_2

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->spanId:Ljava/lang/String;

    .line 11
    .line 12
    if-eqz p3, :cond_1

    .line 13
    .line 14
    iput-object p3, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 15
    .line 16
    if-eqz p4, :cond_0

    .line 17
    .line 18
    iput-object p4, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceState:Lio/opentelemetry/api/trace/TraceState;

    .line 19
    .line 20
    iput-boolean p5, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->remote:Z

    .line 21
    .line 22
    iput-boolean p6, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->valid:Z

    .line 23
    .line 24
    return-void

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 26
    .line 27
    const-string p1, "Null traceState"

    .line 28
    .line 29
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 34
    .line 35
    const-string p1, "Null traceFlags"

    .line 36
    .line 37
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    throw p0

    .line 41
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 42
    .line 43
    const-string p1, "Null spanId"

    .line 44
    .line 45
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 50
    .line 51
    const-string p1, "Null traceId"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
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
    instance-of v1, p1, Lio/opentelemetry/api/internal/ImmutableSpanContext;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/api/internal/ImmutableSpanContext;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceId:Ljava/lang/String;

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->getTraceId()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    if-eqz v1, :cond_1

    .line 23
    .line 24
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->spanId:Ljava/lang/String;

    .line 25
    .line 26
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->getSpanId()Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    if-eqz v1, :cond_1

    .line 35
    .line 36
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 37
    .line 38
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    if-eqz v1, :cond_1

    .line 47
    .line 48
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceState:Lio/opentelemetry/api/trace/TraceState;

    .line 49
    .line 50
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->getTraceState()Lio/opentelemetry/api/trace/TraceState;

    .line 51
    .line 52
    .line 53
    move-result-object v3

    .line 54
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    iget-boolean v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->remote:Z

    .line 61
    .line 62
    invoke-interface {p1}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-ne v1, v3, :cond_1

    .line 67
    .line 68
    iget-boolean p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->valid:Z

    .line 69
    .line 70
    invoke-virtual {p1}, Lio/opentelemetry/api/internal/ImmutableSpanContext;->isValid()Z

    .line 71
    .line 72
    .line 73
    move-result p1

    .line 74
    if-ne p0, p1, :cond_1

    .line 75
    .line 76
    return v0

    .line 77
    :cond_1
    return v2
.end method

.method public getSpanId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->spanId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTraceFlags()Lio/opentelemetry/api/trace/TraceFlags;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTraceId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTraceState()Lio/opentelemetry/api/trace/TraceState;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceState:Lio/opentelemetry/api/trace/TraceState;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 5

    .line 1
    iget-object v0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceId:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget-object v2, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->spanId:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget-object v2, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 21
    .line 22
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    xor-int/2addr v0, v2

    .line 27
    mul-int/2addr v0, v1

    .line 28
    iget-object v2, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceState:Lio/opentelemetry/api/trace/TraceState;

    .line 29
    .line 30
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    xor-int/2addr v0, v2

    .line 35
    mul-int/2addr v0, v1

    .line 36
    iget-boolean v2, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->remote:Z

    .line 37
    .line 38
    const/16 v3, 0x4d5

    .line 39
    .line 40
    const/16 v4, 0x4cf

    .line 41
    .line 42
    if-eqz v2, :cond_0

    .line 43
    .line 44
    move v2, v4

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move v2, v3

    .line 47
    :goto_0
    xor-int/2addr v0, v2

    .line 48
    mul-int/2addr v0, v1

    .line 49
    iget-boolean p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->valid:Z

    .line 50
    .line 51
    if-eqz p0, :cond_1

    .line 52
    .line 53
    move v3, v4

    .line 54
    :cond_1
    xor-int p0, v0, v3

    .line 55
    .line 56
    return p0
.end method

.method public isRemote()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->remote:Z

    .line 2
    .line 3
    return p0
.end method

.method public isValid()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->valid:Z

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
    const-string v1, "ImmutableSpanContext{traceId="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceId:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", spanId="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->spanId:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", traceFlags="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceFlags:Lio/opentelemetry/api/trace/TraceFlags;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", traceState="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->traceState:Lio/opentelemetry/api/trace/TraceState;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", remote="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-boolean v1, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->remote:Z

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", valid="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-boolean p0, p0, Lio/opentelemetry/api/internal/AutoValue_ImmutableSpanContext;->valid:Z

    .line 59
    .line 60
    const-string v1, "}"

    .line 61
    .line 62
    invoke-static {v0, p0, v1}, Lf2/m0;->m(Ljava/lang/StringBuilder;ZLjava/lang/String;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method

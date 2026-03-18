.class final Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/samplers/Sampler;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# instance fields
.field private final localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

.field private final localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

.field private final remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

.field private final remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

.field private final root:Lio/opentelemetry/sdk/trace/samplers/Sampler;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;Lio/opentelemetry/sdk/trace/samplers/Sampler;)V
    .locals 0
    .param p2    # Lio/opentelemetry/sdk/trace/samplers/Sampler;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p3    # Lio/opentelemetry/sdk/trace/samplers/Sampler;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p4    # Lio/opentelemetry/sdk/trace/samplers/Sampler;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p5    # Lio/opentelemetry/sdk/trace/samplers/Sampler;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 5
    .line 6
    if-nez p2, :cond_0

    .line 7
    .line 8
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->alwaysOn()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    :cond_0
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 13
    .line 14
    if-nez p3, :cond_1

    .line 15
    .line 16
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->alwaysOff()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 17
    .line 18
    .line 19
    move-result-object p3

    .line 20
    :cond_1
    iput-object p3, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 21
    .line 22
    if-nez p4, :cond_2

    .line 23
    .line 24
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->alwaysOn()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 25
    .line 26
    .line 27
    move-result-object p4

    .line 28
    :cond_2
    iput-object p4, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 29
    .line 30
    if-nez p5, :cond_3

    .line 31
    .line 32
    invoke-static {}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->alwaysOff()Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 33
    .line 34
    .line 35
    move-result-object p5

    .line 36
    :cond_3
    iput-object p5, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 37
    .line 38
    return-void
.end method


# virtual methods
.method public equals(Ljava/lang/Object;)Z
    .locals 4
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;

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
    check-cast p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;

    .line 12
    .line 13
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 14
    .line 15
    iget-object v3, p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 24
    .line 25
    iget-object v3, p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 26
    .line 27
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 34
    .line 35
    iget-object v3, p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 36
    .line 37
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_2

    .line 42
    .line 43
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 44
    .line 45
    iget-object v3, p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 46
    .line 47
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_2

    .line 52
    .line 53
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 54
    .line 55
    iget-object p1, p1, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p0, :cond_2

    .line 62
    .line 63
    return v0

    .line 64
    :cond_2
    return v2
.end method

.method public getDescription()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    invoke-interface {v0}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->getDescription()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 8
    .line 9
    invoke-interface {v1}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->getDescription()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 14
    .line 15
    invoke-interface {v2}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->getDescription()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    iget-object v3, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 20
    .line 21
    invoke-interface {v3}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->getDescription()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 26
    .line 27
    invoke-interface {p0}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->getDescription()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    const-string v4, ",remoteParentSampled:"

    .line 32
    .line 33
    const-string v5, ",remoteParentNotSampled:"

    .line 34
    .line 35
    const-string v6, "ParentBased{root:"

    .line 36
    .line 37
    invoke-static {v6, v0, v4, v1, v5}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    const-string v1, ",localParentSampled:"

    .line 42
    .line 43
    const-string v4, ",localParentNotSampled:"

    .line 44
    .line 45
    invoke-static {v0, v2, v1, v3, v4}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    const-string v1, "}"

    .line 49
    .line 50
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    return-object p0
.end method

.method public hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v1

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v1

    .line 33
    add-int/2addr v1, v0

    .line 34
    mul-int/lit8 v1, v1, 0x1f

    .line 35
    .line 36
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 37
    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    add-int/2addr p0, v1

    .line 43
    return p0
.end method

.method public shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/context/Context;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/trace/SpanKind;",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/trace/data/LinkData;",
            ">;)",
            "Lio/opentelemetry/sdk/trace/samplers/SamplingResult;"
        }
    .end annotation

    .line 1
    invoke-static {p1}, Lio/opentelemetry/api/trace/Span;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/trace/Span;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lio/opentelemetry/api/trace/Span;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isValid()Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->root:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 16
    .line 17
    invoke-interface/range {p0 .. p6}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0

    .line 22
    :cond_0
    move-object v1, p1

    .line 23
    move-object v2, p2

    .line 24
    move-object v3, p3

    .line 25
    move-object v4, p4

    .line 26
    move-object v5, p5

    .line 27
    move-object v6, p6

    .line 28
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isRemote()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_2

    .line 33
    .line 34
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isSampled()Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_1

    .line 39
    .line 40
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 41
    .line 42
    invoke-interface/range {v0 .. v6}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0

    .line 47
    :cond_1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->remoteParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 48
    .line 49
    invoke-interface/range {v0 .. v6}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_2
    invoke-interface {v0}, Lio/opentelemetry/api/trace/SpanContext;->isSampled()Z

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    if-eqz p1, :cond_3

    .line 59
    .line 60
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 61
    .line 62
    invoke-interface/range {v0 .. v6}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0

    .line 67
    :cond_3
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->localParentNotSampled:Lio/opentelemetry/sdk/trace/samplers/Sampler;

    .line 68
    .line 69
    invoke-interface/range {v0 .. v6}, Lio/opentelemetry/sdk/trace/samplers/Sampler;->shouldSample(Lio/opentelemetry/context/Context;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/trace/samplers/SamplingResult;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/trace/samplers/ParentBasedSampler;->getDescription()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

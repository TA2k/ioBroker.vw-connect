.class final Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;
.super Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final attributes:Lio/opentelemetry/api/common/Attributes;

.field private final spanContext:Lio/opentelemetry/api/trace/SpanContext;

.field private final totalAttributeCount:I


# direct methods
.method public constructor <init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/common/Attributes;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_1

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 7
    .line 8
    if-eqz p2, :cond_0

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 11
    .line 12
    iput p3, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->totalAttributeCount:I

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 16
    .line 17
    const-string p1, "Null attributes"

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
    const-string p1, "Null spanContext"

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
    instance-of v1, p1, Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/trace/data/ImmutableLinkData;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 13
    .line 14
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getSpanContext()Lio/opentelemetry/api/trace/SpanContext;

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
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 25
    .line 26
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getAttributes()Lio/opentelemetry/api/common/Attributes;

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
    iget p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->totalAttributeCount:I

    .line 37
    .line 38
    invoke-interface {p1}, Lio/opentelemetry/sdk/trace/data/LinkData;->getTotalAttributeCount()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    if-ne p0, p1, :cond_1

    .line 43
    .line 44
    return v0

    .line 45
    :cond_1
    return v2
.end method

.method public getAttributes()Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSpanContext()Lio/opentelemetry/api/trace/SpanContext;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTotalAttributeCount()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->totalAttributeCount:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

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
    iget-object v2, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->attributes:Lio/opentelemetry/api/common/Attributes;

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
    iget p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->totalAttributeCount:I

    .line 21
    .line 22
    xor-int/2addr p0, v0

    .line 23
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ImmutableLinkData{spanContext="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->spanContext:Lio/opentelemetry/api/trace/SpanContext;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", attributes="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->attributes:Lio/opentelemetry/api/common/Attributes;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

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
    iget p0, p0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableLinkData;->totalAttributeCount:I

    .line 29
    .line 30
    const-string v1, "}"

    .line 31
    .line 32
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0
.end method

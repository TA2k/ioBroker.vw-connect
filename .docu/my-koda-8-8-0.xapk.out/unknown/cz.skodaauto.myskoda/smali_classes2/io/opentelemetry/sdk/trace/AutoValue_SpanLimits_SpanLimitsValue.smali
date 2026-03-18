.class final Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;
.super Lio/opentelemetry/sdk/trace/SpanLimits$SpanLimitsValue;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final maxAttributeValueLength:I

.field private final maxNumberOfAttributes:I

.field private final maxNumberOfAttributesPerEvent:I

.field private final maxNumberOfAttributesPerLink:I

.field private final maxNumberOfEvents:I

.field private final maxNumberOfLinks:I


# direct methods
.method public constructor <init>(IIIIII)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/trace/SpanLimits$SpanLimitsValue;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributes:I

    .line 5
    .line 6
    iput p2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfEvents:I

    .line 7
    .line 8
    iput p3, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfLinks:I

    .line 9
    .line 10
    iput p4, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerEvent:I

    .line 11
    .line 12
    iput p5, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerLink:I

    .line 13
    .line 14
    iput p6, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxAttributeValueLength:I

    .line 15
    .line 16
    return-void
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
    instance-of v1, p1, Lio/opentelemetry/sdk/trace/SpanLimits$SpanLimitsValue;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/trace/SpanLimits$SpanLimitsValue;

    .line 11
    .line 12
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributes:I

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributes()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-ne v1, v3, :cond_1

    .line 19
    .line 20
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfEvents:I

    .line 21
    .line 22
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfEvents()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ne v1, v3, :cond_1

    .line 27
    .line 28
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfLinks:I

    .line 29
    .line 30
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfLinks()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-ne v1, v3, :cond_1

    .line 35
    .line 36
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerEvent:I

    .line 37
    .line 38
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerEvent()I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    if-ne v1, v3, :cond_1

    .line 43
    .line 44
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerLink:I

    .line 45
    .line 46
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanLimits;->getMaxNumberOfAttributesPerLink()I

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-ne v1, v3, :cond_1

    .line 51
    .line 52
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxAttributeValueLength:I

    .line 53
    .line 54
    invoke-virtual {p1}, Lio/opentelemetry/sdk/trace/SpanLimits$SpanLimitsValue;->getMaxAttributeValueLength()I

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    if-ne p0, p1, :cond_1

    .line 59
    .line 60
    return v0

    .line 61
    :cond_1
    return v2
.end method

.method public getMaxAttributeValueLength()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxAttributeValueLength:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxNumberOfAttributes()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributes:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxNumberOfAttributesPerEvent()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerEvent:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxNumberOfAttributesPerLink()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerLink:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxNumberOfEvents()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfEvents:I

    .line 2
    .line 3
    return p0
.end method

.method public getMaxNumberOfLinks()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfLinks:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributes:I

    .line 2
    .line 3
    const v1, 0xf4243

    .line 4
    .line 5
    .line 6
    xor-int/2addr v0, v1

    .line 7
    mul-int/2addr v0, v1

    .line 8
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfEvents:I

    .line 9
    .line 10
    xor-int/2addr v0, v2

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfLinks:I

    .line 13
    .line 14
    xor-int/2addr v0, v2

    .line 15
    mul-int/2addr v0, v1

    .line 16
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerEvent:I

    .line 17
    .line 18
    xor-int/2addr v0, v2

    .line 19
    mul-int/2addr v0, v1

    .line 20
    iget v2, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerLink:I

    .line 21
    .line 22
    xor-int/2addr v0, v2

    .line 23
    mul-int/2addr v0, v1

    .line 24
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxAttributeValueLength:I

    .line 25
    .line 26
    xor-int/2addr p0, v0

    .line 27
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "SpanLimitsValue{maxNumberOfAttributes="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributes:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", maxNumberOfEvents="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfEvents:I

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", maxNumberOfLinks="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfLinks:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", maxNumberOfAttributesPerEvent="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerEvent:I

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", maxNumberOfAttributesPerLink="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget v1, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxNumberOfAttributesPerLink:I

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", maxAttributeValueLength="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget p0, p0, Lio/opentelemetry/sdk/trace/AutoValue_SpanLimits_SpanLimitsValue;->maxAttributeValueLength:I

    .line 59
    .line 60
    const-string v1, "}"

    .line 61
    .line 62
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    return-object p0
.end method

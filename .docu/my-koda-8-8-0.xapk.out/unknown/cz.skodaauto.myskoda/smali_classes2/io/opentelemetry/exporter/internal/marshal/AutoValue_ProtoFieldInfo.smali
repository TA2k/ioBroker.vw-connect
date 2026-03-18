.class final Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;
.super Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final fieldNumber:I

.field private final jsonName:Ljava/lang/String;

.field private final tag:I

.field private final tagSize:I


# direct methods
.method public constructor <init>(IIILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->fieldNumber:I

    .line 5
    .line 6
    iput p2, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tag:I

    .line 7
    .line 8
    iput p3, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tagSize:I

    .line 9
    .line 10
    if-eqz p4, :cond_0

    .line 11
    .line 12
    iput-object p4, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->jsonName:Ljava/lang/String;

    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 16
    .line 17
    const-string p1, "Null jsonName"

    .line 18
    .line 19
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
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
    instance-of v1, p1, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;

    .line 11
    .line 12
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->fieldNumber:I

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getFieldNumber()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    if-ne v1, v3, :cond_1

    .line 19
    .line 20
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tag:I

    .line 21
    .line 22
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTag()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    if-ne v1, v3, :cond_1

    .line 27
    .line 28
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tagSize:I

    .line 29
    .line 30
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getTagSize()I

    .line 31
    .line 32
    .line 33
    move-result v3

    .line 34
    if-ne v1, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->jsonName:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {p1}, Lio/opentelemetry/exporter/internal/marshal/ProtoFieldInfo;->getJsonName()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    if-eqz p0, :cond_1

    .line 47
    .line 48
    return v0

    .line 49
    :cond_1
    return v2
.end method

.method public getFieldNumber()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->fieldNumber:I

    .line 2
    .line 3
    return p0
.end method

.method public getJsonName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->jsonName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTag()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tag:I

    .line 2
    .line 3
    return p0
.end method

.method public getTagSize()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tagSize:I

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->fieldNumber:I

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
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tag:I

    .line 9
    .line 10
    xor-int/2addr v0, v2

    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget v2, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tagSize:I

    .line 13
    .line 14
    xor-int/2addr v0, v2

    .line 15
    mul-int/2addr v0, v1

    .line 16
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->jsonName:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result p0

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
    const-string v1, "ProtoFieldInfo{fieldNumber="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->fieldNumber:I

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", tag="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tag:I

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", tagSize="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget v1, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->tagSize:I

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", jsonName="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lio/opentelemetry/exporter/internal/marshal/AutoValue_ProtoFieldInfo;->jsonName:Ljava/lang/String;

    .line 39
    .line 40
    const-string v1, "}"

    .line 41
    .line 42
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    return-object p0
.end method

.class final Lio/opentelemetry/sdk/metrics/AutoValue_View;
.super Lio/opentelemetry/sdk/metrics/View;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

.field private final attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

.field private final cardinalityLimit:I

.field private final description:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final name:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/sdk/metrics/Aggregation;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;I)V
    .locals 0
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/View;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->name:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->description:Ljava/lang/String;

    .line 7
    .line 8
    if-eqz p3, :cond_1

    .line 9
    .line 10
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 11
    .line 12
    if-eqz p4, :cond_0

    .line 13
    .line 14
    iput-object p4, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 15
    .line 16
    iput p5, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->cardinalityLimit:I

    .line 17
    .line 18
    return-void

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 20
    .line 21
    const-string p1, "Null attributesProcessor"

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
    const-string p1, "Null aggregation"

    .line 30
    .line 31
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
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
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/View;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_3

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/View;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->name:Ljava/lang/String;

    .line 13
    .line 14
    if-nez v1, :cond_1

    .line 15
    .line 16
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getName()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    if-nez v1, :cond_3

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getName()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_3

    .line 32
    .line 33
    :goto_0
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->description:Ljava/lang/String;

    .line 34
    .line 35
    if-nez v1, :cond_2

    .line 36
    .line 37
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getDescription()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    if-nez v1, :cond_3

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_2
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getDescription()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-virtual {v1, v3}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    if-eqz v1, :cond_3

    .line 53
    .line 54
    :goto_1
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 55
    .line 56
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 57
    .line 58
    .line 59
    move-result-object v3

    .line 60
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-eqz v1, :cond_3

    .line 65
    .line 66
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 67
    .line 68
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 69
    .line 70
    .line 71
    move-result-object v3

    .line 72
    invoke-virtual {v1, v3}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-eqz v1, :cond_3

    .line 77
    .line 78
    iget p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->cardinalityLimit:I

    .line 79
    .line 80
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/View;->getCardinalityLimit()I

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    if-ne p0, p1, :cond_3

    .line 85
    .line 86
    return v0

    .line 87
    :cond_3
    return v2
.end method

.method public getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    return-object p0
.end method

.method public getAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCardinalityLimit()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->cardinalityLimit:I

    .line 2
    .line 3
    return p0
.end method

.method public getDescription()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->description:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getName()Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->name:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->name:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    move v0, v1

    .line 7
    goto :goto_0

    .line 8
    :cond_0
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    :goto_0
    const v2, 0xf4243

    .line 13
    .line 14
    .line 15
    xor-int/2addr v0, v2

    .line 16
    mul-int/2addr v0, v2

    .line 17
    iget-object v3, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->description:Ljava/lang/String;

    .line 18
    .line 19
    if-nez v3, :cond_1

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    :goto_1
    xor-int/2addr v0, v1

    .line 27
    mul-int/2addr v0, v2

    .line 28
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->aggregation:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 29
    .line 30
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    xor-int/2addr v0, v1

    .line 35
    mul-int/2addr v0, v2

    .line 36
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->attributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    xor-int/2addr v0, v1

    .line 43
    mul-int/2addr v0, v2

    .line 44
    iget p0, p0, Lio/opentelemetry/sdk/metrics/AutoValue_View;->cardinalityLimit:I

    .line 45
    .line 46
    xor-int/2addr p0, v0

    .line 47
    return p0
.end method

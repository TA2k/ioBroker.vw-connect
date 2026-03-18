.class final Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;
.super Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final cardinalityLimit:I

.field private final instrumentSelector:Lio/opentelemetry/sdk/metrics/InstrumentSelector;

.field private final view:Lio/opentelemetry/sdk/metrics/View;

.field private final viewAttributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

.field private final viewSourceInfo:Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/metrics/InstrumentSelector;Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;ILio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;-><init>()V

    .line 2
    .line 3
    .line 4
    if-eqz p1, :cond_3

    .line 5
    .line 6
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->instrumentSelector:Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 7
    .line 8
    if-eqz p2, :cond_2

    .line 9
    .line 10
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->view:Lio/opentelemetry/sdk/metrics/View;

    .line 11
    .line 12
    if-eqz p3, :cond_1

    .line 13
    .line 14
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewAttributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 15
    .line 16
    iput p4, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->cardinalityLimit:I

    .line 17
    .line 18
    if-eqz p5, :cond_0

    .line 19
    .line 20
    iput-object p5, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewSourceInfo:Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 24
    .line 25
    const-string p1, "Null viewSourceInfo"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0

    .line 31
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 32
    .line 33
    const-string p1, "Null viewAttributesProcessor"

    .line 34
    .line 35
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw p0

    .line 39
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 40
    .line 41
    const-string p1, "Null view"

    .line 42
    .line 43
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 48
    .line 49
    const-string p1, "Null instrumentSelector"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
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
    instance-of v1, p1, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-eqz v1, :cond_1

    .line 9
    .line 10
    check-cast p1, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;

    .line 11
    .line 12
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->instrumentSelector:Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 13
    .line 14
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getInstrumentSelector()Lio/opentelemetry/sdk/metrics/InstrumentSelector;

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
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->view:Lio/opentelemetry/sdk/metrics/View;

    .line 25
    .line 26
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

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
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewAttributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 37
    .line 38
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

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
    iget v1, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->cardinalityLimit:I

    .line 49
    .line 50
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getCardinalityLimit()I

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    if-ne v1, v3, :cond_1

    .line 55
    .line 56
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewSourceInfo:Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 57
    .line 58
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    if-eqz p0, :cond_1

    .line 67
    .line 68
    return v0

    .line 69
    :cond_1
    return v2
.end method

.method public getCardinalityLimit()I
    .locals 0

    .line 1
    iget p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->cardinalityLimit:I

    .line 2
    .line 3
    return p0
.end method

.method public getInstrumentSelector()Lio/opentelemetry/sdk/metrics/InstrumentSelector;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->instrumentSelector:Lio/opentelemetry/sdk/metrics/InstrumentSelector;

    .line 2
    .line 3
    return-object p0
.end method

.method public getView()Lio/opentelemetry/sdk/metrics/View;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->view:Lio/opentelemetry/sdk/metrics/View;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewAttributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewSourceInfo:Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->instrumentSelector:Lio/opentelemetry/sdk/metrics/InstrumentSelector;

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
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->view:Lio/opentelemetry/sdk/metrics/View;

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
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewAttributesProcessor:Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

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
    iget v2, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->cardinalityLimit:I

    .line 29
    .line 30
    xor-int/2addr v0, v2

    .line 31
    mul-int/2addr v0, v1

    .line 32
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AutoValue_RegisteredView;->viewSourceInfo:Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    xor-int/2addr p0, v0

    .line 39
    return p0
.end method

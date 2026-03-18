.class Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;
.super Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "AppendingAttributesProcessor"
.end annotation


# instance fields
.field private final additionalAttributes:Lio/opentelemetry/api/common/Attributes;


# direct methods
.method private constructor <init>(Lio/opentelemetry/api/common/Attributes;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;->additionalAttributes:Lio/opentelemetry/api/common/Attributes;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;-><init>(Lio/opentelemetry/api/common/Attributes;)V

    return-void
.end method


# virtual methods
.method public process(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;->additionalAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 2
    .line 3
    invoke-interface {p0}, Lio/opentelemetry/api/common/Attributes;->toBuilder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-interface {p0, p1}, Lio/opentelemetry/api/common/AttributesBuilder;->putAll(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "AppendingAttributesProcessor{additionalAttributes="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor$AppendingAttributesProcessor;->additionalAttributes:Lio/opentelemetry/api/common/Attributes;

    .line 9
    .line 10
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string p0, "}"

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public usesContext()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

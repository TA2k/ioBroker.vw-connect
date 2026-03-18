.class Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;
.super Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field static final NOOP:Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;->NOOP:Lio/opentelemetry/sdk/metrics/internal/view/NoopAttributesProcessor;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public process(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/common/Attributes;
    .locals 0

    .line 1
    return-object p1
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "NoopAttributesProcessor{}"

    .line 2
    .line 3
    return-object p0
.end method

.method public usesContext()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

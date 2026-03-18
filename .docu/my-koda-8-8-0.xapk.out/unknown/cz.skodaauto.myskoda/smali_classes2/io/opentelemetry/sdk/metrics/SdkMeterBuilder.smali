.class Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/metrics/MeterBuilder;


# instance fields
.field private final instrumentationScopeName:Ljava/lang/String;

.field private instrumentationScopeVersion:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/metrics/SdkMeter;",
            ">;"
        }
    .end annotation
.end field

.field private schemaUrl:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/metrics/SdkMeter;",
            ">;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->instrumentationScopeName:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public build()Lio/opentelemetry/api/metrics/Meter;
    .locals 4

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->instrumentationScopeName:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->instrumentationScopeVersion:Ljava/lang/String;

    .line 6
    .line 7
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->schemaUrl:Ljava/lang/String;

    .line 8
    .line 9
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    invoke-virtual {v0, v1, v2, p0, v3}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->get(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lio/opentelemetry/api/metrics/Meter;

    .line 18
    .line 19
    return-object p0
.end method

.method public setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->instrumentationScopeVersion:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/api/metrics/MeterBuilder;
    .locals 0

    .line 1
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterBuilder;->schemaUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

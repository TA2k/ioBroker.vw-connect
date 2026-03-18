.class final Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;


# static fields
.field static final INSTANCE:Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;


# instance fields
.field private final descriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, ""

    .line 5
    .line 6
    invoke-static {v0, v0, v0}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->create(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;->descriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public collect(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJ)Lio/opentelemetry/sdk/metrics/data/MetricData;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/aggregator/EmptyMetricData;->getInstance()Lio/opentelemetry/sdk/metrics/data/MetricData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public getMetricDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;->descriptor:Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 2
    .line 3
    return-object p0
.end method

.method public isEnabled()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public recordDouble(DLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    return-void
.end method

.method public recordLong(JLio/opentelemetry/api/common/Attributes;Lio/opentelemetry/context/Context;)V
    .locals 0

    .line 1
    return-void
.end method

.method public setEnabled(Z)V
    .locals 0

    .line 1
    return-void
.end method

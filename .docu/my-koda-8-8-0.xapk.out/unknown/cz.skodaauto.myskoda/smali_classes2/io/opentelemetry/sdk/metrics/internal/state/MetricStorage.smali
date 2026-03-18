.class public interface abstract Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CARDINALITY_OVERFLOW:Lio/opentelemetry/api/common/Attributes;

.field public static final DEFAULT_MAX_CARDINALITY:I = 0x7d0


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->builder()Lio/opentelemetry/api/common/AttributesBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const-string v1, "otel.metric.overflow"

    .line 6
    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-interface {v0, v1, v2}, Lio/opentelemetry/api/common/AttributesBuilder;->put(Ljava/lang/String;Z)Lio/opentelemetry/api/common/AttributesBuilder;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-interface {v0}, Lio/opentelemetry/api/common/AttributesBuilder;->build()Lio/opentelemetry/api/common/Attributes;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;->CARDINALITY_OVERFLOW:Lio/opentelemetry/api/common/Attributes;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public abstract collect(Lio/opentelemetry/sdk/resources/Resource;Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;JJ)Lio/opentelemetry/sdk/metrics/data/MetricData;
.end method

.method public abstract getMetricDescriptor()Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;
.end method

.method public abstract setEnabled(Z)V
.end method

.class public final synthetic Lio/opentelemetry/sdk/metrics/export/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;


# instance fields
.field public final synthetic d:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

.field public final synthetic e:Lio/opentelemetry/sdk/metrics/InstrumentType;

.field public final synthetic f:Lio/opentelemetry/sdk/metrics/Aggregation;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/InstrumentType;Lio/opentelemetry/sdk/metrics/Aggregation;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/export/c;->d:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/export/c;->e:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 7
    .line 8
    iput-object p3, p0, Lio/opentelemetry/sdk/metrics/export/c;->f:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final getDefaultAggregation(Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 2

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/export/c;->e:Lio/opentelemetry/sdk/metrics/InstrumentType;

    .line 2
    .line 3
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/export/c;->f:Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/export/c;->d:Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;

    .line 6
    .line 7
    invoke-static {p0, v0, v1, p1}, Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;->a(Lio/opentelemetry/sdk/metrics/export/DefaultAggregationSelector;Lio/opentelemetry/sdk/metrics/InstrumentType;Lio/opentelemetry/sdk/metrics/Aggregation;Lio/opentelemetry/sdk/metrics/InstrumentType;)Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

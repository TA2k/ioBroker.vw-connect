.class Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/export/CollectionRegistration;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/SdkMeterProvider;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "SdkCollectionRegistration"
.end annotation


# instance fields
.field private final metricProducers:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/export/MetricProducer;",
            ">;"
        }
    .end annotation
.end field

.field private final sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;


# direct methods
.method private constructor <init>(Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/export/MetricProducer;",
            ">;",
            "Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;",
            ")V"
        }
    .end annotation

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->metricProducers:Ljava/util/List;

    .line 4
    iput-object p2, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;Lio/opentelemetry/sdk/metrics/SdkMeterProvider$1;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;-><init>(Ljava/util/List;Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;)V

    return-void
.end method


# virtual methods
.method public collectAllMetrics()Ljava/util/Collection;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Lio/opentelemetry/sdk/metrics/data/MetricData;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->metricProducers:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->sharedState:Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;

    .line 13
    .line 14
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/internal/state/MeterProviderSharedState;->getResource()Lio/opentelemetry/sdk/resources/Resource;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    iget-object v1, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->metricProducers:Ljava/util/List;

    .line 19
    .line 20
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    const/4 v2, 0x1

    .line 25
    if-ne v1, v2, :cond_1

    .line 26
    .line 27
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->metricProducers:Ljava/util/List;

    .line 28
    .line 29
    const/4 v1, 0x0

    .line 30
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    check-cast p0, Lio/opentelemetry/sdk/metrics/export/MetricProducer;

    .line 35
    .line 36
    invoke-interface {p0, v0}, Lio/opentelemetry/sdk/metrics/export/MetricProducer;->produce(Lio/opentelemetry/sdk/resources/Resource;)Ljava/util/Collection;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_1
    new-instance v1, Ljava/util/ArrayList;

    .line 42
    .line 43
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 44
    .line 45
    .line 46
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/SdkMeterProvider$SdkCollectionRegistration;->metricProducers:Ljava/util/List;

    .line 47
    .line 48
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-eqz v2, :cond_2

    .line 57
    .line 58
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Lio/opentelemetry/sdk/metrics/export/MetricProducer;

    .line 63
    .line 64
    invoke-interface {v2, v0}, Lio/opentelemetry/sdk/metrics/export/MetricProducer;->produce(Lio/opentelemetry/sdk/resources/Resource;)Ljava/util/Collection;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 69
    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_2
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

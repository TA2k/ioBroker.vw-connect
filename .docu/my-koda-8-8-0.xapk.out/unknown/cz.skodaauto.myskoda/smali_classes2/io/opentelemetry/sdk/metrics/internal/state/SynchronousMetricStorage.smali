.class public interface abstract Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/internal/state/MetricStorage;
.implements Lio/opentelemetry/sdk/metrics/internal/state/WriteableMetricStorage;


# direct methods
.method public static create(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Z)Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;
    .locals 9
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T::",
            "Lio/opentelemetry/sdk/metrics/data/PointData;",
            ">(",
            "Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;",
            "Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;",
            "Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;",
            "Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;",
            "Z)",
            "Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;"
        }
    .end annotation

    .line 1
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getView()Lio/opentelemetry/sdk/metrics/View;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewSourceInfo()Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {v0, v1, p2}, Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;->create(Lio/opentelemetry/sdk/metrics/View;Lio/opentelemetry/sdk/metrics/internal/debug/SourceInfo;Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;)Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;

    .line 10
    .line 11
    .line 12
    move-result-object v4

    .line 13
    invoke-virtual {v0}, Lio/opentelemetry/sdk/metrics/View;->getAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;

    .line 18
    .line 19
    invoke-virtual {p0}, Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;->getReader()Lio/opentelemetry/sdk/metrics/export/MetricReader;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-interface {v1}, Lio/opentelemetry/sdk/metrics/export/MetricReader;->getMemoryMode()Lio/opentelemetry/sdk/common/export/MemoryMode;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-interface {v0, p2, p3, v1}, Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorFactory;->createAggregator(Lio/opentelemetry/sdk/metrics/internal/descriptor/InstrumentDescriptor;Lio/opentelemetry/sdk/metrics/internal/exemplar/ExemplarFilterInternal;Lio/opentelemetry/sdk/common/export/MemoryMode;)Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;->drop()Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;

    .line 32
    .line 33
    .line 34
    move-result-object p2

    .line 35
    if-ne p2, v5, :cond_0

    .line 36
    .line 37
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;->empty()Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    return-object p0

    .line 42
    :cond_0
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;

    .line 43
    .line 44
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getViewAttributesProcessor()Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;

    .line 45
    .line 46
    .line 47
    move-result-object v6

    .line 48
    invoke-virtual {p1}, Lio/opentelemetry/sdk/metrics/internal/view/RegisteredView;->getCardinalityLimit()I

    .line 49
    .line 50
    .line 51
    move-result v7

    .line 52
    move-object v3, p0

    .line 53
    move v8, p4

    .line 54
    invoke-direct/range {v2 .. v8}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;-><init>(Lio/opentelemetry/sdk/metrics/internal/export/RegisteredReader;Lio/opentelemetry/sdk/metrics/internal/descriptor/MetricDescriptor;Lio/opentelemetry/sdk/metrics/internal/aggregator/Aggregator;Lio/opentelemetry/sdk/metrics/internal/view/AttributesProcessor;IZ)V

    .line 55
    .line 56
    .line 57
    return-object v2
.end method

.method public static empty()Lio/opentelemetry/sdk/metrics/internal/state/SynchronousMetricStorage;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;->INSTANCE:Lio/opentelemetry/sdk/metrics/internal/state/EmptyMetricStorage;

    .line 2
    .line 3
    return-object v0
.end method

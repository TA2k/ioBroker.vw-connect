.class public interface abstract Lio/opentelemetry/sdk/metrics/Aggregation;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static base2ExponentialBucketHistogram()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->getDefault()Lio/opentelemetry/sdk/metrics/Aggregation;

    move-result-object v0

    return-object v0
.end method

.method public static base2ExponentialBucketHistogram(II)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 0

    .line 2
    invoke-static {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/view/Base2ExponentialHistogramAggregation;->create(II)Lio/opentelemetry/sdk/metrics/Aggregation;

    move-result-object p0

    return-object p0
.end method

.method public static defaultAggregation()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/DefaultAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static drop()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/DropAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static explicitBucketHistogram()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/ExplicitBucketHistogramAggregation;->getDefault()Lio/opentelemetry/sdk/metrics/Aggregation;

    move-result-object v0

    return-object v0
.end method

.method public static explicitBucketHistogram(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/Aggregation;"
        }
    .end annotation

    .line 2
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/view/ExplicitBucketHistogramAggregation;->create(Ljava/util/List;)Lio/opentelemetry/sdk/metrics/Aggregation;

    move-result-object p0

    return-object p0
.end method

.method public static lastValue()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/LastValueAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static sum()Lio/opentelemetry/sdk/metrics/Aggregation;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/sdk/metrics/internal/view/SumAggregation;->getInstance()Lio/opentelemetry/sdk/metrics/Aggregation;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

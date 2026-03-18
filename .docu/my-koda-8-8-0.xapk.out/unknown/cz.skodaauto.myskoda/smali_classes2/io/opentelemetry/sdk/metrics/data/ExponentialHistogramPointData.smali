.class public interface abstract Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/PointData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(IDJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(IDJZDZD",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            "JJ",
            "Lio/opentelemetry/api/common/Attributes;",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;"
        }
    .end annotation

    .line 1
    invoke-static/range {p0 .. p18}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramPointData;->create(IDJZDZDLio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;JJLio/opentelemetry/api/common/Attributes;Ljava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramPointData;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getCount()J
.end method

.method public abstract getExemplars()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lio/opentelemetry/sdk/metrics/data/DoubleExemplarData;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getMax()D
.end method

.method public abstract getMin()D
.end method

.method public abstract getNegativeBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
.end method

.method public abstract getPositiveBuckets()Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
.end method

.method public abstract getScale()I
.end method

.method public abstract getSum()D
.end method

.method public abstract getZeroCount()J
.end method

.method public abstract hasMax()Z
.end method

.method public abstract hasMin()Z
.end method

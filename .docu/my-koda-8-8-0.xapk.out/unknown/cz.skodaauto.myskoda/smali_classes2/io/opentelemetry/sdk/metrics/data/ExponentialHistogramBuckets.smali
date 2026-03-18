.class public interface abstract Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static create(IILjava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(II",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;)",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;"
        }
    .end annotation

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;->create(IILjava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method


# virtual methods
.method public abstract getBucketCounts()Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end method

.method public abstract getOffset()I
.end method

.method public abstract getScale()I
.end method

.method public abstract getTotalCount()J
.end method

.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/lang/Long;)J
    .locals 2

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/data/ImmutableExponentialHistogramBuckets;->lambda$create$0(Ljava/lang/Long;)J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static create(IILjava/util/List;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 6
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
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;

    .line 2
    .line 3
    invoke-interface {p2}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    new-instance v2, Lio/opentelemetry/sdk/metrics/internal/data/a;

    .line 8
    .line 9
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 10
    .line 11
    .line 12
    invoke-interface {v1, v2}, Ljava/util/stream/Stream;->mapToLong(Ljava/util/function/ToLongFunction;)Ljava/util/stream/LongStream;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-interface {v1}, Ljava/util/stream/LongStream;->sum()J

    .line 17
    .line 18
    .line 19
    move-result-wide v4

    .line 20
    move v1, p0

    .line 21
    move v2, p1

    .line 22
    move-object v3, p2

    .line 23
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_ImmutableExponentialHistogramBuckets;-><init>(IILjava/util/List;J)V

    .line 24
    .line 25
    .line 26
    return-object v0
.end method

.method private static synthetic lambda$create$0(Ljava/lang/Long;)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Long;->longValue()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

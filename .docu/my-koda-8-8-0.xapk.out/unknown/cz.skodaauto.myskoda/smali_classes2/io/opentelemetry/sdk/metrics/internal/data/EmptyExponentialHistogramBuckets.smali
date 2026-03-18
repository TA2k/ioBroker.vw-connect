.class public abstract Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;


# static fields
.field private static final ZERO_BUCKETS:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/Integer;",
            "Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;->ZERO_BUCKETS:Ljava/util/Map;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Ljava/lang/Integer;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;->lambda$get$0(Ljava/lang/Integer;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static get(I)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/sdk/metrics/internal/data/EmptyExponentialHistogramBuckets;->ZERO_BUCKETS:Ljava/util/Map;

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    new-instance v1, Lfx0/d;

    .line 8
    .line 9
    const/16 v2, 0x10

    .line 10
    .line 11
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 12
    .line 13
    .line 14
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;

    .line 19
    .line 20
    return-object p0
.end method

.method private static synthetic lambda$get$0(Ljava/lang/Integer;)Lio/opentelemetry/sdk/metrics/data/ExponentialHistogramBuckets;
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_EmptyExponentialHistogramBuckets;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 8
    .line 9
    const-wide/16 v4, 0x0

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/metrics/internal/data/AutoValue_EmptyExponentialHistogramBuckets;-><init>(IILjava/util/List;J)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

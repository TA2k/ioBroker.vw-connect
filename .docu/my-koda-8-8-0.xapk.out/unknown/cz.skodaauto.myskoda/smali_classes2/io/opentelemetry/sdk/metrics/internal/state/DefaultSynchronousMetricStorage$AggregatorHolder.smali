.class Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "AggregatorHolder"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T::",
        "Lio/opentelemetry/sdk/metrics/data/PointData;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final activeRecordingThreads:Ljava/util/concurrent/atomic/AtomicInteger;

.field private final aggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 2

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->activeRecordingThreads:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 5
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->aggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;-><init>()V

    return-void
.end method

.method private constructor <init>(Ljava/util/concurrent/ConcurrentHashMap;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Lio/opentelemetry/api/common/Attributes;",
            "Lio/opentelemetry/sdk/metrics/internal/aggregator/AggregatorHandle<",
            "TT;>;>;)V"
        }
    .end annotation

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    new-instance v0, Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>(I)V

    iput-object v0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->activeRecordingThreads:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 8
    iput-object p1, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->aggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/util/concurrent/ConcurrentHashMap;Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$1;)V
    .locals 0

    .line 2
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;-><init>(Ljava/util/concurrent/ConcurrentHashMap;)V

    return-void
.end method

.method public static synthetic access$100(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/ConcurrentHashMap;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->aggregatorHandles:Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    return-object p0
.end method

.method public static synthetic access$200(Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;)Ljava/util/concurrent/atomic/AtomicInteger;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/sdk/metrics/internal/state/DefaultSynchronousMetricStorage$AggregatorHolder;->activeRecordingThreads:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 2
    .line 3
    return-object p0
.end method

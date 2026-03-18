.class public final Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$EntryWeigherView;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SingletonEntryWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SingletonWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$ByteArrayWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$IterableWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$CollectionWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$ListWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SetWeigher;,
        Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$MapWeigher;
    }
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance p0, Ljava/lang/AssertionError;

    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 7
    .line 8
    .line 9
    throw p0
.end method

.method public static asEntryWeigher(Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;)Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/EntryWeigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "-TV;>;)",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/EntryWeigher<",
            "TK;TV;>;"
        }
    .end annotation

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers;->singleton()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-ne p0, v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers;->entrySingleton()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/EntryWeigher;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$EntryWeigherView;

    .line 13
    .line 14
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$EntryWeigherView;-><init>(Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;)V

    .line 15
    .line 16
    .line 17
    return-object v0
.end method

.method public static byteArray()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "[B>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$ByteArrayWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$ByteArrayWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static collection()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "-",
            "Ljava/util/Collection<",
            "TE;>;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$CollectionWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$CollectionWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static entrySingleton()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/EntryWeigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<K:",
            "Ljava/lang/Object;",
            "V:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/EntryWeigher<",
            "TK;TV;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SingletonEntryWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SingletonEntryWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static iterable()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "-",
            "Ljava/lang/Iterable<",
            "TE;>;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$IterableWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$IterableWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static list()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "-",
            "Ljava/util/List<",
            "TE;>;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$ListWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$ListWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static map()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<A:",
            "Ljava/lang/Object;",
            "B:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "-",
            "Ljava/util/Map<",
            "TA;TB;>;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$MapWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$MapWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static set()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<E:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "-",
            "Ljava/util/Set<",
            "TE;>;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SetWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SetWeigher;

    .line 2
    .line 3
    return-object v0
.end method

.method public static singleton()Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<V:",
            "Ljava/lang/Object;",
            ">()",
            "Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weigher<",
            "TV;>;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SingletonWeigher;->INSTANCE:Lio/opentelemetry/instrumentation/api/internal/cache/concurrentlinkedhashmap/Weighers$SingletonWeigher;

    .line 2
    .line 3
    return-object v0
.end method

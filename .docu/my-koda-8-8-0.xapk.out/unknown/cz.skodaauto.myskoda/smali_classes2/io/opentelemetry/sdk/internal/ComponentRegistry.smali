.class public final Lio/opentelemetry/sdk/internal/ComponentRegistry;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<V:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final allComponents:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "TV;>;"
        }
    .end annotation
.end field

.field private final componentByName:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "TV;>;"
        }
    .end annotation
.end field

.field private final componentByNameAndSchema:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "TV;>;>;"
        }
    .end annotation
.end field

.field private final componentByNameAndVersion:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "TV;>;>;"
        }
    .end annotation
.end field

.field private final componentByNameVersionAndSchema:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "TV;>;>;>;"
        }
    .end annotation
.end field

.field private final factory:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "TV;>;"
        }
    .end annotation
.end field

.field private final lock:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/util/function/Function;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            "TV;>;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByName:Ljava/util/Map;

    .line 10
    .line 11
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByNameAndVersion:Ljava/util/Map;

    .line 17
    .line 18
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 19
    .line 20
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByNameAndSchema:Ljava/util/Map;

    .line 24
    .line 25
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 26
    .line 27
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByNameVersionAndSchema:Ljava/util/Map;

    .line 31
    .line 32
    new-instance v0, Ljava/lang/Object;

    .line 33
    .line 34
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lock:Ljava/lang/Object;

    .line 38
    .line 39
    new-instance v0, Ljava/util/IdentityHashMap;

    .line 40
    .line 41
    invoke-direct {v0}, Ljava/util/IdentityHashMap;-><init>()V

    .line 42
    .line 43
    .line 44
    invoke-static {v0}, Ljava/util/Collections;->newSetFromMap(Ljava/util/Map;)Ljava/util/Set;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    iput-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->allComponents:Ljava/util/Set;

    .line 49
    .line 50
    iput-object p1, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->factory:Ljava/util/function/Function;

    .line 51
    .line 52
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3, p4}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$2(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$3(Ljava/lang/String;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private buildComponent(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;",
            ")TV;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->factory:Ljava/util/function/Function;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lock:Ljava/lang/Object;

    .line 8
    .line 9
    monitor-enter v0

    .line 10
    :try_start_0
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->allComponents:Ljava/util/Set;

    .line 11
    .line 12
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    monitor-exit v0

    .line 16
    return-object p1

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

.method public static synthetic c(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$5(Ljava/lang/String;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lio/opentelemetry/sdk/internal/ComponentRegistry;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$7(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p1, p2, p0, p3}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$4(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$1(Ljava/lang/String;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$0(Ljava/lang/String;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic h(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-direct {p1, p2, p0, p3}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lambda$get$6(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$get$0(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method private static synthetic lambda$get$1(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method private synthetic lambda$get$2(Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1, p2}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p1, p4}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p1, p3}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->build()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->buildComponent(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method private static synthetic lambda$get$3(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method private synthetic lambda$get$4(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1, p3}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p1, p2}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->build()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->buildComponent(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method private static synthetic lambda$get$5(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method private synthetic lambda$get$6(Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1, p3}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p1, p2}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->build()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->buildComponent(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method private synthetic lambda$get$7(Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-static {p2}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;->builder(Ljava/lang/String;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-virtual {p2, p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->setAttributes(Lio/opentelemetry/api/common/Attributes;)Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p1}, Lio/opentelemetry/sdk/common/InstrumentationScopeInfoBuilder;->build()Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-direct {p0, p1}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->buildComponent(Lio/opentelemetry/sdk/common/InstrumentationScopeInfo;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public get(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;
    .locals 3
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/Attributes;",
            ")TV;"
        }
    .end annotation

    .line 1
    if-eqz p2, :cond_0

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByNameVersionAndSchema:Ljava/util/Map;

    .line 6
    .line 7
    new-instance v1, Lio/opentelemetry/sdk/internal/b;

    .line 8
    .line 9
    const/4 v2, 0x2

    .line 10
    invoke-direct {v1, v2}, Lio/opentelemetry/sdk/internal/b;-><init>(I)V

    .line 11
    .line 12
    .line 13
    invoke-interface {v0, p1, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    check-cast v0, Ljava/util/Map;

    .line 18
    .line 19
    new-instance v1, Lio/opentelemetry/sdk/internal/b;

    .line 20
    .line 21
    const/4 v2, 0x3

    .line 22
    invoke-direct {v1, v2}, Lio/opentelemetry/sdk/internal/b;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-interface {v0, p2, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    check-cast v0, Ljava/util/Map;

    .line 30
    .line 31
    new-instance v1, Lio/opentelemetry/sdk/internal/c;

    .line 32
    .line 33
    invoke-direct {v1, p4, p0, p1, p2}, Lio/opentelemetry/sdk/internal/c;-><init>(Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    invoke-interface {v0, p3, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0

    .line 41
    :cond_0
    if-eqz p2, :cond_1

    .line 42
    .line 43
    iget-object p3, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByNameAndVersion:Ljava/util/Map;

    .line 44
    .line 45
    new-instance v0, Lio/opentelemetry/sdk/internal/b;

    .line 46
    .line 47
    const/4 v1, 0x4

    .line 48
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/b;-><init>(I)V

    .line 49
    .line 50
    .line 51
    invoke-interface {p3, p1, v0}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p3

    .line 55
    check-cast p3, Ljava/util/Map;

    .line 56
    .line 57
    new-instance v0, Lio/opentelemetry/sdk/internal/d;

    .line 58
    .line 59
    const/4 v1, 0x0

    .line 60
    invoke-direct {v0, p0, p1, p4, v1}, Lio/opentelemetry/sdk/internal/d;-><init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;I)V

    .line 61
    .line 62
    .line 63
    invoke-interface {p3, p2, v0}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :cond_1
    if-eqz p3, :cond_2

    .line 69
    .line 70
    iget-object p2, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByNameAndSchema:Ljava/util/Map;

    .line 71
    .line 72
    new-instance v0, Lio/opentelemetry/sdk/internal/b;

    .line 73
    .line 74
    const/4 v1, 0x5

    .line 75
    invoke-direct {v0, v1}, Lio/opentelemetry/sdk/internal/b;-><init>(I)V

    .line 76
    .line 77
    .line 78
    invoke-interface {p2, p1, v0}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    check-cast p2, Ljava/util/Map;

    .line 83
    .line 84
    new-instance v0, Lio/opentelemetry/sdk/internal/d;

    .line 85
    .line 86
    const/4 v1, 0x1

    .line 87
    invoke-direct {v0, p0, p1, p4, v1}, Lio/opentelemetry/sdk/internal/d;-><init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;I)V

    .line 88
    .line 89
    .line 90
    invoke-interface {p2, p3, v0}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :cond_2
    iget-object p2, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->componentByName:Ljava/util/Map;

    .line 96
    .line 97
    new-instance p3, Lio/opentelemetry/context/b;

    .line 98
    .line 99
    const/4 v0, 0x1

    .line 100
    invoke-direct {p3, v0, p0, p4}, Lio/opentelemetry/context/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-interface {p2, p1, p3}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    return-object p0
.end method

.method public getComponents()Ljava/util/Collection;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "TV;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->lock:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    new-instance v1, Ljava/util/ArrayList;

    .line 5
    .line 6
    iget-object p0, p0, Lio/opentelemetry/sdk/internal/ComponentRegistry;->allComponents:Ljava/util/Set;

    .line 7
    .line 8
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 9
    .line 10
    .line 11
    invoke-static {v1}, Ljava/util/Collections;->unmodifiableCollection(Ljava/util/Collection;)Ljava/util/Collection;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    monitor-exit v0

    .line 16
    return-object p0

    .line 17
    :catchall_0
    move-exception p0

    .line 18
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    throw p0
.end method

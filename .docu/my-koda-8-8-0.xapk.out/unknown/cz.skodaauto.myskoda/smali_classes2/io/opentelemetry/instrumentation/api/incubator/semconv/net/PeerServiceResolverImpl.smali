.class Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolver;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;
    }
.end annotation


# static fields
.field private static final matcherComparator:Ljava/util/Comparator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Comparator<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final mapping:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {}, Ljava/util/Comparator;->naturalOrder()Ljava/util/Comparator;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-static {v1}, Ljava/util/Comparator;->nullsFirst(Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {v0, v1}, Ljava/util/Comparator;->comparing(Ljava/util/function/Function;Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v1, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/b;

    .line 20
    .line 21
    const/4 v2, 0x1

    .line 22
    invoke-direct {v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/b;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {}, Ljava/util/Comparator;->naturalOrder()Ljava/util/Comparator;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    invoke-static {v2}, Ljava/util/Comparator;->nullsFirst(Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    invoke-static {v1, v2}, Ljava/util/Comparator;->comparing(Ljava/util/function/Function;Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-interface {v0, v1}, Ljava/util/Comparator;->thenComparing(Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    invoke-static {v0}, Ljava/util/Comparator;->nullsFirst(Ljava/util/Comparator;)Ljava/util/Comparator;

    .line 42
    .line 43
    .line 44
    move-result-object v0

    .line 45
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->matcherComparator:Ljava/util/Comparator;

    .line 46
    .line 47
    return-void
.end method

.method public constructor <init>(Ljava/util/Map;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->mapping:Ljava/util/Map;

    .line 10
    .line 11
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/c;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/c;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p1, v0}, Ljava/util/Map;->forEach(Ljava/util/function/BiConsumer;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public static synthetic a(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->lambda$new$0(Ljava/lang/String;)Ljava/util/Map;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;Ljava/lang/String;Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->lambda$new$1(Ljava/lang/String;Ljava/lang/String;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Ljava/lang/Integer;Ljava/util/function/Supplier;Ljava/util/Map$Entry;)Z
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->lambda$resolveService$2(Ljava/lang/Integer;Ljava/util/function/Supplier;Ljava/util/Map$Entry;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic d(Ljava/util/Map$Entry;Ljava/util/Map$Entry;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->lambda$resolveService$3(Ljava/util/Map$Entry;Ljava/util/Map$Entry;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static synthetic lambda$new$0(Ljava/lang/String;)Ljava/util/Map;
    .locals 0

    .line 1
    new-instance p0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {p0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method private synthetic lambda$new$1(Ljava/lang/String;Ljava/lang/String;)V
    .locals 4

    .line 1
    const-string v0, "https://"

    .line 2
    .line 3
    invoke-static {v0, p1}, La7/g0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHost(Ljava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getPort(Ljava/lang/String;)Ljava/lang/Integer;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getPath(Ljava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->mapping:Ljava/util/Map;

    .line 20
    .line 21
    new-instance v2, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/b;

    .line 22
    .line 23
    const/4 v3, 0x2

    .line 24
    invoke-direct {v2, v3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/b;-><init>(I)V

    .line 25
    .line 26
    .line 27
    invoke-interface {p0, v0, v2}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Ljava/util/Map;

    .line 32
    .line 33
    invoke-static {v1, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->create(Ljava/lang/Integer;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    invoke-interface {p0, p1, p2}, Ljava/util/Map;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method private static synthetic lambda$resolveService$2(Ljava/lang/Integer;Ljava/util/function/Supplier;Ljava/util/Map$Entry;)Z
    .locals 0

    .line 1
    invoke-interface {p2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    check-cast p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;

    .line 6
    .line 7
    invoke-virtual {p2, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;->matches(Ljava/lang/Integer;Ljava/util/function/Supplier;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method private static synthetic lambda$resolveService$3(Ljava/util/Map$Entry;Ljava/util/Map$Entry;)I
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->matcherComparator:Ljava/util/Comparator;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;

    .line 8
    .line 9
    invoke-interface {p1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl$ServiceMatcher;

    .line 14
    .line 15
    invoke-interface {v0, p0, p1}, Ljava/util/Comparator;->compare(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method


# virtual methods
.method public isEmpty()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->mapping:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0}, Ljava/util/Map;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public resolveService(Ljava/lang/String;Ljava/lang/Integer;Ljava/util/function/Supplier;)Ljava/lang/String;
    .locals 1
    .param p2    # Ljava/lang/Integer;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            "Ljava/util/function/Supplier<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->mapping:Ljava/util/Map;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/util/Map;

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    return-object p1

    .line 13
    :cond_0
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-interface {p0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;

    .line 22
    .line 23
    invoke-direct {v0, p2, p3}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;-><init>(Ljava/lang/Integer;Ljava/util/function/Supplier;)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p0, v0}, Ljava/util/stream/Stream;->filter(Ljava/util/function/Predicate;)Ljava/util/stream/Stream;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    new-instance p2, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/e;

    .line 31
    .line 32
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0, p2}, Ljava/util/stream/Stream;->max(Ljava/util/Comparator;)Ljava/util/Optional;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    new-instance p2, Lfx0/d;

    .line 40
    .line 41
    const/4 p3, 0x5

    .line 42
    invoke-direct {p2, p3}, Lfx0/d;-><init>(I)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p0, p2}, Ljava/util/Optional;->map(Ljava/util/function/Function;)Ljava/util/Optional;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-virtual {p0, p1}, Ljava/util/Optional;->orElse(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ljava/lang/String;

    .line 54
    .line 55
    return-object p0
.end method

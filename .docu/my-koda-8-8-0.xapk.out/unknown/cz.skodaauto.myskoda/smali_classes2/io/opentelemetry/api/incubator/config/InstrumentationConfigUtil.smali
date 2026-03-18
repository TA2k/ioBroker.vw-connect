.class public Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$peerServiceMapping$0(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/util/LinkedHashMap;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$peerServiceMapping$1(Ljava/util/Map;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic c(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$httpServerResponseCapturedHeaders$5(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic d(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$httpServerRequestCapturedHeaders$4(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic e(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$httpClientResponseCapturedHeaders$3(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic f(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$javaInstrumentationConfig$6(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic g(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->lambda$httpClientRequestCapturedHeaders$2(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static getInstrumentationConfigModel(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/lang/String;Lcom/fasterxml/jackson/databind/ObjectMapper;Ljava/lang/Class;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            "Ljava/lang/String;",
            "Lcom/fasterxml/jackson/databind/ObjectMapper;",
            "Ljava/lang/Class<",
            "TT;>;)TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0, p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->javaInstrumentationConfig(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    invoke-static {p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->toMap(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/Map;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-virtual {p2, p0, p3}, Lcom/fasterxml/jackson/databind/ObjectMapper;->convertValue(Ljava/lang/Object;Ljava/lang/Class;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public static varargs getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            "Ljava/util/function/Function<",
            "Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;",
            "TT;>;[",
            "Ljava/lang/String;",
            ")TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/incubator/config/ConfigProvider;->getInstrumentationConfig()Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    array-length v0, p2

    .line 9
    const/4 v1, 0x0

    .line 10
    :goto_0
    if-ge v1, v0, :cond_2

    .line 11
    .line 12
    aget-object v2, p2, v1

    .line 13
    .line 14
    invoke-interface {p0, v2}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getStructured(Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    if-nez p0, :cond_1

    .line 19
    .line 20
    :goto_1
    const/4 p0, 0x0

    .line 21
    return-object p0

    .line 22
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_2
    invoke-interface {p1, p0}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public static httpClientRequestCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/config/b;

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/config/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "http"

    .line 8
    .line 9
    const-string v2, "client"

    .line 10
    .line 11
    const-string v3, "general"

    .line 12
    .line 13
    filled-new-array {v3, v1, v2}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/util/List;

    .line 22
    .line 23
    return-object p0
.end method

.method public static httpClientResponseCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/config/b;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/config/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "http"

    .line 8
    .line 9
    const-string v2, "client"

    .line 10
    .line 11
    const-string v3, "general"

    .line 12
    .line 13
    filled-new-array {v3, v1, v2}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/util/List;

    .line 22
    .line 23
    return-object p0
.end method

.method public static httpServerRequestCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/config/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/config/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "http"

    .line 8
    .line 9
    const-string v2, "server"

    .line 10
    .line 11
    const-string v3, "general"

    .line 12
    .line 13
    filled-new-array {v3, v1, v2}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/util/List;

    .line 22
    .line 23
    return-object p0
.end method

.method public static httpServerResponseCapturedHeaders(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/List;
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            ")",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/config/b;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/config/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "http"

    .line 8
    .line 9
    const-string v2, "server"

    .line 10
    .line 11
    const-string v3, "general"

    .line 12
    .line 13
    filled-new-array {v3, v1, v2}, [Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/util/List;

    .line 22
    .line 23
    return-object p0
.end method

.method public static javaInstrumentationConfig(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 2
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    new-instance v0, Lfx0/e;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, p1, v1}, Lfx0/e;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    const-string p1, "java"

    .line 8
    .line 9
    filled-new-array {p1}, [Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    invoke-static {p0, v0, p1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 18
    .line 19
    return-object p0
.end method

.method private static synthetic lambda$httpClientRequestCapturedHeaders$2(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 2

    .line 1
    const-string v0, "request_captured_headers"

    .line 2
    .line 3
    const-class v1, Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getScalarList(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$httpClientResponseCapturedHeaders$3(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 2

    .line 1
    const-string v0, "response_captured_headers"

    .line 2
    .line 3
    const-class v1, Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getScalarList(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$httpServerRequestCapturedHeaders$4(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 2

    .line 1
    const-string v0, "request_captured_headers"

    .line 2
    .line 3
    const-class v1, Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getScalarList(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$httpServerResponseCapturedHeaders$5(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 2

    .line 1
    const-string v0, "response_captured_headers"

    .line 2
    .line 3
    const-class v1, Ljava/lang/String;

    .line 4
    .line 5
    invoke-interface {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getScalarList(Ljava/lang/String;Ljava/lang/Class;)Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method private static synthetic lambda$javaInstrumentationConfig$6(Ljava/lang/String;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;
    .locals 0

    .line 1
    invoke-interface {p1, p0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getStructured(Ljava/lang/String;)Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$peerServiceMapping$0(Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)Ljava/util/List;
    .locals 1

    .line 1
    const-string v0, "service_mapping"

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getStructuredList(Ljava/lang/String;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static synthetic lambda$peerServiceMapping$1(Ljava/util/Map;Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;)V
    .locals 2

    .line 1
    const-string v0, "peer"

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const-string v1, "service"

    .line 8
    .line 9
    invoke-interface {p1, v1}, Lio/opentelemetry/api/incubator/config/DeclarativeConfigProperties;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    invoke-interface {p0, v0, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void
.end method

.method public static peerServiceMapping(Lio/opentelemetry/api/incubator/config/ConfigProvider;)Ljava/util/Map;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/api/incubator/config/ConfigProvider;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/api/incubator/config/b;

    .line 2
    .line 3
    const/4 v1, 0x4

    .line 4
    invoke-direct {v0, v1}, Lio/opentelemetry/api/incubator/config/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    const-string v1, "general"

    .line 8
    .line 9
    const-string v2, "peer"

    .line 10
    .line 11
    filled-new-array {v1, v2}, [Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-static {p0, v0, v1}, Lio/opentelemetry/api/incubator/config/InstrumentationConfigUtil;->getOrNull(Lio/opentelemetry/api/incubator/config/ConfigProvider;Ljava/util/function/Function;[Ljava/lang/String;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/util/List;

    .line 20
    .line 21
    if-nez p0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 25
    .line 26
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 27
    .line 28
    .line 29
    new-instance v1, Lex0/a;

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    invoke-direct {v1, v0, v2}, Lex0/a;-><init>(Ljava/lang/Object;I)V

    .line 33
    .line 34
    .line 35
    invoke-interface {p0, v1}, Ljava/lang/Iterable;->forEach(Ljava/util/function/Consumer;)V

    .line 36
    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Map;->isEmpty()Z

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eqz p0, :cond_1

    .line 43
    .line 44
    :goto_0
    const/4 p0, 0x0

    .line 45
    return-object p0

    .line 46
    :cond_1
    return-object v0
.end method

.class public final Lio/opentelemetry/exporter/internal/compression/CompressorUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final compressorRegistry:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/compression/Compressor;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lio/opentelemetry/common/ComponentLoader;->forClassLoader(Ljava/lang/ClassLoader;)Lio/opentelemetry/common/ComponentLoader;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;->buildCompressorRegistry(Lio/opentelemetry/common/ComponentLoader;)Ljava/util/Map;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;->compressorRegistry:Ljava/util/Map;

    .line 16
    .line 17
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static buildCompressorRegistry(Lio/opentelemetry/common/ComponentLoader;)Ljava/util/Map;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/common/ComponentLoader;",
            ")",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/exporter/internal/compression/Compressor;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    const-class v1, Lio/opentelemetry/exporter/internal/compression/CompressorProvider;

    .line 7
    .line 8
    invoke-interface {p0, v1}, Lio/opentelemetry/common/ComponentLoader;->load(Ljava/lang/Class;)Ljava/lang/Iterable;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v1

    .line 26
    check-cast v1, Lio/opentelemetry/exporter/internal/compression/CompressorProvider;

    .line 27
    .line 28
    invoke-interface {v1}, Lio/opentelemetry/exporter/internal/compression/CompressorProvider;->getInstance()Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    invoke-interface {v1}, Lio/opentelemetry/exporter/internal/compression/Compressor;->getEncoding()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    invoke-static {}, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;->getInstance()Lio/opentelemetry/exporter/internal/compression/GzipCompressor;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-virtual {p0}, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;->getEncoding()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-static {}, Lio/opentelemetry/exporter/internal/compression/GzipCompressor;->getInstance()Lio/opentelemetry/exporter/internal/compression/GzipCompressor;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-virtual {v0, p0, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    return-object v0
.end method

.method public static validateAndResolveCompressor(Ljava/lang/String;)Lio/opentelemetry/exporter/internal/compression/Compressor;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    const/4 v0, 0x0

    .line 1
    invoke-static {p0, v0}, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;->validateAndResolveCompressor(Ljava/lang/String;Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/internal/compression/Compressor;

    move-result-object p0

    return-object p0
.end method

.method public static validateAndResolveCompressor(Ljava/lang/String;Lio/opentelemetry/common/ComponentLoader;)Lio/opentelemetry/exporter/internal/compression/Compressor;
    .locals 5
    .param p1    # Lio/opentelemetry/common/ComponentLoader;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    if-nez p1, :cond_0

    .line 2
    sget-object p1, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;->compressorRegistry:Ljava/util/Map;

    goto :goto_0

    :cond_0
    invoke-static {p1}, Lio/opentelemetry/exporter/internal/compression/CompressorUtil;->buildCompressorRegistry(Lio/opentelemetry/common/ComponentLoader;)Ljava/util/Map;

    move-result-object p1

    .line 3
    :goto_0
    invoke-interface {p1}, Ljava/util/Map;->keySet()Ljava/util/Set;

    move-result-object v0

    .line 4
    invoke-interface {p1, p0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lio/opentelemetry/exporter/internal/compression/Compressor;

    .line 5
    const-string v1, "none"

    .line 6
    invoke-virtual {v1, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_2

    if-eqz p1, :cond_1

    goto :goto_1

    :cond_1
    const/4 p0, 0x0

    goto :goto_2

    :cond_2
    :goto_1
    const/4 p0, 0x1

    :goto_2
    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unsupported compressionMethod. Compression method must be \"none\" or one of: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 7
    invoke-interface {v0}, Ljava/util/Collection;->stream()Ljava/util/stream/Stream;

    move-result-object v0

    const-string v2, "["

    const-string v3, "]"

    const-string v4, ","

    invoke-static {v4, v2, v3}, Ljava/util/stream/Collectors;->joining(Ljava/lang/CharSequence;Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Ljava/util/stream/Collector;

    move-result-object v2

    invoke-interface {v0, v2}, Ljava/util/stream/Stream;->collect(Ljava/util/stream/Collector;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/String;

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    .line 8
    invoke-static {p0, v0}, Lio/opentelemetry/api/internal/Utils;->checkArgument(ZLjava/lang/String;)V

    return-object p1
.end method

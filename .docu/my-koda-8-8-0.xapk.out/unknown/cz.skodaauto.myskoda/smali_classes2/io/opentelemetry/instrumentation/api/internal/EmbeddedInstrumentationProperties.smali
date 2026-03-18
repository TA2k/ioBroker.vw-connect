.class public final Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties$BootstrapProxy;
    }
.end annotation


# static fields
.field private static final DEFAULT_LOADER:Ljava/lang/ClassLoader;

.field private static volatile loader:Ljava/lang/ClassLoader;

.field private static final logger:Ljava/util/logging/Logger;

.field private static final versions:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-static {v1}, Ljava/util/logging/Logger;->getLogger(Ljava/lang/String;)Ljava/util/logging/Logger;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    sput-object v1, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->logger:Ljava/util/logging/Logger;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    if-nez v0, :cond_0

    .line 18
    .line 19
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties$BootstrapProxy;

    .line 20
    .line 21
    invoke-direct {v0}, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties$BootstrapProxy;-><init>()V

    .line 22
    .line 23
    .line 24
    :cond_0
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->DEFAULT_LOADER:Ljava/lang/ClassLoader;

    .line 25
    .line 26
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->loader:Ljava/lang/ClassLoader;

    .line 27
    .line 28
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 29
    .line 30
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->versions:Ljava/util/Map;

    .line 34
    .line 35
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

.method public static synthetic a(Ljava/lang/String;)Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->loadVersion(Ljava/lang/String;)Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static findVersion(Ljava/lang/String;)Ljava/lang/String;
    .locals 3
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->versions:Ljava/util/Map;

    .line 2
    .line 3
    new-instance v1, Lio/opentelemetry/instrumentation/api/internal/c;

    .line 4
    .line 5
    const/4 v2, 0x4

    .line 6
    invoke-direct {v1, v2}, Lio/opentelemetry/instrumentation/api/internal/c;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-interface {v0, p0, v1}, Ljava/util/Map;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Ljava/lang/String;

    .line 14
    .line 15
    return-object p0
.end method

.method private static loadVersion(Ljava/lang/String;)Ljava/lang/String;
    .locals 6
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const-string v0, "META-INF/io/opentelemetry/instrumentation/"

    .line 2
    .line 3
    const-string v1, ".properties"

    .line 4
    .line 5
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const/4 v0, 0x0

    .line 10
    :try_start_0
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->loader:Ljava/lang/ClassLoader;

    .line 11
    .line 12
    invoke-virtual {v1, p0}, Ljava/lang/ClassLoader;->getResourceAsStream(Ljava/lang/String;)Ljava/io/InputStream;

    .line 13
    .line 14
    .line 15
    move-result-object v1
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    :try_start_1
    sget-object v2, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->logger:Ljava/util/logging/Logger;

    .line 19
    .line 20
    sget-object v3, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 21
    .line 22
    const-string v4, "Did not find embedded instrumentation properties file {0}"

    .line 23
    .line 24
    invoke-virtual {v2, v3, v4, p0}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 25
    .line 26
    .line 27
    if-eqz v1, :cond_0

    .line 28
    .line 29
    :try_start_2
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 30
    .line 31
    .line 32
    return-object v0

    .line 33
    :catch_0
    move-exception v1

    .line 34
    goto :goto_2

    .line 35
    :cond_0
    return-object v0

    .line 36
    :catchall_0
    move-exception v2

    .line 37
    goto :goto_0

    .line 38
    :cond_1
    :try_start_3
    new-instance v2, Ljava/util/Properties;

    .line 39
    .line 40
    invoke-direct {v2}, Ljava/util/Properties;-><init>()V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v2, v1}, Ljava/util/Properties;->load(Ljava/io/InputStream;)V

    .line 44
    .line 45
    .line 46
    const-string v3, "version"

    .line 47
    .line 48
    invoke-virtual {v2, v3}, Ljava/util/Properties;->getProperty(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 52
    :try_start_4
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 53
    .line 54
    .line 55
    return-object v2

    .line 56
    :goto_0
    if-eqz v1, :cond_2

    .line 57
    .line 58
    :try_start_5
    invoke-virtual {v1}, Ljava/io/InputStream;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :catchall_1
    move-exception v1

    .line 63
    :try_start_6
    invoke-virtual {v2, v1}, Ljava/lang/Throwable;->addSuppressed(Ljava/lang/Throwable;)V

    .line 64
    .line 65
    .line 66
    :cond_2
    :goto_1
    throw v2
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0

    .line 67
    :goto_2
    sget-object v2, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->logger:Ljava/util/logging/Logger;

    .line 68
    .line 69
    sget-object v3, Ljava/util/logging/Level;->FINE:Ljava/util/logging/Level;

    .line 70
    .line 71
    new-instance v4, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v5, "Failed to load embedded instrumentation properties file "

    .line 74
    .line 75
    invoke-direct {v4, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-virtual {v2, v3, p0, v1}, Ljava/util/logging/Logger;->log(Ljava/util/logging/Level;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 86
    .line 87
    .line 88
    return-object v0
.end method

.method public static setPropertiesLoader(Ljava/lang/ClassLoader;)V
    .locals 2

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->loader:Ljava/lang/ClassLoader;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->DEFAULT_LOADER:Ljava/lang/ClassLoader;

    .line 4
    .line 5
    if-eq v0, v1, :cond_0

    .line 6
    .line 7
    sget-object p0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->logger:Ljava/util/logging/Logger;

    .line 8
    .line 9
    const-string v0, "Embedded properties loader has already been set up, further setPropertiesLoader() calls are ignored"

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Ljava/util/logging/Logger;->warning(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    sput-object p0, Lio/opentelemetry/instrumentation/api/internal/EmbeddedInstrumentationProperties;->loader:Ljava/lang/ClassLoader;

    .line 16
    .line 17
    return-void
.end method

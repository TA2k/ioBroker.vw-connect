.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;
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

.method public static synthetic a(Ljava/lang/Character;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->lambda$getHostEndIndexExclusive$0(Ljava/lang/Character;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic b(Ljava/lang/Character;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->lambda$getPathEndIndexExclusive$2(Ljava/lang/Character;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static synthetic c(Ljava/lang/Character;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->lambda$getPortEndIndexExclusive$1(Ljava/lang/Character;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method private static getEndIndexExclusive(Ljava/lang/String;ILjava/util/function/Predicate;)I
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "I",
            "Ljava/util/function/Predicate<",
            "Ljava/lang/Character;",
            ">;)I"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    :goto_0
    if-ge p1, v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/lang/String;->charAt(I)C

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    invoke-interface {p2, v1}, Ljava/util/function/Predicate;->test(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_1
    :goto_1
    return p1
.end method

.method public static getHost(Ljava/lang/String;)Ljava/lang/String;
    .locals 3
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHostStartIndex(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, -0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    return-object v2

    .line 10
    :cond_0
    invoke-static {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHostEndIndexExclusive(Ljava/lang/String;I)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-ne v1, v0, :cond_1

    .line 15
    .line 16
    return-object v2

    .line 17
    :cond_1
    invoke-virtual {p0, v0, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    return-object p0
.end method

.method private static getHostEndIndexExclusive(Ljava/lang/String;I)I
    .locals 2

    .line 1
    new-instance v0, Lgx0/a;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lgx0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getEndIndexExclusive(Ljava/lang/String;ILjava/util/function/Predicate;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method private static getHostStartIndex(Ljava/lang/String;)I
    .locals 5

    .line 1
    const/16 v0, 0x3a

    .line 2
    .line 3
    invoke-virtual {p0, v0}, Ljava/lang/String;->indexOf(I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, -0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    return v1

    .line 11
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    add-int/lit8 v3, v0, 0x2

    .line 16
    .line 17
    if-le v2, v3, :cond_2

    .line 18
    .line 19
    add-int/lit8 v2, v0, 0x1

    .line 20
    .line 21
    invoke-virtual {p0, v2}, Ljava/lang/String;->charAt(I)C

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    const/16 v4, 0x2f

    .line 26
    .line 27
    if-ne v2, v4, :cond_2

    .line 28
    .line 29
    invoke-virtual {p0, v3}, Ljava/lang/String;->charAt(I)C

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    if-eq p0, v4, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    add-int/lit8 v0, v0, 0x3

    .line 37
    .line 38
    return v0

    .line 39
    :cond_2
    :goto_0
    return v1
.end method

.method public static getPath(Ljava/lang/String;)Ljava/lang/String;
    .locals 4
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHostStartIndex(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, -0x1

    .line 7
    if-ne v0, v2, :cond_0

    .line 8
    .line 9
    return-object v1

    .line 10
    :cond_0
    invoke-static {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHostEndIndexExclusive(Ljava/lang/String;I)I

    .line 11
    .line 12
    .line 13
    move-result v3

    .line 14
    if-ne v3, v0, :cond_1

    .line 15
    .line 16
    return-object v1

    .line 17
    :cond_1
    const/16 v0, 0x2f

    .line 18
    .line 19
    invoke-virtual {p0, v0, v3}, Ljava/lang/String;->indexOf(II)I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    if-ne v0, v2, :cond_2

    .line 24
    .line 25
    return-object v1

    .line 26
    :cond_2
    invoke-static {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getPathEndIndexExclusive(Ljava/lang/String;I)I

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    if-ne v2, v0, :cond_3

    .line 31
    .line 32
    return-object v1

    .line 33
    :cond_3
    invoke-virtual {p0, v0, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method private static getPathEndIndexExclusive(Ljava/lang/String;I)I
    .locals 2

    .line 1
    new-instance v0, Lgx0/a;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lgx0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getEndIndexExclusive(Ljava/lang/String;ILjava/util/function/Predicate;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method public static getPort(Ljava/lang/String;)Ljava/lang/Integer;
    .locals 4
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHostStartIndex(Ljava/lang/String;)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, -0x1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-ne v0, v1, :cond_0

    .line 8
    .line 9
    return-object v2

    .line 10
    :cond_0
    invoke-static {p0, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getHostEndIndexExclusive(Ljava/lang/String;I)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-ne v1, v0, :cond_1

    .line 15
    .line 16
    return-object v2

    .line 17
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-ge v1, v0, :cond_2

    .line 22
    .line 23
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    const/16 v3, 0x3a

    .line 28
    .line 29
    if-eq v0, v3, :cond_2

    .line 30
    .line 31
    return-object v2

    .line 32
    :cond_2
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    invoke-static {p0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getPortEndIndexExclusive(Ljava/lang/String;I)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-ne v0, v1, :cond_3

    .line 39
    .line 40
    return-object v2

    .line 41
    :cond_3
    invoke-virtual {p0, v1, v0}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->safeParse(Ljava/lang/String;)Ljava/lang/Integer;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    return-object p0
.end method

.method private static getPortEndIndexExclusive(Ljava/lang/String;I)I
    .locals 2

    .line 1
    new-instance v0, Lgx0/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lgx0/a;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-static {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/internal/UrlParser;->getEndIndexExclusive(Ljava/lang/String;ILjava/util/function/Predicate;)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

.method private static synthetic lambda$getHostEndIndexExclusive$0(Ljava/lang/Character;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x3a

    .line 6
    .line 7
    if-eq v0, v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/16 v1, 0x2f

    .line 14
    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    const/16 v1, 0x3f

    .line 22
    .line 23
    if-eq v0, v1, :cond_1

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    const/16 v0, 0x23

    .line 30
    .line 31
    if-ne p0, v0, :cond_0

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p0, 0x0

    .line 35
    return p0

    .line 36
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 37
    return p0
.end method

.method private static synthetic lambda$getPathEndIndexExclusive$2(Ljava/lang/Character;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x3f

    .line 6
    .line 7
    if-eq v0, v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    const/16 v0, 0x23

    .line 14
    .line 15
    if-ne p0, v0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method private static synthetic lambda$getPortEndIndexExclusive$1(Ljava/lang/Character;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x2f

    .line 6
    .line 7
    if-eq v0, v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    const/16 v1, 0x3f

    .line 14
    .line 15
    if-eq v0, v1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Character;->charValue()C

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    const/16 v0, 0x23

    .line 22
    .line 23
    if-ne p0, v0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 29
    return p0
.end method

.method private static safeParse(Ljava/lang/String;)Ljava/lang/Integer;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    :try_start_0
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(Ljava/lang/String;)Ljava/lang/Integer;

    .line 2
    .line 3
    .line 4
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 5
    return-object p0

    .line 6
    :catch_0
    const/4 p0, 0x0

    .line 7
    return-object p0
.end method

.class public final Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/propagation/TextMapPropagator;


# static fields
.field private static final FIELD:Ljava/lang/String; = "baggage"

.field private static final FIELDS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private static final INSTANCE:Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;

.field private static final URL_ESCAPER:Lio/opentelemetry/api/internal/PercentEscaper;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "baggage"

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->FIELDS:Ljava/util/List;

    .line 8
    .line 9
    new-instance v0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;

    .line 10
    .line 11
    invoke-direct {v0}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->INSTANCE:Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;

    .line 15
    .line 16
    invoke-static {}, Lio/opentelemetry/api/internal/PercentEscaper;->create()Lio/opentelemetry/api/internal/PercentEscaper;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->URL_ESCAPER:Lio/opentelemetry/api/internal/PercentEscaper;

    .line 21
    .line 22
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

.method public static synthetic a(Ljava/lang/StringBuilder;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->lambda$baggageToString$0(Ljava/lang/StringBuilder;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static baggageIsInvalid(Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)Z
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->isValidBaggageKey(Ljava/lang/String;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_1

    .line 6
    .line 7
    invoke-interface {p1}, Lio/opentelemetry/api/baggage/BaggageEntry;->getValue()Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {p0}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->isValidBaggageValue(Ljava/lang/String;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-nez p0, :cond_0

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

.method private static baggageToString(Lio/opentelemetry/api/baggage/Baggage;)Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lio/opentelemetry/api/baggage/propagation/a;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, v2, v0}, Lio/opentelemetry/api/baggage/propagation/a;-><init>(ILjava/lang/StringBuilder;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, v1}, Lio/opentelemetry/api/baggage/Baggage;->forEach(Ljava/util/function/BiConsumer;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    if-nez p0, :cond_0

    .line 20
    .line 21
    const-string p0, ""

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->length()I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/lit8 p0, p0, -0x1

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->setLength(I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method private static encodeValue(Ljava/lang/String;)Ljava/lang/String;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->URL_ESCAPER:Lio/opentelemetry/api/internal/PercentEscaper;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lio/opentelemetry/api/internal/PercentEscaper;->escape(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method private static extractEntries(Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageBuilder;)V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/propagation/Parser;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/api/baggage/propagation/Parser;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p1}, Lio/opentelemetry/api/baggage/propagation/Parser;->parseInto(Lio/opentelemetry/api/baggage/BaggageBuilder;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method private static extractMulti(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/context/Context;
    .locals 3
    .param p1    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<C:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "TC;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TC;>;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    const-string v0, "baggage"

    .line 2
    .line 3
    invoke-interface {p2, p1, v0}, Lio/opentelemetry/context/propagation/TextMapGetter;->getAll(Ljava/lang/Object;Ljava/lang/String;)Ljava/util/Iterator;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    invoke-static {}, Lio/opentelemetry/api/baggage/Baggage;->builder()Lio/opentelemetry/api/baggage/BaggageBuilder;

    .line 11
    .line 12
    .line 13
    move-result-object p2

    .line 14
    const/4 v0, 0x0

    .line 15
    :catch_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v1}, Ljava/lang/String;->isEmpty()Z

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    if-eqz v2, :cond_1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    :try_start_0
    invoke-static {v1, p2}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->extractEntries(Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageBuilder;)V
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    goto :goto_0

    .line 39
    :cond_2
    if-eqz v0, :cond_3

    .line 40
    .line 41
    invoke-interface {p2}, Lio/opentelemetry/api/baggage/BaggageBuilder;->build()Lio/opentelemetry/api/baggage/Baggage;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    invoke-interface {p0, p1}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ImplicitContextKeyed;)Lio/opentelemetry/context/Context;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :cond_3
    return-object p0
.end method

.method public static getInstance()Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->INSTANCE:Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;

    .line 2
    .line 3
    return-object v0
.end method

.method private static isValidBaggageKey(Ljava/lang/String;)Z
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0}, Ljava/lang/String;->isEmpty()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-static {p0}, Lio/opentelemetry/api/internal/StringUtils;->isPrintableString(Ljava/lang/String;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method private static isValidBaggageValue(Ljava/lang/String;)Z
    .locals 0

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    const/4 p0, 0x1

    .line 4
    return p0

    .line 5
    :cond_0
    const/4 p0, 0x0

    .line 6
    return p0
.end method

.method private static synthetic lambda$baggageToString$0(Ljava/lang/StringBuilder;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V
    .locals 1

    .line 1
    invoke-static {p1, p2}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->baggageIsInvalid(Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    const-string p1, "="

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 14
    .line 15
    .line 16
    invoke-interface {p2}, Lio/opentelemetry/api/baggage/BaggageEntry;->getValue()Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    invoke-static {p1}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->encodeValue(Ljava/lang/String;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-interface {p2}, Lio/opentelemetry/api/baggage/BaggageEntry;->getMetadata()Lio/opentelemetry/api/baggage/BaggageEntryMetadata;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-interface {p1}, Lio/opentelemetry/api/baggage/BaggageEntryMetadata;->getValue()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    if-eqz p1, :cond_1

    .line 36
    .line 37
    invoke-virtual {p1}, Ljava/lang/String;->isEmpty()Z

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    if-nez p2, :cond_1

    .line 42
    .line 43
    const-string p2, ";"

    .line 44
    .line 45
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-static {p1}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->encodeValue(Ljava/lang/String;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    :cond_1
    const-string p1, ","

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    return-void
.end method


# virtual methods
.method public extract(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/context/Context;
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<C:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "TC;",
            "Lio/opentelemetry/context/propagation/TextMapGetter<",
            "TC;>;)",
            "Lio/opentelemetry/context/Context;"
        }
    .end annotation

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Lio/opentelemetry/context/Context;->root()Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0

    .line 8
    :cond_0
    if-nez p3, :cond_1

    .line 9
    .line 10
    return-object p1

    .line 11
    :cond_1
    invoke-static {p1, p2, p3}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->extractMulti(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapGetter;)Lio/opentelemetry/context/Context;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public fields()Ljava/util/Collection;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object p0, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->FIELDS:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public inject(Lio/opentelemetry/context/Context;Ljava/lang/Object;Lio/opentelemetry/context/propagation/TextMapSetter;)V
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<C:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/context/Context;",
            "TC;",
            "Lio/opentelemetry/context/propagation/TextMapSetter<",
            "TC;>;)V"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    if-nez p3, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    invoke-static {p1}, Lio/opentelemetry/api/baggage/Baggage;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/baggage/Baggage;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0}, Lio/opentelemetry/api/baggage/Baggage;->isEmpty()Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    invoke-static {p0}, Lio/opentelemetry/api/baggage/propagation/W3CBaggagePropagator;->baggageToString(Lio/opentelemetry/api/baggage/Baggage;)Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p0}, Ljava/lang/String;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    if-nez p1, :cond_2

    .line 26
    .line 27
    const-string p1, "baggage"

    .line 28
    .line 29
    invoke-interface {p3, p2, p1, p0}, Lio/opentelemetry/context/propagation/TextMapSetter;->set(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    :cond_2
    :goto_0
    return-void
.end method

.method public toString()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "W3CBaggagePropagator"

    .line 2
    .line 3
    return-object p0
.end method

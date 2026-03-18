.class public interface abstract Lio/opentelemetry/api/baggage/Baggage;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/ImplicitContextKeyed;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# direct methods
.method public static synthetic b(Ljava/lang/String;[Lio/opentelemetry/api/baggage/BaggageEntry;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lio/opentelemetry/api/baggage/Baggage;->lambda$getEntry$0(Ljava/lang/String;[Lio/opentelemetry/api/baggage/BaggageEntry;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static builder()Lio/opentelemetry/api/baggage/BaggageBuilder;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/baggage/ImmutableBaggage;->builder()Lio/opentelemetry/api/baggage/BaggageBuilder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static current()Lio/opentelemetry/api/baggage/Baggage;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/context/Context;->current()Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {v0}, Lio/opentelemetry/api/baggage/Baggage;->fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/baggage/Baggage;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    return-object v0
.end method

.method public static empty()Lio/opentelemetry/api/baggage/Baggage;
    .locals 1

    .line 1
    invoke-static {}, Lio/opentelemetry/api/baggage/ImmutableBaggage;->empty()Lio/opentelemetry/api/baggage/Baggage;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    return-object v0
.end method

.method public static fromContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/baggage/Baggage;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/BaggageContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/api/baggage/Baggage;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    invoke-static {}, Lio/opentelemetry/api/baggage/Baggage;->empty()Lio/opentelemetry/api/baggage/Baggage;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public static fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/api/baggage/Baggage;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/BaggageContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/api/baggage/Baggage;

    .line 8
    .line 9
    return-object p0
.end method

.method private static synthetic lambda$getEntry$0(Ljava/lang/String;[Lio/opentelemetry/api/baggage/BaggageEntry;Ljava/lang/String;Lio/opentelemetry/api/baggage/BaggageEntry;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    aput-object p3, p1, p0

    .line 9
    .line 10
    :cond_0
    return-void
.end method


# virtual methods
.method public abstract asMap()Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/baggage/BaggageEntry;",
            ">;"
        }
    .end annotation
.end method

.method public abstract forEach(Ljava/util/function/BiConsumer;)V
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/function/BiConsumer<",
            "-",
            "Ljava/lang/String;",
            "-",
            "Lio/opentelemetry/api/baggage/BaggageEntry;",
            ">;)V"
        }
    .end annotation
.end method

.method public getEntry(Ljava/lang/String;)Lio/opentelemetry/api/baggage/BaggageEntry;
    .locals 3
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    filled-new-array {v0}, [Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    new-instance v1, Lio/opentelemetry/api/baggage/a;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    invoke-direct {v1, v2, p1, v0}, Lio/opentelemetry/api/baggage/a;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    invoke-interface {p0, v1}, Lio/opentelemetry/api/baggage/Baggage;->forEach(Ljava/util/function/BiConsumer;)V

    .line 13
    .line 14
    .line 15
    const/4 p0, 0x0

    .line 16
    aget-object p0, v0, p0

    .line 17
    .line 18
    return-object p0
.end method

.method public abstract getEntryValue(Ljava/lang/String;)Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public isEmpty()Z
    .locals 0

    .line 1
    invoke-interface {p0}, Lio/opentelemetry/api/baggage/Baggage;->size()I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public abstract size()I
.end method

.method public storeInContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/BaggageContextKey;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, v0, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public abstract toBuilder()Lio/opentelemetry/api/baggage/BaggageBuilder;
.end method

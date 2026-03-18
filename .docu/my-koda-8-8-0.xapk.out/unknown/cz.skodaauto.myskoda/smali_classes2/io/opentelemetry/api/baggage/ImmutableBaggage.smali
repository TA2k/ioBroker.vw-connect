.class final Lio/opentelemetry/api/baggage/ImmutableBaggage;
.super Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/baggage/Baggage;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lio/opentelemetry/api/internal/ImmutableKeyValuePairs<",
        "Ljava/lang/String;",
        "Lio/opentelemetry/api/baggage/BaggageEntry;",
        ">;",
        "Lio/opentelemetry/api/baggage/Baggage;"
    }
.end annotation

.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final EMPTY:Lio/opentelemetry/api/baggage/Baggage;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;->build()Lio/opentelemetry/api/baggage/Baggage;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    sput-object v0, Lio/opentelemetry/api/baggage/ImmutableBaggage;->EMPTY:Lio/opentelemetry/api/baggage/Baggage;

    .line 11
    .line 12
    return-void
.end method

.method private constructor <init>([Ljava/lang/Object;)V
    .locals 1

    .line 1
    invoke-static {}, Ljava/util/Comparator;->naturalOrder()Ljava/util/Comparator;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-direct {p0, p1, v0}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;-><init>([Ljava/lang/Object;Ljava/util/Comparator;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static synthetic access$000([Ljava/lang/Object;)Lio/opentelemetry/api/baggage/Baggage;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/api/baggage/ImmutableBaggage;->sortAndFilterToBaggage([Ljava/lang/Object;)Lio/opentelemetry/api/baggage/Baggage;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static builder()Lio/opentelemetry/api/baggage/BaggageBuilder;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;

    .line 2
    .line 3
    invoke-direct {v0}, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;-><init>()V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static empty()Lio/opentelemetry/api/baggage/Baggage;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/ImmutableBaggage;->EMPTY:Lio/opentelemetry/api/baggage/Baggage;

    .line 2
    .line 3
    return-object v0
.end method

.method private static sortAndFilterToBaggage([Ljava/lang/Object;)Lio/opentelemetry/api/baggage/Baggage;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/ImmutableBaggage;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lio/opentelemetry/api/baggage/ImmutableBaggage;-><init>([Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public getEntry(Ljava/lang/String;)Lio/opentelemetry/api/baggage/BaggageEntry;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 6
    .line 7
    return-object p0
.end method

.method public getEntryValue(Ljava/lang/String;)Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    check-cast p0, Lio/opentelemetry/api/baggage/BaggageEntry;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    invoke-interface {p0}, Lio/opentelemetry/api/baggage/BaggageEntry;->getValue()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return-object p0
.end method

.method public toBuilder()Lio/opentelemetry/api/baggage/BaggageBuilder;
    .locals 2

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;

    .line 2
    .line 3
    new-instance v1, Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {p0}, Lio/opentelemetry/api/internal/ImmutableKeyValuePairs;->data()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-direct {v1, p0}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 10
    .line 11
    .line 12
    invoke-direct {v0, v1}, Lio/opentelemetry/api/baggage/ImmutableBaggage$Builder;-><init>(Ljava/util/List;)V

    .line 13
    .line 14
    .line 15
    return-object v0
.end method

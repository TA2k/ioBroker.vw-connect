.class public final Lio/opentelemetry/semconv/AttributeKeyTemplate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# instance fields
.field private final keyBuilder:Ljava/util/function/Function;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/function/Function<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final keysCache:Ljava/util/concurrent/ConcurrentMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentMap<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;>;"
        }
    .end annotation
.end field

.field private final prefix:Ljava/lang/String;


# direct methods
.method private constructor <init>(Ljava/lang/String;Ljava/util/function/Function;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/function/Function<",
            "Ljava/lang/String;",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;>;)V"
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
    const/4 v1, 0x1

    .line 7
    invoke-direct {v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(I)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;->keysCache:Ljava/util/concurrent/ConcurrentMap;

    .line 11
    .line 12
    iput-object p1, p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;->prefix:Ljava/lang/String;

    .line 13
    .line 14
    iput-object p2, p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;->keyBuilder:Ljava/util/function/Function;

    .line 15
    .line 16
    return-void
.end method

.method public static synthetic a(Lio/opentelemetry/semconv/AttributeKeyTemplate;Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;->createAttributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static booleanArrayKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/util/List<",
            "Ljava/lang/Boolean;",
            ">;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x18

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static booleanKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/lang/Boolean;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x17

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method private createAttributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;->prefix:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "."

    .line 9
    .line 10
    invoke-static {v0, v1, v2, p1}, Lu/w;->h(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iget-object p0, p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;->keyBuilder:Ljava/util/function/Function;

    .line 15
    .line 16
    invoke-interface {p0, p1}, Ljava/util/function/Function;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    check-cast p0, Lio/opentelemetry/api/common/AttributeKey;

    .line 21
    .line 22
    return-object p0
.end method

.method public static doubleArrayKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/util/List<",
            "Ljava/lang/Double;",
            ">;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x1c

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static doubleKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/lang/Double;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x1b

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static longArrayKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/util/List<",
            "Ljava/lang/Long;",
            ">;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x19

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static longKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x1d

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static stringArrayKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Lfx0/d;

    .line 4
    .line 5
    const/16 v2, 0x1a

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lfx0/d;-><init>(I)V

    .line 8
    .line 9
    .line 10
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static stringKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 2
    .line 3
    new-instance v1, Ljx0/a;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v1, v2}, Ljx0/a;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, p0, v1}, Lio/opentelemetry/semconv/AttributeKeyTemplate;-><init>(Ljava/lang/String;Ljava/util/function/Function;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method


# virtual methods
.method public getAttributeKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lio/opentelemetry/semconv/AttributeKeyTemplate;->keysCache:Ljava/util/concurrent/ConcurrentMap;

    .line 2
    .line 3
    new-instance v1, Lfx0/e;

    .line 4
    .line 5
    const/4 v2, 0x6

    .line 6
    invoke-direct {v1, p0, v2}, Lfx0/e;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    invoke-interface {v0, p1, v1}, Ljava/util/concurrent/ConcurrentMap;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lio/opentelemetry/api/common/AttributeKey;

    .line 14
    .line 15
    return-object p0
.end method

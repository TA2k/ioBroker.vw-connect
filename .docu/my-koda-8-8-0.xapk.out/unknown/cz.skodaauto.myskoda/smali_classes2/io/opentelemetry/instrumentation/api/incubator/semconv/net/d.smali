.class public final synthetic Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Predicate;


# instance fields
.field public final synthetic a:Ljava/lang/Integer;

.field public final synthetic b:Ljava/util/function/Supplier;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Integer;Ljava/util/function/Supplier;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;->a:Ljava/lang/Integer;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;->b:Ljava/util/function/Supplier;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final test(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;->b:Ljava/util/function/Supplier;

    .line 2
    .line 3
    check-cast p1, Ljava/util/Map$Entry;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/d;->a:Ljava/lang/Integer;

    .line 6
    .line 7
    invoke-static {p0, v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/net/PeerServiceResolverImpl;->c(Ljava/lang/Integer;Ljava/util/function/Supplier;Ljava/util/Map$Entry;)Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0
.end method

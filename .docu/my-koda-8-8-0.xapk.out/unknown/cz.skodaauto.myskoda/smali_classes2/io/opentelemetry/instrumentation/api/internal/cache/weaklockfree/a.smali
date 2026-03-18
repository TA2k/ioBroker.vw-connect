.class public final synthetic Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/Function;


# instance fields
.field public final synthetic a:Ljava/util/function/Function;

.field public final synthetic b:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/util/function/Function;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/a;->a:Ljava/util/function/Function;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/a;->b:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/a;->b:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/AbstractWeakConcurrentMap$WeakKey;

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/a;->a:Ljava/util/function/Function;

    .line 6
    .line 7
    invoke-static {p0, v0, p1}, Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/AbstractWeakConcurrentMap;->c(Ljava/util/function/Function;Ljava/lang/Object;Lio/opentelemetry/instrumentation/api/internal/cache/weaklockfree/AbstractWeakConcurrentMap$WeakKey;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

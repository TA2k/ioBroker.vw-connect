.class final Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;
.super Lio/opentelemetry/instrumentation/api/util/VirtualField;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "CacheBasedVirtualField"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        "F:",
        "Ljava/lang/Object;",
        ">",
        "Lio/opentelemetry/instrumentation/api/util/VirtualField<",
        "TT;TF;>;"
    }
.end annotation


# instance fields
.field private final cache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/internal/cache/Cache<",
            "TT;TF;>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/util/VirtualField;-><init>()V

    .line 2
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->weak()Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;->cache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$1;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;-><init>()V

    return-void
.end method


# virtual methods
.method public get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)TF;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;->cache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public set(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;TF;)V"
        }
    .end annotation

    .line 1
    if-nez p2, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;->cache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->remove(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;->cache:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 10
    .line 11
    invoke-interface {p0, p1, p2}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->put(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

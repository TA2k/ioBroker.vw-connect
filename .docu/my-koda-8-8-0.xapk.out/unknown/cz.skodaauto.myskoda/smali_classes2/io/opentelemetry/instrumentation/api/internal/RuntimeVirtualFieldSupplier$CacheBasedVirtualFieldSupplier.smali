.class final Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "CacheBasedVirtualFieldSupplier"
.end annotation


# instance fields
.field private final ownerToFieldToImplementationMap:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/instrumentation/api/internal/cache/Cache<",
            "Ljava/lang/Class<",
            "*>;",
            "Lio/opentelemetry/instrumentation/api/internal/cache/Cache<",
            "Ljava/lang/Class<",
            "*>;",
            "Lio/opentelemetry/instrumentation/api/util/VirtualField<",
            "**>;>;>;"
        }
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->weak()Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    move-result-object v0

    iput-object v0, p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;->ownerToFieldToImplementationMap:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$1;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;-><init>()V

    return-void
.end method

.method public static synthetic a(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;->lambda$find$1(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic b(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/internal/cache/Cache;
    .locals 0

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;->lambda$find$0(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$find$0(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/internal/cache/Cache;
    .locals 0

    .line 1
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->weak()Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method private static synthetic lambda$find$1(Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;
    .locals 1

    .line 1
    new-instance p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, v0}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualField;-><init>(Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$1;)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method


# virtual methods
.method public find(Ljava/lang/Class;Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<U:TT;V:TF;T:",
            "Ljava/lang/Object;",
            "F:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/lang/Class<",
            "TT;>;",
            "Ljava/lang/Class<",
            "TF;>;)",
            "Lio/opentelemetry/instrumentation/api/util/VirtualField<",
            "TU;TV;>;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$CacheBasedVirtualFieldSupplier;->ownerToFieldToImplementationMap:Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 2
    .line 3
    new-instance v0, Lio/opentelemetry/instrumentation/api/internal/c;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, v1}, Lio/opentelemetry/instrumentation/api/internal/c;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-interface {p0, p1, v0}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    check-cast p0, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;

    .line 14
    .line 15
    new-instance p1, Lio/opentelemetry/instrumentation/api/internal/c;

    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    invoke-direct {p1, v0}, Lio/opentelemetry/instrumentation/api/internal/c;-><init>(I)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p0, p2, p1}, Lio/opentelemetry/instrumentation/api/internal/cache/Cache;->computeIfAbsent(Ljava/lang/Object;Ljava/util/function/Function;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    check-cast p0, Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 26
    .line 27
    return-object p0
.end method

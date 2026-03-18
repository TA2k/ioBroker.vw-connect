.class public abstract Lio/opentelemetry/instrumentation/api/util/VirtualField;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "<T:",
        "Ljava/lang/Object;",
        "F:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static find(Ljava/lang/Class;Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;
    .locals 1
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
    invoke-static {}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier;->get()Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/internal/RuntimeVirtualFieldSupplier$VirtualFieldSupplier;->find(Ljava/lang/Class;Ljava/lang/Class;)Lio/opentelemetry/instrumentation/api/util/VirtualField;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public abstract get(Ljava/lang/Object;)Ljava/lang/Object;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;)TF;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end method

.method public abstract set(Ljava/lang/Object;Ljava/lang/Object;)V
    .param p2    # Ljava/lang/Object;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TT;TF;)V"
        }
    .end annotation
.end method

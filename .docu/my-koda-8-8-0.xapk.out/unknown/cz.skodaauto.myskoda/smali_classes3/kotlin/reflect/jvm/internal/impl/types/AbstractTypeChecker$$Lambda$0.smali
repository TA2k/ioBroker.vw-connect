.class Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;
.super Ljava/lang/Object;

# interfaces
.implements Lay0/k;


# instance fields
.field private final arg$0:Ljava/util/Collection;

.field private final arg$1:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;

.field private final arg$2:Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

.field private final arg$3:Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;


# direct methods
.method public constructor <init>(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$0:Ljava/util/Collection;

    .line 5
    .line 6
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$1:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;

    .line 7
    .line 8
    iput-object p3, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$2:Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 9
    .line 10
    iput-object p4, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$3:Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$0:Ljava/util/Collection;

    .line 2
    .line 3
    iget-object v1, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$1:Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;

    .line 4
    .line 5
    iget-object v2, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$2:Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;

    .line 6
    .line 7
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker$$Lambda$0;->arg$3:Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;

    .line 8
    .line 9
    check-cast p1, Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$ForkPointContext;

    .line 10
    .line 11
    invoke-static {v0, v1, v2, p0, p1}, Lkotlin/reflect/jvm/internal/impl/types/AbstractTypeChecker;->accessor$AbstractTypeChecker$lambda0(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState;Lkotlin/reflect/jvm/internal/impl/types/model/TypeSystemContext;Lkotlin/reflect/jvm/internal/impl/types/model/RigidTypeMarker;Lkotlin/reflect/jvm/internal/impl/types/TypeCheckerState$ForkPointContext;)Llx0/b0;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

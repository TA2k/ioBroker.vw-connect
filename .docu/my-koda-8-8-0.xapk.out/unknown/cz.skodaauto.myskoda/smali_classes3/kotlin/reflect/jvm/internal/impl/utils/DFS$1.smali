.class final Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;
.super Lkotlin/reflect/jvm/internal/impl/utils/DFS$AbstractNodeHandler;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lkotlin/reflect/jvm/internal/impl/utils/DFS;->ifAny(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lay0/k;)Ljava/lang/Boolean;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/reflect/jvm/internal/impl/utils/DFS$AbstractNodeHandler<",
        "TN;",
        "Ljava/lang/Boolean;",
        ">;"
    }
.end annotation


# instance fields
.field final synthetic val$predicate:Lay0/k;

.field final synthetic val$result:[Z


# direct methods
.method public constructor <init>(Lay0/k;[Z)V
    .locals 0

    .line 1
    iput-object p1, p0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->val$predicate:Lay0/k;

    .line 2
    .line 3
    iput-object p2, p0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->val$result:[Z

    .line 4
    .line 5
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$AbstractNodeHandler;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public beforeChildren(Ljava/lang/Object;)Z
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(TN;)Z"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->val$predicate:Lay0/k;

    .line 2
    .line 3
    invoke-interface {v0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Ljava/lang/Boolean;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 10
    .line 11
    .line 12
    move-result p1

    .line 13
    const/4 v0, 0x1

    .line 14
    const/4 v1, 0x0

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    iget-object p1, p0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->val$result:[Z

    .line 18
    .line 19
    aput-boolean v0, p1, v1

    .line 20
    .line 21
    :cond_0
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->val$result:[Z

    .line 22
    .line 23
    aget-boolean p0, p0, v1

    .line 24
    .line 25
    xor-int/2addr p0, v0

    .line 26
    return p0
.end method

.method public result()Ljava/lang/Boolean;
    .locals 1

    .line 2
    iget-object p0, p0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->val$result:[Z

    const/4 v0, 0x0

    aget-boolean p0, p0, v0

    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p0

    return-object p0
.end method

.method public bridge synthetic result()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;->result()Ljava/lang/Boolean;

    move-result-object p0

    return-object p0
.end method

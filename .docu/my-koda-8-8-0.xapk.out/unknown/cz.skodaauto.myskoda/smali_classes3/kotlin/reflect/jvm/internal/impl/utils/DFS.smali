.class public Lkotlin/reflect/jvm/internal/impl/utils/DFS;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandlerWithListResult;,
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$CollectingNodeHandler;,
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$VisitedWithSet;,
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$AbstractNodeHandler;,
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;,
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;,
        Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;
    }
.end annotation


# direct methods
.method private static synthetic $$$reportNull$$$0(I)V
    .locals 3

    .line 1
    const/4 v0, 0x3

    .line 2
    new-array v0, v0, [Ljava/lang/Object;

    .line 3
    .line 4
    const/4 v1, 0x0

    .line 5
    packed-switch p0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    :pswitch_0
    const-string v2, "nodes"

    .line 9
    .line 10
    aput-object v2, v0, v1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :pswitch_1
    const-string v2, "current"

    .line 14
    .line 15
    aput-object v2, v0, v1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :pswitch_2
    const-string v2, "node"

    .line 19
    .line 20
    aput-object v2, v0, v1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :pswitch_3
    const-string v2, "predicate"

    .line 24
    .line 25
    aput-object v2, v0, v1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_4
    const-string v2, "handler"

    .line 29
    .line 30
    aput-object v2, v0, v1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :pswitch_5
    const-string v2, "visited"

    .line 34
    .line 35
    aput-object v2, v0, v1

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :pswitch_6
    const-string v2, "neighbors"

    .line 39
    .line 40
    aput-object v2, v0, v1

    .line 41
    .line 42
    :goto_0
    const/4 v1, 0x1

    .line 43
    const-string v2, "kotlin/reflect/jvm/internal/impl/utils/DFS"

    .line 44
    .line 45
    aput-object v2, v0, v1

    .line 46
    .line 47
    const/4 v1, 0x2

    .line 48
    packed-switch p0, :pswitch_data_1

    .line 49
    .line 50
    .line 51
    const-string p0, "dfs"

    .line 52
    .line 53
    aput-object p0, v0, v1

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :pswitch_7
    const-string p0, "doDfs"

    .line 57
    .line 58
    aput-object p0, v0, v1

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :pswitch_8
    const-string p0, "topologicalOrder"

    .line 62
    .line 63
    aput-object p0, v0, v1

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :pswitch_9
    const-string p0, "dfsFromNode"

    .line 67
    .line 68
    aput-object p0, v0, v1

    .line 69
    .line 70
    goto :goto_1

    .line 71
    :pswitch_a
    const-string p0, "ifAny"

    .line 72
    .line 73
    aput-object p0, v0, v1

    .line 74
    .line 75
    :goto_1
    const-string p0, "Argument for @NotNull parameter \'%s\' of %s.%s must not be null"

    .line 76
    .line 77
    invoke-static {p0, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 82
    .line 83
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 84
    .line 85
    .line 86
    throw v0

    .line 87
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_0
        :pswitch_6
        :pswitch_4
        :pswitch_0
        :pswitch_6
        :pswitch_3
        :pswitch_2
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_2
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_6
        :pswitch_5
        :pswitch_0
        :pswitch_6
        :pswitch_1
        :pswitch_6
        :pswitch_5
        :pswitch_4
    .end packed-switch

    .line 88
    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    .line 106
    .line 107
    .line 108
    .line 109
    .line 110
    .line 111
    .line 112
    .line 113
    .line 114
    .line 115
    .line 116
    .line 117
    .line 118
    .line 119
    .line 120
    .line 121
    .line 122
    .line 123
    .line 124
    .line 125
    .line 126
    .line 127
    :pswitch_data_1
    .packed-switch 0x7
        :pswitch_a
        :pswitch_a
        :pswitch_a
        :pswitch_9
        :pswitch_9
        :pswitch_9
        :pswitch_9
        :pswitch_9
        :pswitch_9
        :pswitch_9
        :pswitch_8
        :pswitch_8
        :pswitch_8
        :pswitch_8
        :pswitch_8
        :pswitch_7
        :pswitch_7
        :pswitch_7
        :pswitch_7
    .end packed-switch
.end method

.method public static dfs(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<N:",
            "Ljava/lang/Object;",
            "R:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Collection<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler<",
            "TN;TR;>;)TR;"
        }
    .end annotation

    if-nez p0, :cond_0

    const/4 v0, 0x4

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    :cond_0
    if-nez p1, :cond_1

    const/4 v0, 0x5

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    :cond_1
    if-nez p2, :cond_2

    const/4 v0, 0x6

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 4
    :cond_2
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/utils/DFS$VisitedWithSet;

    invoke-direct {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$VisitedWithSet;-><init>()V

    invoke-static {p0, p1, v0, p2}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->dfs(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static dfs(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)Ljava/lang/Object;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<N:",
            "Ljava/lang/Object;",
            "R:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Collection<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler<",
            "TN;TR;>;)TR;"
        }
    .end annotation

    if-nez p0, :cond_0

    const/4 v0, 0x0

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    :cond_0
    if-nez p1, :cond_1

    const/4 v0, 0x1

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    :cond_1
    if-nez p2, :cond_2

    const/4 v0, 0x2

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    :cond_2
    if-nez p3, :cond_3

    const/4 v0, 0x3

    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 1
    :cond_3
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_4

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    .line 2
    invoke-static {v0, p1, p2, p3}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->doDfs(Ljava/lang/Object;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)V

    goto :goto_0

    .line 3
    :cond_4
    invoke-interface {p3}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;->result()Ljava/lang/Object;

    move-result-object p0

    return-object p0
.end method

.method public static doDfs(Ljava/lang/Object;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)V
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<N:",
            "Ljava/lang/Object;",
            ">(TN;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler<",
            "TN;*>;)V"
        }
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/16 v0, 0x16

    .line 4
    .line 5
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 6
    .line 7
    .line 8
    :cond_0
    if-nez p1, :cond_1

    .line 9
    .line 10
    const/16 v0, 0x17

    .line 11
    .line 12
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 13
    .line 14
    .line 15
    :cond_1
    if-nez p2, :cond_2

    .line 16
    .line 17
    const/16 v0, 0x18

    .line 18
    .line 19
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 20
    .line 21
    .line 22
    :cond_2
    if-nez p3, :cond_3

    .line 23
    .line 24
    const/16 v0, 0x19

    .line 25
    .line 26
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 27
    .line 28
    .line 29
    :cond_3
    invoke-interface {p2, p0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;->checkAndMarkVisited(Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_4

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_4
    invoke-interface {p3, p0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;->beforeChildren(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    if-nez v0, :cond_5

    .line 41
    .line 42
    :goto_0
    return-void

    .line 43
    :cond_5
    invoke-interface {p1, p0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;->getNeighbors(Ljava/lang/Object;)Ljava/lang/Iterable;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    if-eqz v1, :cond_6

    .line 56
    .line 57
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-static {v1, p1, p2, p3}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->doDfs(Ljava/lang/Object;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Visited;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_6
    invoke-interface {p3, p0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;->afterChildren(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    return-void
.end method

.method public static ifAny(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lay0/k;)Ljava/lang/Boolean;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<N:",
            "Ljava/lang/Object;",
            ">(",
            "Ljava/util/Collection<",
            "TN;>;",
            "Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors<",
            "TN;>;",
            "Lay0/k;",
            ")",
            "Ljava/lang/Boolean;"
        }
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const/4 v0, 0x7

    .line 4
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 5
    .line 6
    .line 7
    :cond_0
    if-nez p1, :cond_1

    .line 8
    .line 9
    const/16 v0, 0x8

    .line 10
    .line 11
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 12
    .line 13
    .line 14
    :cond_1
    if-nez p2, :cond_2

    .line 15
    .line 16
    const/16 v0, 0x9

    .line 17
    .line 18
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->$$$reportNull$$$0(I)V

    .line 19
    .line 20
    .line 21
    :cond_2
    const/4 v0, 0x1

    .line 22
    new-array v0, v0, [Z

    .line 23
    .line 24
    new-instance v1, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;

    .line 25
    .line 26
    invoke-direct {v1, p2, v0}, Lkotlin/reflect/jvm/internal/impl/utils/DFS$1;-><init>(Lay0/k;[Z)V

    .line 27
    .line 28
    .line 29
    invoke-static {p0, p1, v1}, Lkotlin/reflect/jvm/internal/impl/utils/DFS;->dfs(Ljava/util/Collection;Lkotlin/reflect/jvm/internal/impl/utils/DFS$Neighbors;Lkotlin/reflect/jvm/internal/impl/utils/DFS$NodeHandler;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    check-cast p0, Ljava/lang/Boolean;

    .line 34
    .line 35
    return-object p0
.end method

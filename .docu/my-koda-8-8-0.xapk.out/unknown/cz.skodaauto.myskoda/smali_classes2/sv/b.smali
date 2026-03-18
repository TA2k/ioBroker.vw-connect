.class public final Lsv/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lca/m;


# direct methods
.method public constructor <init>(Lsv/d;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Lca/m;

    .line 5
    .line 6
    invoke-direct {v0}, Lca/m;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v1, Lc11/b;

    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    invoke-direct {v1, v2}, Lc11/b;-><init>(I)V

    .line 13
    .line 14
    .line 15
    new-instance v3, Lc11/b;

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    invoke-direct {v3, v4}, Lc11/b;-><init>(I)V

    .line 19
    .line 20
    .line 21
    iget-boolean p1, p1, Lsv/d;->a:Z

    .line 22
    .line 23
    if-eqz p1, :cond_0

    .line 24
    .line 25
    new-instance p1, La11/a;

    .line 26
    .line 27
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p1, 0x0

    .line 32
    :goto_0
    const/4 v5, 0x3

    .line 33
    new-array v5, v5, [Lz01/a;

    .line 34
    .line 35
    aput-object v1, v5, v4

    .line 36
    .line 37
    aput-object v3, v5, v2

    .line 38
    .line 39
    const/4 v1, 0x2

    .line 40
    aput-object p1, v5, v1

    .line 41
    .line 42
    invoke-static {v5}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    :cond_1
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_2

    .line 55
    .line 56
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    check-cast v1, Lz01/a;

    .line 61
    .line 62
    instance-of v2, v1, Lk11/a;

    .line 63
    .line 64
    if-eqz v2, :cond_1

    .line 65
    .line 66
    check-cast v1, Lk11/a;

    .line 67
    .line 68
    invoke-interface {v1, v0}, Lk11/a;->a(Lca/m;)V

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    new-instance p1, Lca/m;

    .line 73
    .line 74
    invoke-direct {p1, v0}, Lca/m;-><init>(Lca/m;)V

    .line 75
    .line 76
    .line 77
    iput-object p1, p0, Lsv/b;->a:Lca/m;

    .line 78
    .line 79
    return-void
.end method

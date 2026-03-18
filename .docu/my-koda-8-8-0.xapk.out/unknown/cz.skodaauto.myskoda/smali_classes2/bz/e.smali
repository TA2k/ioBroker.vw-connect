.class public final Lbz/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lzy/z;

.field public final j:Lzy/w;

.field public final k:Lij0/a;

.field public final l:Lzy/c;

.field public final m:Lzy/j;

.field public final n:Lzy/q;


# direct methods
.method public constructor <init>(Ltr0/b;Lzy/z;Lzy/w;Lij0/a;Lzy/c;Lzy/j;Lzy/q;)V
    .locals 3

    .line 1
    new-instance v0, Lbz/d;

    .line 2
    .line 3
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    invoke-direct {v0, v1, v1, v2}, Lbz/d;-><init>(Ljava/util/List;Ljava/util/List;Z)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, p0, Lbz/e;->h:Ltr0/b;

    .line 13
    .line 14
    iput-object p2, p0, Lbz/e;->i:Lzy/z;

    .line 15
    .line 16
    iput-object p3, p0, Lbz/e;->j:Lzy/w;

    .line 17
    .line 18
    iput-object p4, p0, Lbz/e;->k:Lij0/a;

    .line 19
    .line 20
    iput-object p5, p0, Lbz/e;->l:Lzy/c;

    .line 21
    .line 22
    iput-object p6, p0, Lbz/e;->m:Lzy/j;

    .line 23
    .line 24
    iput-object p7, p0, Lbz/e;->n:Lzy/q;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lbz/b;

    .line 31
    .line 32
    const/4 p3, 0x0

    .line 33
    const/4 p4, 0x0

    .line 34
    invoke-direct {p2, p0, p4, p3}, Lbz/b;-><init>(Lbz/e;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final h(Lbz/e;Lrx0/i;)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Lbz/d;

    .line 6
    .line 7
    iget-object v0, v0, Lbz/d;->a:Ljava/util/List;

    .line 8
    .line 9
    check-cast v0, Ljava/lang/Iterable;

    .line 10
    .line 11
    new-instance v1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v2

    .line 30
    move-object v3, v2

    .line 31
    check-cast v3, Lbz/c;

    .line 32
    .line 33
    iget-boolean v3, v3, Lbz/c;->d:Z

    .line 34
    .line 35
    if-eqz v3, :cond_0

    .line 36
    .line 37
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    new-instance v0, Ljava/util/ArrayList;

    .line 42
    .line 43
    const/16 v2, 0xa

    .line 44
    .line 45
    invoke-static {v1, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    if-eqz v2, :cond_2

    .line 61
    .line 62
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v2

    .line 66
    check-cast v2, Lbz/c;

    .line 67
    .line 68
    iget-object v2, v2, Lbz/c;->c:Laz/c;

    .line 69
    .line 70
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_2
    iget-object v1, p0, Lbz/e;->l:Lzy/c;

    .line 75
    .line 76
    new-instance v2, Lzy/a;

    .line 77
    .line 78
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    check-cast p0, Lbz/d;

    .line 83
    .line 84
    iget-object p0, p0, Lbz/d;->c:Ljava/util/List;

    .line 85
    .line 86
    invoke-direct {v2, v0, p0}, Lzy/a;-><init>(Ljava/util/ArrayList;Ljava/util/List;)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1, v2, p1}, Lzy/c;->b(Lzy/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 94
    .line 95
    if-ne p0, p1, :cond_3

    .line 96
    .line 97
    return-object p0

    .line 98
    :cond_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 99
    .line 100
    return-object p0
.end method

.class public final Lzc/k;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lxh/e;

.field public final e:Lxh/e;

.field public final f:Lz70/u;

.field public final g:Lth/b;

.field public final h:Lth/b;

.field public final i:Lth/b;

.field public final j:Lyp0/d;

.field public final k:Lyy0/l1;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/c2;

.field public final n:Llx0/q;

.field public o:Ltc/q;


# direct methods
.method public constructor <init>(Lxh/e;Lxh/e;Lz70/u;Lth/b;Lth/b;Lth/b;Lyp0/d;Lyy0/l1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzc/k;->d:Lxh/e;

    .line 5
    .line 6
    iput-object p2, p0, Lzc/k;->e:Lxh/e;

    .line 7
    .line 8
    iput-object p3, p0, Lzc/k;->f:Lz70/u;

    .line 9
    .line 10
    iput-object p4, p0, Lzc/k;->g:Lth/b;

    .line 11
    .line 12
    iput-object p5, p0, Lzc/k;->h:Lth/b;

    .line 13
    .line 14
    iput-object p6, p0, Lzc/k;->i:Lth/b;

    .line 15
    .line 16
    iput-object p7, p0, Lzc/k;->j:Lyp0/d;

    .line 17
    .line 18
    iput-object p8, p0, Lzc/k;->k:Lyy0/l1;

    .line 19
    .line 20
    new-instance p1, Llc/q;

    .line 21
    .line 22
    sget-object p2, Llc/a;->c:Llc/c;

    .line 23
    .line 24
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iput-object p1, p0, Lzc/k;->l:Lyy0/c2;

    .line 32
    .line 33
    iput-object p1, p0, Lzc/k;->m:Lyy0/c2;

    .line 34
    .line 35
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object p1, p0, Lzc/k;->n:Llx0/q;

    .line 40
    .line 41
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance p2, Lzc/i;

    .line 46
    .line 47
    const/4 p3, 0x0

    .line 48
    const/4 p4, 0x0

    .line 49
    invoke-direct {p2, p0, p4, p3}, Lzc/i;-><init>(Lzc/k;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    const/4 p0, 0x3

    .line 53
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public static final a(Lzc/k;Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lzc/k;->l:Lyy0/c2;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    invoke-static {p1, p0, v0}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static final b(Lzc/k;Ltc/q;)V
    .locals 4

    .line 1
    iput-object p1, p0, Lzc/k;->o:Ltc/q;

    .line 2
    .line 3
    iget-object v0, p1, Ltc/q;->e:Ljava/util/List;

    .line 4
    .line 5
    check-cast v0, Ljava/lang/Iterable;

    .line 6
    .line 7
    new-instance v1, Ljava/util/ArrayList;

    .line 8
    .line 9
    const/16 v2, 0xa

    .line 10
    .line 11
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-direct {v1, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 16
    .line 17
    .line 18
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    check-cast v2, Ltc/e;

    .line 33
    .line 34
    iget-object v3, p0, Lzc/k;->j:Lyp0/d;

    .line 35
    .line 36
    iget-object v2, v2, Ltc/e;->g:Ljava/lang/String;

    .line 37
    .line 38
    invoke-virtual {v3, v2}, Lyp0/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Lkc/e;

    .line 43
    .line 44
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    iget-object v0, p1, Ltc/q;->e:Ljava/util/List;

    .line 49
    .line 50
    check-cast v0, Ljava/util/Collection;

    .line 51
    .line 52
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    const/4 v2, 0x0

    .line 57
    if-nez v0, :cond_1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    move-object v1, v2

    .line 61
    :goto_1
    if-nez v1, :cond_2

    .line 62
    .line 63
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 64
    .line 65
    :cond_2
    iget-object p0, p0, Lzc/k;->l:Lyy0/c2;

    .line 66
    .line 67
    invoke-static {p1, v1}, Ljp/x0;->b(Ltc/q;Ljava/util/List;)Lzc/h;

    .line 68
    .line 69
    .line 70
    move-result-object p1

    .line 71
    new-instance v0, Llc/q;

    .line 72
    .line 73
    invoke-direct {v0, p1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 80
    .line 81
    .line 82
    return-void
.end method

.method public static final d(Lzc/k;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lzc/k;->l:Lyy0/c2;

    .line 2
    .line 3
    new-instance v1, Llc/q;

    .line 4
    .line 5
    sget-object v2, Llc/a;->c:Llc/c;

    .line 6
    .line 7
    invoke-direct {v1, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v0, v2, v1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lzc/i;

    .line 22
    .line 23
    const/4 v3, 0x1

    .line 24
    invoke-direct {v1, p0, v2, v3}, Lzc/i;-><init>(Lzc/k;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x3

    .line 28
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 29
    .line 30
    .line 31
    return-void
.end method

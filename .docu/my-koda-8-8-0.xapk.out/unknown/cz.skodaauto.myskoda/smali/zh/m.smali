.class public final Lzh/m;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lz70/u;

.field public final e:Lxh/e;

.field public final f:Lxh/e;

.field public final g:Lth/b;

.field public final h:Lth/b;

.field public final i:Lai/d;

.field public final j:I

.field public final k:Lai/d;

.field public final l:Lxh/e;

.field public final m:Lxh/e;

.field public final n:Lyy0/c2;

.field public final o:Lyy0/c2;

.field public final p:Llx0/q;

.field public final q:Lvy0/z1;

.field public final r:Lpw0/a;

.field public s:Ljava/util/List;

.field public final t:Ljava/util/ArrayList;

.field public final u:Lzh/k;


# direct methods
.method public constructor <init>(Lz70/u;Lxh/e;Lxh/e;Lth/b;Lth/b;Lai/d;Lai/d;Lxh/e;Lxh/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lzh/m;->d:Lz70/u;

    .line 5
    .line 6
    iput-object p2, p0, Lzh/m;->e:Lxh/e;

    .line 7
    .line 8
    iput-object p3, p0, Lzh/m;->f:Lxh/e;

    .line 9
    .line 10
    iput-object p4, p0, Lzh/m;->g:Lth/b;

    .line 11
    .line 12
    iput-object p5, p0, Lzh/m;->h:Lth/b;

    .line 13
    .line 14
    iput-object p6, p0, Lzh/m;->i:Lai/d;

    .line 15
    .line 16
    const p1, 0x7fffffff

    .line 17
    .line 18
    .line 19
    iput p1, p0, Lzh/m;->j:I

    .line 20
    .line 21
    iput-object p7, p0, Lzh/m;->k:Lai/d;

    .line 22
    .line 23
    iput-object p8, p0, Lzh/m;->l:Lxh/e;

    .line 24
    .line 25
    iput-object p9, p0, Lzh/m;->m:Lxh/e;

    .line 26
    .line 27
    new-instance p1, Llc/q;

    .line 28
    .line 29
    sget-object p2, Llc/a;->c:Llc/c;

    .line 30
    .line 31
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iput-object p1, p0, Lzh/m;->n:Lyy0/c2;

    .line 39
    .line 40
    iput-object p1, p0, Lzh/m;->o:Lyy0/c2;

    .line 41
    .line 42
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    iput-object p1, p0, Lzh/m;->p:Llx0/q;

    .line 47
    .line 48
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    iput-object p1, p0, Lzh/m;->q:Lvy0/z1;

    .line 53
    .line 54
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 55
    .line 56
    sget-object p2, Laz0/m;->a:Lwy0/c;

    .line 57
    .line 58
    invoke-virtual {p2, p1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iput-object p1, p0, Lzh/m;->r:Lpw0/a;

    .line 67
    .line 68
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 69
    .line 70
    iput-object p1, p0, Lzh/m;->s:Ljava/util/List;

    .line 71
    .line 72
    new-instance p1, Ljava/util/ArrayList;

    .line 73
    .line 74
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 75
    .line 76
    .line 77
    iput-object p1, p0, Lzh/m;->t:Ljava/util/ArrayList;

    .line 78
    .line 79
    new-instance p1, Lzh/k;

    .line 80
    .line 81
    const/4 p2, 0x0

    .line 82
    invoke-direct {p1, p0, p2}, Lzh/k;-><init>(Lzh/m;I)V

    .line 83
    .line 84
    .line 85
    iput-object p1, p0, Lzh/m;->u:Lzh/k;

    .line 86
    .line 87
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    new-instance p3, Lzh/l;

    .line 92
    .line 93
    const/4 p4, 0x0

    .line 94
    invoke-direct {p3, p0, p4, p2}, Lzh/l;-><init>(Lzh/m;Lkotlin/coroutines/Continuation;I)V

    .line 95
    .line 96
    .line 97
    const/4 p0, 0x3

    .line 98
    invoke-static {p1, p4, p4, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 99
    .line 100
    .line 101
    return-void
.end method

.method public static final a(Lzh/m;Ljava/util/List;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    iget-object p0, p0, Lzh/m;->f:Lxh/e;

    .line 11
    .line 12
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lxh/e;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iput-object p1, p0, Lzh/m;->s:Ljava/util/List;

    .line 19
    .line 20
    iget-object v0, p0, Lzh/m;->n:Lyy0/c2;

    .line 21
    .line 22
    iget-object p0, p0, Lzh/m;->k:Lai/d;

    .line 23
    .line 24
    invoke-static {p1, p0}, Landroidx/datastore/preferences/protobuf/o1;->g(Ljava/util/List;Lai/d;)Lzh/j;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    new-instance p1, Llc/q;

    .line 29
    .line 30
    invoke-direct {p1, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 34
    .line 35
    .line 36
    const/4 p0, 0x0

    .line 37
    invoke-virtual {v0, p0, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public static final b(Lzh/m;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lzh/m;->n:Lyy0/c2;

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
    iget-object v0, p0, Lzh/m;->p:Llx0/q;

    .line 18
    .line 19
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    check-cast v0, Lzb/k0;

    .line 24
    .line 25
    new-instance v1, Lws/b;

    .line 26
    .line 27
    const/16 v3, 0x14

    .line 28
    .line 29
    invoke-direct {v1, p0, v2, v3}, Lws/b;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x6

    .line 33
    const-string v3, "POLLING_TAG"

    .line 34
    .line 35
    invoke-static {v0, v3, v2, v1, p0}, Lzb/k0;->c(Lzb/k0;Ljava/lang/String;Lvy0/x;Lay0/n;I)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

.method public static final d(Lzh/m;Ljava/lang/String;Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lzh/m;->t:Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object v1, p0, Lzh/m;->s:Ljava/util/List;

    .line 4
    .line 5
    check-cast v1, Ljava/lang/Iterable;

    .line 6
    .line 7
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    :cond_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lzg/h;

    .line 22
    .line 23
    iget-object v3, v2, Lzg/h;->i:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    if-eqz v3, :cond_0

    .line 30
    .line 31
    iput-boolean p2, v2, Lzg/h;->v:Z

    .line 32
    .line 33
    if-eqz p2, :cond_1

    .line 34
    .line 35
    new-instance p2, Lgh/b;

    .line 36
    .line 37
    iget-object v1, p0, Lzh/m;->u:Lzh/k;

    .line 38
    .line 39
    invoke-direct {p2, p1, v1}, Lgh/b;-><init>(Ljava/lang/String;Lay0/a;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_1
    invoke-static {p1, v0}, Lkp/w8;->b(Ljava/lang/String;Ljava/util/ArrayList;)V

    .line 47
    .line 48
    .line 49
    :goto_0
    iget-object p1, p0, Lzh/m;->n:Lyy0/c2;

    .line 50
    .line 51
    iget-object p2, p0, Lzh/m;->s:Ljava/util/List;

    .line 52
    .line 53
    iget-object p0, p0, Lzh/m;->k:Lai/d;

    .line 54
    .line 55
    invoke-static {p2, p0}, Landroidx/datastore/preferences/protobuf/o1;->g(Ljava/util/List;Lai/d;)Lzh/j;

    .line 56
    .line 57
    .line 58
    move-result-object p0

    .line 59
    new-instance p2, Llc/q;

    .line 60
    .line 61
    invoke-direct {p2, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 65
    .line 66
    .line 67
    const/4 p0, 0x0

    .line 68
    invoke-virtual {p1, p0, p2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_2
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 73
    .line 74
    const-string p1, "Collection contains no element matching the predicate."

    .line 75
    .line 76
    invoke-direct {p0, p1}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0
.end method


# virtual methods
.method public final f()V
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    iget-object v1, p0, Lzh/m;->t:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const/4 v3, 0x0

    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Lgh/b;

    .line 24
    .line 25
    iget-object v2, v2, Lgh/b;->e:Lpw0/a;

    .line 26
    .line 27
    invoke-static {v2, v3}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 32
    .line 33
    .line 34
    iget-object v0, p0, Lzh/m;->q:Lvy0/z1;

    .line 35
    .line 36
    invoke-virtual {v0}, Lvy0/p1;->b()Lky0/j;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Lky0/m;

    .line 41
    .line 42
    iget-object v0, v0, Lky0/m;->b:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Lrx0/h;

    .line 45
    .line 46
    invoke-static {v0}, Llp/ke;->a(Lay0/n;)Lky0/k;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    :goto_1
    invoke-virtual {v0}, Lky0/k;->hasNext()Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-eqz v1, :cond_1

    .line 55
    .line 56
    invoke-virtual {v0}, Lky0/k;->next()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    check-cast v1, Lvy0/i1;

    .line 61
    .line 62
    invoke-interface {v1, v3}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 63
    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_1
    iget-object p0, p0, Lzh/m;->p:Llx0/q;

    .line 67
    .line 68
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    check-cast p0, Lzb/k0;

    .line 73
    .line 74
    const-string v0, "POLLING_TAG"

    .line 75
    .line 76
    invoke-static {p0, v0}, Lzb/k0;->a(Lzb/k0;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    return-void
.end method

.method public final g(Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lzh/m;->f()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget-object p0, p0, Lzh/m;->n:Lyy0/c2;

    .line 10
    .line 11
    invoke-static {p1, p0, v0}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.class public final Lhh/h;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lai/e;

.field public final e:Lxh/e;

.field public final f:Lzb/s0;

.field public final g:Lag/c;

.field public final h:Lag/c;

.field public final i:Lhh/c;

.field public final j:I

.field public final k:Lai/d;

.field public final l:Lyy0/c2;

.field public final m:Lyy0/l1;

.field public final n:Llx0/q;

.field public o:Lzg/h;

.field public p:Lgh/b;

.field public final q:Lvy0/z1;

.field public final r:Lpw0/a;


# direct methods
.method public constructor <init>(Lai/e;Lxh/e;Lzb/s0;Lag/c;Lag/c;Lhh/c;Lai/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhh/h;->d:Lai/e;

    .line 5
    .line 6
    iput-object p2, p0, Lhh/h;->e:Lxh/e;

    .line 7
    .line 8
    iput-object p3, p0, Lhh/h;->f:Lzb/s0;

    .line 9
    .line 10
    iput-object p4, p0, Lhh/h;->g:Lag/c;

    .line 11
    .line 12
    iput-object p5, p0, Lhh/h;->h:Lag/c;

    .line 13
    .line 14
    iput-object p6, p0, Lhh/h;->i:Lhh/c;

    .line 15
    .line 16
    const p1, 0x7fffffff

    .line 17
    .line 18
    .line 19
    iput p1, p0, Lhh/h;->j:I

    .line 20
    .line 21
    iput-object p7, p0, Lhh/h;->k:Lai/d;

    .line 22
    .line 23
    new-instance p1, Llc/q;

    .line 24
    .line 25
    sget-object p2, Llc/a;->c:Llc/c;

    .line 26
    .line 27
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    iput-object p1, p0, Lhh/h;->l:Lyy0/c2;

    .line 35
    .line 36
    new-instance p2, Lyy0/l1;

    .line 37
    .line 38
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 39
    .line 40
    .line 41
    iput-object p2, p0, Lhh/h;->m:Lyy0/l1;

    .line 42
    .line 43
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    iput-object p1, p0, Lhh/h;->n:Llx0/q;

    .line 48
    .line 49
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 50
    .line 51
    .line 52
    move-result-object p1

    .line 53
    iput-object p1, p0, Lhh/h;->q:Lvy0/z1;

    .line 54
    .line 55
    sget-object p2, Lvy0/p0;->a:Lcz0/e;

    .line 56
    .line 57
    sget-object p2, Laz0/m;->a:Lwy0/c;

    .line 58
    .line 59
    invoke-virtual {p2, p1}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    invoke-static {p1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    iput-object p1, p0, Lhh/h;->r:Lpw0/a;

    .line 68
    .line 69
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    new-instance p2, Lhh/g;

    .line 74
    .line 75
    const/4 p3, 0x0

    .line 76
    const/4 p4, 0x0

    .line 77
    invoke-direct {p2, p0, p4, p3}, Lhh/g;-><init>(Lhh/h;Lkotlin/coroutines/Continuation;I)V

    .line 78
    .line 79
    .line 80
    const/4 p0, 0x3

    .line 81
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 82
    .line 83
    .line 84
    return-void
.end method

.method public static final a(Lhh/h;Lzg/h;)V
    .locals 4

    .line 1
    iput-object p1, p0, Lhh/h;->o:Lzg/h;

    .line 2
    .line 3
    if-eqz p1, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lhh/h;->l:Lyy0/c2;

    .line 6
    .line 7
    :cond_0
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    move-object v2, v1

    .line 12
    check-cast v2, Llc/q;

    .line 13
    .line 14
    iget-object v2, p0, Lhh/h;->k:Lai/d;

    .line 15
    .line 16
    invoke-static {p1, v2}, Llp/w0;->f(Lzg/h;Lai/d;)Lhh/e;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    new-instance v3, Llc/q;

    .line 21
    .line 22
    invoke-direct {v3, v2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public static final b(Lhh/h;Z)V
    .locals 4

    .line 1
    iget-object v0, p0, Lhh/h;->o:Lzg/h;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-static {v0, p1}, Lzg/h;->a(Lzg/h;Z)Lzg/h;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    goto :goto_0

    .line 11
    :cond_0
    move-object v0, v1

    .line 12
    :goto_0
    iput-object v0, p0, Lhh/h;->o:Lzg/h;

    .line 13
    .line 14
    if-eqz v0, :cond_3

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    iget-object p1, v0, Lzg/h;->i:Ljava/lang/String;

    .line 19
    .line 20
    new-instance v2, Lhh/f;

    .line 21
    .line 22
    const/4 v3, 0x0

    .line 23
    invoke-direct {v2, p0, v3}, Lhh/f;-><init>(Lhh/h;I)V

    .line 24
    .line 25
    .line 26
    new-instance v3, Lgh/b;

    .line 27
    .line 28
    invoke-direct {v3, p1, v2}, Lgh/b;-><init>(Ljava/lang/String;Lay0/a;)V

    .line 29
    .line 30
    .line 31
    iput-object v3, p0, Lhh/h;->p:Lgh/b;

    .line 32
    .line 33
    goto :goto_1

    .line 34
    :cond_1
    iget-object p1, p0, Lhh/h;->p:Lgh/b;

    .line 35
    .line 36
    if-eqz p1, :cond_2

    .line 37
    .line 38
    iget-object p1, p1, Lgh/b;->e:Lpw0/a;

    .line 39
    .line 40
    invoke-static {p1, v1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 41
    .line 42
    .line 43
    :cond_2
    iput-object v1, p0, Lhh/h;->p:Lgh/b;

    .line 44
    .line 45
    :goto_1
    iget-object p1, p0, Lhh/h;->l:Lyy0/c2;

    .line 46
    .line 47
    iget-object p0, p0, Lhh/h;->k:Lai/d;

    .line 48
    .line 49
    invoke-static {v0, p0}, Llp/w0;->f(Lzg/h;Lai/d;)Lhh/e;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    new-instance v0, Llc/q;

    .line 54
    .line 55
    invoke-direct {v0, p0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1, v1, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    :cond_3
    return-void
.end method


# virtual methods
.method public final d()V
    .locals 3

    .line 1
    iget-object v0, p0, Lhh/h;->p:Lgh/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iget-object v0, v0, Lgh/b;->e:Lpw0/a;

    .line 7
    .line 8
    invoke-static {v0, v1}, Lvy0/e0;->j(Lvy0/b0;Ljava/util/concurrent/CancellationException;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    iput-object v1, p0, Lhh/h;->p:Lgh/b;

    .line 12
    .line 13
    iget-object v0, p0, Lhh/h;->q:Lvy0/z1;

    .line 14
    .line 15
    invoke-virtual {v0}, Lvy0/p1;->b()Lky0/j;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lky0/m;

    .line 20
    .line 21
    iget-object v0, v0, Lky0/m;->b:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v0, Lrx0/h;

    .line 24
    .line 25
    invoke-static {v0}, Llp/ke;->a(Lay0/n;)Lky0/k;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    :goto_0
    invoke-virtual {v0}, Lky0/k;->hasNext()Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    invoke-virtual {v0}, Lky0/k;->next()Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    check-cast v2, Lvy0/i1;

    .line 40
    .line 41
    invoke-interface {v2, v1}, Lvy0/i1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    iget-object p0, p0, Lhh/h;->n:Llx0/q;

    .line 46
    .line 47
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    check-cast p0, Lzb/k0;

    .line 52
    .line 53
    const-string v0, "POLLING_TAG"

    .line 54
    .line 55
    invoke-static {p0, v0}, Lzb/k0;->a(Lzb/k0;Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public final f(Ljava/lang/Throwable;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lhh/h;->d()V

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
    iget-object p0, p0, Lhh/h;->l:Lyy0/c2;

    .line 10
    .line 11
    invoke-static {p1, p0, v0}, Lia/b;->v(Llc/l;Lyy0/c2;Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final g()V
    .locals 4

    .line 1
    new-instance v0, Llc/q;

    .line 2
    .line 3
    sget-object v1, Llc/a;->c:Llc/c;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lhh/h;->l:Lyy0/c2;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    invoke-virtual {v1, v2, v0}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    new-instance v1, Lg1/y2;

    .line 22
    .line 23
    const/16 v3, 0xf

    .line 24
    .line 25
    invoke-direct {v1, p0, v2, v3}, Lg1/y2;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x3

    .line 29
    invoke-static {v0, v2, v2, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 30
    .line 31
    .line 32
    return-void
.end method

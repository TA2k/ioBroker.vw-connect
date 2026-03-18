.class public final Lzi0/d;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwi0/p;

.field public final i:Lcs0/i;

.field public final j:Lcs0/j0;

.field public final k:Lwi0/d;

.field public final l:Lbd0/c;

.field public final m:Lzd0/a;

.field public final n:Lwi0/b;

.field public final o:Lwi0/f;


# direct methods
.method public constructor <init>(Lwi0/p;Lcs0/i;Lcs0/j0;Lwi0/d;Lbd0/c;Lzd0/a;Lwi0/b;Lwi0/f;)V
    .locals 2

    .line 1
    new-instance v0, Lzi0/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lzi0/b;-><init>(I)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lzi0/d;->h:Lwi0/p;

    .line 11
    .line 12
    iput-object p2, p0, Lzi0/d;->i:Lcs0/i;

    .line 13
    .line 14
    iput-object p3, p0, Lzi0/d;->j:Lcs0/j0;

    .line 15
    .line 16
    iput-object p4, p0, Lzi0/d;->k:Lwi0/d;

    .line 17
    .line 18
    iput-object p5, p0, Lzi0/d;->l:Lbd0/c;

    .line 19
    .line 20
    iput-object p6, p0, Lzi0/d;->m:Lzd0/a;

    .line 21
    .line 22
    iput-object p7, p0, Lzi0/d;->n:Lwi0/b;

    .line 23
    .line 24
    iput-object p8, p0, Lzi0/d;->o:Lwi0/f;

    .line 25
    .line 26
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    new-instance p2, Lzi0/a;

    .line 31
    .line 32
    const/4 p3, 0x0

    .line 33
    const/4 p4, 0x0

    .line 34
    invoke-direct {p2, p0, p4, p3}, Lzi0/a;-><init>(Lzi0/d;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    invoke-static {p1, p4, p4, p2, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public static final h(Lzi0/d;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p1, Lzi0/c;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p1

    .line 9
    check-cast v0, Lzi0/c;

    .line 10
    .line 11
    iget v1, v0, Lzi0/c;->f:I

    .line 12
    .line 13
    const/high16 v2, -0x80000000

    .line 14
    .line 15
    and-int v3, v1, v2

    .line 16
    .line 17
    if-eqz v3, :cond_0

    .line 18
    .line 19
    sub-int/2addr v1, v2

    .line 20
    iput v1, v0, Lzi0/c;->f:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lzi0/c;

    .line 24
    .line 25
    invoke-direct {v0, p0, p1}, Lzi0/c;-><init>(Lzi0/d;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p1, v0, Lzi0/c;->d:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lzi0/c;->f:I

    .line 33
    .line 34
    const/4 v3, 0x1

    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iget-object p1, p0, Lzi0/d;->n:Lwi0/b;

    .line 55
    .line 56
    iput v3, v0, Lzi0/c;->f:I

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p1, v0}, Lwi0/b;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    invoke-virtual {p0}, Lzi0/d;->j()V

    .line 69
    .line 70
    .line 71
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    return-object p0
.end method


# virtual methods
.method public final j()V
    .locals 2

    .line 1
    new-instance v0, Lne0/e;

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lzi0/d;->m:Lzd0/a;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Lzd0/a;->a(Lne0/t;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

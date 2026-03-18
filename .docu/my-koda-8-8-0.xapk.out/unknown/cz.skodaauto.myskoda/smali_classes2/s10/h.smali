.class public final Ls10/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcs0/n;

.field public final i:Ltr0/b;

.field public final j:Lij0/a;

.field public final k:Llb0/e0;

.field public l:Lqr0/q;


# direct methods
.method public constructor <init>(Lq10/l;Lcs0/n;Ltr0/b;Lij0/a;Llb0/e0;)V
    .locals 6

    .line 1
    new-instance v0, Ls10/g;

    .line 2
    .line 3
    new-instance v1, Ls10/f;

    .line 4
    .line 5
    const/high16 v2, 0x3fc00000    # 1.5f

    .line 6
    .line 7
    const/16 v3, 0x10

    .line 8
    .line 9
    const-string v4, ""

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    invoke-direct {v1, v4, v5, v2, v3}, Ls10/f;-><init>(Ljava/lang/String;FFI)V

    .line 13
    .line 14
    .line 15
    const/4 v2, 0x0

    .line 16
    invoke-direct {v0, v2, v1}, Ls10/g;-><init>(Lql0/g;Ls10/f;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 20
    .line 21
    .line 22
    iput-object p2, p0, Ls10/h;->h:Lcs0/n;

    .line 23
    .line 24
    iput-object p3, p0, Ls10/h;->i:Ltr0/b;

    .line 25
    .line 26
    iput-object p4, p0, Ls10/h;->j:Lij0/a;

    .line 27
    .line 28
    iput-object p5, p0, Ls10/h;->k:Llb0/e0;

    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    new-instance p3, Lr60/t;

    .line 35
    .line 36
    const/4 p4, 0x7

    .line 37
    invoke-direct {p3, p4, p1, p0, v2}, Lr60/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 38
    .line 39
    .line 40
    const/4 p0, 0x3

    .line 41
    invoke-static {p2, v2, v2, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 42
    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public final h(Lqr0/q;)Ls10/f;
    .locals 7

    .line 1
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    check-cast v0, Ls10/g;

    .line 6
    .line 7
    iget-object v0, v0, Ls10/g;->b:Ls10/f;

    .line 8
    .line 9
    iget-wide v1, p1, Lqr0/q;->a:D

    .line 10
    .line 11
    invoke-static {p1}, Lkp/p6;->e(Lqr0/q;)D

    .line 12
    .line 13
    .line 14
    move-result-wide v3

    .line 15
    cmpg-double v3, v1, v3

    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    iget-object p0, p0, Ls10/h;->j:Lij0/a;

    .line 19
    .line 20
    if-nez v3, :cond_0

    .line 21
    .line 22
    new-array v1, v4, [Ljava/lang/Object;

    .line 23
    .line 24
    check-cast p0, Ljj0/f;

    .line 25
    .line 26
    const v2, 0x7f1200cf

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    invoke-static {p1}, Lkp/p6;->d(Lqr0/q;)D

    .line 35
    .line 36
    .line 37
    move-result-wide v5

    .line 38
    cmpg-double v1, v1, v5

    .line 39
    .line 40
    if-nez v1, :cond_1

    .line 41
    .line 42
    new-array v1, v4, [Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p0, Ljj0/f;

    .line 45
    .line 46
    const v2, 0x7f1200ce

    .line 47
    .line 48
    .line 49
    invoke-virtual {p0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    goto :goto_0

    .line 54
    :cond_1
    invoke-static {p1, p0}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    :goto_0
    invoke-static {p1}, Lkp/p6;->c(Lqr0/q;)F

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    iget v1, v0, Ls10/f;->c:F

    .line 63
    .line 64
    iget v2, v0, Ls10/f;->d:I

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 67
    .line 68
    .line 69
    new-instance v0, Ls10/f;

    .line 70
    .line 71
    invoke-direct {v0, p0, p1, v1, v2}, Ls10/f;-><init>(Ljava/lang/String;FFI)V

    .line 72
    .line 73
    .line 74
    return-object v0
.end method

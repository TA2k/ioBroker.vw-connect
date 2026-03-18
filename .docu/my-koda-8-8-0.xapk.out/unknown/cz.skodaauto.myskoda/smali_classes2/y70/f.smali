.class public final Ly70/f;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lw70/n0;

.field public final j:Lw70/o0;

.field public final k:Lw70/g;

.field public final l:Lbq0/o;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lw70/n0;Lw70/o0;Lw70/g;Lbq0/o;Lij0/a;)V
    .locals 10

    .line 1
    new-instance v0, Ly70/d;

    .line 2
    .line 3
    const-string v5, ""

    .line 4
    .line 5
    const/4 v7, 0x0

    .line 6
    const/4 v1, 0x0

    .line 7
    const/4 v2, 0x0

    .line 8
    const/4 v3, 0x0

    .line 9
    const/4 v4, 0x1

    .line 10
    sget-object v6, Lmx0/s;->d:Lmx0/s;

    .line 11
    .line 12
    const/4 v8, 0x0

    .line 13
    move-object v9, v6

    .line 14
    invoke-direct/range {v0 .. v9}, Ly70/d;-><init>(Lql0/g;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;ZLjava/lang/String;Ljava/util/List;ZLqr0/d;Ljava/util/List;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 18
    .line 19
    .line 20
    iput-object p1, p0, Ly70/f;->h:Ltr0/b;

    .line 21
    .line 22
    iput-object p2, p0, Ly70/f;->i:Lw70/n0;

    .line 23
    .line 24
    iput-object p3, p0, Ly70/f;->j:Lw70/o0;

    .line 25
    .line 26
    iput-object p4, p0, Ly70/f;->k:Lw70/g;

    .line 27
    .line 28
    iput-object p5, p0, Ly70/f;->l:Lbq0/o;

    .line 29
    .line 30
    move-object/from16 p1, p6

    .line 31
    .line 32
    iput-object p1, p0, Ly70/f;->m:Lij0/a;

    .line 33
    .line 34
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    new-instance p2, Lxm0/g;

    .line 39
    .line 40
    const/4 p3, 0x4

    .line 41
    const/4 p4, 0x0

    .line 42
    invoke-direct {p2, p0, p4, p3}, Lxm0/g;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    const/4 p3, 0x3

    .line 46
    invoke-static {p1, p4, p4, p2, p3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 47
    .line 48
    .line 49
    new-instance p1, Ly70/b;

    .line 50
    .line 51
    const/4 p2, 0x0

    .line 52
    invoke-direct {p1, p0, p4, p2}, Ly70/b;-><init>(Ly70/f;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 56
    .line 57
    .line 58
    return-void
.end method

.method public static final h(Ly70/f;Lcq0/i;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Ly70/e;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Ly70/e;

    .line 10
    .line 11
    iget v1, v0, Ly70/e;->f:I

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
    iput v1, v0, Ly70/e;->f:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Ly70/e;

    .line 24
    .line 25
    invoke-direct {v0, p0, p2}, Ly70/e;-><init>(Ly70/f;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p2, v0, Ly70/e;->d:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Ly70/e;->f:I

    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    const/4 v4, 0x1

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_3

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object p2, p0, Ly70/f;->j:Lw70/o0;

    .line 62
    .line 63
    iput v4, v0, Ly70/e;->f:I

    .line 64
    .line 65
    iget-object v2, p2, Lw70/o0;->c:Lkf0/o;

    .line 66
    .line 67
    invoke-static {v2}, Lly0/q;->c(Ltr0/c;)Lyy0/m1;

    .line 68
    .line 69
    .line 70
    move-result-object v2

    .line 71
    new-instance v4, Lo20/c;

    .line 72
    .line 73
    const/4 v5, 0x0

    .line 74
    const/16 v6, 0x14

    .line 75
    .line 76
    invoke-direct {v4, v6, p2, p1, v5}, Lo20/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    invoke-static {v2, v4}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 80
    .line 81
    .line 82
    move-result-object p2

    .line 83
    if-ne p2, v1, :cond_4

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_4
    :goto_1
    check-cast p2, Lyy0/i;

    .line 87
    .line 88
    invoke-static {p2}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    new-instance p2, Ly70/a;

    .line 93
    .line 94
    const/4 v2, 0x1

    .line 95
    invoke-direct {p2, p0, v2}, Ly70/a;-><init>(Ly70/f;I)V

    .line 96
    .line 97
    .line 98
    iput v3, v0, Ly70/e;->f:I

    .line 99
    .line 100
    invoke-virtual {p1, p2, v0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    if-ne p0, v1, :cond_5

    .line 105
    .line 106
    :goto_2
    return-object v1

    .line 107
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 108
    .line 109
    return-object p0
.end method

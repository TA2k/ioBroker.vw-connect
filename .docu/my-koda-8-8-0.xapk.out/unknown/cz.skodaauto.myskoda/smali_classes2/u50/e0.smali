.class public final Lu50/e0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lrs0/b;

.field public final j:Ls50/p;

.field public final k:Ls50/c0;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Ltr0/b;Lrs0/b;Ls50/p;Ls50/c0;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lu50/b0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Lu50/b0;-><init>(Lql0/g;Z)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lu50/e0;->h:Ltr0/b;

    .line 12
    .line 13
    iput-object p2, p0, Lu50/e0;->i:Lrs0/b;

    .line 14
    .line 15
    iput-object p3, p0, Lu50/e0;->j:Ls50/p;

    .line 16
    .line 17
    iput-object p4, p0, Lu50/e0;->k:Ls50/c0;

    .line 18
    .line 19
    iput-object p5, p0, Lu50/e0;->l:Lij0/a;

    .line 20
    .line 21
    return-void
.end method

.method public static final h(Lu50/e0;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Lu50/d0;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Lu50/d0;

    .line 10
    .line 11
    iget v1, v0, Lu50/d0;->f:I

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
    iput v1, v0, Lu50/d0;->f:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lu50/d0;

    .line 24
    .line 25
    invoke-direct {v0, p0, p2}, Lu50/d0;-><init>(Lu50/e0;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p2, v0, Lu50/d0;->d:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lu50/d0;->f:I

    .line 33
    .line 34
    const/4 v3, 0x2

    .line 35
    const/4 v4, 0x1

    .line 36
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 37
    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object v5

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object p2, p0, Lu50/e0;->j:Ls50/p;

    .line 64
    .line 65
    iput v4, v0, Lu50/d0;->f:I

    .line 66
    .line 67
    iget-object p2, p2, Ls50/p;->a:Lp50/d;

    .line 68
    .line 69
    invoke-virtual {p2, p1, v0}, Lp50/d;->c(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    if-ne p2, v1, :cond_4

    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_4
    :goto_1
    check-cast p2, Lyy0/i;

    .line 77
    .line 78
    iput v3, v0, Lu50/d0;->f:I

    .line 79
    .line 80
    new-instance p1, Lqg/l;

    .line 81
    .line 82
    const/16 v2, 0x13

    .line 83
    .line 84
    sget-object v3, Lzy0/q;->d:Lzy0/q;

    .line 85
    .line 86
    invoke-direct {p1, v2, v3, p0}, Lqg/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    invoke-interface {p2, p1, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    if-ne p0, v1, :cond_5

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_5
    move-object p0, v5

    .line 97
    :goto_2
    if-ne p0, v1, :cond_6

    .line 98
    .line 99
    goto :goto_3

    .line 100
    :cond_6
    move-object p0, v5

    .line 101
    :goto_3
    if-ne p0, v1, :cond_7

    .line 102
    .line 103
    :goto_4
    return-object v1

    .line 104
    :cond_7
    return-object v5
.end method

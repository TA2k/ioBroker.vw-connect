.class public final Lwk0/b1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Luk0/b0;

.field public final i:Lpp0/z;

.field public final j:Luk0/i0;

.field public final k:Lkf0/k;

.field public final l:Lnn0/d0;


# direct methods
.method public constructor <init>(Luk0/b0;Lpp0/z;Luk0/i0;Lkf0/k;Lnn0/d0;)V
    .locals 1

    .line 1
    new-instance v0, Lwk0/z0;

    .line 2
    .line 3
    invoke-direct {v0}, Lwk0/z0;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lwk0/b1;->h:Luk0/b0;

    .line 10
    .line 11
    iput-object p2, p0, Lwk0/b1;->i:Lpp0/z;

    .line 12
    .line 13
    iput-object p3, p0, Lwk0/b1;->j:Luk0/i0;

    .line 14
    .line 15
    iput-object p4, p0, Lwk0/b1;->k:Lkf0/k;

    .line 16
    .line 17
    iput-object p5, p0, Lwk0/b1;->l:Lnn0/d0;

    .line 18
    .line 19
    new-instance p1, Lvo0/e;

    .line 20
    .line 21
    const/16 p2, 0xe

    .line 22
    .line 23
    const/4 p3, 0x0

    .line 24
    invoke-direct {p1, p0, p3, p2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static final h(Lwk0/b1;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lwk0/a1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwk0/a1;

    .line 7
    .line 8
    iget v1, v0, Lwk0/a1;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lwk0/a1;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwk0/a1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwk0/a1;-><init>(Lwk0/b1;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwk0/a1;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwk0/a1;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_3

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
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iget-object p1, p0, Lwk0/b1;->i:Lpp0/z;

    .line 59
    .line 60
    iput v4, v0, Lwk0/a1;->f:I

    .line 61
    .line 62
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lpp0/z;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    if-ne p1, v1, :cond_4

    .line 70
    .line 71
    goto :goto_2

    .line 72
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 73
    .line 74
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 75
    .line 76
    .line 77
    move-result p1

    .line 78
    if-nez p1, :cond_6

    .line 79
    .line 80
    iget-object p0, p0, Lwk0/b1;->k:Lkf0/k;

    .line 81
    .line 82
    iput v3, v0, Lwk0/a1;->f:I

    .line 83
    .line 84
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p0, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object p1

    .line 91
    if-ne p1, v1, :cond_5

    .line 92
    .line 93
    :goto_2
    return-object v1

    .line 94
    :cond_5
    :goto_3
    check-cast p1, Lss0/b;

    .line 95
    .line 96
    sget-object p0, Lvk0/e;->a:Ljava/util/List;

    .line 97
    .line 98
    sget-object p0, Lss0/e;->t1:Lss0/e;

    .line 99
    .line 100
    sget-object v0, Lvk0/e;->a:Ljava/util/List;

    .line 101
    .line 102
    invoke-static {p1, p0, v0}, Llp/pf;->f(Lss0/b;Lss0/e;Ljava/util/List;)Z

    .line 103
    .line 104
    .line 105
    move-result p0

    .line 106
    if-eqz p0, :cond_6

    .line 107
    .line 108
    goto :goto_4

    .line 109
    :cond_6
    const/4 v4, 0x0

    .line 110
    :goto_4
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0
.end method

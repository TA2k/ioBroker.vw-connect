.class public final Lx60/f;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lzd0/b;

.field public final j:Lu60/c;

.field public final k:Ltr0/b;


# direct methods
.method public constructor <init>(Lij0/a;Lzd0/b;Lu60/c;Ltr0/b;)V
    .locals 2

    .line 1
    new-instance v0, Lx60/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Lx60/d;-><init>(Lae0/a;Lql0/g;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lx60/f;->h:Lij0/a;

    .line 11
    .line 12
    iput-object p2, p0, Lx60/f;->i:Lzd0/b;

    .line 13
    .line 14
    iput-object p3, p0, Lx60/f;->j:Lu60/c;

    .line 15
    .line 16
    iput-object p4, p0, Lx60/f;->k:Ltr0/b;

    .line 17
    .line 18
    new-instance p1, Lx60/c;

    .line 19
    .line 20
    const/4 p2, 0x0

    .line 21
    invoke-direct {p1, p0, v1, p2}, Lx60/c;-><init>(Lx60/f;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lx60/c;

    .line 32
    .line 33
    const/4 p3, 0x1

    .line 34
    invoke-direct {p2, p0, v1, p3}, Lx60/c;-><init>(Lx60/f;Lkotlin/coroutines/Continuation;I)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x3

    .line 38
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final h(Lx60/f;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget-object v0, p0, Lx60/f;->h:Lij0/a;

    .line 2
    .line 3
    instance-of v1, p1, Lx60/e;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p1

    .line 8
    check-cast v1, Lx60/e;

    .line 9
    .line 10
    iget v2, v1, Lx60/e;->f:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lx60/e;->f:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lx60/e;

    .line 23
    .line 24
    invoke-direct {v1, p0, p1}, Lx60/e;-><init>(Lx60/f;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v1, Lx60/e;->d:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lx60/e;->f:I

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v3, :cond_2

    .line 35
    .line 36
    if-ne v3, v4, :cond_1

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    iget-object p1, p0, Lx60/f;->j:Lu60/c;

    .line 54
    .line 55
    iput v4, v1, Lx60/e;->f:I

    .line 56
    .line 57
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-virtual {p1, v1}, Lu60/c;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    if-ne p1, v2, :cond_3

    .line 65
    .line 66
    return-object v2

    .line 67
    :cond_3
    :goto_1
    check-cast p1, Lne0/t;

    .line 68
    .line 69
    instance-of v1, p1, Lne0/c;

    .line 70
    .line 71
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 72
    .line 73
    if-eqz v1, :cond_7

    .line 74
    .line 75
    check-cast p1, Lne0/c;

    .line 76
    .line 77
    iget-object v1, p1, Lne0/c;->a:Ljava/lang/Throwable;

    .line 78
    .line 79
    instance-of v3, v1, Lcd0/b;

    .line 80
    .line 81
    const/4 v5, 0x0

    .line 82
    if-eqz v3, :cond_4

    .line 83
    .line 84
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 85
    .line 86
    .line 87
    move-result-object v1

    .line 88
    check-cast v1, Lx60/d;

    .line 89
    .line 90
    const/4 v3, 0x4

    .line 91
    invoke-static {p1, v0, v3}, Lkp/h6;->b(Lne0/c;Lij0/a;I)Lql0/g;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    invoke-static {v1, v5, p1, v4}, Lx60/d;->a(Lx60/d;Lae0/a;Lql0/g;I)Lx60/d;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    goto :goto_2

    .line 100
    :cond_4
    instance-of v3, v1, Lv60/a;

    .line 101
    .line 102
    if-nez v3, :cond_6

    .line 103
    .line 104
    instance-of v3, v1, Llc0/e;

    .line 105
    .line 106
    if-nez v3, :cond_6

    .line 107
    .line 108
    instance-of v1, v1, Lcd0/a;

    .line 109
    .line 110
    if-eqz v1, :cond_5

    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_5
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 114
    .line 115
    .line 116
    move-result-object v1

    .line 117
    check-cast v1, Lx60/d;

    .line 118
    .line 119
    invoke-static {p1, v0}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-static {v1, v5, p1, v4}, Lx60/d;->a(Lx60/d;Lae0/a;Lql0/g;I)Lx60/d;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    :goto_2
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 128
    .line 129
    .line 130
    return-object v2

    .line 131
    :cond_6
    :goto_3
    iget-object p0, p0, Lx60/f;->k:Ltr0/b;

    .line 132
    .line 133
    invoke-static {p0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    :cond_7
    return-object v2
.end method

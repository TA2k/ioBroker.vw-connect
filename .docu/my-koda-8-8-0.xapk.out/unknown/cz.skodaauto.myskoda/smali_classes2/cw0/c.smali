.class public interface abstract Lcw0/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lvy0/b0;
.implements Ljava/io/Closeable;


# direct methods
.method public static u0(Lcw0/c;Lss/b;Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    instance-of v0, p2, Lcw0/a;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    move-object v0, p2

    .line 9
    check-cast v0, Lcw0/a;

    .line 10
    .line 11
    iget v1, v0, Lcw0/a;->g:I

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
    iput v1, v0, Lcw0/a;->g:I

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    new-instance v0, Lcw0/a;

    .line 24
    .line 25
    invoke-direct {v0, p0, p2}, Lcw0/a;-><init>(Lcw0/c;Lrx0/c;)V

    .line 26
    .line 27
    .line 28
    :goto_0
    iget-object p2, v0, Lcw0/a;->e:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 31
    .line 32
    iget v2, v0, Lcw0/a;->g:I

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
    return-object p2

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
    iget-object p1, v0, Lcw0/a;->d:Lss/b;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iget-object p2, p1, Lss/b;->i:Ljava/lang/Object;

    .line 64
    .line 65
    check-cast p2, Lvy0/i1;

    .line 66
    .line 67
    iput-object p1, v0, Lcw0/a;->d:Lss/b;

    .line 68
    .line 69
    iput v4, v0, Lcw0/a;->g:I

    .line 70
    .line 71
    sget-object v2, Lcw0/h;->a:Lvy0/a0;

    .line 72
    .line 73
    new-instance v2, Lvy0/k1;

    .line 74
    .line 75
    invoke-direct {v2, p2}, Lvy0/k1;-><init>(Lvy0/i1;)V

    .line 76
    .line 77
    .line 78
    invoke-interface {p0}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    invoke-interface {p2, v2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    sget-object v5, Lcw0/h;->a:Lvy0/a0;

    .line 87
    .line 88
    invoke-interface {p2, v5}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    sget-object v6, Lvy0/h1;->d:Lvy0/h1;

    .line 97
    .line 98
    invoke-interface {v5, v6}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 99
    .line 100
    .line 101
    move-result-object v5

    .line 102
    check-cast v5, Lvy0/i1;

    .line 103
    .line 104
    if-nez v5, :cond_4

    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_4
    new-instance v6, Lag/t;

    .line 108
    .line 109
    const/4 v7, 0x3

    .line 110
    invoke-direct {v6, v2, v7}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 111
    .line 112
    .line 113
    invoke-interface {v5, v4, v4, v6}, Lvy0/i1;->f(ZZLay0/k;)Lvy0/r0;

    .line 114
    .line 115
    .line 116
    move-result-object v4

    .line 117
    new-instance v5, Lag/t;

    .line 118
    .line 119
    invoke-direct {v5, v4, v3}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v2, v5}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 123
    .line 124
    .line 125
    :goto_1
    if-ne p2, v1, :cond_5

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_5
    :goto_2
    check-cast p2, Lpx0/g;

    .line 129
    .line 130
    new-instance v2, Lcw0/i;

    .line 131
    .line 132
    invoke-direct {v2, p2}, Lcw0/i;-><init>(Lpx0/g;)V

    .line 133
    .line 134
    .line 135
    invoke-interface {p2, v2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 136
    .line 137
    .line 138
    move-result-object p2

    .line 139
    new-instance v2, Lc80/l;

    .line 140
    .line 141
    const/16 v4, 0x12

    .line 142
    .line 143
    const/4 v5, 0x0

    .line 144
    invoke-direct {v2, v4, p0, p1, v5}, Lc80/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 145
    .line 146
    .line 147
    invoke-static {p0, p2, v2, v3}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    iput-object v5, v0, Lcw0/a;->d:Lss/b;

    .line 152
    .line 153
    iput v3, v0, Lcw0/a;->g:I

    .line 154
    .line 155
    invoke-virtual {p0, v0}, Lvy0/p1;->y(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    if-ne p0, v1, :cond_6

    .line 160
    .line 161
    :goto_3
    return-object v1

    .line 162
    :cond_6
    return-object p0
.end method


# virtual methods
.method public b0()Ljava/util/Set;
    .locals 0

    .line 1
    sget-object p0, Lmx0/u;->d:Lmx0/u;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract p()Ldw0/a;
.end method

.method public abstract s(Lss/b;Lrx0/c;)Ljava/lang/Object;
.end method

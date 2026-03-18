.class public final Lzl/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lnm/i;
.implements Lt3/c0;


# instance fields
.field public b:J

.field public c:Ljava/util/ArrayList;


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 1

    .line 1
    invoke-virtual {p0, p3, p4}, Lzl/n;->j(J)V

    .line 2
    .line 3
    .line 4
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    iget p2, p0, Lt3/e1;->d:I

    .line 9
    .line 10
    iget p3, p0, Lt3/e1;->e:I

    .line 11
    .line 12
    new-instance p4, Lam/a;

    .line 13
    .line 14
    const/16 v0, 0x13

    .line 15
    .line 16
    invoke-direct {p4, p0, v0}, Lam/a;-><init>(Lt3/e1;I)V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 20
    .line 21
    invoke-interface {p1, p2, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method

.method public final h(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lzl/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lzl/m;

    .line 7
    .line 8
    iget v1, v0, Lzl/m;->g:I

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
    iput v1, v0, Lzl/m;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lzl/m;

    .line 21
    .line 22
    check-cast p1, Lrx0/c;

    .line 23
    .line 24
    invoke-direct {v0, p0, p1}, Lzl/m;-><init>(Lzl/n;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p1, v0, Lzl/m;->e:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, v0, Lzl/m;->g:I

    .line 32
    .line 33
    const/4 v3, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v3, :cond_1

    .line 37
    .line 38
    iget-object v0, v0, Lzl/m;->d:Lkotlin/jvm/internal/f0;

    .line 39
    .line 40
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :catchall_0
    move-exception p1

    .line 45
    goto :goto_2

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    iget-wide v4, p0, Lzl/n;->b:J

    .line 58
    .line 59
    invoke-static {v4, v5}, Lt4/a;->k(J)Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_4

    .line 64
    .line 65
    new-instance p1, Lkotlin/jvm/internal/f0;

    .line 66
    .line 67
    invoke-direct {p1}, Ljava/lang/Object;-><init>()V

    .line 68
    .line 69
    .line 70
    :try_start_1
    iput-object p1, v0, Lzl/m;->d:Lkotlin/jvm/internal/f0;

    .line 71
    .line 72
    iput v3, v0, Lzl/m;->g:I

    .line 73
    .line 74
    new-instance v2, Lvy0/l;

    .line 75
    .line 76
    invoke-static {v0}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 77
    .line 78
    .line 79
    move-result-object v0

    .line 80
    invoke-direct {v2, v3, v0}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v2}, Lvy0/l;->q()V

    .line 84
    .line 85
    .line 86
    iput-object v2, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 87
    .line 88
    iget-object v0, p0, Lzl/n;->c:Ljava/util/ArrayList;

    .line 89
    .line 90
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 91
    .line 92
    .line 93
    invoke-virtual {v2}, Lvy0/l;->p()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 97
    if-ne v0, v1, :cond_3

    .line 98
    .line 99
    return-object v1

    .line 100
    :cond_3
    move-object v0, p1

    .line 101
    :goto_1
    iget-object p1, p0, Lzl/n;->c:Ljava/util/ArrayList;

    .line 102
    .line 103
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 104
    .line 105
    invoke-static {p1}, Lkotlin/jvm/internal/j0;->a(Ljava/lang/Object;)Ljava/util/Collection;

    .line 106
    .line 107
    .line 108
    move-result-object p1

    .line 109
    invoke-interface {p1, v0}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    goto :goto_3

    .line 113
    :catchall_1
    move-exception v0

    .line 114
    move-object v6, v0

    .line 115
    move-object v0, p1

    .line 116
    move-object p1, v6

    .line 117
    :goto_2
    iget-object p0, p0, Lzl/n;->c:Ljava/util/ArrayList;

    .line 118
    .line 119
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 120
    .line 121
    invoke-static {p0}, Lkotlin/jvm/internal/j0;->a(Ljava/lang/Object;)Ljava/util/Collection;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    invoke-interface {p0, v0}, Ljava/util/Collection;->remove(Ljava/lang/Object;)Z

    .line 126
    .line 127
    .line 128
    throw p1

    .line 129
    :cond_4
    :goto_3
    iget-wide p0, p0, Lzl/n;->b:J

    .line 130
    .line 131
    new-instance v0, Lnm/h;

    .line 132
    .line 133
    invoke-static {p0, p1}, Lt4/a;->h(J)I

    .line 134
    .line 135
    .line 136
    move-result v1

    .line 137
    sget-object v2, Lnm/b;->a:Lnm/b;

    .line 138
    .line 139
    const v3, 0x7fffffff

    .line 140
    .line 141
    .line 142
    if-eq v1, v3, :cond_5

    .line 143
    .line 144
    invoke-static {v1}, Ljp/sa;->a(I)V

    .line 145
    .line 146
    .line 147
    new-instance v4, Lnm/a;

    .line 148
    .line 149
    invoke-direct {v4, v1}, Lnm/a;-><init>(I)V

    .line 150
    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_5
    move-object v4, v2

    .line 154
    :goto_4
    invoke-static {p0, p1}, Lt4/a;->g(J)I

    .line 155
    .line 156
    .line 157
    move-result p0

    .line 158
    if-eq p0, v3, :cond_6

    .line 159
    .line 160
    invoke-static {p0}, Ljp/sa;->a(I)V

    .line 161
    .line 162
    .line 163
    new-instance v2, Lnm/a;

    .line 164
    .line 165
    invoke-direct {v2, p0}, Lnm/a;-><init>(I)V

    .line 166
    .line 167
    .line 168
    :cond_6
    invoke-direct {v0, v4, v2}, Lnm/h;-><init>(Lnm/c;Lnm/c;)V

    .line 169
    .line 170
    .line 171
    return-object v0
.end method

.method public final j(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lzl/n;->b:J

    .line 2
    .line 3
    invoke-static {p1, p2}, Lt4/a;->k(J)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lzl/n;->c:Ljava/util/ArrayList;

    .line 10
    .line 11
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 12
    .line 13
    .line 14
    move-result p2

    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    new-instance p2, Ljava/util/ArrayList;

    .line 18
    .line 19
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 20
    .line 21
    .line 22
    iput-object p2, p0, Lzl/n;->c:Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lkotlin/coroutines/Continuation;

    .line 39
    .line 40
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    invoke-interface {p1, p2}, Lkotlin/coroutines/Continuation;->resumeWith(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_0
    return-void
.end method

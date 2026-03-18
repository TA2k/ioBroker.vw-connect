.class public abstract Llp/vf;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ld01/t0;)Lim/r;
    .locals 10

    .line 1
    iget v1, p0, Ld01/t0;->g:I

    .line 2
    .line 3
    iget-wide v2, p0, Ld01/t0;->o:J

    .line 4
    .line 5
    iget-wide v4, p0, Ld01/t0;->p:J

    .line 6
    .line 7
    iget-object v0, p0, Ld01/t0;->i:Ld01/y;

    .line 8
    .line 9
    new-instance v6, Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    invoke-direct {v6}, Ljava/util/LinkedHashMap;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Ld01/y;->iterator()Ljava/util/Iterator;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    :goto_0
    move-object v7, v0

    .line 19
    check-cast v7, Landroidx/collection/d1;

    .line 20
    .line 21
    invoke-virtual {v7}, Landroidx/collection/d1;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v8

    .line 25
    if-eqz v8, :cond_1

    .line 26
    .line 27
    invoke-virtual {v7}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v7

    .line 31
    check-cast v7, Llx0/l;

    .line 32
    .line 33
    iget-object v8, v7, Llx0/l;->d:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v8, Ljava/lang/String;

    .line 36
    .line 37
    iget-object v7, v7, Llx0/l;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v7, Ljava/lang/String;

    .line 40
    .line 41
    sget-object v9, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 42
    .line 43
    invoke-virtual {v8, v9}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v8

    .line 47
    const-string v9, "toLowerCase(...)"

    .line 48
    .line 49
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v6, v8}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v9

    .line 56
    if-nez v9, :cond_0

    .line 57
    .line 58
    new-instance v9, Ljava/util/ArrayList;

    .line 59
    .line 60
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 61
    .line 62
    .line 63
    invoke-interface {v6, v8, v9}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    :cond_0
    check-cast v9, Ljava/util/List;

    .line 67
    .line 68
    check-cast v9, Ljava/util/Collection;

    .line 69
    .line 70
    invoke-interface {v9, v7}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_1
    new-instance v0, Lim/p;

    .line 75
    .line 76
    invoke-static {v6}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    invoke-direct {v0, v6}, Lim/p;-><init>(Ljava/util/Map;)V

    .line 81
    .line 82
    .line 83
    iget-object v6, p0, Ld01/t0;->j:Ld01/v0;

    .line 84
    .line 85
    if-eqz v6, :cond_2

    .line 86
    .line 87
    invoke-virtual {v6}, Ld01/v0;->p0()Lu01/h;

    .line 88
    .line 89
    .line 90
    move-result-object v6

    .line 91
    if-eqz v6, :cond_2

    .line 92
    .line 93
    new-instance v7, Lim/s;

    .line 94
    .line 95
    invoke-direct {v7, v6}, Lim/s;-><init>(Lu01/h;)V

    .line 96
    .line 97
    .line 98
    :goto_1
    move-object v6, v0

    .line 99
    goto :goto_2

    .line 100
    :cond_2
    const/4 v7, 0x0

    .line 101
    goto :goto_1

    .line 102
    :goto_2
    new-instance v0, Lim/r;

    .line 103
    .line 104
    move-object v8, p0

    .line 105
    invoke-direct/range {v0 .. v8}, Lim/r;-><init>(IJJLim/p;Lim/s;Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    return-object v0
.end method

.method public static final b(Lim/q;Lrx0/c;)Ld01/k0;
    .locals 5

    .line 1
    instance-of v0, p1, Llm/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Llm/e;

    .line 7
    .line 8
    iget v1, v0, Llm/e;->e:I

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
    iput v1, v0, Llm/e;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Llm/e;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Llm/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v0, v0, Llm/e;->e:I

    .line 30
    .line 31
    const/4 v1, 0x0

    .line 32
    if-eqz v0, :cond_3

    .line 33
    .line 34
    const/4 p0, 0x1

    .line 35
    if-ne v0, p0, :cond_2

    .line 36
    .line 37
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    check-cast p1, Lu01/i;

    .line 41
    .line 42
    if-eqz p1, :cond_1

    .line 43
    .line 44
    sget-object p0, Ld01/r0;->Companion:Ld01/q0;

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 47
    .line 48
    .line 49
    new-instance p0, Ld01/n0;

    .line 50
    .line 51
    invoke-direct {p0, v1, p1}, Ld01/n0;-><init>(Ld01/d0;Lu01/i;)V

    .line 52
    .line 53
    .line 54
    move-object p1, v1

    .line 55
    move-object v0, p1

    .line 56
    move-object v2, v0

    .line 57
    goto :goto_2

    .line 58
    :cond_1
    move-object p0, v1

    .line 59
    move-object p1, p0

    .line 60
    move-object v0, p1

    .line 61
    move-object v2, v0

    .line 62
    goto :goto_1

    .line 63
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 64
    .line 65
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    new-instance p1, Ld01/j0;

    .line 75
    .line 76
    invoke-direct {p1}, Ld01/j0;-><init>()V

    .line 77
    .line 78
    .line 79
    iget-object v0, p0, Lim/q;->a:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {p1, v0}, Ld01/j0;->f(Ljava/lang/String;)V

    .line 82
    .line 83
    .line 84
    iget-object v0, p0, Lim/q;->b:Ljava/lang/String;

    .line 85
    .line 86
    move-object v2, v0

    .line 87
    move-object v0, p1

    .line 88
    :goto_1
    move-object v4, p1

    .line 89
    move-object p1, p0

    .line 90
    move-object p0, v1

    .line 91
    move-object v1, v4

    .line 92
    :goto_2
    invoke-virtual {v1, v2, p0}, Ld01/j0;->e(Ljava/lang/String;Ld01/r0;)V

    .line 93
    .line 94
    .line 95
    iget-object p0, p1, Lim/q;->c:Lim/p;

    .line 96
    .line 97
    new-instance p1, Ld01/x;

    .line 98
    .line 99
    const/4 v1, 0x0

    .line 100
    invoke-direct {p1, v1, v1}, Ld01/x;-><init>(BI)V

    .line 101
    .line 102
    .line 103
    iget-object p0, p0, Lim/p;->a:Ljava/util/Map;

    .line 104
    .line 105
    invoke-interface {p0}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    invoke-interface {p0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    :cond_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    if-eqz v1, :cond_5

    .line 118
    .line 119
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object v1

    .line 123
    check-cast v1, Ljava/util/Map$Entry;

    .line 124
    .line 125
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    check-cast v2, Ljava/lang/String;

    .line 130
    .line 131
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    check-cast v1, Ljava/util/List;

    .line 136
    .line 137
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 138
    .line 139
    .line 140
    move-result-object v1

    .line 141
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 142
    .line 143
    .line 144
    move-result v3

    .line 145
    if-eqz v3, :cond_4

    .line 146
    .line 147
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v3

    .line 151
    check-cast v3, Ljava/lang/String;

    .line 152
    .line 153
    invoke-virtual {p1, v2, v3}, Ld01/x;->h(Ljava/lang/String;Ljava/lang/String;)V

    .line 154
    .line 155
    .line 156
    goto :goto_3

    .line 157
    :cond_5
    invoke-virtual {p1}, Ld01/x;->j()Ld01/y;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    invoke-virtual {v0, p0}, Ld01/j0;->d(Ld01/y;)V

    .line 162
    .line 163
    .line 164
    new-instance p0, Ld01/k0;

    .line 165
    .line 166
    invoke-direct {p0, v0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 167
    .line 168
    .line 169
    return-object p0
.end method

.method public static final c(Lcom/google/common/util/concurrent/ListenableFuture;Lrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    :try_start_0
    invoke-interface {p0}, Ljava/util/concurrent/Future;->isDone()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {p0}, Ly4/g;->g(Ljava/util/concurrent/Future;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0
    :try_end_0
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance v0, Lvy0/l;

    .line 13
    .line 14
    invoke-static {p1}, Ljp/hg;->b(Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-direct {v0, v1, p1}, Lvy0/l;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 20
    .line 21
    .line 22
    new-instance p1, Lfb/l;

    .line 23
    .line 24
    invoke-direct {p1, p0, v0, v1}, Lfb/l;-><init>(Lcom/google/common/util/concurrent/ListenableFuture;Lvy0/l;I)V

    .line 25
    .line 26
    .line 27
    sget-object v1, Ly4/l;->d:Ly4/l;

    .line 28
    .line 29
    invoke-interface {p0, v1, p1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 30
    .line 31
    .line 32
    new-instance p1, Lw3/a0;

    .line 33
    .line 34
    const/16 v1, 0x9

    .line 35
    .line 36
    invoke-direct {p1, p0, v1}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v0, p1}, Lvy0/l;->s(Lay0/k;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0}, Lvy0/l;->p()Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 47
    .line 48
    return-object p0

    .line 49
    :catch_0
    move-exception p0

    .line 50
    invoke-virtual {p0}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    if-eqz p0, :cond_1

    .line 55
    .line 56
    throw p0

    .line 57
    :cond_1
    new-instance p0, Llx0/g;

    .line 58
    .line 59
    invoke-direct {p0}, Ljava/lang/NullPointerException;-><init>()V

    .line 60
    .line 61
    .line 62
    const-class p1, Lkotlin/jvm/internal/m;

    .line 63
    .line 64
    invoke-virtual {p1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->l(Ljava/lang/RuntimeException;Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p0
.end method

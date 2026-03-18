.class public final Le1/a1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lez0/a;

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;

.field public g:Le1/b1;

.field public h:I

.field public synthetic i:Ljava/lang/Object;

.field public final synthetic j:Le1/w0;

.field public final synthetic k:Le1/b1;

.field public final synthetic l:Lrx0/i;

.field public final synthetic m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Le1/w0;Le1/b1;Lay0/n;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Le1/a1;->j:Le1/w0;

    .line 2
    .line 3
    iput-object p2, p0, Le1/a1;->k:Le1/b1;

    .line 4
    .line 5
    check-cast p3, Lrx0/i;

    .line 6
    .line 7
    iput-object p3, p0, Le1/a1;->l:Lrx0/i;

    .line 8
    .line 9
    iput-object p4, p0, Le1/a1;->m:Ljava/lang/Object;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p5}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 6

    .line 1
    new-instance v0, Le1/a1;

    .line 2
    .line 3
    iget-object v3, p0, Le1/a1;->l:Lrx0/i;

    .line 4
    .line 5
    iget-object v4, p0, Le1/a1;->m:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v1, p0, Le1/a1;->j:Le1/w0;

    .line 8
    .line 9
    iget-object v2, p0, Le1/a1;->k:Le1/b1;

    .line 10
    .line 11
    move-object v5, p2

    .line 12
    invoke-direct/range {v0 .. v5}, Le1/a1;-><init>(Le1/w0;Le1/b1;Lay0/n;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, v0, Le1/a1;->i:Ljava/lang/Object;

    .line 16
    .line 17
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lvy0/b0;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Le1/a1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Le1/a1;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Le1/a1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 2
    .line 3
    iget v1, p0, Le1/a1;->h:I

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    if-eqz v1, :cond_2

    .line 9
    .line 10
    if-eq v1, v3, :cond_1

    .line 11
    .line 12
    if-ne v1, v2, :cond_0

    .line 13
    .line 14
    iget-object v0, p0, Le1/a1;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Le1/b1;

    .line 17
    .line 18
    iget-object v1, p0, Le1/a1;->d:Lez0/a;

    .line 19
    .line 20
    iget-object p0, p0, Le1/a1;->i:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Le1/y0;

    .line 23
    .line 24
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 25
    .line 26
    .line 27
    goto/16 :goto_2

    .line 28
    .line 29
    :catchall_0
    move-exception p1

    .line 30
    goto/16 :goto_4

    .line 31
    .line 32
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_1
    iget-object v1, p0, Le1/a1;->g:Le1/b1;

    .line 41
    .line 42
    iget-object v3, p0, Le1/a1;->f:Ljava/lang/Object;

    .line 43
    .line 44
    iget-object v5, p0, Le1/a1;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast v5, Lay0/n;

    .line 47
    .line 48
    iget-object v6, p0, Le1/a1;->d:Lez0/a;

    .line 49
    .line 50
    iget-object v7, p0, Le1/a1;->i:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v7, Le1/y0;

    .line 53
    .line 54
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    move-object p1, v6

    .line 58
    move-object v6, v5

    .line 59
    move-object v5, p1

    .line 60
    move-object p1, v1

    .line 61
    move-object v1, v7

    .line 62
    goto :goto_0

    .line 63
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Le1/a1;->i:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast p1, Lvy0/b0;

    .line 69
    .line 70
    new-instance v1, Le1/y0;

    .line 71
    .line 72
    invoke-interface {p1}, Lvy0/b0;->getCoroutineContext()Lpx0/g;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    sget-object v5, Lvy0/h1;->d:Lvy0/h1;

    .line 77
    .line 78
    invoke-interface {p1, v5}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    check-cast p1, Lvy0/i1;

    .line 86
    .line 87
    iget-object v5, p0, Le1/a1;->j:Le1/w0;

    .line 88
    .line 89
    invoke-direct {v1, v5, p1}, Le1/y0;-><init>(Le1/w0;Lvy0/i1;)V

    .line 90
    .line 91
    .line 92
    iget-object p1, p0, Le1/a1;->k:Le1/b1;

    .line 93
    .line 94
    invoke-static {p1, v1}, Le1/b1;->a(Le1/b1;Le1/y0;)V

    .line 95
    .line 96
    .line 97
    iget-object v5, p1, Le1/b1;->b:Lez0/c;

    .line 98
    .line 99
    iput-object v1, p0, Le1/a1;->i:Ljava/lang/Object;

    .line 100
    .line 101
    iput-object v5, p0, Le1/a1;->d:Lez0/a;

    .line 102
    .line 103
    iget-object v6, p0, Le1/a1;->l:Lrx0/i;

    .line 104
    .line 105
    iput-object v6, p0, Le1/a1;->e:Ljava/lang/Object;

    .line 106
    .line 107
    iget-object v7, p0, Le1/a1;->m:Ljava/lang/Object;

    .line 108
    .line 109
    iput-object v7, p0, Le1/a1;->f:Ljava/lang/Object;

    .line 110
    .line 111
    iput-object p1, p0, Le1/a1;->g:Le1/b1;

    .line 112
    .line 113
    iput v3, p0, Le1/a1;->h:I

    .line 114
    .line 115
    invoke-virtual {v5, p0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v3

    .line 119
    if-ne v3, v0, :cond_3

    .line 120
    .line 121
    goto :goto_1

    .line 122
    :cond_3
    move-object v3, v7

    .line 123
    :goto_0
    :try_start_1
    iput-object v1, p0, Le1/a1;->i:Ljava/lang/Object;

    .line 124
    .line 125
    iput-object v5, p0, Le1/a1;->d:Lez0/a;

    .line 126
    .line 127
    iput-object p1, p0, Le1/a1;->e:Ljava/lang/Object;

    .line 128
    .line 129
    iput-object v4, p0, Le1/a1;->f:Ljava/lang/Object;

    .line 130
    .line 131
    iput-object v4, p0, Le1/a1;->g:Le1/b1;

    .line 132
    .line 133
    iput v2, p0, Le1/a1;->h:I

    .line 134
    .line 135
    invoke-interface {v6, v3, p0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_2

    .line 139
    if-ne p0, v0, :cond_4

    .line 140
    .line 141
    :goto_1
    return-object v0

    .line 142
    :cond_4
    move-object v0, p1

    .line 143
    move-object p1, p0

    .line 144
    move-object p0, v1

    .line 145
    move-object v1, v5

    .line 146
    :goto_2
    :try_start_2
    iget-object v0, v0, Le1/b1;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 147
    .line 148
    :cond_5
    invoke-virtual {v0, p0, v4}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v2

    .line 152
    if-eqz v2, :cond_6

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_6
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 159
    if-eq v2, p0, :cond_5

    .line 160
    .line 161
    :goto_3
    invoke-interface {v1, v4}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    return-object p1

    .line 165
    :catchall_1
    move-exception p0

    .line 166
    goto :goto_6

    .line 167
    :catchall_2
    move-exception p0

    .line 168
    move-object v0, p1

    .line 169
    move-object p1, p0

    .line 170
    move-object p0, v1

    .line 171
    move-object v1, v5

    .line 172
    :goto_4
    :try_start_3
    iget-object v0, v0, Le1/b1;->a:Ljava/util/concurrent/atomic/AtomicReference;

    .line 173
    .line 174
    :goto_5
    invoke-virtual {v0, p0, v4}, Ljava/util/concurrent/atomic/AtomicReference;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    if-nez v2, :cond_7

    .line 179
    .line 180
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    if-ne v2, p0, :cond_7

    .line 185
    .line 186
    goto :goto_5

    .line 187
    :cond_7
    throw p1
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 188
    :goto_6
    invoke-interface {v1, v4}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 189
    .line 190
    .line 191
    throw p0
.end method

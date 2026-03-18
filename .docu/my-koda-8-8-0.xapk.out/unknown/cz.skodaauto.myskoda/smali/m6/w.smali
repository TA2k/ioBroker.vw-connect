.class public final Lm6/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm6/g;


# instance fields
.field public final a:Lm6/b0;

.field public final b:Lm6/c;

.field public final c:Lvy0/b0;

.field public final d:Lyy0/m1;

.field public final e:Lez0/c;

.field public f:I

.field public g:Lvy0/x1;

.field public final h:Lm6/x;

.field public final i:Lcom/google/firebase/messaging/w;

.field public final j:Llx0/q;

.field public final k:Llx0/q;

.field public final l:Lcom/google/firebase/messaging/w;


# direct methods
.method public constructor <init>(Lm6/b0;Ljava/util/List;Lm6/c;Lvy0/b0;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lm6/w;->a:Lm6/b0;

    .line 5
    .line 6
    iput-object p3, p0, Lm6/w;->b:Lm6/c;

    .line 7
    .line 8
    iput-object p4, p0, Lm6/w;->c:Lvy0/b0;

    .line 9
    .line 10
    new-instance p1, Lk31/l;

    .line 11
    .line 12
    const/16 p3, 0x11

    .line 13
    .line 14
    const/4 v0, 0x0

    .line 15
    invoke-direct {p1, p0, v0, p3}, Lk31/l;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 16
    .line 17
    .line 18
    new-instance p3, Lyy0/m1;

    .line 19
    .line 20
    invoke-direct {p3, p1}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 21
    .line 22
    .line 23
    iput-object p3, p0, Lm6/w;->d:Lyy0/m1;

    .line 24
    .line 25
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lm6/w;->e:Lez0/c;

    .line 30
    .line 31
    new-instance p1, Lm6/x;

    .line 32
    .line 33
    invoke-direct {p1}, Lm6/x;-><init>()V

    .line 34
    .line 35
    .line 36
    iput-object p1, p0, Lm6/w;->h:Lm6/x;

    .line 37
    .line 38
    new-instance p1, Lcom/google/firebase/messaging/w;

    .line 39
    .line 40
    invoke-direct {p1, p0, p2}, Lcom/google/firebase/messaging/w;-><init>(Lm6/w;Ljava/util/List;)V

    .line 41
    .line 42
    .line 43
    iput-object p1, p0, Lm6/w;->i:Lcom/google/firebase/messaging/w;

    .line 44
    .line 45
    new-instance p1, Lm6/l;

    .line 46
    .line 47
    const/4 p2, 0x1

    .line 48
    invoke-direct {p1, p0, p2}, Lm6/l;-><init>(Lm6/w;I)V

    .line 49
    .line 50
    .line 51
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    iput-object p1, p0, Lm6/w;->j:Llx0/q;

    .line 56
    .line 57
    new-instance p1, Lm6/l;

    .line 58
    .line 59
    const/4 p2, 0x0

    .line 60
    invoke-direct {p1, p0, p2}, Lm6/l;-><init>(Lm6/w;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 64
    .line 65
    .line 66
    move-result-object p1

    .line 67
    iput-object p1, p0, Lm6/w;->k:Llx0/q;

    .line 68
    .line 69
    new-instance p1, Lcom/google/firebase/messaging/w;

    .line 70
    .line 71
    new-instance p2, La3/f;

    .line 72
    .line 73
    const/16 p3, 0x18

    .line 74
    .line 75
    invoke-direct {p2, p0, p3}, La3/f;-><init>(Ljava/lang/Object;I)V

    .line 76
    .line 77
    .line 78
    new-instance p3, Lk31/t;

    .line 79
    .line 80
    const/16 v1, 0x15

    .line 81
    .line 82
    invoke-direct {p3, p0, v0, v1}, Lk31/t;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 83
    .line 84
    .line 85
    invoke-direct {p1, p4, p2, p3}, Lcom/google/firebase/messaging/w;-><init>(Lvy0/b0;La3/f;Lk31/t;)V

    .line 86
    .line 87
    .line 88
    iput-object p1, p0, Lm6/w;->l:Lcom/google/firebase/messaging/w;

    .line 89
    .line 90
    return-void
.end method

.method public static final b(Lm6/w;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lm6/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lm6/o;

    .line 7
    .line 8
    iget v1, v0, Lm6/o;->h:I

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
    iput v1, v0, Lm6/o;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lm6/o;-><init>(Lm6/w;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lm6/o;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/o;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lm6/o;->e:Lez0/c;

    .line 37
    .line 38
    iget-object v0, v0, Lm6/o;->d:Lm6/w;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object p1, p0

    .line 44
    move-object p0, v0

    .line 45
    goto :goto_1

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
    iget-object p1, p0, Lm6/w;->e:Lez0/c;

    .line 58
    .line 59
    iput-object p0, v0, Lm6/o;->d:Lm6/w;

    .line 60
    .line 61
    iput-object p1, v0, Lm6/o;->e:Lez0/c;

    .line 62
    .line 63
    iput v3, v0, Lm6/o;->h:I

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    if-ne v0, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    const/4 v0, 0x0

    .line 73
    :try_start_0
    iget v1, p0, Lm6/w;->f:I

    .line 74
    .line 75
    add-int/lit8 v1, v1, -0x1

    .line 76
    .line 77
    iput v1, p0, Lm6/w;->f:I

    .line 78
    .line 79
    if-nez v1, :cond_5

    .line 80
    .line 81
    iget-object v1, p0, Lm6/w;->g:Lvy0/x1;

    .line 82
    .line 83
    if-eqz v1, :cond_4

    .line 84
    .line 85
    invoke-virtual {v1, v0}, Lvy0/p1;->d(Ljava/util/concurrent/CancellationException;)V

    .line 86
    .line 87
    .line 88
    goto :goto_2

    .line 89
    :catchall_0
    move-exception p0

    .line 90
    goto :goto_3

    .line 91
    :cond_4
    :goto_2
    iput-object v0, p0, Lm6/w;->g:Lvy0/x1;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 92
    .line 93
    :cond_5
    invoke-interface {p1, v0}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 97
    .line 98
    return-object p0

    .line 99
    :goto_3
    invoke-interface {p1, v0}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    throw p0
.end method

.method public static final c(Lm6/w;Lm6/j0;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lm6/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm6/p;

    .line 7
    .line 8
    iget v1, v0, Lm6/p;->i:I

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
    iput v1, v0, Lm6/p;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lm6/p;-><init>(Lm6/w;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm6/p;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/p;->i:I

    .line 30
    .line 31
    const/4 v8, 0x0

    .line 32
    const/4 v3, 0x3

    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_4

    .line 36
    .line 37
    if-eq v2, v5, :cond_1

    .line 38
    .line 39
    if-eq v2, v4, :cond_3

    .line 40
    .line 41
    if-ne v2, v3, :cond_2

    .line 42
    .line 43
    :cond_1
    iget-object p0, v0, Lm6/p;->d:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast p0, Lvy0/q;

    .line 46
    .line 47
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto/16 :goto_7

    .line 51
    .line 52
    :catchall_0
    move-exception v0

    .line 53
    move-object p1, v0

    .line 54
    goto/16 :goto_6

    .line 55
    .line 56
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :cond_3
    iget-object p0, v0, Lm6/p;->f:Lvy0/r;

    .line 65
    .line 66
    iget-object p1, v0, Lm6/p;->e:Lm6/w;

    .line 67
    .line 68
    iget-object v2, v0, Lm6/p;->d:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v2, Lm6/j0;

    .line 71
    .line 72
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    .line 74
    .line 75
    move-object v5, p1

    .line 76
    move-object p1, v2

    .line 77
    goto/16 :goto_4

    .line 78
    .line 79
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    iget-object p2, p1, Lm6/j0;->b:Lvy0/r;

    .line 83
    .line 84
    :try_start_2
    iget-object v2, p0, Lm6/w;->h:Lm6/x;

    .line 85
    .line 86
    invoke-virtual {v2}, Lm6/x;->a()Lm6/z0;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    instance-of v6, v2, Lm6/d;

    .line 91
    .line 92
    if-eqz v6, :cond_6

    .line 93
    .line 94
    iget-object v7, p1, Lm6/j0;->a:Lay0/n;

    .line 95
    .line 96
    iget-object v6, p1, Lm6/j0;->d:Lpx0/g;

    .line 97
    .line 98
    iput-object p2, v0, Lm6/p;->d:Ljava/lang/Object;

    .line 99
    .line 100
    iput v5, v0, Lm6/p;->i:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 101
    .line 102
    :try_start_3
    invoke-virtual {p0}, Lm6/w;->g()Lm6/i0;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    new-instance v3, Ld40/k;

    .line 107
    .line 108
    const/16 v4, 0x8

    .line 109
    .line 110
    move-object v5, p0

    .line 111
    invoke-direct/range {v3 .. v8}, Ld40/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 112
    .line 113
    .line 114
    invoke-interface {p1, v3, v0}, Lm6/i0;->a(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 118
    if-ne p0, v1, :cond_5

    .line 119
    .line 120
    goto :goto_5

    .line 121
    :cond_5
    move-object v9, p2

    .line 122
    move-object p2, p0

    .line 123
    move-object p0, v9

    .line 124
    goto/16 :goto_7

    .line 125
    .line 126
    :goto_1
    move-object p1, p0

    .line 127
    goto :goto_2

    .line 128
    :catchall_1
    move-exception v0

    .line 129
    move-object p0, v0

    .line 130
    goto :goto_1

    .line 131
    :goto_2
    move-object p0, p2

    .line 132
    goto :goto_6

    .line 133
    :catchall_2
    move-exception v0

    .line 134
    move-object p1, v0

    .line 135
    goto :goto_2

    .line 136
    :cond_6
    :try_start_4
    instance-of v6, v2, Lm6/s0;

    .line 137
    .line 138
    if-eqz v6, :cond_7

    .line 139
    .line 140
    goto :goto_3

    .line 141
    :cond_7
    instance-of v5, v2, Lm6/a1;

    .line 142
    .line 143
    :goto_3
    if-eqz v5, :cond_a

    .line 144
    .line 145
    iget-object v5, p1, Lm6/j0;->c:Lm6/z0;

    .line 146
    .line 147
    if-ne v2, v5, :cond_9

    .line 148
    .line 149
    iput-object p1, v0, Lm6/p;->d:Ljava/lang/Object;

    .line 150
    .line 151
    iput-object p0, v0, Lm6/p;->e:Lm6/w;

    .line 152
    .line 153
    iput-object p2, v0, Lm6/p;->f:Lvy0/r;

    .line 154
    .line 155
    iput v4, v0, Lm6/p;->i:I

    .line 156
    .line 157
    invoke-virtual {p0, v0}, Lm6/w;->h(Lrx0/c;)Ljava/lang/Object;

    .line 158
    .line 159
    .line 160
    move-result-object v2
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 161
    if-ne v2, v1, :cond_8

    .line 162
    .line 163
    goto :goto_5

    .line 164
    :cond_8
    move-object v5, p0

    .line 165
    move-object p0, p2

    .line 166
    :goto_4
    :try_start_5
    iget-object v7, p1, Lm6/j0;->a:Lay0/n;

    .line 167
    .line 168
    iget-object v6, p1, Lm6/j0;->d:Lpx0/g;

    .line 169
    .line 170
    iput-object p0, v0, Lm6/p;->d:Ljava/lang/Object;

    .line 171
    .line 172
    iput-object v8, v0, Lm6/p;->e:Lm6/w;

    .line 173
    .line 174
    iput-object v8, v0, Lm6/p;->f:Lvy0/r;

    .line 175
    .line 176
    iput v3, v0, Lm6/p;->i:I

    .line 177
    .line 178
    invoke-virtual {v5}, Lm6/w;->g()Lm6/i0;

    .line 179
    .line 180
    .line 181
    move-result-object p1

    .line 182
    new-instance v3, Ld40/k;

    .line 183
    .line 184
    const/16 v4, 0x8

    .line 185
    .line 186
    invoke-direct/range {v3 .. v8}, Ld40/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 187
    .line 188
    .line 189
    invoke-interface {p1, v3, v0}, Lm6/i0;->a(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 193
    if-ne p2, v1, :cond_c

    .line 194
    .line 195
    :goto_5
    return-object v1

    .line 196
    :cond_9
    :try_start_6
    const-string p0, "null cannot be cast to non-null type androidx.datastore.core.ReadException<T of androidx.datastore.core.DataStoreImpl.handleUpdate$lambda$2>"

    .line 197
    .line 198
    invoke-static {v2, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 199
    .line 200
    .line 201
    check-cast v2, Lm6/s0;

    .line 202
    .line 203
    iget-object p0, v2, Lm6/s0;->b:Ljava/lang/Throwable;

    .line 204
    .line 205
    throw p0

    .line 206
    :cond_a
    instance-of p0, v2, Lm6/h0;

    .line 207
    .line 208
    if-eqz p0, :cond_b

    .line 209
    .line 210
    check-cast v2, Lm6/h0;

    .line 211
    .line 212
    iget-object p0, v2, Lm6/h0;->b:Ljava/lang/Throwable;

    .line 213
    .line 214
    throw p0

    .line 215
    :cond_b
    new-instance p0, La8/r0;

    .line 216
    .line 217
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 218
    .line 219
    .line 220
    throw p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 221
    :goto_6
    invoke-static {p1}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 222
    .line 223
    .line 224
    move-result-object p2

    .line 225
    :cond_c
    :goto_7
    invoke-static {p2}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 226
    .line 227
    .line 228
    move-result-object p1

    .line 229
    check-cast p0, Lvy0/r;

    .line 230
    .line 231
    if-nez p1, :cond_d

    .line 232
    .line 233
    invoke-virtual {p0, p2}, Lvy0/p1;->W(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    goto :goto_8

    .line 237
    :cond_d
    invoke-virtual {p0, p1}, Lvy0/r;->l0(Ljava/lang/Throwable;)Z

    .line 238
    .line 239
    .line 240
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 241
    .line 242
    return-object p0
.end method

.method public static final d(Lm6/w;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lm6/q;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lm6/q;

    .line 7
    .line 8
    iget v1, v0, Lm6/q;->h:I

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
    iput v1, v0, Lm6/q;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/q;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lm6/q;-><init>(Lm6/w;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lm6/q;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/q;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lm6/q;->e:Lez0/c;

    .line 37
    .line 38
    iget-object v0, v0, Lm6/q;->d:Lm6/w;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    move-object p1, p0

    .line 44
    move-object p0, v0

    .line 45
    goto :goto_1

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
    iget-object p1, p0, Lm6/w;->e:Lez0/c;

    .line 58
    .line 59
    iput-object p0, v0, Lm6/q;->d:Lm6/w;

    .line 60
    .line 61
    iput-object p1, v0, Lm6/q;->e:Lez0/c;

    .line 62
    .line 63
    iput v3, v0, Lm6/q;->h:I

    .line 64
    .line 65
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    if-ne v0, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    :goto_1
    const/4 v0, 0x0

    .line 73
    :try_start_0
    iget v1, p0, Lm6/w;->f:I

    .line 74
    .line 75
    add-int/2addr v1, v3

    .line 76
    iput v1, p0, Lm6/w;->f:I

    .line 77
    .line 78
    if-ne v1, v3, :cond_4

    .line 79
    .line 80
    iget-object v1, p0, Lm6/w;->c:Lvy0/b0;

    .line 81
    .line 82
    new-instance v2, Lm6/m;

    .line 83
    .line 84
    const/4 v3, 0x1

    .line 85
    invoke-direct {v2, p0, v0, v3}, Lm6/m;-><init>(Lm6/w;Lkotlin/coroutines/Continuation;I)V

    .line 86
    .line 87
    .line 88
    const/4 v3, 0x3

    .line 89
    invoke-static {v1, v0, v0, v2, v3}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 90
    .line 91
    .line 92
    move-result-object v1

    .line 93
    iput-object v1, p0, Lm6/w;->g:Lvy0/x1;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :catchall_0
    move-exception p0

    .line 97
    goto :goto_3

    .line 98
    :cond_4
    :goto_2
    invoke-interface {p1, v0}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    return-object p0

    .line 104
    :goto_3
    invoke-interface {p1, v0}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    throw p0
.end method

.method public static final e(Lm6/w;ZLkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lm6/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm6/s;

    .line 7
    .line 8
    iget v1, v0, Lm6/s;->i:I

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
    iput v1, v0, Lm6/s;->i:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lm6/s;-><init>(Lm6/w;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lm6/s;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/s;->i:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    if-eq v2, v5, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lm6/s;->d:Lm6/w;

    .line 43
    .line 44
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto/16 :goto_5

    .line 48
    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p0, v0, Lm6/s;->d:Lm6/w;

    .line 58
    .line 59
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    iget-boolean p1, v0, Lm6/s;->f:Z

    .line 64
    .line 65
    iget-object p0, v0, Lm6/s;->e:Lm6/z0;

    .line 66
    .line 67
    iget-object v2, v0, Lm6/s;->d:Lm6/w;

    .line 68
    .line 69
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object p2, p0, Lm6/w;->h:Lm6/x;

    .line 77
    .line 78
    invoke-virtual {p2}, Lm6/x;->a()Lm6/z0;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    instance-of v2, p2, Lm6/a1;

    .line 83
    .line 84
    if-nez v2, :cond_c

    .line 85
    .line 86
    invoke-virtual {p0}, Lm6/w;->g()Lm6/i0;

    .line 87
    .line 88
    .line 89
    move-result-object v2

    .line 90
    iput-object p0, v0, Lm6/s;->d:Lm6/w;

    .line 91
    .line 92
    iput-object p2, v0, Lm6/s;->e:Lm6/z0;

    .line 93
    .line 94
    iput-boolean p1, v0, Lm6/s;->f:Z

    .line 95
    .line 96
    iput v5, v0, Lm6/s;->i:I

    .line 97
    .line 98
    invoke-interface {v2, v0}, Lm6/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    if-ne v2, v1, :cond_5

    .line 103
    .line 104
    goto :goto_4

    .line 105
    :cond_5
    move-object v7, v2

    .line 106
    move-object v2, p0

    .line 107
    move-object p0, p2

    .line 108
    move-object p2, v7

    .line 109
    :goto_1
    check-cast p2, Ljava/lang/Number;

    .line 110
    .line 111
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 112
    .line 113
    .line 114
    move-result p2

    .line 115
    instance-of v5, p0, Lm6/d;

    .line 116
    .line 117
    if-eqz v5, :cond_6

    .line 118
    .line 119
    iget v6, p0, Lm6/z0;->a:I

    .line 120
    .line 121
    goto :goto_2

    .line 122
    :cond_6
    const/4 v6, -0x1

    .line 123
    :goto_2
    if-eqz v5, :cond_7

    .line 124
    .line 125
    if-ne p2, v6, :cond_7

    .line 126
    .line 127
    return-object p0

    .line 128
    :cond_7
    const/4 p0, 0x0

    .line 129
    if-eqz p1, :cond_9

    .line 130
    .line 131
    invoke-virtual {v2}, Lm6/w;->g()Lm6/i0;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    new-instance p2, Llo0/b;

    .line 136
    .line 137
    invoke-direct {p2, v2, p0}, Llo0/b;-><init>(Lm6/w;Lkotlin/coroutines/Continuation;)V

    .line 138
    .line 139
    .line 140
    iput-object v2, v0, Lm6/s;->d:Lm6/w;

    .line 141
    .line 142
    iput-object p0, v0, Lm6/s;->e:Lm6/z0;

    .line 143
    .line 144
    iput v4, v0, Lm6/s;->i:I

    .line 145
    .line 146
    invoke-interface {p1, p2, v0}, Lm6/i0;->a(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p2

    .line 150
    if-ne p2, v1, :cond_8

    .line 151
    .line 152
    goto :goto_4

    .line 153
    :cond_8
    move-object p0, v2

    .line 154
    :goto_3
    check-cast p2, Llx0/l;

    .line 155
    .line 156
    goto :goto_6

    .line 157
    :cond_9
    invoke-virtual {v2}, Lm6/w;->g()Lm6/i0;

    .line 158
    .line 159
    .line 160
    move-result-object p1

    .line 161
    new-instance p2, Lfw0/e;

    .line 162
    .line 163
    const/4 v4, 0x1

    .line 164
    invoke-direct {p2, v2, v6, p0, v4}, Lfw0/e;-><init>(Lm6/w;ILkotlin/coroutines/Continuation;I)V

    .line 165
    .line 166
    .line 167
    iput-object v2, v0, Lm6/s;->d:Lm6/w;

    .line 168
    .line 169
    iput-object p0, v0, Lm6/s;->e:Lm6/z0;

    .line 170
    .line 171
    iput v3, v0, Lm6/s;->i:I

    .line 172
    .line 173
    invoke-interface {p1, p2, v0}, Lm6/i0;->d(Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p2

    .line 177
    if-ne p2, v1, :cond_a

    .line 178
    .line 179
    :goto_4
    return-object v1

    .line 180
    :cond_a
    move-object p0, v2

    .line 181
    :goto_5
    check-cast p2, Llx0/l;

    .line 182
    .line 183
    :goto_6
    iget-object p1, p2, Llx0/l;->d:Ljava/lang/Object;

    .line 184
    .line 185
    check-cast p1, Lm6/z0;

    .line 186
    .line 187
    iget-object p2, p2, Llx0/l;->e:Ljava/lang/Object;

    .line 188
    .line 189
    check-cast p2, Ljava/lang/Boolean;

    .line 190
    .line 191
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 192
    .line 193
    .line 194
    move-result p2

    .line 195
    if-eqz p2, :cond_b

    .line 196
    .line 197
    iget-object p0, p0, Lm6/w;->h:Lm6/x;

    .line 198
    .line 199
    invoke-virtual {p0, p1}, Lm6/x;->b(Lm6/z0;)V

    .line 200
    .line 201
    .line 202
    :cond_b
    return-object p1

    .line 203
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 204
    .line 205
    const-string p1, "This is a bug in DataStore. Please file a bug at: https://issuetracker.google.com/issues/new?component=907884&template=1466542"

    .line 206
    .line 207
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    throw p0
.end method

.method public static final f(Lm6/w;ZLrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p2, Lm6/t;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lm6/t;

    .line 7
    .line 8
    iget v1, v0, Lm6/t;->l:I

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
    iput v1, v0, Lm6/t;->l:I

    .line 18
    .line 19
    :goto_0
    move-object p2, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lm6/t;

    .line 22
    .line 23
    invoke-direct {v0, p0, p2}, Lm6/t;-><init>(Lm6/w;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p2, Lm6/t;->j:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, p2, Lm6/t;->l:I

    .line 32
    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v9, 0x0

    .line 35
    packed-switch v2, :pswitch_data_0

    .line 36
    .line 37
    .line 38
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :pswitch_0
    iget-object p0, p2, Lm6/t;->f:Ljava/io/Serializable;

    .line 47
    .line 48
    check-cast p0, Lkotlin/jvm/internal/d0;

    .line 49
    .line 50
    iget-object p1, p2, Lm6/t;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast p1, Lkotlin/jvm/internal/f0;

    .line 53
    .line 54
    iget-object p2, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast p2, Lm6/b;

    .line 57
    .line 58
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    goto/16 :goto_a

    .line 62
    .line 63
    :catchall_0
    move-exception v0

    .line 64
    move-object p0, v0

    .line 65
    goto/16 :goto_d

    .line 66
    .line 67
    :pswitch_1
    iget-boolean p0, p2, Lm6/t;->h:Z

    .line 68
    .line 69
    iget-object p1, p2, Lm6/t;->g:Lkotlin/jvm/internal/f0;

    .line 70
    .line 71
    iget-object v2, p2, Lm6/t;->f:Ljava/io/Serializable;

    .line 72
    .line 73
    check-cast v2, Lkotlin/jvm/internal/f0;

    .line 74
    .line 75
    iget-object v4, p2, Lm6/t;->e:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v4, Lm6/b;

    .line 78
    .line 79
    iget-object v5, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v5, Lm6/w;

    .line 82
    .line 83
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    move-object v6, v2

    .line 87
    move-object v2, v4

    .line 88
    move-object v7, v5

    .line 89
    goto/16 :goto_8

    .line 90
    .line 91
    :pswitch_2
    iget-boolean p1, p2, Lm6/t;->h:Z

    .line 92
    .line 93
    iget-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 94
    .line 95
    check-cast p0, Lm6/w;

    .line 96
    .line 97
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Lm6/b; {:try_start_1 .. :try_end_1} :catch_0

    .line 98
    .line 99
    .line 100
    goto/16 :goto_6

    .line 101
    .line 102
    :catch_0
    move-exception v0

    .line 103
    goto/16 :goto_7

    .line 104
    .line 105
    :pswitch_3
    iget-boolean p1, p2, Lm6/t;->h:Z

    .line 106
    .line 107
    iget-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 108
    .line 109
    check-cast p0, Lm6/w;

    .line 110
    .line 111
    :try_start_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catch Lm6/b; {:try_start_2 .. :try_end_2} :catch_0

    .line 112
    .line 113
    .line 114
    goto/16 :goto_5

    .line 115
    .line 116
    :pswitch_4
    iget p0, p2, Lm6/t;->i:I

    .line 117
    .line 118
    iget-boolean p1, p2, Lm6/t;->h:Z

    .line 119
    .line 120
    iget-object v2, p2, Lm6/t;->e:Ljava/lang/Object;

    .line 121
    .line 122
    iget-object v4, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v4, Lm6/w;

    .line 125
    .line 126
    :try_start_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_3
    .catch Lm6/b; {:try_start_3 .. :try_end_3} :catch_1

    .line 127
    .line 128
    .line 129
    goto :goto_4

    .line 130
    :catch_1
    move-exception v0

    .line 131
    move-object p0, v4

    .line 132
    goto/16 :goto_7

    .line 133
    .line 134
    :pswitch_5
    iget-boolean p1, p2, Lm6/t;->h:Z

    .line 135
    .line 136
    iget-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p0, Lm6/w;

    .line 139
    .line 140
    :try_start_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_4
    .catch Lm6/b; {:try_start_4 .. :try_end_4} :catch_0

    .line 141
    .line 142
    .line 143
    goto :goto_2

    .line 144
    :pswitch_6
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    if-eqz p1, :cond_4

    .line 148
    .line 149
    :try_start_5
    iput-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 150
    .line 151
    iput-boolean p1, p2, Lm6/t;->h:Z

    .line 152
    .line 153
    const/4 v0, 0x1

    .line 154
    iput v0, p2, Lm6/t;->l:I

    .line 155
    .line 156
    invoke-virtual {p0, p2}, Lm6/w;->i(Lrx0/c;)Ljava/lang/Object;

    .line 157
    .line 158
    .line 159
    move-result-object v0

    .line 160
    if-ne v0, v1, :cond_1

    .line 161
    .line 162
    goto/16 :goto_b

    .line 163
    .line 164
    :cond_1
    :goto_2
    if-eqz v0, :cond_2

    .line 165
    .line 166
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    goto :goto_3

    .line 171
    :cond_2
    move v2, v3

    .line 172
    :goto_3
    invoke-virtual {p0}, Lm6/w;->g()Lm6/i0;

    .line 173
    .line 174
    .line 175
    move-result-object v4

    .line 176
    iput-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 177
    .line 178
    iput-object v0, p2, Lm6/t;->e:Ljava/lang/Object;

    .line 179
    .line 180
    iput-boolean p1, p2, Lm6/t;->h:Z

    .line 181
    .line 182
    iput v2, p2, Lm6/t;->i:I

    .line 183
    .line 184
    const/4 v5, 0x2

    .line 185
    iput v5, p2, Lm6/t;->l:I

    .line 186
    .line 187
    invoke-interface {v4, p2}, Lm6/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v4
    :try_end_5
    .catch Lm6/b; {:try_start_5 .. :try_end_5} :catch_0

    .line 191
    if-ne v4, v1, :cond_3

    .line 192
    .line 193
    goto/16 :goto_b

    .line 194
    .line 195
    :cond_3
    move-object v10, v4

    .line 196
    move-object v4, p0

    .line 197
    move p0, v2

    .line 198
    move-object v2, v0

    .line 199
    move-object v0, v10

    .line 200
    :goto_4
    :try_start_6
    check-cast v0, Ljava/lang/Number;

    .line 201
    .line 202
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 203
    .line 204
    .line 205
    move-result v0

    .line 206
    new-instance v5, Lm6/d;

    .line 207
    .line 208
    invoke-direct {v5, v2, p0, v0}, Lm6/d;-><init>(Ljava/lang/Object;II)V
    :try_end_6
    .catch Lm6/b; {:try_start_6 .. :try_end_6} :catch_1

    .line 209
    .line 210
    .line 211
    return-object v5

    .line 212
    :cond_4
    :try_start_7
    invoke-virtual {p0}, Lm6/w;->g()Lm6/i0;

    .line 213
    .line 214
    .line 215
    move-result-object v0

    .line 216
    iput-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 217
    .line 218
    iput-boolean p1, p2, Lm6/t;->h:Z

    .line 219
    .line 220
    const/4 v2, 0x3

    .line 221
    iput v2, p2, Lm6/t;->l:I

    .line 222
    .line 223
    invoke-interface {v0, p2}, Lm6/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    if-ne v0, v1, :cond_5

    .line 228
    .line 229
    goto/16 :goto_b

    .line 230
    .line 231
    :cond_5
    :goto_5
    check-cast v0, Ljava/lang/Number;

    .line 232
    .line 233
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 234
    .line 235
    .line 236
    move-result v0

    .line 237
    invoke-virtual {p0}, Lm6/w;->g()Lm6/i0;

    .line 238
    .line 239
    .line 240
    move-result-object v2

    .line 241
    new-instance v4, Lfw0/e;

    .line 242
    .line 243
    const/4 v5, 0x2

    .line 244
    invoke-direct {v4, p0, v0, v9, v5}, Lfw0/e;-><init>(Lm6/w;ILkotlin/coroutines/Continuation;I)V

    .line 245
    .line 246
    .line 247
    iput-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 248
    .line 249
    iput-boolean p1, p2, Lm6/t;->h:Z

    .line 250
    .line 251
    const/4 v0, 0x4

    .line 252
    iput v0, p2, Lm6/t;->l:I

    .line 253
    .line 254
    invoke-interface {v2, v4, p2}, Lm6/i0;->d(Lay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    if-ne v0, v1, :cond_6

    .line 259
    .line 260
    goto/16 :goto_b

    .line 261
    .line 262
    :cond_6
    :goto_6
    check-cast v0, Lm6/d;
    :try_end_7
    .catch Lm6/b; {:try_start_7 .. :try_end_7} :catch_0

    .line 263
    .line 264
    return-object v0

    .line 265
    :goto_7
    new-instance v2, Lkotlin/jvm/internal/f0;

    .line 266
    .line 267
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 268
    .line 269
    .line 270
    iget-object v4, p0, Lm6/w;->b:Lm6/c;

    .line 271
    .line 272
    iput-object p0, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 273
    .line 274
    iput-object v0, p2, Lm6/t;->e:Ljava/lang/Object;

    .line 275
    .line 276
    iput-object v2, p2, Lm6/t;->f:Ljava/io/Serializable;

    .line 277
    .line 278
    iput-object v2, p2, Lm6/t;->g:Lkotlin/jvm/internal/f0;

    .line 279
    .line 280
    iput-boolean p1, p2, Lm6/t;->h:Z

    .line 281
    .line 282
    const/4 v5, 0x5

    .line 283
    iput v5, p2, Lm6/t;->l:I

    .line 284
    .line 285
    invoke-interface {v4, v0}, Lm6/c;->b(Lm6/b;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v4

    .line 289
    if-ne v4, v1, :cond_7

    .line 290
    .line 291
    goto :goto_b

    .line 292
    :cond_7
    move-object v7, p0

    .line 293
    move p0, p1

    .line 294
    move-object p1, v2

    .line 295
    move-object v6, p1

    .line 296
    move-object v2, v0

    .line 297
    move-object v0, v4

    .line 298
    :goto_8
    iput-object v0, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 299
    .line 300
    new-instance v8, Lkotlin/jvm/internal/d0;

    .line 301
    .line 302
    invoke-direct {v8}, Ljava/lang/Object;-><init>()V

    .line 303
    .line 304
    .line 305
    :try_start_8
    new-instance v4, Ld40/k;

    .line 306
    .line 307
    const/4 v5, 0x7

    .line 308
    invoke-direct/range {v4 .. v9}, Ld40/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 309
    .line 310
    .line 311
    iput-object v2, p2, Lm6/t;->d:Ljava/lang/Object;

    .line 312
    .line 313
    iput-object v6, p2, Lm6/t;->e:Ljava/lang/Object;

    .line 314
    .line 315
    iput-object v8, p2, Lm6/t;->f:Ljava/io/Serializable;

    .line 316
    .line 317
    iput-object v9, p2, Lm6/t;->g:Lkotlin/jvm/internal/f0;

    .line 318
    .line 319
    const/4 p1, 0x6

    .line 320
    iput p1, p2, Lm6/t;->l:I

    .line 321
    .line 322
    if-eqz p0, :cond_8

    .line 323
    .line 324
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 325
    .line 326
    .line 327
    invoke-virtual {v4, p2}, Ld40/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 328
    .line 329
    .line 330
    move-result-object p0

    .line 331
    goto :goto_9

    .line 332
    :cond_8
    invoke-virtual {v7}, Lm6/w;->g()Lm6/i0;

    .line 333
    .line 334
    .line 335
    move-result-object p0

    .line 336
    new-instance p1, La90/s;

    .line 337
    .line 338
    const/16 v0, 0x10

    .line 339
    .line 340
    invoke-direct {p1, v4, v9, v0}, La90/s;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 341
    .line 342
    .line 343
    invoke-interface {p0, p1, p2}, Lm6/i0;->a(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 344
    .line 345
    .line 346
    move-result-object p0
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_1

    .line 347
    :goto_9
    if-ne p0, v1, :cond_9

    .line 348
    .line 349
    goto :goto_b

    .line 350
    :cond_9
    move-object p1, v6

    .line 351
    move-object p0, v8

    .line 352
    :goto_a
    new-instance v1, Lm6/d;

    .line 353
    .line 354
    iget-object p1, p1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 355
    .line 356
    if-eqz p1, :cond_a

    .line 357
    .line 358
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 359
    .line 360
    .line 361
    move-result v3

    .line 362
    :cond_a
    iget p0, p0, Lkotlin/jvm/internal/d0;->d:I

    .line 363
    .line 364
    invoke-direct {v1, p1, v3, p0}, Lm6/d;-><init>(Ljava/lang/Object;II)V

    .line 365
    .line 366
    .line 367
    :goto_b
    return-object v1

    .line 368
    :goto_c
    move-object p2, v2

    .line 369
    goto :goto_d

    .line 370
    :catchall_1
    move-exception v0

    .line 371
    move-object p0, v0

    .line 372
    goto :goto_c

    .line 373
    :goto_d
    invoke-static {p2, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 374
    .line 375
    .line 376
    throw p2

    .line 377
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    invoke-interface {p2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lm6/c1;->d:Lm6/c1;

    .line 6
    .line 7
    invoke-interface {v0, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lm6/d1;

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Lm6/d1;->c(Lm6/w;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    new-instance v1, Lm6/d1;

    .line 19
    .line 20
    invoke-direct {v1, v0, p0}, Lm6/d1;-><init>(Lm6/d1;Lm6/w;)V

    .line 21
    .line 22
    .line 23
    new-instance v0, Lk31/l;

    .line 24
    .line 25
    const/4 v2, 0x0

    .line 26
    const/16 v3, 0x12

    .line 27
    .line 28
    invoke-direct {v0, v3, p0, p1, v2}, Lk31/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    invoke-static {v1, v0, p2}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0
.end method

.method public final g()Lm6/i0;
    .locals 0

    .line 1
    iget-object p0, p0, Lm6/w;->k:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lm6/i0;

    .line 8
    .line 9
    return-object p0
.end method

.method public final getData()Lyy0/i;
    .locals 0

    .line 1
    iget-object p0, p0, Lm6/w;->d:Lyy0/m1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lm6/r;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lm6/r;

    .line 7
    .line 8
    iget v1, v0, Lm6/r;->h:I

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
    iput v1, v0, Lm6/r;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/r;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lm6/r;-><init>(Lm6/w;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lm6/r;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/r;->h:I

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
    iget p0, v0, Lm6/r;->e:I

    .line 40
    .line 41
    iget-object v0, v0, Lm6/r;->d:Lm6/w;

    .line 42
    .line 43
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    .line 45
    .line 46
    goto :goto_3

    .line 47
    :catchall_0
    move-exception p1

    .line 48
    goto :goto_4

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p0, v0, Lm6/r;->d:Lm6/w;

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    invoke-virtual {p0}, Lm6/w;->g()Lm6/i0;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    iput-object p0, v0, Lm6/r;->d:Lm6/w;

    .line 71
    .line 72
    iput v4, v0, Lm6/r;->h:I

    .line 73
    .line 74
    invoke-interface {p1, v0}, Lm6/i0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    if-ne p1, v1, :cond_4

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/Number;

    .line 82
    .line 83
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 84
    .line 85
    .line 86
    move-result p1

    .line 87
    :try_start_1
    iget-object v2, p0, Lm6/w;->i:Lcom/google/firebase/messaging/w;

    .line 88
    .line 89
    iput-object p0, v0, Lm6/r;->d:Lm6/w;

    .line 90
    .line 91
    iput p1, v0, Lm6/r;->e:I

    .line 92
    .line 93
    iput v3, v0, Lm6/r;->h:I

    .line 94
    .line 95
    invoke-virtual {v2, v0}, Lcom/google/firebase/messaging/w;->q(Lrx0/c;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 99
    if-ne p0, v1, :cond_5

    .line 100
    .line 101
    :goto_2
    return-object v1

    .line 102
    :cond_5
    :goto_3
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    return-object p0

    .line 105
    :catchall_1
    move-exception v0

    .line 106
    move-object v5, v0

    .line 107
    move-object v0, p0

    .line 108
    move p0, p1

    .line 109
    move-object p1, v5

    .line 110
    :goto_4
    iget-object v0, v0, Lm6/w;->h:Lm6/x;

    .line 111
    .line 112
    new-instance v1, Lm6/s0;

    .line 113
    .line 114
    invoke-direct {v1, p1, p0}, Lm6/s0;-><init>(Ljava/lang/Throwable;I)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v0, v1}, Lm6/x;->b(Lm6/z0;)V

    .line 118
    .line 119
    .line 120
    throw p1
.end method

.method public final i(Lrx0/c;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object p0, p0, Lm6/w;->j:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {p0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lm6/e0;

    .line 8
    .line 9
    new-instance v0, Lkn/o;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-direct {v0, v2, v1}, Lkn/o;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0, p1}, Lm6/e0;->a(Lkn/o;Lrx0/c;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    return-object p0
.end method

.method public final j(Ljava/lang/Object;ZLrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p3, Lm6/u;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lm6/u;

    .line 7
    .line 8
    iget v1, v0, Lm6/u;->g:I

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
    iput v1, v0, Lm6/u;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lm6/u;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lm6/u;-><init>(Lm6/w;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lm6/u;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lm6/u;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lm6/u;->d:Lkotlin/jvm/internal/d0;

    .line 37
    .line 38
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance v5, Lkotlin/jvm/internal/d0;

    .line 54
    .line 55
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    iget-object p3, p0, Lm6/w;->j:Llx0/q;

    .line 59
    .line 60
    invoke-virtual {p3}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p3

    .line 64
    check-cast p3, Lm6/e0;

    .line 65
    .line 66
    new-instance v4, Lm6/v;

    .line 67
    .line 68
    const/4 v9, 0x0

    .line 69
    move-object v6, p0

    .line 70
    move-object v7, p1

    .line 71
    move v8, p2

    .line 72
    invoke-direct/range {v4 .. v9}, Lm6/v;-><init>(Lkotlin/jvm/internal/d0;Lm6/w;Ljava/lang/Object;ZLkotlin/coroutines/Continuation;)V

    .line 73
    .line 74
    .line 75
    iput-object v5, v0, Lm6/u;->d:Lkotlin/jvm/internal/d0;

    .line 76
    .line 77
    iput v3, v0, Lm6/u;->g:I

    .line 78
    .line 79
    invoke-virtual {p3, v4, v0}, Lm6/e0;->b(Lm6/v;Lrx0/c;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    if-ne p0, v1, :cond_3

    .line 84
    .line 85
    return-object v1

    .line 86
    :cond_3
    move-object p0, v5

    .line 87
    :goto_1
    iget p0, p0, Lkotlin/jvm/internal/d0;->d:I

    .line 88
    .line 89
    new-instance p1, Ljava/lang/Integer;

    .line 90
    .line 91
    invoke-direct {p1, p0}, Ljava/lang/Integer;-><init>(I)V

    .line 92
    .line 93
    .line 94
    return-object p1
.end method

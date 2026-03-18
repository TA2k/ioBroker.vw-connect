.class public final Lk4/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ll2/t2;


# instance fields
.field public final d:Ljava/util/List;

.field public final e:Lk4/f0;

.field public final f:Lil/g;

.field public final g:Lay0/k;

.field public final h:Lcq/r1;

.field public final i:Ll2/j1;

.field public j:Z


# direct methods
.method public constructor <init>(Ljava/util/List;Ljava/lang/Object;Lk4/f0;Lil/g;Lay0/k;Lcq/r1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk4/f;->d:Ljava/util/List;

    .line 5
    .line 6
    iput-object p3, p0, Lk4/f;->e:Lk4/f0;

    .line 7
    .line 8
    iput-object p4, p0, Lk4/f;->f:Lil/g;

    .line 9
    .line 10
    iput-object p5, p0, Lk4/f;->g:Lay0/k;

    .line 11
    .line 12
    iput-object p6, p0, Lk4/f;->h:Lcq/r1;

    .line 13
    .line 14
    invoke-static {p2}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    iput-object p1, p0, Lk4/f;->i:Ll2/j1;

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    iput-boolean p1, p0, Lk4/f;->j:Z

    .line 22
    .line 23
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    instance-of v2, v0, Lk4/d;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v0

    .line 10
    check-cast v2, Lk4/d;

    .line 11
    .line 12
    iget v3, v2, Lk4/d;->j:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lk4/d;->j:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lk4/d;

    .line 25
    .line 26
    invoke-direct {v2, v1, v0}, Lk4/d;-><init>(Lk4/f;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v0, v2, Lk4/d;->h:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lk4/d;->j:I

    .line 34
    .line 35
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    const/4 v6, 0x0

    .line 38
    iget-object v7, v1, Lk4/f;->g:Lay0/k;

    .line 39
    .line 40
    const/4 v8, 0x2

    .line 41
    iget-object v9, v1, Lk4/f;->i:Ll2/j1;

    .line 42
    .line 43
    const/4 v10, 0x1

    .line 44
    if-eqz v4, :cond_3

    .line 45
    .line 46
    if-eq v4, v10, :cond_2

    .line 47
    .line 48
    if-ne v4, v8, :cond_1

    .line 49
    .line 50
    iget v4, v2, Lk4/d;->g:I

    .line 51
    .line 52
    iget v12, v2, Lk4/d;->f:I

    .line 53
    .line 54
    iget-object v13, v2, Lk4/d;->d:Ljava/util/List;

    .line 55
    .line 56
    check-cast v13, Ljava/util/List;

    .line 57
    .line 58
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    .line 61
    goto/16 :goto_5

    .line 62
    .line 63
    :catchall_0
    move-exception v0

    .line 64
    goto/16 :goto_6

    .line 65
    .line 66
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 69
    .line 70
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    throw v0

    .line 74
    :cond_2
    iget v4, v2, Lk4/d;->g:I

    .line 75
    .line 76
    iget v12, v2, Lk4/d;->f:I

    .line 77
    .line 78
    iget-object v13, v2, Lk4/d;->e:Lk4/l;

    .line 79
    .line 80
    iget-object v14, v2, Lk4/d;->d:Ljava/util/List;

    .line 81
    .line 82
    check-cast v14, Ljava/util/List;

    .line 83
    .line 84
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 85
    .line 86
    .line 87
    move-object v8, v13

    .line 88
    move-object v13, v14

    .line 89
    goto :goto_2

    .line 90
    :cond_3
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :try_start_2
    iget-object v0, v1, Lk4/f;->d:Ljava/util/List;

    .line 94
    .line 95
    move-object v4, v0

    .line 96
    check-cast v4, Ljava/util/Collection;

    .line 97
    .line 98
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 99
    .line 100
    .line 101
    move-result v4

    .line 102
    const/4 v12, 0x0

    .line 103
    :goto_1
    if-ge v12, v4, :cond_8

    .line 104
    .line 105
    invoke-interface {v0, v12}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v13

    .line 109
    check-cast v13, Lk4/l;

    .line 110
    .line 111
    invoke-interface {v13}, Lk4/l;->a()I

    .line 112
    .line 113
    .line 114
    move-result v14

    .line 115
    if-ne v14, v8, :cond_7

    .line 116
    .line 117
    iget-object v14, v1, Lk4/f;->f:Lil/g;

    .line 118
    .line 119
    iget-object v15, v1, Lk4/f;->h:Lcq/r1;

    .line 120
    .line 121
    new-instance v8, La2/c;

    .line 122
    .line 123
    const/16 v11, 0x18

    .line 124
    .line 125
    invoke-direct {v8, v11, v1, v13, v6}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 126
    .line 127
    .line 128
    move-object v11, v0

    .line 129
    check-cast v11, Ljava/util/List;

    .line 130
    .line 131
    iput-object v11, v2, Lk4/d;->d:Ljava/util/List;

    .line 132
    .line 133
    iput-object v13, v2, Lk4/d;->e:Lk4/l;

    .line 134
    .line 135
    iput v12, v2, Lk4/d;->f:I

    .line 136
    .line 137
    iput v4, v2, Lk4/d;->g:I

    .line 138
    .line 139
    iput v10, v2, Lk4/d;->j:I

    .line 140
    .line 141
    invoke-virtual {v14, v13, v15, v8, v2}, Lil/g;->W(Lk4/l;Lcq/r1;La2/c;Lrx0/c;)Ljava/lang/Object;

    .line 142
    .line 143
    .line 144
    move-result-object v8

    .line 145
    if-ne v8, v3, :cond_4

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_4
    move-object/from16 v16, v13

    .line 149
    .line 150
    move-object v13, v0

    .line 151
    move-object v0, v8

    .line 152
    move-object/from16 v8, v16

    .line 153
    .line 154
    :goto_2
    if-eqz v0, :cond_5

    .line 155
    .line 156
    iget-object v3, v1, Lk4/f;->e:Lk4/f0;

    .line 157
    .line 158
    iget v4, v3, Lk4/f0;->d:I

    .line 159
    .line 160
    iget-object v6, v3, Lk4/f0;->b:Lk4/x;

    .line 161
    .line 162
    iget v3, v3, Lk4/f0;->c:I

    .line 163
    .line 164
    invoke-static {v4, v0, v8, v6, v3}, Llp/yc;->b(ILjava/lang/Object;Lk4/l;Lk4/x;I)Ljava/lang/Object;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    invoke-virtual {v9, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 169
    .line 170
    .line 171
    invoke-interface {v2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 172
    .line 173
    .line 174
    move-result-object v0

    .line 175
    invoke-static {v0}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 176
    .line 177
    .line 178
    move-result v0

    .line 179
    const/4 v2, 0x0

    .line 180
    iput-boolean v2, v1, Lk4/f;->j:Z

    .line 181
    .line 182
    new-instance v1, Lk4/h0;

    .line 183
    .line 184
    invoke-virtual {v9}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    move-result-object v2

    .line 188
    invoke-direct {v1, v2, v0}, Lk4/h0;-><init>(Ljava/lang/Object;Z)V

    .line 189
    .line 190
    .line 191
    :goto_3
    invoke-interface {v7, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 192
    .line 193
    .line 194
    return-object v5

    .line 195
    :cond_5
    :try_start_3
    move-object v0, v13

    .line 196
    check-cast v0, Ljava/util/List;

    .line 197
    .line 198
    iput-object v0, v2, Lk4/d;->d:Ljava/util/List;

    .line 199
    .line 200
    iput-object v6, v2, Lk4/d;->e:Lk4/l;

    .line 201
    .line 202
    iput v12, v2, Lk4/d;->f:I

    .line 203
    .line 204
    iput v4, v2, Lk4/d;->g:I

    .line 205
    .line 206
    const/4 v8, 0x2

    .line 207
    iput v8, v2, Lk4/d;->j:I

    .line 208
    .line 209
    invoke-static {v2}, Lvy0/e0;->U(Lrx0/c;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 213
    if-ne v0, v3, :cond_6

    .line 214
    .line 215
    :goto_4
    return-object v3

    .line 216
    :cond_6
    :goto_5
    move-object v0, v13

    .line 217
    :cond_7
    add-int/2addr v12, v10

    .line 218
    goto :goto_1

    .line 219
    :cond_8
    invoke-interface {v2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 220
    .line 221
    .line 222
    move-result-object v0

    .line 223
    invoke-static {v0}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 224
    .line 225
    .line 226
    move-result v0

    .line 227
    const/4 v2, 0x0

    .line 228
    iput-boolean v2, v1, Lk4/f;->j:Z

    .line 229
    .line 230
    new-instance v1, Lk4/h0;

    .line 231
    .line 232
    invoke-virtual {v9}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v2

    .line 236
    invoke-direct {v1, v2, v0}, Lk4/h0;-><init>(Ljava/lang/Object;Z)V

    .line 237
    .line 238
    .line 239
    goto :goto_3

    .line 240
    :goto_6
    invoke-interface {v2}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 241
    .line 242
    .line 243
    move-result-object v2

    .line 244
    invoke-static {v2}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    const/4 v3, 0x0

    .line 249
    iput-boolean v3, v1, Lk4/f;->j:Z

    .line 250
    .line 251
    new-instance v1, Lk4/h0;

    .line 252
    .line 253
    invoke-virtual {v9}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object v3

    .line 257
    invoke-direct {v1, v3, v2}, Lk4/h0;-><init>(Ljava/lang/Object;Z)V

    .line 258
    .line 259
    .line 260
    invoke-interface {v7, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    throw v0
.end method

.method public final b(Lk4/l;Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p2, Lk4/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lk4/e;

    .line 7
    .line 8
    iget v1, v0, Lk4/e;->g:I

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
    iput v1, v0, Lk4/e;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lk4/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lk4/e;-><init>(Lk4/f;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lk4/e;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lk4/e;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-object p1, v0, Lk4/e;->d:Lk4/l;

    .line 38
    .line 39
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 40
    .line 41
    .line 42
    return-object p2

    .line 43
    :catch_0
    move-exception p0

    .line 44
    goto :goto_1

    .line 45
    :catch_1
    move-exception p0

    .line 46
    goto :goto_2

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :try_start_1
    new-instance p2, Lk31/t;

    .line 59
    .line 60
    const/4 v2, 0x4

    .line 61
    invoke-direct {p2, v2, p0, p1, v4}, Lk31/t;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v0, Lk4/e;->d:Lk4/l;

    .line 65
    .line 66
    iput v3, v0, Lk4/e;->g:I

    .line 67
    .line 68
    const-wide/16 v2, 0x3a98

    .line 69
    .line 70
    invoke-static {v2, v3, p2, v0}, Lvy0/e0;->T(JLay0/n;Lrx0/c;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 74
    if-ne p0, v1, :cond_3

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_3
    return-object p0

    .line 78
    :goto_1
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 79
    .line 80
    .line 81
    move-result-object p2

    .line 82
    sget-object v1, Lvy0/y;->d:Lvy0/y;

    .line 83
    .line 84
    invoke-interface {p2, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    check-cast p2, Lvy0/z;

    .line 89
    .line 90
    if-eqz p2, :cond_4

    .line 91
    .line 92
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 97
    .line 98
    new-instance v2, Ljava/lang/StringBuilder;

    .line 99
    .line 100
    const-string v3, "Unable to load font "

    .line 101
    .line 102
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p1

    .line 112
    invoke-direct {v1, p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 113
    .line 114
    .line 115
    invoke-interface {p2, v0, v1}, Lvy0/z;->handleException(Lpx0/g;Ljava/lang/Throwable;)V

    .line 116
    .line 117
    .line 118
    goto :goto_3

    .line 119
    :goto_2
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 120
    .line 121
    .line 122
    move-result-object p1

    .line 123
    invoke-static {p1}, Lvy0/e0;->A(Lpx0/g;)Z

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    if-eqz p1, :cond_5

    .line 128
    .line 129
    :cond_4
    :goto_3
    return-object v4

    .line 130
    :cond_5
    throw p0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lk4/f;->i:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.class public final Lru0/j0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lru0/k0;

.field public e:Lpw0/a;

.field public f:Ld01/x;

.field public g:Ld01/x;

.field public h:I

.field public i:I

.field public synthetic j:Ljava/lang/Object;

.field public final synthetic k:Lru0/k0;

.field public final synthetic l:Ljava/util/List;


# direct methods
.method public constructor <init>(Lru0/k0;Ljava/util/List;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lru0/j0;->k:Lru0/k0;

    .line 2
    .line 3
    iput-object p2, p0, Lru0/j0;->l:Ljava/util/List;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    new-instance v0, Lru0/j0;

    .line 2
    .line 3
    iget-object v1, p0, Lru0/j0;->k:Lru0/k0;

    .line 4
    .line 5
    iget-object p0, p0, Lru0/j0;->l:Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {v0, v1, p0, p2}, Lru0/j0;-><init>(Lru0/k0;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 11
    .line 12
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lru0/j0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lru0/j0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lru0/j0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lyy0/j;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lru0/j0;->i:I

    .line 10
    .line 11
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    const/4 v5, 0x5

    .line 14
    const/4 v6, 0x4

    .line 15
    const/4 v7, 0x3

    .line 16
    const/4 v8, 0x1

    .line 17
    const/4 v9, 0x0

    .line 18
    const/4 v10, 0x2

    .line 19
    const/4 v11, 0x0

    .line 20
    if-eqz v3, :cond_5

    .line 21
    .line 22
    if-eq v3, v8, :cond_4

    .line 23
    .line 24
    if-eq v3, v10, :cond_3

    .line 25
    .line 26
    if-eq v3, v7, :cond_2

    .line 27
    .line 28
    if-eq v3, v6, :cond_0

    .line 29
    .line 30
    if-ne v3, v5, :cond_1

    .line 31
    .line 32
    :cond_0
    iget-object v0, v0, Lru0/j0;->d:Lru0/k0;

    .line 33
    .line 34
    check-cast v0, Lvy0/b0;

    .line 35
    .line 36
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    return-object v4

    .line 40
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw v0

    .line 48
    :cond_2
    iget v3, v0, Lru0/j0;->h:I

    .line 49
    .line 50
    iget-object v7, v0, Lru0/j0;->d:Lru0/k0;

    .line 51
    .line 52
    check-cast v7, Lvy0/b0;

    .line 53
    .line 54
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    move v8, v3

    .line 58
    move-object/from16 v3, p1

    .line 59
    .line 60
    goto/16 :goto_3

    .line 61
    .line 62
    :cond_3
    iget v3, v0, Lru0/j0;->h:I

    .line 63
    .line 64
    iget-object v8, v0, Lru0/j0;->g:Ld01/x;

    .line 65
    .line 66
    iget-object v10, v0, Lru0/j0;->f:Ld01/x;

    .line 67
    .line 68
    iget-object v12, v0, Lru0/j0;->e:Lpw0/a;

    .line 69
    .line 70
    iget-object v13, v0, Lru0/j0;->d:Lru0/k0;

    .line 71
    .line 72
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    move-object v14, v13

    .line 76
    move-object v13, v12

    .line 77
    move-object v12, v10

    .line 78
    move-object v10, v8

    .line 79
    move v8, v3

    .line 80
    move-object/from16 v3, p1

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_4
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    goto :goto_0

    .line 87
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    iput-object v1, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 91
    .line 92
    iput v8, v0, Lru0/j0;->i:I

    .line 93
    .line 94
    sget-object v3, Lne0/d;->a:Lne0/d;

    .line 95
    .line 96
    invoke-interface {v1, v3, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v3

    .line 100
    if-ne v3, v2, :cond_6

    .line 101
    .line 102
    goto/16 :goto_5

    .line 103
    .line 104
    :cond_6
    :goto_0
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 105
    .line 106
    .line 107
    move-result-object v3

    .line 108
    invoke-static {v3}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 109
    .line 110
    .line 111
    move-result-object v12

    .line 112
    new-instance v8, Ld01/x;

    .line 113
    .line 114
    invoke-direct {v8, v10}, Ld01/x;-><init>(I)V

    .line 115
    .line 116
    .line 117
    iput-object v1, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 118
    .line 119
    iget-object v13, v0, Lru0/j0;->k:Lru0/k0;

    .line 120
    .line 121
    iput-object v13, v0, Lru0/j0;->d:Lru0/k0;

    .line 122
    .line 123
    iput-object v12, v0, Lru0/j0;->e:Lpw0/a;

    .line 124
    .line 125
    iput-object v8, v0, Lru0/j0;->f:Ld01/x;

    .line 126
    .line 127
    iput-object v8, v0, Lru0/j0;->g:Ld01/x;

    .line 128
    .line 129
    iput v9, v0, Lru0/j0;->h:I

    .line 130
    .line 131
    iput v10, v0, Lru0/j0;->i:I

    .line 132
    .line 133
    iget-object v3, v0, Lru0/j0;->l:Ljava/util/List;

    .line 134
    .line 135
    invoke-static {v13, v3, v12, v0}, Lru0/k0;->a(Lru0/k0;Ljava/util/List;Lpw0/a;Lrx0/c;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object v3

    .line 139
    if-ne v3, v2, :cond_7

    .line 140
    .line 141
    goto/16 :goto_5

    .line 142
    .line 143
    :cond_7
    move-object v10, v8

    .line 144
    move-object v14, v13

    .line 145
    move v8, v9

    .line 146
    move-object v13, v12

    .line 147
    move-object v12, v10

    .line 148
    :goto_1
    check-cast v3, Ljava/util/Collection;

    .line 149
    .line 150
    new-array v9, v9, [Lvy0/h0;

    .line 151
    .line 152
    invoke-interface {v3, v9}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v3

    .line 156
    invoke-virtual {v10, v3}, Ld01/x;->g(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    new-instance v3, Lrp0/a;

    .line 160
    .line 161
    const/4 v9, 0x2

    .line 162
    invoke-direct {v3, v14, v11, v9}, Lrp0/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 163
    .line 164
    .line 165
    invoke-static {v13, v11, v3, v7}, Lvy0/e0;->g(Lvy0/b0;Lpx0/g;Lay0/n;I)Lvy0/i0;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    invoke-virtual {v12, v3}, Ld01/x;->b(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    iget-object v3, v12, Ld01/x;->b:Ljava/util/ArrayList;

    .line 173
    .line 174
    invoke-virtual {v3}, Ljava/util/ArrayList;->size()I

    .line 175
    .line 176
    .line 177
    move-result v9

    .line 178
    new-array v9, v9, [Lvy0/h0;

    .line 179
    .line 180
    invoke-virtual {v3, v9}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v3

    .line 184
    check-cast v3, [Lvy0/h0;

    .line 185
    .line 186
    iput-object v1, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 187
    .line 188
    iput-object v11, v0, Lru0/j0;->d:Lru0/k0;

    .line 189
    .line 190
    iput-object v11, v0, Lru0/j0;->e:Lpw0/a;

    .line 191
    .line 192
    iput-object v11, v0, Lru0/j0;->f:Ld01/x;

    .line 193
    .line 194
    iput-object v11, v0, Lru0/j0;->g:Ld01/x;

    .line 195
    .line 196
    iput v8, v0, Lru0/j0;->h:I

    .line 197
    .line 198
    iput v7, v0, Lru0/j0;->i:I

    .line 199
    .line 200
    array-length v7, v3

    .line 201
    if-nez v7, :cond_8

    .line 202
    .line 203
    sget-object v3, Lmx0/s;->d:Lmx0/s;

    .line 204
    .line 205
    goto :goto_2

    .line 206
    :cond_8
    new-instance v7, Lvy0/e;

    .line 207
    .line 208
    invoke-direct {v7, v3}, Lvy0/e;-><init>([Lvy0/h0;)V

    .line 209
    .line 210
    .line 211
    invoke-virtual {v7, v0}, Lvy0/e;->a(Lrx0/c;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v3

    .line 215
    :goto_2
    if-ne v3, v2, :cond_9

    .line 216
    .line 217
    goto :goto_5

    .line 218
    :cond_9
    :goto_3
    check-cast v3, Ljava/lang/Iterable;

    .line 219
    .line 220
    invoke-interface {v3}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    :cond_a
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 225
    .line 226
    .line 227
    move-result v7

    .line 228
    if-eqz v7, :cond_b

    .line 229
    .line 230
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 231
    .line 232
    .line 233
    move-result-object v7

    .line 234
    instance-of v9, v7, Lne0/c;

    .line 235
    .line 236
    if-eqz v9, :cond_a

    .line 237
    .line 238
    goto :goto_4

    .line 239
    :cond_b
    move-object v7, v11

    .line 240
    :goto_4
    if-eqz v7, :cond_c

    .line 241
    .line 242
    new-instance v12, Lne0/c;

    .line 243
    .line 244
    new-instance v13, Ljava/lang/IllegalStateException;

    .line 245
    .line 246
    const-string v3, "Unable to refresh home features."

    .line 247
    .line 248
    invoke-direct {v13, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 249
    .line 250
    .line 251
    move-object v14, v7

    .line 252
    check-cast v14, Lne0/c;

    .line 253
    .line 254
    const/16 v16, 0x0

    .line 255
    .line 256
    const/16 v17, 0x1c

    .line 257
    .line 258
    const/4 v15, 0x0

    .line 259
    invoke-direct/range {v12 .. v17}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 260
    .line 261
    .line 262
    iput-object v1, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 263
    .line 264
    iput-object v11, v0, Lru0/j0;->d:Lru0/k0;

    .line 265
    .line 266
    iput-object v11, v0, Lru0/j0;->e:Lpw0/a;

    .line 267
    .line 268
    iput v8, v0, Lru0/j0;->h:I

    .line 269
    .line 270
    iput v6, v0, Lru0/j0;->i:I

    .line 271
    .line 272
    invoke-interface {v1, v12, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 273
    .line 274
    .line 275
    move-result-object v0

    .line 276
    if-ne v0, v2, :cond_d

    .line 277
    .line 278
    goto :goto_5

    .line 279
    :cond_c
    new-instance v3, Lne0/e;

    .line 280
    .line 281
    invoke-direct {v3, v4}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    iput-object v11, v0, Lru0/j0;->j:Ljava/lang/Object;

    .line 285
    .line 286
    iput-object v11, v0, Lru0/j0;->d:Lru0/k0;

    .line 287
    .line 288
    iput-object v11, v0, Lru0/j0;->e:Lpw0/a;

    .line 289
    .line 290
    iput v8, v0, Lru0/j0;->h:I

    .line 291
    .line 292
    iput v5, v0, Lru0/j0;->i:I

    .line 293
    .line 294
    invoke-interface {v1, v3, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v0

    .line 298
    if-ne v0, v2, :cond_d

    .line 299
    .line 300
    :goto_5
    return-object v2

    .line 301
    :cond_d
    return-object v4
.end method

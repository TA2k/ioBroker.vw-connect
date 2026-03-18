.class public final Lpp0/i;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lyy0/j;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lpp0/j;

.field public h:Lyy0/j;

.field public i:Lqp0/g;

.field public j:Lqp0/r;

.field public k:Lnp0/c;

.field public l:I

.field public m:I

.field public n:Z


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Lpp0/j;)V
    .locals 0

    .line 1
    iput-object p2, p0, Lpp0/i;->g:Lpp0/j;

    .line 2
    .line 3
    const/4 p2, 0x3

    .line 4
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    new-instance v0, Lpp0/i;

    .line 6
    .line 7
    iget-object p0, p0, Lpp0/i;->g:Lpp0/j;

    .line 8
    .line 9
    invoke-direct {v0, p3, p0}, Lpp0/i;-><init>(Lkotlin/coroutines/Continuation;Lpp0/j;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lpp0/i;->e:Lyy0/j;

    .line 13
    .line 14
    iput-object p2, v0, Lpp0/i;->f:Ljava/lang/Object;

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Lpp0/i;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Lpp0/i;->d:I

    .line 6
    .line 7
    const/4 v3, 0x3

    .line 8
    const/4 v4, 0x2

    .line 9
    const/4 v5, 0x1

    .line 10
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v7, v0, Lpp0/i;->g:Lpp0/j;

    .line 13
    .line 14
    const/4 v8, 0x0

    .line 15
    if-eqz v2, :cond_3

    .line 16
    .line 17
    if-eq v2, v5, :cond_2

    .line 18
    .line 19
    if-eq v2, v4, :cond_1

    .line 20
    .line 21
    if-ne v2, v3, :cond_0

    .line 22
    .line 23
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    return-object v6

    .line 27
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 30
    .line 31
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    throw v0

    .line 35
    :cond_1
    iget-boolean v2, v0, Lpp0/i;->n:Z

    .line 36
    .line 37
    iget-object v4, v0, Lpp0/i;->k:Lnp0/c;

    .line 38
    .line 39
    iget-object v5, v0, Lpp0/i;->j:Lqp0/r;

    .line 40
    .line 41
    iget-object v9, v0, Lpp0/i;->i:Lqp0/g;

    .line 42
    .line 43
    iget-object v10, v0, Lpp0/i;->h:Lyy0/j;

    .line 44
    .line 45
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    move-object v11, v10

    .line 49
    move-object v10, v9

    .line 50
    move-object v9, v5

    .line 51
    move v5, v2

    .line 52
    move-object/from16 v2, p1

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_2
    iget v2, v0, Lpp0/i;->m:I

    .line 56
    .line 57
    iget v5, v0, Lpp0/i;->l:I

    .line 58
    .line 59
    iget-object v9, v0, Lpp0/i;->j:Lqp0/r;

    .line 60
    .line 61
    iget-object v10, v0, Lpp0/i;->i:Lqp0/g;

    .line 62
    .line 63
    iget-object v11, v0, Lpp0/i;->h:Lyy0/j;

    .line 64
    .line 65
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move v12, v5

    .line 69
    move-object/from16 v5, p1

    .line 70
    .line 71
    goto :goto_0

    .line 72
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v2, v0, Lpp0/i;->e:Lyy0/j;

    .line 76
    .line 77
    iget-object v9, v0, Lpp0/i;->f:Ljava/lang/Object;

    .line 78
    .line 79
    check-cast v9, Llx0/l;

    .line 80
    .line 81
    iget-object v10, v9, Llx0/l;->d:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast v10, Lqp0/g;

    .line 84
    .line 85
    iget-object v9, v9, Llx0/l;->e:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v9, Lqp0/r;

    .line 88
    .line 89
    if-eqz v10, :cond_c

    .line 90
    .line 91
    iget-object v11, v7, Lpp0/j;->a:Lkf0/k;

    .line 92
    .line 93
    iput-object v8, v0, Lpp0/i;->e:Lyy0/j;

    .line 94
    .line 95
    iput-object v8, v0, Lpp0/i;->f:Ljava/lang/Object;

    .line 96
    .line 97
    iput-object v2, v0, Lpp0/i;->h:Lyy0/j;

    .line 98
    .line 99
    iput-object v10, v0, Lpp0/i;->i:Lqp0/g;

    .line 100
    .line 101
    iput-object v9, v0, Lpp0/i;->j:Lqp0/r;

    .line 102
    .line 103
    const/4 v12, 0x0

    .line 104
    iput v12, v0, Lpp0/i;->l:I

    .line 105
    .line 106
    iput v12, v0, Lpp0/i;->m:I

    .line 107
    .line 108
    iput v5, v0, Lpp0/i;->d:I

    .line 109
    .line 110
    invoke-virtual {v11, v0}, Lkf0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v5

    .line 114
    if-ne v5, v1, :cond_4

    .line 115
    .line 116
    goto/16 :goto_7

    .line 117
    .line 118
    :cond_4
    move-object v11, v2

    .line 119
    move v2, v12

    .line 120
    :goto_0
    check-cast v5, Lss0/b;

    .line 121
    .line 122
    sget-object v13, Lss0/e;->t:Lss0/e;

    .line 123
    .line 124
    invoke-static {v5, v13}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 125
    .line 126
    .line 127
    move-result v5

    .line 128
    iget-object v13, v7, Lpp0/j;->d:Lnp0/c;

    .line 129
    .line 130
    iget-object v14, v7, Lpp0/j;->b:Lkf0/o;

    .line 131
    .line 132
    iput-object v8, v0, Lpp0/i;->e:Lyy0/j;

    .line 133
    .line 134
    iput-object v8, v0, Lpp0/i;->f:Ljava/lang/Object;

    .line 135
    .line 136
    iput-object v11, v0, Lpp0/i;->h:Lyy0/j;

    .line 137
    .line 138
    iput-object v10, v0, Lpp0/i;->i:Lqp0/g;

    .line 139
    .line 140
    iput-object v9, v0, Lpp0/i;->j:Lqp0/r;

    .line 141
    .line 142
    iput-object v13, v0, Lpp0/i;->k:Lnp0/c;

    .line 143
    .line 144
    iput v12, v0, Lpp0/i;->l:I

    .line 145
    .line 146
    iput v2, v0, Lpp0/i;->m:I

    .line 147
    .line 148
    iput-boolean v5, v0, Lpp0/i;->n:Z

    .line 149
    .line 150
    iput v4, v0, Lpp0/i;->d:I

    .line 151
    .line 152
    invoke-virtual {v14, v6, v0}, Lkf0/o;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    if-ne v2, v1, :cond_5

    .line 157
    .line 158
    goto/16 :goto_7

    .line 159
    .line 160
    :cond_5
    move-object v4, v13

    .line 161
    :goto_1
    check-cast v2, Lne0/t;

    .line 162
    .line 163
    instance-of v12, v2, Lne0/c;

    .line 164
    .line 165
    if-eqz v12, :cond_6

    .line 166
    .line 167
    move-object v2, v8

    .line 168
    goto :goto_2

    .line 169
    :cond_6
    instance-of v12, v2, Lne0/e;

    .line 170
    .line 171
    if-eqz v12, :cond_b

    .line 172
    .line 173
    check-cast v2, Lne0/e;

    .line 174
    .line 175
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 176
    .line 177
    :goto_2
    check-cast v2, Lss0/j0;

    .line 178
    .line 179
    if-eqz v2, :cond_7

    .line 180
    .line 181
    iget-object v2, v2, Lss0/j0;->d:Ljava/lang/String;

    .line 182
    .line 183
    goto :goto_3

    .line 184
    :cond_7
    move-object v2, v8

    .line 185
    :goto_3
    iget-object v12, v10, Lqp0/g;->a:Ljava/util/List;

    .line 186
    .line 187
    check-cast v12, Ljava/lang/Iterable;

    .line 188
    .line 189
    new-instance v13, Ljava/util/ArrayList;

    .line 190
    .line 191
    const/16 v14, 0xa

    .line 192
    .line 193
    invoke-static {v12, v14}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 194
    .line 195
    .line 196
    move-result v14

    .line 197
    invoke-direct {v13, v14}, Ljava/util/ArrayList;-><init>(I)V

    .line 198
    .line 199
    .line 200
    invoke-interface {v12}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 201
    .line 202
    .line 203
    move-result-object v12

    .line 204
    :goto_4
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 205
    .line 206
    .line 207
    move-result v14

    .line 208
    if-eqz v14, :cond_8

    .line 209
    .line 210
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v14

    .line 214
    check-cast v14, Llx0/l;

    .line 215
    .line 216
    iget-object v14, v14, Llx0/l;->e:Ljava/lang/Object;

    .line 217
    .line 218
    check-cast v14, Lqp0/b0;

    .line 219
    .line 220
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 221
    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_8
    new-instance v12, Ljava/util/ArrayList;

    .line 225
    .line 226
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 227
    .line 228
    .line 229
    invoke-virtual {v13}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 230
    .line 231
    .line 232
    move-result-object v13

    .line 233
    :cond_9
    :goto_5
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 234
    .line 235
    .line 236
    move-result v14

    .line 237
    if-eqz v14, :cond_a

    .line 238
    .line 239
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 240
    .line 241
    .line 242
    move-result-object v14

    .line 243
    move-object v15, v14

    .line 244
    check-cast v15, Lqp0/b0;

    .line 245
    .line 246
    invoke-static {v15}, Ljp/eg;->e(Lqp0/b0;)Z

    .line 247
    .line 248
    .line 249
    move-result v15

    .line 250
    if-nez v15, :cond_9

    .line 251
    .line 252
    invoke-virtual {v12, v14}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 253
    .line 254
    .line 255
    goto :goto_5

    .line 256
    :cond_a
    new-instance v13, Lqp0/s;

    .line 257
    .line 258
    invoke-direct {v13, v9, v5}, Lqp0/s;-><init>(Lqp0/r;Z)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v4, v2, v12, v13}, Lnp0/c;->a(Ljava/lang/String;Ljava/util/List;Lqp0/s;)Lyy0/m1;

    .line 262
    .line 263
    .line 264
    move-result-object v2

    .line 265
    new-instance v4, Lnz/g;

    .line 266
    .line 267
    const/16 v5, 0x8

    .line 268
    .line 269
    invoke-direct {v4, v5, v7, v10, v8}, Lnz/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 270
    .line 271
    .line 272
    invoke-static {v4, v2}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 273
    .line 274
    .line 275
    move-result-object v2

    .line 276
    move-object v4, v2

    .line 277
    move-object v2, v11

    .line 278
    goto :goto_6

    .line 279
    :cond_b
    new-instance v0, La8/r0;

    .line 280
    .line 281
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 282
    .line 283
    .line 284
    throw v0

    .line 285
    :cond_c
    new-instance v9, Lne0/c;

    .line 286
    .line 287
    new-instance v10, Ljava/lang/Exception;

    .line 288
    .line 289
    const-string v4, "No modified route available"

    .line 290
    .line 291
    invoke-direct {v10, v4}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    const/4 v13, 0x0

    .line 295
    const/16 v14, 0x1e

    .line 296
    .line 297
    const/4 v11, 0x0

    .line 298
    const/4 v12, 0x0

    .line 299
    invoke-direct/range {v9 .. v14}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 300
    .line 301
    .line 302
    new-instance v4, Lyy0/m;

    .line 303
    .line 304
    const/4 v5, 0x0

    .line 305
    invoke-direct {v4, v9, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 306
    .line 307
    .line 308
    :goto_6
    iput-object v8, v0, Lpp0/i;->e:Lyy0/j;

    .line 309
    .line 310
    iput-object v8, v0, Lpp0/i;->f:Ljava/lang/Object;

    .line 311
    .line 312
    iput-object v8, v0, Lpp0/i;->h:Lyy0/j;

    .line 313
    .line 314
    iput-object v8, v0, Lpp0/i;->i:Lqp0/g;

    .line 315
    .line 316
    iput-object v8, v0, Lpp0/i;->j:Lqp0/r;

    .line 317
    .line 318
    iput-object v8, v0, Lpp0/i;->k:Lnp0/c;

    .line 319
    .line 320
    iput v3, v0, Lpp0/i;->d:I

    .line 321
    .line 322
    invoke-static {v2, v4, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 323
    .line 324
    .line 325
    move-result-object v0

    .line 326
    if-ne v0, v1, :cond_d

    .line 327
    .line 328
    :goto_7
    return-object v1

    .line 329
    :cond_d
    return-object v6
.end method

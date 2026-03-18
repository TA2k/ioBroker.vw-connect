.class public final Luk0/l;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lyy0/j;

.field public synthetic f:Ljava/lang/Object;

.field public g:Lyy0/j;

.field public h:I

.field public final synthetic i:Luk0/r;

.field public final synthetic j:Luk0/k;

.field public final synthetic k:Ljava/lang/Boolean;

.field public final synthetic l:Ljava/lang/String;

.field public m:Lxj0/f;

.field public n:Lqp0/r;

.field public o:Lsk0/f;

.field public p:Ljava/lang/String;

.field public q:Lvk0/k0;

.field public r:Ljava/lang/String;

.field public s:I


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Luk0/r;Luk0/k;Ljava/lang/Boolean;Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p2, p0, Luk0/l;->i:Luk0/r;

    .line 2
    .line 3
    iput-object p3, p0, Luk0/l;->j:Luk0/k;

    .line 4
    .line 5
    iput-object p4, p0, Luk0/l;->k:Ljava/lang/Boolean;

    .line 6
    .line 7
    iput-object p5, p0, Luk0/l;->l:Ljava/lang/String;

    .line 8
    .line 9
    const/4 p2, 0x3

    .line 10
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    move-object v1, p3

    .line 4
    check-cast v1, Lkotlin/coroutines/Continuation;

    .line 5
    .line 6
    new-instance v0, Luk0/l;

    .line 7
    .line 8
    iget-object v4, p0, Luk0/l;->k:Ljava/lang/Boolean;

    .line 9
    .line 10
    iget-object v5, p0, Luk0/l;->l:Ljava/lang/String;

    .line 11
    .line 12
    iget-object v2, p0, Luk0/l;->i:Luk0/r;

    .line 13
    .line 14
    iget-object v3, p0, Luk0/l;->j:Luk0/k;

    .line 15
    .line 16
    invoke-direct/range {v0 .. v5}, Luk0/l;-><init>(Lkotlin/coroutines/Continuation;Luk0/r;Luk0/k;Ljava/lang/Boolean;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, v0, Luk0/l;->e:Lyy0/j;

    .line 20
    .line 21
    iput-object p2, v0, Luk0/l;->f:Ljava/lang/Object;

    .line 22
    .line 23
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Luk0/l;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Luk0/l;->d:I

    .line 6
    .line 7
    iget-object v3, v0, Luk0/l;->i:Luk0/r;

    .line 8
    .line 9
    const/4 v4, 0x3

    .line 10
    const/4 v5, 0x2

    .line 11
    const/4 v6, 0x1

    .line 12
    const/4 v7, 0x0

    .line 13
    const/4 v8, 0x0

    .line 14
    if-eqz v2, :cond_3

    .line 15
    .line 16
    if-eq v2, v6, :cond_2

    .line 17
    .line 18
    if-eq v2, v5, :cond_1

    .line 19
    .line 20
    if-ne v2, v4, :cond_0

    .line 21
    .line 22
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    goto/16 :goto_7

    .line 26
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
    iget-object v2, v0, Luk0/l;->r:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, v0, Luk0/l;->q:Lvk0/k0;

    .line 38
    .line 39
    iget-object v5, v0, Luk0/l;->p:Ljava/lang/String;

    .line 40
    .line 41
    iget-object v6, v0, Luk0/l;->o:Lsk0/f;

    .line 42
    .line 43
    iget-object v9, v0, Luk0/l;->n:Lqp0/r;

    .line 44
    .line 45
    iget-object v10, v0, Luk0/l;->m:Lxj0/f;

    .line 46
    .line 47
    iget-object v11, v0, Luk0/l;->g:Lyy0/j;

    .line 48
    .line 49
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    move-object v15, v3

    .line 53
    move-object/from16 v3, p1

    .line 54
    .line 55
    goto/16 :goto_1

    .line 56
    .line 57
    :cond_2
    iget v2, v0, Luk0/l;->s:I

    .line 58
    .line 59
    iget v6, v0, Luk0/l;->h:I

    .line 60
    .line 61
    iget-object v9, v0, Luk0/l;->m:Lxj0/f;

    .line 62
    .line 63
    iget-object v10, v0, Luk0/l;->g:Lyy0/j;

    .line 64
    .line 65
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    move-object v11, v10

    .line 69
    move-object v10, v9

    .line 70
    move v9, v6

    .line 71
    move-object/from16 v6, p1

    .line 72
    .line 73
    goto :goto_0

    .line 74
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    iget-object v2, v0, Luk0/l;->e:Lyy0/j;

    .line 78
    .line 79
    iget-object v9, v0, Luk0/l;->f:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v9, Lne0/s;

    .line 82
    .line 83
    instance-of v10, v9, Lne0/e;

    .line 84
    .line 85
    if-eqz v10, :cond_9

    .line 86
    .line 87
    check-cast v9, Lne0/e;

    .line 88
    .line 89
    iget-object v9, v9, Lne0/e;->a:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v9, Lxj0/f;

    .line 92
    .line 93
    iget-object v10, v3, Luk0/r;->b:Lpp0/l0;

    .line 94
    .line 95
    invoke-virtual {v10}, Lpp0/l0;->invoke()Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v10

    .line 99
    check-cast v10, Lyy0/i;

    .line 100
    .line 101
    iput-object v8, v0, Luk0/l;->e:Lyy0/j;

    .line 102
    .line 103
    iput-object v8, v0, Luk0/l;->f:Ljava/lang/Object;

    .line 104
    .line 105
    iput-object v2, v0, Luk0/l;->g:Lyy0/j;

    .line 106
    .line 107
    iput-object v9, v0, Luk0/l;->m:Lxj0/f;

    .line 108
    .line 109
    iput v7, v0, Luk0/l;->h:I

    .line 110
    .line 111
    iput v7, v0, Luk0/l;->s:I

    .line 112
    .line 113
    iput v6, v0, Luk0/l;->d:I

    .line 114
    .line 115
    invoke-static {v10, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 116
    .line 117
    .line 118
    move-result-object v6

    .line 119
    if-ne v6, v1, :cond_4

    .line 120
    .line 121
    goto/16 :goto_6

    .line 122
    .line 123
    :cond_4
    move-object v11, v2

    .line 124
    move v2, v7

    .line 125
    move-object v10, v9

    .line 126
    move v9, v2

    .line 127
    :goto_0
    check-cast v6, Lqp0/r;

    .line 128
    .line 129
    iget-object v12, v3, Luk0/r;->a:Lsk0/f;

    .line 130
    .line 131
    iget-object v13, v0, Luk0/l;->j:Luk0/k;

    .line 132
    .line 133
    iget-object v14, v13, Luk0/k;->a:Ljava/lang/String;

    .line 134
    .line 135
    iget-object v15, v13, Luk0/k;->b:Lvk0/k0;

    .line 136
    .line 137
    iget-object v13, v13, Luk0/k;->c:Ljava/lang/String;

    .line 138
    .line 139
    if-eqz v13, :cond_7

    .line 140
    .line 141
    iget-object v3, v3, Luk0/r;->h:Lal0/v;

    .line 142
    .line 143
    iput-object v8, v0, Luk0/l;->e:Lyy0/j;

    .line 144
    .line 145
    iput-object v8, v0, Luk0/l;->f:Ljava/lang/Object;

    .line 146
    .line 147
    iput-object v11, v0, Luk0/l;->g:Lyy0/j;

    .line 148
    .line 149
    iput-object v10, v0, Luk0/l;->m:Lxj0/f;

    .line 150
    .line 151
    iput-object v6, v0, Luk0/l;->n:Lqp0/r;

    .line 152
    .line 153
    iput-object v12, v0, Luk0/l;->o:Lsk0/f;

    .line 154
    .line 155
    iput-object v14, v0, Luk0/l;->p:Ljava/lang/String;

    .line 156
    .line 157
    iput-object v15, v0, Luk0/l;->q:Lvk0/k0;

    .line 158
    .line 159
    iput-object v13, v0, Luk0/l;->r:Ljava/lang/String;

    .line 160
    .line 161
    iput v9, v0, Luk0/l;->h:I

    .line 162
    .line 163
    iput v2, v0, Luk0/l;->s:I

    .line 164
    .line 165
    iput v5, v0, Luk0/l;->d:I

    .line 166
    .line 167
    iget-object v2, v3, Lal0/v;->a:Lal0/b0;

    .line 168
    .line 169
    check-cast v2, Lyk0/e;

    .line 170
    .line 171
    iget-object v3, v2, Lyk0/e;->e:Ljava/util/UUID;

    .line 172
    .line 173
    if-nez v3, :cond_5

    .line 174
    .line 175
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    iput-object v3, v2, Lyk0/e;->e:Ljava/util/UUID;

    .line 180
    .line 181
    const-string v2, "also(...)"

    .line 182
    .line 183
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    :cond_5
    if-ne v3, v1, :cond_6

    .line 187
    .line 188
    goto/16 :goto_6

    .line 189
    .line 190
    :cond_6
    move-object v9, v6

    .line 191
    move-object v6, v12

    .line 192
    move-object v2, v13

    .line 193
    move-object v5, v14

    .line 194
    :goto_1
    check-cast v3, Ljava/util/UUID;

    .line 195
    .line 196
    move-object/from16 v16, v2

    .line 197
    .line 198
    move-object/from16 v17, v3

    .line 199
    .line 200
    move-object v14, v5

    .line 201
    move-object v12, v10

    .line 202
    move-object v10, v6

    .line 203
    move-object v6, v9

    .line 204
    :goto_2
    move-object v2, v11

    .line 205
    move-object v11, v15

    .line 206
    goto :goto_3

    .line 207
    :cond_7
    move-object v2, v12

    .line 208
    move-object v12, v10

    .line 209
    move-object v10, v2

    .line 210
    move-object/from16 v17, v8

    .line 211
    .line 212
    move-object/from16 v16, v13

    .line 213
    .line 214
    goto :goto_2

    .line 215
    :goto_3
    if-eqz v6, :cond_8

    .line 216
    .line 217
    invoke-static {v6, v7}, Ljp/cg;->c(Lqp0/r;Z)Ljava/util/List;

    .line 218
    .line 219
    .line 220
    move-result-object v3

    .line 221
    move-object/from16 v18, v3

    .line 222
    .line 223
    goto :goto_4

    .line 224
    :cond_8
    move-object/from16 v18, v8

    .line 225
    .line 226
    :goto_4
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 227
    .line 228
    .line 229
    const-string v3, "poiId"

    .line 230
    .line 231
    invoke-static {v14, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    const-string v3, "poiType"

    .line 235
    .line 236
    invoke-static {v11, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 237
    .line 238
    .line 239
    iget-object v3, v10, Lsk0/f;->a:Lxl0/f;

    .line 240
    .line 241
    new-instance v9, Lsk0/e;

    .line 242
    .line 243
    const/16 v19, 0x0

    .line 244
    .line 245
    iget-object v13, v0, Luk0/l;->l:Ljava/lang/String;

    .line 246
    .line 247
    iget-object v15, v0, Luk0/l;->k:Ljava/lang/Boolean;

    .line 248
    .line 249
    invoke-direct/range {v9 .. v19}, Lsk0/e;-><init>(Lsk0/f;Lvk0/k0;Lxj0/f;Ljava/lang/String;Ljava/lang/String;Ljava/lang/Boolean;Ljava/lang/String;Ljava/util/UUID;Ljava/util/List;Lkotlin/coroutines/Continuation;)V

    .line 250
    .line 251
    .line 252
    new-instance v5, Lsb/a;

    .line 253
    .line 254
    const/16 v6, 0xa

    .line 255
    .line 256
    invoke-direct {v5, v6}, Lsb/a;-><init>(I)V

    .line 257
    .line 258
    .line 259
    invoke-virtual {v3, v9, v5, v8}, Lxl0/f;->e(Lay0/k;Lay0/k;Lay0/k;)Lyy0/m1;

    .line 260
    .line 261
    .line 262
    move-result-object v3

    .line 263
    goto :goto_5

    .line 264
    :cond_9
    instance-of v3, v9, Lne0/c;

    .line 265
    .line 266
    if-eqz v3, :cond_a

    .line 267
    .line 268
    new-instance v3, Lyy0/m;

    .line 269
    .line 270
    const/4 v5, 0x0

    .line 271
    invoke-direct {v3, v9, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 272
    .line 273
    .line 274
    goto :goto_5

    .line 275
    :cond_a
    instance-of v3, v9, Lne0/d;

    .line 276
    .line 277
    if-eqz v3, :cond_c

    .line 278
    .line 279
    new-instance v3, Lyy0/m;

    .line 280
    .line 281
    const/4 v5, 0x0

    .line 282
    sget-object v6, Lne0/d;->a:Lne0/d;

    .line 283
    .line 284
    invoke-direct {v3, v6, v5}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 285
    .line 286
    .line 287
    :goto_5
    iput-object v8, v0, Luk0/l;->e:Lyy0/j;

    .line 288
    .line 289
    iput-object v8, v0, Luk0/l;->f:Ljava/lang/Object;

    .line 290
    .line 291
    iput-object v8, v0, Luk0/l;->g:Lyy0/j;

    .line 292
    .line 293
    iput-object v8, v0, Luk0/l;->m:Lxj0/f;

    .line 294
    .line 295
    iput-object v8, v0, Luk0/l;->n:Lqp0/r;

    .line 296
    .line 297
    iput-object v8, v0, Luk0/l;->o:Lsk0/f;

    .line 298
    .line 299
    iput-object v8, v0, Luk0/l;->p:Ljava/lang/String;

    .line 300
    .line 301
    iput-object v8, v0, Luk0/l;->q:Lvk0/k0;

    .line 302
    .line 303
    iput-object v8, v0, Luk0/l;->r:Ljava/lang/String;

    .line 304
    .line 305
    iput v4, v0, Luk0/l;->d:I

    .line 306
    .line 307
    invoke-static {v2, v3, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v0

    .line 311
    if-ne v0, v1, :cond_b

    .line 312
    .line 313
    :goto_6
    return-object v1

    .line 314
    :cond_b
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 315
    .line 316
    return-object v0

    .line 317
    :cond_c
    new-instance v0, La8/r0;

    .line 318
    .line 319
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 320
    .line 321
    .line 322
    throw v0
.end method

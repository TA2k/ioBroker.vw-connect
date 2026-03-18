.class public final synthetic Lh2/h0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Z

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;

.field public final synthetic i:Ljava/lang/Object;

.field public final synthetic j:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p7, p0, Lh2/h0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lh2/h0;->f:Ljava/lang/Object;

    .line 4
    .line 5
    iput-boolean p2, p0, Lh2/h0;->e:Z

    .line 6
    .line 7
    iput-object p3, p0, Lh2/h0;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p4, p0, Lh2/h0;->h:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p5, p0, Lh2/h0;->i:Ljava/lang/Object;

    .line 12
    .line 13
    iput-object p6, p0, Lh2/h0;->j:Ljava/lang/Object;

    .line 14
    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lh2/h0;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    iget-object v3, v0, Lh2/h0;->j:Ljava/lang/Object;

    .line 8
    .line 9
    iget-object v4, v0, Lh2/h0;->i:Ljava/lang/Object;

    .line 10
    .line 11
    iget-object v5, v0, Lh2/h0;->h:Ljava/lang/Object;

    .line 12
    .line 13
    iget-object v6, v0, Lh2/h0;->g:Ljava/lang/Object;

    .line 14
    .line 15
    iget-boolean v7, v0, Lh2/h0;->e:Z

    .line 16
    .line 17
    iget-object v0, v0, Lh2/h0;->f:Ljava/lang/Object;

    .line 18
    .line 19
    const/4 v8, 0x1

    .line 20
    packed-switch v1, :pswitch_data_0

    .line 21
    .line 22
    .line 23
    check-cast v0, Lt1/p0;

    .line 24
    .line 25
    iget-object v1, v0, Lt1/p0;->o:Ll2/j1;

    .line 26
    .line 27
    check-cast v6, Lw3/j2;

    .line 28
    .line 29
    check-cast v5, Le2/w0;

    .line 30
    .line 31
    move-object v10, v4

    .line 32
    check-cast v10, Ll4/v;

    .line 33
    .line 34
    move-object v11, v3

    .line 35
    check-cast v11, Ll4/p;

    .line 36
    .line 37
    move-object/from16 v3, p1

    .line 38
    .line 39
    check-cast v3, Lt3/y;

    .line 40
    .line 41
    iput-object v3, v0, Lt1/p0;->h:Lt3/y;

    .line 42
    .line 43
    invoke-virtual {v0}, Lt1/p0;->d()Lt1/j1;

    .line 44
    .line 45
    .line 46
    move-result-object v4

    .line 47
    if-eqz v4, :cond_0

    .line 48
    .line 49
    iput-object v3, v4, Lt1/j1;->b:Lt3/y;

    .line 50
    .line 51
    :cond_0
    if-eqz v7, :cond_5

    .line 52
    .line 53
    invoke-virtual {v0}, Lt1/p0;->a()Lt1/c0;

    .line 54
    .line 55
    .line 56
    move-result-object v3

    .line 57
    sget-object v4, Lt1/c0;->e:Lt1/c0;

    .line 58
    .line 59
    const/4 v7, 0x0

    .line 60
    if-ne v3, v4, :cond_2

    .line 61
    .line 62
    iget-object v3, v0, Lt1/p0;->l:Ll2/j1;

    .line 63
    .line 64
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    check-cast v3, Ljava/lang/Boolean;

    .line 69
    .line 70
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 71
    .line 72
    .line 73
    move-result v3

    .line 74
    if-eqz v3, :cond_1

    .line 75
    .line 76
    check-cast v6, Lw3/r1;

    .line 77
    .line 78
    iget-object v3, v6, Lw3/r1;->c:Ll2/j1;

    .line 79
    .line 80
    invoke-virtual {v3}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    check-cast v3, Ljava/lang/Boolean;

    .line 85
    .line 86
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    if-eqz v3, :cond_1

    .line 91
    .line 92
    invoke-virtual {v5}, Le2/w0;->q()V

    .line 93
    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_1
    invoke-virtual {v5}, Le2/w0;->n()V

    .line 97
    .line 98
    .line 99
    :goto_0
    invoke-static {v5, v8}, Lkp/w;->c(Le2/w0;Z)Z

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    iget-object v4, v0, Lt1/p0;->m:Ll2/j1;

    .line 104
    .line 105
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    invoke-virtual {v4, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v5, v7}, Lkp/w;->c(Le2/w0;Z)Z

    .line 113
    .line 114
    .line 115
    move-result v3

    .line 116
    iget-object v4, v0, Lt1/p0;->n:Ll2/j1;

    .line 117
    .line 118
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 119
    .line 120
    .line 121
    move-result-object v3

    .line 122
    invoke-virtual {v4, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 123
    .line 124
    .line 125
    iget-wide v3, v10, Ll4/v;->b:J

    .line 126
    .line 127
    invoke-static {v3, v4}, Lg4/o0;->c(J)Z

    .line 128
    .line 129
    .line 130
    move-result v3

    .line 131
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 132
    .line 133
    .line 134
    move-result-object v3

    .line 135
    invoke-virtual {v1, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    goto :goto_1

    .line 139
    :cond_2
    invoke-virtual {v0}, Lt1/p0;->a()Lt1/c0;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    sget-object v4, Lt1/c0;->f:Lt1/c0;

    .line 144
    .line 145
    if-ne v3, v4, :cond_3

    .line 146
    .line 147
    invoke-static {v5, v8}, Lkp/w;->c(Le2/w0;Z)Z

    .line 148
    .line 149
    .line 150
    move-result v3

    .line 151
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 152
    .line 153
    .line 154
    move-result-object v3

    .line 155
    invoke-virtual {v1, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_3
    :goto_1
    invoke-static {v0, v10, v11}, Lt1/l0;->v(Lt1/p0;Ll4/v;Ll4/p;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0}, Lt1/p0;->d()Lt1/j1;

    .line 162
    .line 163
    .line 164
    move-result-object v1

    .line 165
    if-eqz v1, :cond_5

    .line 166
    .line 167
    iget-object v3, v0, Lt1/p0;->e:Ll4/a0;

    .line 168
    .line 169
    if-eqz v3, :cond_5

    .line 170
    .line 171
    invoke-virtual {v0}, Lt1/p0;->b()Z

    .line 172
    .line 173
    .line 174
    move-result v0

    .line 175
    if-eqz v0, :cond_5

    .line 176
    .line 177
    iget-object v0, v1, Lt1/j1;->b:Lt3/y;

    .line 178
    .line 179
    if-eqz v0, :cond_5

    .line 180
    .line 181
    invoke-interface {v0}, Lt3/y;->g()Z

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    if-nez v4, :cond_4

    .line 186
    .line 187
    goto :goto_2

    .line 188
    :cond_4
    iget-object v4, v1, Lt1/j1;->c:Lt3/y;

    .line 189
    .line 190
    if-eqz v4, :cond_5

    .line 191
    .line 192
    iget-object v12, v1, Lt1/j1;->a:Lg4/l0;

    .line 193
    .line 194
    new-instance v13, Lag/t;

    .line 195
    .line 196
    const/16 v1, 0xc

    .line 197
    .line 198
    invoke-direct {v13, v0, v1}, Lag/t;-><init>(Ljava/lang/Object;I)V

    .line 199
    .line 200
    .line 201
    invoke-static {v0}, Lkp/u;->b(Lt3/y;)Ld3/c;

    .line 202
    .line 203
    .line 204
    move-result-object v14

    .line 205
    invoke-interface {v0, v4, v7}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 206
    .line 207
    .line 208
    move-result-object v15

    .line 209
    iget-object v0, v3, Ll4/a0;->a:Ll4/w;

    .line 210
    .line 211
    iget-object v0, v0, Ll4/w;->b:Ljava/util/concurrent/atomic/AtomicReference;

    .line 212
    .line 213
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    check-cast v0, Ll4/a0;

    .line 218
    .line 219
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 220
    .line 221
    .line 222
    move-result v0

    .line 223
    if-eqz v0, :cond_5

    .line 224
    .line 225
    iget-object v9, v3, Ll4/a0;->b:Ll4/q;

    .line 226
    .line 227
    invoke-interface/range {v9 .. v15}, Ll4/q;->f(Ll4/v;Ll4/p;Lg4/l0;Lag/t;Ld3/c;Ld3/c;)V

    .line 228
    .line 229
    .line 230
    :cond_5
    :goto_2
    return-object v2

    .line 231
    :pswitch_0
    check-cast v0, Lh2/r8;

    .line 232
    .line 233
    check-cast v6, Ljava/lang/String;

    .line 234
    .line 235
    check-cast v5, Ljava/lang/String;

    .line 236
    .line 237
    check-cast v4, Ljava/lang/String;

    .line 238
    .line 239
    check-cast v3, Lvy0/b0;

    .line 240
    .line 241
    move-object/from16 v1, p1

    .line 242
    .line 243
    check-cast v1, Ld4/l;

    .line 244
    .line 245
    iget-object v9, v0, Lh2/r8;->e:Li2/p;

    .line 246
    .line 247
    invoke-virtual {v9}, Li2/p;->d()Li2/u0;

    .line 248
    .line 249
    .line 250
    move-result-object v10

    .line 251
    iget-object v9, v9, Li2/p;->d:Lay0/k;

    .line 252
    .line 253
    iget-object v10, v10, Li2/u0;->a:Ljava/util/Map;

    .line 254
    .line 255
    invoke-interface {v10}, Ljava/util/Map;->size()I

    .line 256
    .line 257
    .line 258
    move-result v10

    .line 259
    if-le v10, v8, :cond_8

    .line 260
    .line 261
    if-eqz v7, :cond_8

    .line 262
    .line 263
    invoke-virtual {v0}, Lh2/r8;->c()Lh2/s8;

    .line 264
    .line 265
    .line 266
    move-result-object v7

    .line 267
    sget-object v10, Lh2/s8;->f:Lh2/s8;

    .line 268
    .line 269
    if-ne v7, v10, :cond_6

    .line 270
    .line 271
    sget-object v5, Lh2/s8;->e:Lh2/s8;

    .line 272
    .line 273
    invoke-interface {v9, v5}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    check-cast v5, Ljava/lang/Boolean;

    .line 278
    .line 279
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 280
    .line 281
    .line 282
    move-result v5

    .line 283
    if-eqz v5, :cond_7

    .line 284
    .line 285
    new-instance v5, Lh2/g0;

    .line 286
    .line 287
    invoke-direct {v5, v3, v0, v8}, Lh2/g0;-><init>(Lvy0/b0;Lh2/r8;I)V

    .line 288
    .line 289
    .line 290
    sget-object v7, Ld4/x;->a:[Lhy0/z;

    .line 291
    .line 292
    sget-object v7, Ld4/k;->s:Ld4/z;

    .line 293
    .line 294
    new-instance v8, Ld4/a;

    .line 295
    .line 296
    invoke-direct {v8, v6, v5}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {v1, v7, v8}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    goto :goto_3

    .line 303
    :cond_6
    invoke-interface {v9, v10}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 304
    .line 305
    .line 306
    move-result-object v6

    .line 307
    check-cast v6, Ljava/lang/Boolean;

    .line 308
    .line 309
    invoke-virtual {v6}, Ljava/lang/Boolean;->booleanValue()Z

    .line 310
    .line 311
    .line 312
    move-result v6

    .line 313
    if-eqz v6, :cond_7

    .line 314
    .line 315
    new-instance v6, Lh2/g0;

    .line 316
    .line 317
    const/4 v7, 0x2

    .line 318
    invoke-direct {v6, v3, v0, v7}, Lh2/g0;-><init>(Lvy0/b0;Lh2/r8;I)V

    .line 319
    .line 320
    .line 321
    sget-object v7, Ld4/x;->a:[Lhy0/z;

    .line 322
    .line 323
    sget-object v7, Ld4/k;->t:Ld4/z;

    .line 324
    .line 325
    new-instance v8, Ld4/a;

    .line 326
    .line 327
    invoke-direct {v8, v5, v6}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v1, v7, v8}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 331
    .line 332
    .line 333
    :cond_7
    :goto_3
    iget-boolean v5, v0, Lh2/r8;->c:Z

    .line 334
    .line 335
    if-nez v5, :cond_8

    .line 336
    .line 337
    new-instance v5, Lh2/g0;

    .line 338
    .line 339
    const/4 v6, 0x3

    .line 340
    invoke-direct {v5, v3, v0, v6}, Lh2/g0;-><init>(Lvy0/b0;Lh2/r8;I)V

    .line 341
    .line 342
    .line 343
    sget-object v0, Ld4/x;->a:[Lhy0/z;

    .line 344
    .line 345
    sget-object v0, Ld4/k;->u:Ld4/z;

    .line 346
    .line 347
    new-instance v3, Ld4/a;

    .line 348
    .line 349
    invoke-direct {v3, v4, v5}, Ld4/a;-><init>(Ljava/lang/String;Llx0/e;)V

    .line 350
    .line 351
    .line 352
    invoke-virtual {v1, v0, v3}, Ld4/l;->i(Ld4/z;Ljava/lang/Object;)V

    .line 353
    .line 354
    .line 355
    :cond_8
    return-object v2

    .line 356
    nop

    .line 357
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

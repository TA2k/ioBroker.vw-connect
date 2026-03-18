.class public abstract Ltv/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:F


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/16 v0, 0x40

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    sput v0, Ltv/l;->a:F

    .line 5
    .line 6
    return-void
.end method

.method public static final a(Ljava/lang/String;Ljava/lang/String;Lx2/s;Ll2/o;I)V
    .locals 12

    .line 1
    const-string v0, "url"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v9, p3

    .line 7
    check-cast v9, Ll2/t;

    .line 8
    .line 9
    const v0, -0x3a774601

    .line 10
    .line 11
    .line 12
    invoke-virtual {v9, v0}, Ll2/t;->a0(I)Ll2/t;

    .line 13
    .line 14
    .line 15
    invoke-virtual {v9, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x4

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    const/4 v0, 0x2

    .line 24
    :goto_0
    or-int v0, p4, v0

    .line 25
    .line 26
    invoke-virtual {v9, p1}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    const/16 v1, 0x20

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    const/16 v1, 0x10

    .line 36
    .line 37
    :goto_1
    or-int/2addr v0, v1

    .line 38
    and-int/lit16 v0, v0, 0x16db

    .line 39
    .line 40
    const/16 v1, 0x492

    .line 41
    .line 42
    if-ne v0, v1, :cond_3

    .line 43
    .line 44
    invoke-virtual {v9}, Ll2/t;->A()Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-nez v0, :cond_2

    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    invoke-virtual {v9}, Ll2/t;->R()V

    .line 52
    .line 53
    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :cond_3
    :goto_2
    new-instance v0, Ltl/g;

    .line 57
    .line 58
    sget-object v1, Landroidx/compose/ui/platform/AndroidCompositionLocals_androidKt;->b:Ll2/u2;

    .line 59
    .line 60
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    check-cast v2, Landroid/content/Context;

    .line 65
    .line 66
    invoke-direct {v0, v2}, Ltl/g;-><init>(Landroid/content/Context;)V

    .line 67
    .line 68
    .line 69
    iput-object p0, v0, Ltl/g;->c:Ljava/lang/Object;

    .line 70
    .line 71
    sget-object v2, Lul/g;->c:Lul/g;

    .line 72
    .line 73
    new-instance v2, Lul/e;

    .line 74
    .line 75
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 76
    .line 77
    .line 78
    iput-object v2, v0, Ltl/g;->m:Lul/h;

    .line 79
    .line 80
    const/4 v2, 0x0

    .line 81
    iput-object v2, v0, Ltl/g;->o:Landroidx/lifecycle/r;

    .line 82
    .line 83
    iput-object v2, v0, Ltl/g;->p:Lul/h;

    .line 84
    .line 85
    iput-object v2, v0, Ltl/g;->q:Lul/f;

    .line 86
    .line 87
    new-instance v5, Lwl/a;

    .line 88
    .line 89
    const/16 v6, 0x64

    .line 90
    .line 91
    invoke-direct {v5, v6}, Lwl/a;-><init>(I)V

    .line 92
    .line 93
    .line 94
    iput-object v5, v0, Ltl/g;->g:Lwl/e;

    .line 95
    .line 96
    invoke-virtual {v0}, Ltl/g;->a()Ltl/h;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    const v5, -0x591033e3

    .line 101
    .line 102
    .line 103
    invoke-virtual {v9, v5}, Ll2/t;->Z(I)V

    .line 104
    .line 105
    .line 106
    sget-object v5, Ljl/a;->f:Ljl/a;

    .line 107
    .line 108
    sget-object v6, Lt3/j;->b:Lt3/x0;

    .line 109
    .line 110
    sget-object v7, Ljl/m;->a:Ll2/u2;

    .line 111
    .line 112
    invoke-virtual {v9, v7}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    check-cast v7, Lil/j;

    .line 117
    .line 118
    if-nez v7, :cond_5

    .line 119
    .line 120
    invoke-virtual {v9, v1}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object v1

    .line 124
    check-cast v1, Landroid/content/Context;

    .line 125
    .line 126
    sget-object v7, Lil/a;->b:Lil/j;

    .line 127
    .line 128
    if-nez v7, :cond_5

    .line 129
    .line 130
    sget-object v8, Lil/a;->a:Lil/a;

    .line 131
    .line 132
    monitor-enter v8

    .line 133
    :try_start_0
    sget-object v7, Lil/a;->b:Lil/j;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 134
    .line 135
    if-eqz v7, :cond_4

    .line 136
    .line 137
    monitor-exit v8

    .line 138
    goto :goto_3

    .line 139
    :cond_4
    :try_start_1
    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 140
    .line 141
    .line 142
    invoke-static {v1}, Llp/ma;->b(Landroid/content/Context;)Lil/j;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    sput-object v1, Lil/a;->b:Lil/j;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 147
    .line 148
    monitor-exit v8

    .line 149
    move-object v7, v1

    .line 150
    goto :goto_3

    .line 151
    :catchall_0
    move-exception v0

    .line 152
    :try_start_2
    monitor-exit v8
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 153
    throw v0

    .line 154
    :cond_5
    :goto_3
    const v1, -0x78701fba

    .line 155
    .line 156
    .line 157
    invoke-virtual {v9, v1}, Ll2/t;->Z(I)V

    .line 158
    .line 159
    .line 160
    sget v1, Ljl/n;->a:I

    .line 161
    .line 162
    iget-object v1, v0, Ltl/h;->b:Ljava/lang/Object;

    .line 163
    .line 164
    instance-of v8, v1, Ltl/g;

    .line 165
    .line 166
    if-nez v8, :cond_c

    .line 167
    .line 168
    instance-of v8, v1, Le3/f;

    .line 169
    .line 170
    if-nez v8, :cond_b

    .line 171
    .line 172
    instance-of v8, v1, Lj3/f;

    .line 173
    .line 174
    if-nez v8, :cond_a

    .line 175
    .line 176
    instance-of v1, v1, Li3/c;

    .line 177
    .line 178
    if-nez v1, :cond_9

    .line 179
    .line 180
    iget-object v1, v0, Ltl/h;->c:Lvl/a;

    .line 181
    .line 182
    if-nez v1, :cond_8

    .line 183
    .line 184
    const v1, -0x1d58f75c

    .line 185
    .line 186
    .line 187
    invoke-virtual {v9, v1}, Ll2/t;->Z(I)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v9}, Ll2/t;->L()Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    sget-object v2, Ll2/n;->a:Ll2/x0;

    .line 195
    .line 196
    if-ne v1, v2, :cond_6

    .line 197
    .line 198
    new-instance v1, Ljl/h;

    .line 199
    .line 200
    invoke-direct {v1, v0, v7}, Ljl/h;-><init>(Ltl/h;Lil/j;)V

    .line 201
    .line 202
    .line 203
    invoke-virtual {v9, v1}, Ll2/t;->j0(Ljava/lang/Object;)V

    .line 204
    .line 205
    .line 206
    :cond_6
    const/4 v2, 0x0

    .line 207
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 208
    .line 209
    .line 210
    check-cast v1, Ljl/h;

    .line 211
    .line 212
    iput-object v5, v1, Ljl/h;->p:Lay0/k;

    .line 213
    .line 214
    iput-object v6, v1, Ljl/h;->q:Lt3/k;

    .line 215
    .line 216
    const/4 v5, 0x1

    .line 217
    iput v5, v1, Ljl/h;->r:I

    .line 218
    .line 219
    sget-object v5, Lw3/q1;->a:Ll2/u2;

    .line 220
    .line 221
    invoke-virtual {v9, v5}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 222
    .line 223
    .line 224
    move-result-object v5

    .line 225
    check-cast v5, Ljava/lang/Boolean;

    .line 226
    .line 227
    invoke-virtual {v5}, Ljava/lang/Boolean;->booleanValue()Z

    .line 228
    .line 229
    .line 230
    move-result v5

    .line 231
    iput-boolean v5, v1, Ljl/h;->s:Z

    .line 232
    .line 233
    iget-object v5, v1, Ljl/h;->v:Ll2/j1;

    .line 234
    .line 235
    invoke-virtual {v5, v7}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 236
    .line 237
    .line 238
    iget-object v5, v1, Ljl/h;->u:Ll2/j1;

    .line 239
    .line 240
    invoke-virtual {v5, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 241
    .line 242
    .line 243
    invoke-virtual {v1}, Ljl/h;->c()V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {v9, v2}, Ll2/t;->q(Z)V

    .line 250
    .line 251
    .line 252
    sget-object v0, Lw3/h1;->h:Ll2/u2;

    .line 253
    .line 254
    invoke-virtual {v9, v0}, Ll2/t;->k(Ll2/s1;)Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v0

    .line 258
    check-cast v0, Lt4/c;

    .line 259
    .line 260
    sget-object v6, Lx2/c;->h:Lx2/j;

    .line 261
    .line 262
    new-instance v5, Ltv/k;

    .line 263
    .line 264
    invoke-direct {v5, v0, v1, p1, v2}, Ltv/k;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 265
    .line 266
    .line 267
    const v0, -0x71a8bb2b

    .line 268
    .line 269
    .line 270
    invoke-static {v0, v9, v5}, Lt2/c;->b(ILl2/o;Llx0/e;)Lt2/b;

    .line 271
    .line 272
    .line 273
    move-result-object v8

    .line 274
    const/16 v10, 0xc36

    .line 275
    .line 276
    const/4 v11, 0x4

    .line 277
    const/4 v7, 0x0

    .line 278
    move-object v5, p2

    .line 279
    invoke-static/range {v5 .. v11}, Lk1/d;->a(Lx2/s;Lx2/e;ZLt2/b;Ll2/o;II)V

    .line 280
    .line 281
    .line 282
    :goto_4
    invoke-virtual {v9}, Ll2/t;->s()Ll2/u1;

    .line 283
    .line 284
    .line 285
    move-result-object v6

    .line 286
    if-eqz v6, :cond_7

    .line 287
    .line 288
    new-instance v0, Lf7/f;

    .line 289
    .line 290
    const/4 v2, 0x2

    .line 291
    move-object v3, p0

    .line 292
    move-object v4, p1

    .line 293
    move-object v5, p2

    .line 294
    move/from16 v1, p4

    .line 295
    .line 296
    invoke-direct/range {v0 .. v5}, Lf7/f;-><init>(IILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 297
    .line 298
    .line 299
    iput-object v0, v6, Ll2/u1;->d:Lay0/n;

    .line 300
    .line 301
    :cond_7
    return-void

    .line 302
    :cond_8
    const-string v0, "request.target must be null."

    .line 303
    .line 304
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 305
    .line 306
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    throw v1

    .line 310
    :cond_9
    const-string v0, "Painter"

    .line 311
    .line 312
    invoke-static {v0}, Ljl/j;->a(Ljava/lang/String;)V

    .line 313
    .line 314
    .line 315
    throw v2

    .line 316
    :cond_a
    const-string v0, "ImageVector"

    .line 317
    .line 318
    invoke-static {v0}, Ljl/j;->a(Ljava/lang/String;)V

    .line 319
    .line 320
    .line 321
    throw v2

    .line 322
    :cond_b
    const-string v0, "ImageBitmap"

    .line 323
    .line 324
    invoke-static {v0}, Ljl/j;->a(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw v2

    .line 328
    :cond_c
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 329
    .line 330
    const-string v1, "Unsupported type: ImageRequest.Builder. Did you forget to call ImageRequest.Builder.build()?"

    .line 331
    .line 332
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 333
    .line 334
    .line 335
    throw v0
.end method

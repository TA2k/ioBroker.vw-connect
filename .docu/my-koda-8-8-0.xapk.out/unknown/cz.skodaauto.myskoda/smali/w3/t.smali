.class public final Lw3/t;
.super Landroid/view/ViewGroup;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/o1;
.implements Lv3/w1;
.implements Lp3/g;
.implements Landroidx/lifecycle/f;
.implements Lv3/m1;


# static fields
.field public static T1:Ljava/lang/Class;

.field public static U1:Ljava/lang/reflect/Method;

.field public static V1:Ljava/lang/reflect/Method;

.field public static final W1:Landroidx/collection/l0;

.field public static X1:Lu/g;

.field public static Y1:Ljava/lang/reflect/Method;


# instance fields
.field public final A:Ljava/util/ArrayList;

.field public final A1:Ll3/b;

.field public B:Ljava/util/ArrayList;

.field public final B1:Lm3/c;

.field public C:Z

.field public final C1:Lu3/d;

.field public D:Z

.field public final D1:Lw3/n0;

.field public final E:Lp3/h;

.field public E1:Landroid/view/MotionEvent;

.field public final F:Lvv0/d;

.field public F1:J

.field public G:Lay0/k;

.field public final G1:Lb81/b;

.field public final H:Lun/a;

.field public final H1:Landroidx/collection/l0;

.field public final I:Ly2/b;

.field public I1:F

.field public J:Z

.field public J1:F

.field public final K:Lw3/i;

.field public final K1:Lvp/g4;

.field public final L:Lw3/h;

.field public final L1:Lm8/o;

.field public final M:Lv3/q1;

.field public M1:Z

.field public N:Z

.field public final N1:Lw3/q;

.field public O:Lw3/t0;

.field public final O1:Lw3/a1;

.field public P:Lt4/a;

.field public P1:Z

.field public Q:Z

.field public final Q1:Laq/a;

.field public final R:Lv3/w0;

.field public R1:Landroid/view/View;

.field public S:J

.field public final S1:Lw3/r;

.field public final T:[I

.field public final U:[F

.field public final V:[F

.field public final W:[F

.field public a0:J

.field public b0:Z

.field public c0:J

.field public d:J

.field public final d0:Ll2/j1;

.field public final e:Z

.field public final e0:Ll2/h0;

.field public final f:Lv3/j0;

.field public f0:Lay0/k;

.field public final g:Ll2/j1;

.field public final g0:Lq61/l;

.field public final h:Landroid/view/View;

.field public final i:Z

.field public final j:Lc3/l;

.field public k:Lpx0/g;

.field public final l:La3/a;

.field public final m:Lw3/r1;

.field public final n:Laq/a;

.field public final o:Lw3/s0;

.field public final p:Lt3/s;

.field public final q:Lv3/h0;

.field public final q1:Lw3/j;

.field public final r:Landroidx/collection/b0;

.field public final r1:Lw3/k;

.field public final s:Le4/a;

.field public final s1:Ll4/y;

.field public final t:Lw3/t;

.field public final t1:Ll4/w;

.field public final u:Ld4/s;

.field public final u1:Ljava/util/concurrent/atomic/AtomicReference;

.field public final v:Lw3/z;

.field public final v1:Lw3/i1;

.field public w:Lz2/e;

.field public final w1:Lw3/x0;

.field public final x:Lw3/g;

.field public final x1:Ll2/j1;

.field public final y:Le3/e;

.field public y1:I

.field public final z:Ly2/h;

.field public final z1:Ll2/j1;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroidx/collection/l0;

    .line 2
    .line 3
    invoke-direct {v0}, Landroidx/collection/l0;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lw3/t;->W1:Landroidx/collection/l0;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lpx0/g;)V
    .locals 18

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    move-object/from16 v8, p1

    .line 4
    .line 5
    invoke-direct/range {p0 .. p1}, Landroid/view/ViewGroup;-><init>(Landroid/content/Context;)V

    .line 6
    .line 7
    .line 8
    const-wide v0, 0x7fc000007fc00000L    # 2.247117487993712E307

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    iput-wide v0, v2, Lw3/t;->d:J

    .line 14
    .line 15
    const/4 v9, 0x1

    .line 16
    iput-boolean v9, v2, Lw3/t;->e:Z

    .line 17
    .line 18
    new-instance v0, Lv3/j0;

    .line 19
    .line 20
    invoke-direct {v0}, Lv3/j0;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v0, v2, Lw3/t;->f:Lv3/j0;

    .line 24
    .line 25
    invoke-static {v8}, Lkp/z8;->a(Landroid/content/Context;)Lt4/e;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    sget-object v10, Ll2/x0;->g:Ll2/x0;

    .line 30
    .line 31
    new-instance v1, Ll2/j1;

    .line 32
    .line 33
    invoke-direct {v1, v0, v10}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 34
    .line 35
    .line 36
    iput-object v1, v2, Lw3/t;->g:Ll2/j1;

    .line 37
    .line 38
    sget v11, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 39
    .line 40
    const/16 v0, 0x23

    .line 41
    .line 42
    if-lt v11, v0, :cond_0

    .line 43
    .line 44
    move v13, v9

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    const/4 v13, 0x0

    .line 47
    :goto_0
    iput-boolean v13, v2, Lw3/t;->i:Z

    .line 48
    .line 49
    new-instance v14, Ld4/e;

    .line 50
    .line 51
    invoke-direct {v14}, Lx2/r;-><init>()V

    .line 52
    .line 53
    .line 54
    new-instance v15, Landroidx/compose/ui/semantics/EmptySemanticsElement;

    .line 55
    .line 56
    invoke-direct {v15, v14}, Landroidx/compose/ui/semantics/EmptySemanticsElement;-><init>(Ld4/e;)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Landroidx/compose/ui/platform/AndroidComposeView$bringIntoViewNode$1;

    .line 60
    .line 61
    invoke-direct {v0, v2}, Landroidx/compose/ui/platform/AndroidComposeView$bringIntoViewNode$1;-><init>(Lw3/t;)V

    .line 62
    .line 63
    .line 64
    new-instance v1, Lc3/l;

    .line 65
    .line 66
    invoke-direct {v1, v2, v2}, Lc3/l;-><init>(Lw3/t;Lw3/t;)V

    .line 67
    .line 68
    .line 69
    iput-object v1, v2, Lw3/t;->j:Lc3/l;

    .line 70
    .line 71
    move-object/from16 v1, p2

    .line 72
    .line 73
    iput-object v1, v2, Lw3/t;->k:Lpx0/g;

    .line 74
    .line 75
    new-instance v1, La3/a;

    .line 76
    .line 77
    move-object v3, v0

    .line 78
    new-instance v0, Laj/a;

    .line 79
    .line 80
    const/4 v6, 0x0

    .line 81
    const/4 v7, 0x2

    .line 82
    move-object v4, v1

    .line 83
    const/4 v1, 0x3

    .line 84
    move-object v5, v3

    .line 85
    const-class v3, Lw3/t;

    .line 86
    .line 87
    move-object/from16 v16, v4

    .line 88
    .line 89
    const-string v4, "startDrag"

    .line 90
    .line 91
    move-object/from16 v17, v5

    .line 92
    .line 93
    const-string v5, "startDrag-12SF9DM(Landroidx/compose/ui/draganddrop/DragAndDropTransferData;JLkotlin/jvm/functions/Function1;)Z"

    .line 94
    .line 95
    move-object/from16 v9, v16

    .line 96
    .line 97
    move-object/from16 v12, v17

    .line 98
    .line 99
    invoke-direct/range {v0 .. v7}, Laj/a;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 100
    .line 101
    .line 102
    invoke-direct {v9, v0}, La3/a;-><init>(Laj/a;)V

    .line 103
    .line 104
    .line 105
    iput-object v9, v2, Lw3/t;->l:La3/a;

    .line 106
    .line 107
    new-instance v0, Lw3/r1;

    .line 108
    .line 109
    invoke-direct {v0}, Lw3/r1;-><init>()V

    .line 110
    .line 111
    .line 112
    iput-object v0, v2, Lw3/t;->m:Lw3/r1;

    .line 113
    .line 114
    new-instance v0, Lw3/m;

    .line 115
    .line 116
    const/4 v1, 0x1

    .line 117
    invoke-direct {v0, v2, v1}, Lw3/m;-><init>(Lw3/t;I)V

    .line 118
    .line 119
    .line 120
    sget-object v1, Lx2/p;->b:Lx2/p;

    .line 121
    .line 122
    invoke-static {v1, v0}, Landroidx/compose/ui/input/key/a;->a(Lx2/s;Lay0/k;)Lx2/s;

    .line 123
    .line 124
    .line 125
    move-result-object v0

    .line 126
    invoke-static {}, Landroidx/compose/ui/input/rotary/a;->a()Lx2/s;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    new-instance v3, Laq/a;

    .line 131
    .line 132
    const/16 v4, 0x11

    .line 133
    .line 134
    invoke-direct {v3, v4}, Laq/a;-><init>(I)V

    .line 135
    .line 136
    .line 137
    iput-object v3, v2, Lw3/t;->n:Laq/a;

    .line 138
    .line 139
    new-instance v3, Lw3/s0;

    .line 140
    .line 141
    invoke-static {v8}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 142
    .line 143
    .line 144
    move-result-object v4

    .line 145
    invoke-direct {v3, v4}, Lw3/s0;-><init>(Landroid/view/ViewConfiguration;)V

    .line 146
    .line 147
    .line 148
    iput-object v3, v2, Lw3/t;->o:Lw3/s0;

    .line 149
    .line 150
    new-instance v3, Lt3/s;

    .line 151
    .line 152
    invoke-direct {v3}, Lt3/s;-><init>()V

    .line 153
    .line 154
    .line 155
    iput-object v3, v2, Lw3/t;->p:Lt3/s;

    .line 156
    .line 157
    new-instance v4, Lv3/h0;

    .line 158
    .line 159
    const/4 v5, 0x3

    .line 160
    invoke-direct {v4, v5}, Lv3/h0;-><init>(I)V

    .line 161
    .line 162
    .line 163
    sget-object v5, Lt3/h1;->b:Lt3/h1;

    .line 164
    .line 165
    invoke-virtual {v4, v5}, Lv3/h0;->h0(Lt3/q0;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v2}, Lw3/t;->getDensity()Lt4/c;

    .line 169
    .line 170
    .line 171
    move-result-object v5

    .line 172
    invoke-virtual {v4, v5}, Lv3/h0;->d0(Lt4/c;)V

    .line 173
    .line 174
    .line 175
    invoke-virtual {v2}, Lw3/t;->getViewConfiguration()Lw3/h2;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    invoke-virtual {v4, v5}, Lv3/h0;->j0(Lw3/h2;)V

    .line 180
    .line 181
    .line 182
    invoke-static {v3}, Landroidx/compose/ui/layout/b;->b(Lt3/s;)Lx2/s;

    .line 183
    .line 184
    .line 185
    move-result-object v3

    .line 186
    invoke-interface {v3, v15}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 187
    .line 188
    .line 189
    move-result-object v3

    .line 190
    invoke-interface {v3, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    invoke-interface {v1, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    invoke-virtual {v2}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 199
    .line 200
    .line 201
    move-result-object v1

    .line 202
    check-cast v1, Lc3/l;

    .line 203
    .line 204
    iget-object v1, v1, Lc3/l;->e:Landroidx/compose/ui/focus/FocusOwnerImpl$modifier$1;

    .line 205
    .line 206
    invoke-interface {v0, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    invoke-virtual {v2}, Lw3/t;->getDragAndDropManager()La3/a;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    iget-object v1, v1, La3/a;->c:Landroidx/compose/ui/draganddrop/AndroidDragAndDropManager$modifier$1;

    .line 215
    .line 216
    invoke-interface {v0, v1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 217
    .line 218
    .line 219
    move-result-object v0

    .line 220
    invoke-interface {v0, v12}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 221
    .line 222
    .line 223
    move-result-object v0

    .line 224
    invoke-virtual {v4, v0}, Lv3/h0;->i0(Lx2/s;)V

    .line 225
    .line 226
    .line 227
    iput-object v4, v2, Lw3/t;->q:Lv3/h0;

    .line 228
    .line 229
    sget-object v0, Landroidx/collection/q;->a:Landroidx/collection/b0;

    .line 230
    .line 231
    new-instance v0, Landroidx/collection/b0;

    .line 232
    .line 233
    invoke-direct {v0}, Landroidx/collection/b0;-><init>()V

    .line 234
    .line 235
    .line 236
    iput-object v0, v2, Lw3/t;->r:Landroidx/collection/b0;

    .line 237
    .line 238
    new-instance v0, Le4/a;

    .line 239
    .line 240
    invoke-virtual {v2}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    .line 241
    .line 242
    .line 243
    invoke-direct {v0}, Le4/a;-><init>()V

    .line 244
    .line 245
    .line 246
    iput-object v0, v2, Lw3/t;->s:Le4/a;

    .line 247
    .line 248
    iput-object v2, v2, Lw3/t;->t:Lw3/t;

    .line 249
    .line 250
    new-instance v0, Ld4/s;

    .line 251
    .line 252
    invoke-virtual {v2}, Lw3/t;->getRoot()Lv3/h0;

    .line 253
    .line 254
    .line 255
    move-result-object v1

    .line 256
    invoke-virtual {v2}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    .line 257
    .line 258
    .line 259
    move-result-object v3

    .line 260
    invoke-direct {v0, v1, v14, v3}, Ld4/s;-><init>(Lv3/h0;Ld4/e;Landroidx/collection/b0;)V

    .line 261
    .line 262
    .line 263
    iput-object v0, v2, Lw3/t;->u:Ld4/s;

    .line 264
    .line 265
    new-instance v9, Lw3/z;

    .line 266
    .line 267
    invoke-direct {v9, v2}, Lw3/z;-><init>(Lw3/t;)V

    .line 268
    .line 269
    .line 270
    iput-object v9, v2, Lw3/t;->v:Lw3/z;

    .line 271
    .line 272
    new-instance v12, Lz2/e;

    .line 273
    .line 274
    new-instance v0, Lw00/h;

    .line 275
    .line 276
    const/4 v6, 0x1

    .line 277
    const/4 v7, 0x3

    .line 278
    const/4 v1, 0x0

    .line 279
    const-class v3, Lw3/h0;

    .line 280
    .line 281
    const-string v4, "getContentCaptureSessionCompat"

    .line 282
    .line 283
    const-string v5, "getContentCaptureSessionCompat(Landroid/view/View;)Landroidx/compose/ui/platform/coreshims/ContentCaptureSessionCompat;"

    .line 284
    .line 285
    invoke-direct/range {v0 .. v7}, Lw00/h;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 286
    .line 287
    .line 288
    invoke-direct {v12, v2, v0}, Lz2/e;-><init>(Lw3/t;Lw00/h;)V

    .line 289
    .line 290
    .line 291
    iput-object v12, v2, Lw3/t;->w:Lz2/e;

    .line 292
    .line 293
    new-instance v0, Lw3/g;

    .line 294
    .line 295
    invoke-direct {v0, v8}, Lw3/g;-><init>(Landroid/content/Context;)V

    .line 296
    .line 297
    .line 298
    iput-object v0, v2, Lw3/t;->x:Lw3/g;

    .line 299
    .line 300
    new-instance v0, Le3/e;

    .line 301
    .line 302
    invoke-direct {v0, v2}, Le3/e;-><init>(Lw3/t;)V

    .line 303
    .line 304
    .line 305
    iput-object v0, v2, Lw3/t;->y:Le3/e;

    .line 306
    .line 307
    new-instance v0, Ly2/h;

    .line 308
    .line 309
    invoke-direct {v0}, Ly2/h;-><init>()V

    .line 310
    .line 311
    .line 312
    iput-object v0, v2, Lw3/t;->z:Ly2/h;

    .line 313
    .line 314
    new-instance v0, Ljava/util/ArrayList;

    .line 315
    .line 316
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 317
    .line 318
    .line 319
    iput-object v0, v2, Lw3/t;->A:Ljava/util/ArrayList;

    .line 320
    .line 321
    new-instance v0, Lp3/h;

    .line 322
    .line 323
    invoke-direct {v0}, Lp3/h;-><init>()V

    .line 324
    .line 325
    .line 326
    iput-object v0, v2, Lw3/t;->E:Lp3/h;

    .line 327
    .line 328
    new-instance v0, Lvv0/d;

    .line 329
    .line 330
    invoke-virtual {v2}, Lw3/t;->getRoot()Lv3/h0;

    .line 331
    .line 332
    .line 333
    move-result-object v1

    .line 334
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 335
    .line 336
    .line 337
    iput-object v1, v0, Lvv0/d;->b:Ljava/lang/Object;

    .line 338
    .line 339
    new-instance v3, Lp3/d;

    .line 340
    .line 341
    iget-object v1, v1, Lv3/h0;->H:Lg1/q;

    .line 342
    .line 343
    iget-object v1, v1, Lg1/q;->d:Ljava/lang/Object;

    .line 344
    .line 345
    check-cast v1, Lv3/u;

    .line 346
    .line 347
    invoke-direct {v3, v1}, Lp3/d;-><init>(Lt3/y;)V

    .line 348
    .line 349
    .line 350
    iput-object v3, v0, Lvv0/d;->c:Ljava/lang/Object;

    .line 351
    .line 352
    new-instance v1, Lhu/q;

    .line 353
    .line 354
    const/16 v3, 0x1d

    .line 355
    .line 356
    const/4 v4, 0x0

    .line 357
    invoke-direct {v1, v4, v3}, Lhu/q;-><init>(BI)V

    .line 358
    .line 359
    .line 360
    iput-object v1, v0, Lvv0/d;->d:Ljava/lang/Object;

    .line 361
    .line 362
    new-instance v1, Lv3/s;

    .line 363
    .line 364
    invoke-direct {v1}, Lv3/s;-><init>()V

    .line 365
    .line 366
    .line 367
    iput-object v1, v0, Lvv0/d;->e:Ljava/lang/Object;

    .line 368
    .line 369
    iput-object v0, v2, Lw3/t;->F:Lvv0/d;

    .line 370
    .line 371
    sget-object v0, Lw3/o;->g:Lw3/o;

    .line 372
    .line 373
    iput-object v0, v2, Lw3/t;->G:Lay0/k;

    .line 374
    .line 375
    new-instance v0, Lun/a;

    .line 376
    .line 377
    invoke-virtual {v2}, Lw3/t;->getAutofillTree()Ly2/h;

    .line 378
    .line 379
    .line 380
    move-result-object v1

    .line 381
    invoke-direct {v0, v2, v1}, Lun/a;-><init>(Lw3/t;Ly2/h;)V

    .line 382
    .line 383
    .line 384
    iput-object v0, v2, Lw3/t;->H:Lun/a;

    .line 385
    .line 386
    const-class v0, Landroid/view/autofill/AutofillManager;

    .line 387
    .line 388
    invoke-virtual {v8, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/Class;)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object v0

    .line 392
    check-cast v0, Landroid/view/autofill/AutofillManager;

    .line 393
    .line 394
    if-eqz v0, :cond_8

    .line 395
    .line 396
    new-instance v1, Ly2/b;

    .line 397
    .line 398
    move-object v3, v1

    .line 399
    new-instance v1, Lpv/g;

    .line 400
    .line 401
    const/16 v6, 0x1c

    .line 402
    .line 403
    invoke-direct {v1, v0, v6}, Lpv/g;-><init>(Ljava/lang/Object;I)V

    .line 404
    .line 405
    .line 406
    invoke-virtual/range {p0 .. p0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 407
    .line 408
    .line 409
    move-result-object v2

    .line 410
    invoke-virtual/range {p0 .. p0}, Lw3/t;->getRectManager()Le4/a;

    .line 411
    .line 412
    .line 413
    move-result-object v4

    .line 414
    invoke-virtual {v8}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 415
    .line 416
    .line 417
    move-result-object v5

    .line 418
    move-object v0, v3

    .line 419
    move-object/from16 v3, p0

    .line 420
    .line 421
    invoke-direct/range {v0 .. v5}, Ly2/b;-><init>(Lpv/g;Ld4/s;Lw3/t;Le4/a;Ljava/lang/String;)V

    .line 422
    .line 423
    .line 424
    move-object v2, v3

    .line 425
    iput-object v0, v2, Lw3/t;->I:Ly2/b;

    .line 426
    .line 427
    new-instance v0, Lw3/i;

    .line 428
    .line 429
    invoke-direct {v0, v8}, Lw3/i;-><init>(Landroid/content/Context;)V

    .line 430
    .line 431
    .line 432
    iput-object v0, v2, Lw3/t;->K:Lw3/i;

    .line 433
    .line 434
    new-instance v0, Lw3/h;

    .line 435
    .line 436
    invoke-virtual {v2}, Lw3/t;->getClipboardManager()Lw3/i;

    .line 437
    .line 438
    .line 439
    move-result-object v1

    .line 440
    invoke-direct {v0, v1}, Lw3/h;-><init>(Lw3/i;)V

    .line 441
    .line 442
    .line 443
    iput-object v0, v2, Lw3/t;->L:Lw3/h;

    .line 444
    .line 445
    new-instance v0, Lv3/q1;

    .line 446
    .line 447
    new-instance v1, Lw3/m;

    .line 448
    .line 449
    const/4 v3, 0x2

    .line 450
    invoke-direct {v1, v2, v3}, Lw3/m;-><init>(Lw3/t;I)V

    .line 451
    .line 452
    .line 453
    invoke-direct {v0, v1}, Lv3/q1;-><init>(Lw3/m;)V

    .line 454
    .line 455
    .line 456
    iput-object v0, v2, Lw3/t;->M:Lv3/q1;

    .line 457
    .line 458
    new-instance v0, Lv3/w0;

    .line 459
    .line 460
    invoke-virtual {v2}, Lw3/t;->getRoot()Lv3/h0;

    .line 461
    .line 462
    .line 463
    move-result-object v1

    .line 464
    invoke-direct {v0, v1}, Lv3/w0;-><init>(Lv3/h0;)V

    .line 465
    .line 466
    .line 467
    iput-object v0, v2, Lw3/t;->R:Lv3/w0;

    .line 468
    .line 469
    const v0, 0x7fffffff

    .line 470
    .line 471
    .line 472
    int-to-long v0, v0

    .line 473
    const/16 v4, 0x20

    .line 474
    .line 475
    shl-long v4, v0, v4

    .line 476
    .line 477
    const-wide v14, 0xffffffffL

    .line 478
    .line 479
    .line 480
    .line 481
    .line 482
    and-long/2addr v0, v14

    .line 483
    or-long/2addr v0, v4

    .line 484
    iput-wide v0, v2, Lw3/t;->S:J

    .line 485
    .line 486
    const/4 v4, 0x0

    .line 487
    filled-new-array {v4, v4}, [I

    .line 488
    .line 489
    .line 490
    move-result-object v0

    .line 491
    iput-object v0, v2, Lw3/t;->T:[I

    .line 492
    .line 493
    invoke-static {}, Le3/c0;->a()[F

    .line 494
    .line 495
    .line 496
    move-result-object v0

    .line 497
    iput-object v0, v2, Lw3/t;->U:[F

    .line 498
    .line 499
    invoke-static {}, Le3/c0;->a()[F

    .line 500
    .line 501
    .line 502
    move-result-object v0

    .line 503
    iput-object v0, v2, Lw3/t;->V:[F

    .line 504
    .line 505
    invoke-static {}, Le3/c0;->a()[F

    .line 506
    .line 507
    .line 508
    move-result-object v0

    .line 509
    iput-object v0, v2, Lw3/t;->W:[F

    .line 510
    .line 511
    const-wide/16 v0, -0x1

    .line 512
    .line 513
    iput-wide v0, v2, Lw3/t;->a0:J

    .line 514
    .line 515
    const-wide v0, 0x7f8000007f800000L    # 1.404448428688076E306

    .line 516
    .line 517
    .line 518
    .line 519
    .line 520
    iput-wide v0, v2, Lw3/t;->c0:J

    .line 521
    .line 522
    const/4 v0, 0x0

    .line 523
    invoke-static {v0}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 524
    .line 525
    .line 526
    move-result-object v1

    .line 527
    iput-object v1, v2, Lw3/t;->d0:Ll2/j1;

    .line 528
    .line 529
    new-instance v1, Lw3/q;

    .line 530
    .line 531
    invoke-direct {v1, v2, v3}, Lw3/q;-><init>(Lw3/t;I)V

    .line 532
    .line 533
    .line 534
    invoke-static {v1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 535
    .line 536
    .line 537
    move-result-object v1

    .line 538
    iput-object v1, v2, Lw3/t;->e0:Ll2/h0;

    .line 539
    .line 540
    new-instance v1, Lq61/l;

    .line 541
    .line 542
    const/4 v4, 0x1

    .line 543
    invoke-direct {v1, v2, v4}, Lq61/l;-><init>(Ljava/lang/Object;I)V

    .line 544
    .line 545
    .line 546
    iput-object v1, v2, Lw3/t;->g0:Lq61/l;

    .line 547
    .line 548
    new-instance v1, Lw3/j;

    .line 549
    .line 550
    invoke-direct {v1, v2}, Lw3/j;-><init>(Lw3/t;)V

    .line 551
    .line 552
    .line 553
    iput-object v1, v2, Lw3/t;->q1:Lw3/j;

    .line 554
    .line 555
    new-instance v1, Lw3/k;

    .line 556
    .line 557
    invoke-direct {v1, v2}, Lw3/k;-><init>(Lw3/t;)V

    .line 558
    .line 559
    .line 560
    iput-object v1, v2, Lw3/t;->r1:Lw3/k;

    .line 561
    .line 562
    new-instance v1, Ll4/y;

    .line 563
    .line 564
    invoke-virtual {v2}, Lw3/t;->getView()Landroid/view/View;

    .line 565
    .line 566
    .line 567
    move-result-object v4

    .line 568
    invoke-direct {v1, v4, v2}, Ll4/y;-><init>(Landroid/view/View;Lw3/t;)V

    .line 569
    .line 570
    .line 571
    iput-object v1, v2, Lw3/t;->s1:Ll4/y;

    .line 572
    .line 573
    new-instance v4, Ll4/w;

    .line 574
    .line 575
    invoke-direct {v4, v1}, Ll4/w;-><init>(Ll4/q;)V

    .line 576
    .line 577
    .line 578
    iput-object v4, v2, Lw3/t;->t1:Ll4/w;

    .line 579
    .line 580
    new-instance v1, Ljava/util/concurrent/atomic/AtomicReference;

    .line 581
    .line 582
    invoke-direct {v1, v0}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    .line 583
    .line 584
    .line 585
    iput-object v1, v2, Lw3/t;->u1:Ljava/util/concurrent/atomic/AtomicReference;

    .line 586
    .line 587
    new-instance v1, Lw3/i1;

    .line 588
    .line 589
    invoke-virtual {v2}, Lw3/t;->getTextInputService()Ll4/w;

    .line 590
    .line 591
    .line 592
    move-result-object v4

    .line 593
    invoke-direct {v1, v4}, Lw3/i1;-><init>(Ll4/w;)V

    .line 594
    .line 595
    .line 596
    iput-object v1, v2, Lw3/t;->v1:Lw3/i1;

    .line 597
    .line 598
    new-instance v1, Lw3/x0;

    .line 599
    .line 600
    const/4 v4, 0x4

    .line 601
    invoke-direct {v1, v4}, Lw3/x0;-><init>(I)V

    .line 602
    .line 603
    .line 604
    iput-object v1, v2, Lw3/t;->w1:Lw3/x0;

    .line 605
    .line 606
    invoke-static {v8}, Llp/wc;->a(Landroid/content/Context;)Lk4/o;

    .line 607
    .line 608
    .line 609
    move-result-object v1

    .line 610
    new-instance v4, Ll2/j1;

    .line 611
    .line 612
    invoke-direct {v4, v1, v10}, Ll2/j1;-><init>(Ljava/lang/Object;Ll2/n2;)V

    .line 613
    .line 614
    .line 615
    iput-object v4, v2, Lw3/t;->x1:Ll2/j1;

    .line 616
    .line 617
    invoke-virtual {v8}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 618
    .line 619
    .line 620
    move-result-object v1

    .line 621
    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 622
    .line 623
    .line 624
    move-result-object v1

    .line 625
    const/16 v4, 0x1f

    .line 626
    .line 627
    if-lt v11, v4, :cond_1

    .line 628
    .line 629
    invoke-static {v1}, Lh4/b;->a(Landroid/content/res/Configuration;)I

    .line 630
    .line 631
    .line 632
    move-result v1

    .line 633
    goto :goto_1

    .line 634
    :cond_1
    const/4 v1, 0x0

    .line 635
    :goto_1
    iput v1, v2, Lw3/t;->y1:I

    .line 636
    .line 637
    invoke-virtual {v8}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 638
    .line 639
    .line 640
    move-result-object v1

    .line 641
    invoke-virtual {v1}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    .line 642
    .line 643
    .line 644
    move-result-object v1

    .line 645
    invoke-virtual {v1}, Landroid/content/res/Configuration;->getLayoutDirection()I

    .line 646
    .line 647
    .line 648
    move-result v1

    .line 649
    if-eqz v1, :cond_3

    .line 650
    .line 651
    const/4 v5, 0x1

    .line 652
    if-eq v1, v5, :cond_2

    .line 653
    .line 654
    move-object v1, v0

    .line 655
    goto :goto_2

    .line 656
    :cond_2
    sget-object v1, Lt4/m;->e:Lt4/m;

    .line 657
    .line 658
    goto :goto_2

    .line 659
    :cond_3
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 660
    .line 661
    :goto_2
    if-nez v1, :cond_4

    .line 662
    .line 663
    sget-object v1, Lt4/m;->d:Lt4/m;

    .line 664
    .line 665
    :cond_4
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 666
    .line 667
    .line 668
    move-result-object v1

    .line 669
    iput-object v1, v2, Lw3/t;->z1:Ll2/j1;

    .line 670
    .line 671
    new-instance v1, Ll3/b;

    .line 672
    .line 673
    const/4 v5, 0x0

    .line 674
    invoke-direct {v1, v2, v5}, Ll3/b;-><init>(Landroid/view/View;I)V

    .line 675
    .line 676
    .line 677
    iput-object v1, v2, Lw3/t;->A1:Ll3/b;

    .line 678
    .line 679
    new-instance v1, Lm3/c;

    .line 680
    .line 681
    invoke-virtual {v2}, Landroid/view/View;->isInTouchMode()Z

    .line 682
    .line 683
    .line 684
    move-result v7

    .line 685
    if-eqz v7, :cond_5

    .line 686
    .line 687
    const/4 v7, 0x1

    .line 688
    goto :goto_3

    .line 689
    :cond_5
    move v7, v3

    .line 690
    :goto_3
    new-instance v10, Lw3/m;

    .line 691
    .line 692
    invoke-direct {v10, v2, v5}, Lw3/m;-><init>(Lw3/t;I)V

    .line 693
    .line 694
    .line 695
    invoke-direct {v1, v7, v10}, Lm3/c;-><init>(ILw3/m;)V

    .line 696
    .line 697
    .line 698
    iput-object v1, v2, Lw3/t;->B1:Lm3/c;

    .line 699
    .line 700
    new-instance v1, Lu3/d;

    .line 701
    .line 702
    invoke-direct {v1, v2}, Lu3/d;-><init>(Lw3/t;)V

    .line 703
    .line 704
    .line 705
    iput-object v1, v2, Lw3/t;->C1:Lu3/d;

    .line 706
    .line 707
    new-instance v1, Lw3/n0;

    .line 708
    .line 709
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 710
    .line 711
    .line 712
    new-instance v5, Landroidx/lifecycle/c1;

    .line 713
    .line 714
    new-instance v7, La7/j;

    .line 715
    .line 716
    const/16 v10, 0x1b

    .line 717
    .line 718
    invoke-direct {v7, v1, v10}, La7/j;-><init>(Ljava/lang/Object;I)V

    .line 719
    .line 720
    .line 721
    invoke-direct {v5, v7}, Landroidx/lifecycle/c1;-><init>(La7/j;)V

    .line 722
    .line 723
    .line 724
    sget-object v5, Lw3/e2;->d:[Lw3/e2;

    .line 725
    .line 726
    iput-object v1, v2, Lw3/t;->D1:Lw3/n0;

    .line 727
    .line 728
    new-instance v1, Lb81/b;

    .line 729
    .line 730
    invoke-direct {v1, v6}, Lb81/b;-><init>(I)V

    .line 731
    .line 732
    .line 733
    iput-object v1, v2, Lw3/t;->G1:Lb81/b;

    .line 734
    .line 735
    new-instance v1, Landroidx/collection/l0;

    .line 736
    .line 737
    invoke-direct {v1}, Landroidx/collection/l0;-><init>()V

    .line 738
    .line 739
    .line 740
    iput-object v1, v2, Lw3/t;->H1:Landroidx/collection/l0;

    .line 741
    .line 742
    new-instance v1, Lvp/g4;

    .line 743
    .line 744
    invoke-direct {v1, v2, v3}, Lvp/g4;-><init>(Ljava/lang/Object;I)V

    .line 745
    .line 746
    .line 747
    iput-object v1, v2, Lw3/t;->K1:Lvp/g4;

    .line 748
    .line 749
    new-instance v1, Lm8/o;

    .line 750
    .line 751
    const/16 v3, 0x15

    .line 752
    .line 753
    invoke-direct {v1, v2, v3}, Lm8/o;-><init>(Ljava/lang/Object;I)V

    .line 754
    .line 755
    .line 756
    iput-object v1, v2, Lw3/t;->L1:Lm8/o;

    .line 757
    .line 758
    new-instance v1, Lw3/q;

    .line 759
    .line 760
    const/4 v5, 0x1

    .line 761
    invoke-direct {v1, v2, v5}, Lw3/q;-><init>(Lw3/t;I)V

    .line 762
    .line 763
    .line 764
    iput-object v1, v2, Lw3/t;->N1:Lw3/q;

    .line 765
    .line 766
    new-instance v1, Lw3/a1;

    .line 767
    .line 768
    invoke-direct {v1}, Lw3/a1;-><init>()V

    .line 769
    .line 770
    .line 771
    iput-object v1, v2, Lw3/t;->O1:Lw3/a1;

    .line 772
    .line 773
    iget-object v1, v2, Lw3/t;->w:Lz2/e;

    .line 774
    .line 775
    invoke-virtual {v2, v1}, Landroid/view/View;->addOnAttachStateChangeListener(Landroid/view/View$OnAttachStateChangeListener;)V

    .line 776
    .line 777
    .line 778
    const/4 v1, 0x0

    .line 779
    invoke-virtual {v2, v1}, Landroid/view/View;->setWillNotDraw(Z)V

    .line 780
    .line 781
    .line 782
    invoke-virtual {v2, v5}, Landroid/view/View;->setFocusable(Z)V

    .line 783
    .line 784
    .line 785
    sget-object v3, Lw3/g0;->a:Lw3/g0;

    .line 786
    .line 787
    invoke-virtual {v3, v2, v5, v1}, Lw3/g0;->a(Landroid/view/View;IZ)V

    .line 788
    .line 789
    .line 790
    invoke-virtual {v2, v5}, Landroid/view/View;->setFocusableInTouchMode(Z)V

    .line 791
    .line 792
    .line 793
    invoke-virtual {v2, v1}, Landroid/view/ViewGroup;->setClipChildren(Z)V

    .line 794
    .line 795
    .line 796
    invoke-static {v2, v9}, Ld6/r0;->i(Landroid/view/View;Ld6/b;)V

    .line 797
    .line 798
    .line 799
    invoke-virtual {v2}, Lw3/t;->getDragAndDropManager()La3/a;

    .line 800
    .line 801
    .line 802
    move-result-object v1

    .line 803
    invoke-virtual {v2, v1}, Landroid/view/View;->setOnDragListener(Landroid/view/View$OnDragListener;)V

    .line 804
    .line 805
    .line 806
    invoke-virtual {v2}, Lw3/t;->getRoot()Lv3/h0;

    .line 807
    .line 808
    .line 809
    move-result-object v1

    .line 810
    invoke-virtual {v1, v2}, Lv3/h0;->c(Lv3/o1;)V

    .line 811
    .line 812
    .line 813
    sget-object v1, Lw3/b0;->a:Lw3/b0;

    .line 814
    .line 815
    invoke-virtual {v1, v2}, Lw3/b0;->a(Landroid/view/View;)V

    .line 816
    .line 817
    .line 818
    if-eqz v13, :cond_6

    .line 819
    .line 820
    new-instance v1, Landroid/view/View;

    .line 821
    .line 822
    invoke-direct {v1, v8}, Landroid/view/View;-><init>(Landroid/content/Context;)V

    .line 823
    .line 824
    .line 825
    new-instance v3, Landroid/view/ViewGroup$LayoutParams;

    .line 826
    .line 827
    const/4 v5, 0x1

    .line 828
    invoke-direct {v3, v5, v5}, Landroid/view/ViewGroup$LayoutParams;-><init>(II)V

    .line 829
    .line 830
    .line 831
    invoke-virtual {v1, v3}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 832
    .line 833
    .line 834
    const v3, 0x7f0a018c

    .line 835
    .line 836
    .line 837
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 838
    .line 839
    invoke-virtual {v1, v3, v5}, Landroid/view/View;->setTag(ILjava/lang/Object;)V

    .line 840
    .line 841
    .line 842
    iput-object v1, v2, Lw3/t;->h:Landroid/view/View;

    .line 843
    .line 844
    const/4 v3, -0x1

    .line 845
    invoke-virtual {v2, v1, v3}, Lw3/t;->addView(Landroid/view/View;I)V

    .line 846
    .line 847
    .line 848
    :cond_6
    if-lt v11, v4, :cond_7

    .line 849
    .line 850
    new-instance v0, Laq/a;

    .line 851
    .line 852
    const/16 v1, 0x9

    .line 853
    .line 854
    invoke-direct {v0, v1}, Laq/a;-><init>(I)V

    .line 855
    .line 856
    .line 857
    :cond_7
    iput-object v0, v2, Lw3/t;->Q1:Laq/a;

    .line 858
    .line 859
    new-instance v0, Lw3/r;

    .line 860
    .line 861
    invoke-direct {v0, v2}, Lw3/r;-><init>(Lw3/t;)V

    .line 862
    .line 863
    .line 864
    iput-object v0, v2, Lw3/t;->S1:Lw3/r;

    .line 865
    .line 866
    return-void

    .line 867
    :cond_8
    const-string v0, "Autofill service could not be located."

    .line 868
    .line 869
    invoke-static {v0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 870
    .line 871
    .line 872
    move-result-object v0

    .line 873
    throw v0
.end method

.method public static final a(Lw3/t;ILandroid/view/accessibility/AccessibilityNodeInfo;Ljava/lang/String;)V
    .locals 2

    .line 1
    iget-object p0, p0, Lw3/t;->v:Lw3/z;

    .line 2
    .line 3
    iget-object v0, p0, Lw3/z;->G:Ljava/lang/String;

    .line 4
    .line 5
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, -0x1

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object p0, p0, Lw3/z;->E:Landroidx/collection/z;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Landroidx/collection/z;->d(I)I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eq p0, v1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p2}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p1, p3, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_0
    iget-object v0, p0, Lw3/z;->H:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_1

    .line 35
    .line 36
    iget-object p0, p0, Lw3/z;->F:Landroidx/collection/z;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Landroidx/collection/z;->d(I)I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    if-eq p0, v1, :cond_1

    .line 43
    .line 44
    invoke-virtual {p2}, Landroid/view/accessibility/AccessibilityNodeInfo;->getExtras()Landroid/os/Bundle;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    invoke-virtual {p1, p3, p0}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    :cond_1
    return-void
.end method

.method public static final synthetic b(Landroid/view/MotionEvent;Lw3/t;)Z
    .locals 0

    .line 1
    invoke-super {p1, p0}, Landroid/view/View;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final synthetic c(Lw3/t;Landroid/view/KeyEvent;)Z
    .locals 0

    .line 1
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public static final synthetic d(Lw3/t;)Lw3/l;
    .locals 0

    .line 1
    invoke-direct {p0}, Lw3/t;->get_viewTreeOwners()Lw3/l;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static e(Landroid/view/ViewGroup;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Landroid/view/ViewGroup;->getChildCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    :goto_0
    if-ge v1, v0, :cond_2

    .line 7
    .line 8
    invoke-virtual {p0, v1}, Landroid/view/ViewGroup;->getChildAt(I)Landroid/view/View;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    instance-of v3, v2, Lw3/t;

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    check-cast v2, Lw3/t;

    .line 17
    .line 18
    invoke-virtual {v2}, Lw3/t;->u()V

    .line 19
    .line 20
    .line 21
    goto :goto_1

    .line 22
    :cond_0
    instance-of v3, v2, Landroid/view/ViewGroup;

    .line 23
    .line 24
    if-eqz v3, :cond_1

    .line 25
    .line 26
    check-cast v2, Landroid/view/ViewGroup;

    .line 27
    .line 28
    invoke-static {v2}, Lw3/t;->e(Landroid/view/ViewGroup;)V

    .line 29
    .line 30
    .line 31
    :cond_1
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    return-void
.end method

.method public static g(I)J
    .locals 4

    .line 1
    invoke-static {p0}, Landroid/view/View$MeasureSpec;->getMode(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0}, Landroid/view/View$MeasureSpec;->getSize(I)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    const/high16 v1, -0x80000000

    .line 10
    .line 11
    const/16 v2, 0x20

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    if-eq v0, v1, :cond_2

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    const/high16 v1, 0x40000000    # 2.0f

    .line 19
    .line 20
    if-ne v0, v1, :cond_0

    .line 21
    .line 22
    int-to-long v0, p0

    .line 23
    shl-long v2, v0, v2

    .line 24
    .line 25
    or-long/2addr v0, v2

    .line 26
    return-wide v0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0}, Ljava/lang/IllegalStateException;-><init>()V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    int-to-long v0, v3

    .line 34
    shl-long/2addr v0, v2

    .line 35
    const p0, 0x7fffffff

    .line 36
    .line 37
    .line 38
    int-to-long v2, p0

    .line 39
    or-long/2addr v0, v2

    .line 40
    return-wide v0

    .line 41
    :cond_2
    int-to-long v0, v3

    .line 42
    shl-long/2addr v0, v2

    .line 43
    int-to-long v2, p0

    .line 44
    or-long/2addr v0, v2

    .line 45
    return-wide v0
.end method

.method public static synthetic getFontLoader$annotations()V
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method

.method public static synthetic getLastMatrixRecalculationAnimationTime$ui_release$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getRoot$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getShowLayoutBounds$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getTextInputService$annotations()V
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    return-void
.end method

.method private final get_viewTreeOwners()Lw3/l;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->d0:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lw3/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public static k(Lv3/h0;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Lv3/h0;->D()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lv3/h0;->z()Ln2/b;

    .line 5
    .line 6
    .line 7
    move-result-object p0

    .line 8
    iget-object v0, p0, Ln2/b;->d:[Ljava/lang/Object;

    .line 9
    .line 10
    iget p0, p0, Ln2/b;->f:I

    .line 11
    .line 12
    const/4 v1, 0x0

    .line 13
    :goto_0
    if-ge v1, p0, :cond_0

    .line 14
    .line 15
    aget-object v2, v0, v1

    .line 16
    .line 17
    check-cast v2, Lv3/h0;

    .line 18
    .line 19
    invoke-static {v2}, Lw3/t;->k(Lv3/h0;)V

    .line 20
    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-void
.end method

.method public static m(Landroid/view/MotionEvent;)Z
    .locals 7

    .line 1
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getX()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const v1, 0x7fffffff

    .line 10
    .line 11
    .line 12
    and-int/2addr v0, v1

    .line 13
    const/4 v2, 0x0

    .line 14
    const/4 v3, 0x1

    .line 15
    const/high16 v4, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 16
    .line 17
    if-ge v0, v4, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getY()F

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    and-int/2addr v0, v1

    .line 28
    if-ge v0, v4, :cond_0

    .line 29
    .line 30
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getRawX()F

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    and-int/2addr v0, v1

    .line 39
    if-ge v0, v4, :cond_0

    .line 40
    .line 41
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getRawY()F

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    and-int/2addr v0, v1

    .line 50
    if-ge v0, v4, :cond_0

    .line 51
    .line 52
    move v0, v2

    .line 53
    goto :goto_0

    .line 54
    :cond_0
    move v0, v3

    .line 55
    :goto_0
    if-nez v0, :cond_3

    .line 56
    .line 57
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 58
    .line 59
    .line 60
    move-result v5

    .line 61
    move v6, v3

    .line 62
    :goto_1
    if-ge v6, v5, :cond_3

    .line 63
    .line 64
    invoke-virtual {p0, v6}, Landroid/view/MotionEvent;->getX(I)F

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    and-int/2addr v0, v1

    .line 73
    if-ge v0, v4, :cond_2

    .line 74
    .line 75
    invoke-virtual {p0, v6}, Landroid/view/MotionEvent;->getY(I)F

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    and-int/2addr v0, v1

    .line 84
    if-ge v0, v4, :cond_2

    .line 85
    .line 86
    sget-object v0, Lw3/t1;->a:Lw3/t1;

    .line 87
    .line 88
    invoke-virtual {v0, p0, v6}, Lw3/t1;->a(Landroid/view/MotionEvent;I)Z

    .line 89
    .line 90
    .line 91
    move-result v0

    .line 92
    if-nez v0, :cond_1

    .line 93
    .line 94
    goto :goto_2

    .line 95
    :cond_1
    move v0, v2

    .line 96
    goto :goto_3

    .line 97
    :cond_2
    :goto_2
    move v0, v3

    .line 98
    :goto_3
    if-nez v0, :cond_3

    .line 99
    .line 100
    add-int/lit8 v6, v6, 0x1

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_3
    return v0
.end method

.method private setDensity(Lt4/c;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private setFontFamilyResolver(Lk4/m;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->x1:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private setLayoutDirection(Lt4/m;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->z1:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method private final set_viewTreeOwners(Lw3/l;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->d0:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final A(Landroid/view/MotionEvent;)V
    .locals 9

    .line 1
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lw3/t;->a0:J

    .line 6
    .line 7
    iget-object v0, p0, Lw3/t;->O1:Lw3/a1;

    .line 8
    .line 9
    iget-object v1, p0, Lw3/t;->V:[F

    .line 10
    .line 11
    invoke-virtual {v0, p0, v1}, Lw3/a1;->a(Landroid/view/View;[F)V

    .line 12
    .line 13
    .line 14
    iget-object v0, p0, Lw3/t;->W:[F

    .line 15
    .line 16
    invoke-static {v1, v0}, Lw3/h0;->w([F[F)Z

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    int-to-long v3, v0

    .line 32
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    int-to-long v5, v0

    .line 37
    const/16 v0, 0x20

    .line 38
    .line 39
    shl-long v2, v3, v0

    .line 40
    .line 41
    const-wide v7, 0xffffffffL

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    and-long v4, v5, v7

    .line 47
    .line 48
    or-long/2addr v2, v4

    .line 49
    invoke-static {v2, v3, v1}, Le3/c0;->b(J[F)J

    .line 50
    .line 51
    .line 52
    move-result-wide v1

    .line 53
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawX()F

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    shr-long v4, v1, v0

    .line 58
    .line 59
    long-to-int v4, v4

    .line 60
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    sub-float/2addr v3, v4

    .line 65
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawY()F

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    and-long/2addr v1, v7

    .line 70
    long-to-int v1, v1

    .line 71
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 72
    .line 73
    .line 74
    move-result v1

    .line 75
    sub-float/2addr p1, v1

    .line 76
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    int-to-long v1, v1

    .line 81
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    int-to-long v3, p1

    .line 86
    shl-long v0, v1, v0

    .line 87
    .line 88
    and-long v2, v3, v7

    .line 89
    .line 90
    or-long/2addr v0, v2

    .line 91
    iput-wide v0, p0, Lw3/t;->c0:J

    .line 92
    .line 93
    return-void
.end method

.method public final B()Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_1

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->hasFocus()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/16 v0, 0x82

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-super {p0, v0, v1}, Landroid/view/ViewGroup;->requestFocus(ILandroid/graphics/Rect;)Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0

    .line 22
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 23
    return p0
.end method

.method public final C(Lv3/h0;)V
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isLayoutRequested()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_5

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-eqz v0, :cond_5

    .line 12
    .line 13
    if-eqz p1, :cond_2

    .line 14
    .line 15
    :goto_0
    if-eqz p1, :cond_1

    .line 16
    .line 17
    invoke-virtual {p1}, Lv3/h0;->s()Lv3/f0;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    sget-object v1, Lv3/f0;->d:Lv3/f0;

    .line 22
    .line 23
    if-ne v0, v1, :cond_1

    .line 24
    .line 25
    iget-boolean v0, p0, Lw3/t;->Q:Z

    .line 26
    .line 27
    if-nez v0, :cond_0

    .line 28
    .line 29
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    iget-object v0, v0, Lv3/h0;->H:Lg1/q;

    .line 36
    .line 37
    iget-object v0, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v0, Lv3/u;

    .line 40
    .line 41
    iget-wide v0, v0, Lt3/e1;->g:J

    .line 42
    .line 43
    invoke-static {v0, v1}, Lt4/a;->f(J)Z

    .line 44
    .line 45
    .line 46
    move-result v2

    .line 47
    if-eqz v2, :cond_0

    .line 48
    .line 49
    invoke-static {v0, v1}, Lt4/a;->e(J)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-eqz v0, :cond_0

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_0
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 57
    .line 58
    .line 59
    move-result-object p1

    .line 60
    goto :goto_0

    .line 61
    :cond_1
    :goto_1
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    if-ne p1, v0, :cond_2

    .line 66
    .line 67
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :cond_2
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    if-eqz p1, :cond_4

    .line 76
    .line 77
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 78
    .line 79
    .line 80
    move-result p1

    .line 81
    if-nez p1, :cond_3

    .line 82
    .line 83
    goto :goto_2

    .line 84
    :cond_3
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    .line 85
    .line 86
    .line 87
    return-void

    .line 88
    :cond_4
    :goto_2
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 89
    .line 90
    .line 91
    :cond_5
    return-void
.end method

.method public final D(J)J
    .locals 6

    .line 1
    invoke-virtual {p0}, Lw3/t;->z()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0x20

    .line 5
    .line 6
    shr-long v1, p1, v0

    .line 7
    .line 8
    long-to-int v1, v1

    .line 9
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    iget-wide v2, p0, Lw3/t;->c0:J

    .line 14
    .line 15
    shr-long/2addr v2, v0

    .line 16
    long-to-int v2, v2

    .line 17
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    sub-float/2addr v1, v2

    .line 22
    const-wide v2, 0xffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    and-long/2addr p1, v2

    .line 28
    long-to-int p1, p1

    .line 29
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    iget-wide v4, p0, Lw3/t;->c0:J

    .line 34
    .line 35
    and-long/2addr v4, v2

    .line 36
    long-to-int p2, v4

    .line 37
    invoke-static {p2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    sub-float/2addr p1, p2

    .line 42
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 43
    .line 44
    .line 45
    move-result p2

    .line 46
    int-to-long v4, p2

    .line 47
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 48
    .line 49
    .line 50
    move-result p1

    .line 51
    int-to-long p1, p1

    .line 52
    shl-long v0, v4, v0

    .line 53
    .line 54
    and-long/2addr p1, v2

    .line 55
    or-long/2addr p1, v0

    .line 56
    iget-object p0, p0, Lw3/t;->W:[F

    .line 57
    .line 58
    invoke-static {p1, p2, p0}, Le3/c0;->b(J[F)J

    .line 59
    .line 60
    .line 61
    move-result-wide p0

    .line 62
    return-wide p0
.end method

.method public final E(Landroid/view/MotionEvent;)I
    .locals 8

    .line 1
    iget-boolean v0, p0, Lw3/t;->P1:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    iput-boolean v1, p0, Lw3/t;->P1:Z

    .line 7
    .line 8
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getMetaState()I

    .line 9
    .line 10
    .line 11
    move-result v0

    .line 12
    iget-object v2, p0, Lw3/t;->m:Lw3/r1;

    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    sget-object v2, Lw3/k2;->a:Ll2/j1;

    .line 18
    .line 19
    new-instance v3, Lp3/c0;

    .line 20
    .line 21
    invoke-direct {v3, v0}, Lp3/c0;-><init>(I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v2, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    :cond_0
    iget-object v0, p0, Lw3/t;->E:Lp3/h;

    .line 28
    .line 29
    invoke-virtual {v0, p1, p0}, Lp3/h;->a(Landroid/view/MotionEvent;Lw3/t;)Lc2/k;

    .line 30
    .line 31
    .line 32
    move-result-object v2

    .line 33
    iget-object v3, p0, Lw3/t;->F:Lvv0/d;

    .line 34
    .line 35
    if-eqz v2, :cond_8

    .line 36
    .line 37
    iget-object v1, v2, Lc2/k;->e:Ljava/lang/Object;

    .line 38
    .line 39
    check-cast v1, Ljava/util/List;

    .line 40
    .line 41
    move-object v4, v1

    .line 42
    check-cast v4, Ljava/util/Collection;

    .line 43
    .line 44
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 45
    .line 46
    .line 47
    move-result v4

    .line 48
    add-int/lit8 v4, v4, -0x1

    .line 49
    .line 50
    const/4 v5, 0x0

    .line 51
    if-ltz v4, :cond_3

    .line 52
    .line 53
    :goto_0
    add-int/lit8 v6, v4, -0x1

    .line 54
    .line 55
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v4

    .line 59
    move-object v7, v4

    .line 60
    check-cast v7, Lp3/v;

    .line 61
    .line 62
    iget-boolean v7, v7, Lp3/v;->e:Z

    .line 63
    .line 64
    if-eqz v7, :cond_1

    .line 65
    .line 66
    goto :goto_2

    .line 67
    :cond_1
    if-gez v6, :cond_2

    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_2
    move v4, v6

    .line 71
    goto :goto_0

    .line 72
    :cond_3
    :goto_1
    move-object v4, v5

    .line 73
    :goto_2
    check-cast v4, Lp3/v;

    .line 74
    .line 75
    if-eqz v4, :cond_4

    .line 76
    .line 77
    iget-wide v6, v4, Lp3/v;->d:J

    .line 78
    .line 79
    iput-wide v6, p0, Lw3/t;->d:J

    .line 80
    .line 81
    :cond_4
    invoke-virtual {p0, p1}, Lw3/t;->n(Landroid/view/MotionEvent;)Z

    .line 82
    .line 83
    .line 84
    move-result v1

    .line 85
    invoke-virtual {v3, v2, p0, v1}, Lvv0/d;->i(Lc2/k;Lw3/t;Z)I

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    iput-object v5, v2, Lc2/k;->f:Ljava/lang/Object;

    .line 90
    .line 91
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 92
    .line 93
    .line 94
    move-result v1

    .line 95
    if-eqz v1, :cond_5

    .line 96
    .line 97
    const/4 v2, 0x5

    .line 98
    if-ne v1, v2, :cond_6

    .line 99
    .line 100
    :cond_5
    and-int/lit8 v1, p0, 0x1

    .line 101
    .line 102
    if-eqz v1, :cond_7

    .line 103
    .line 104
    :cond_6
    return p0

    .line 105
    :cond_7
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    iget-object v1, v0, Lp3/h;->e:Ljava/lang/Object;

    .line 114
    .line 115
    check-cast v1, Landroid/util/SparseBooleanArray;

    .line 116
    .line 117
    invoke-virtual {v1, p1}, Landroid/util/SparseBooleanArray;->delete(I)V

    .line 118
    .line 119
    .line 120
    iget-object v0, v0, Lp3/h;->d:Ljava/lang/Object;

    .line 121
    .line 122
    check-cast v0, Landroid/util/SparseLongArray;

    .line 123
    .line 124
    invoke-virtual {v0, p1}, Landroid/util/SparseLongArray;->delete(I)V

    .line 125
    .line 126
    .line 127
    return p0

    .line 128
    :cond_8
    iget-boolean p0, v3, Lvv0/d;->a:Z

    .line 129
    .line 130
    if-nez p0, :cond_9

    .line 131
    .line 132
    iget-object p0, v3, Lvv0/d;->d:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast p0, Lhu/q;

    .line 135
    .line 136
    iget-object p0, p0, Lhu/q;->e:Ljava/lang/Object;

    .line 137
    .line 138
    check-cast p0, Landroidx/collection/u;

    .line 139
    .line 140
    invoke-virtual {p0}, Landroidx/collection/u;->a()V

    .line 141
    .line 142
    .line 143
    iget-object p0, v3, Lvv0/d;->c:Ljava/lang/Object;

    .line 144
    .line 145
    check-cast p0, Lp3/d;

    .line 146
    .line 147
    invoke-virtual {p0}, Lp3/d;->c()V

    .line 148
    .line 149
    .line 150
    :cond_9
    return v1
.end method

.method public final F(Landroid/view/MotionEvent;IJZ)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move/from16 v5, p2

    .line 6
    .line 7
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    const/4 v3, -0x1

    .line 12
    const/4 v6, 0x1

    .line 13
    if-eq v2, v6, :cond_1

    .line 14
    .line 15
    const/4 v7, 0x6

    .line 16
    if-eq v2, v7, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionIndex()I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    const/16 v2, 0x9

    .line 25
    .line 26
    if-eq v5, v2, :cond_2

    .line 27
    .line 28
    const/16 v2, 0xa

    .line 29
    .line 30
    if-eq v5, v2, :cond_2

    .line 31
    .line 32
    const/4 v3, 0x0

    .line 33
    :cond_2
    :goto_0
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-ltz v3, :cond_3

    .line 38
    .line 39
    move v7, v6

    .line 40
    goto :goto_1

    .line 41
    :cond_3
    const/4 v7, 0x0

    .line 42
    :goto_1
    sub-int/2addr v2, v7

    .line 43
    if-nez v2, :cond_4

    .line 44
    .line 45
    return-void

    .line 46
    :cond_4
    new-array v7, v2, [Landroid/view/MotionEvent$PointerProperties;

    .line 47
    .line 48
    const/4 v8, 0x0

    .line 49
    :goto_2
    if-ge v8, v2, :cond_5

    .line 50
    .line 51
    new-instance v9, Landroid/view/MotionEvent$PointerProperties;

    .line 52
    .line 53
    invoke-direct {v9}, Landroid/view/MotionEvent$PointerProperties;-><init>()V

    .line 54
    .line 55
    .line 56
    aput-object v9, v7, v8

    .line 57
    .line 58
    add-int/lit8 v8, v8, 0x1

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_5
    new-array v8, v2, [Landroid/view/MotionEvent$PointerCoords;

    .line 62
    .line 63
    const/4 v9, 0x0

    .line 64
    :goto_3
    if-ge v9, v2, :cond_6

    .line 65
    .line 66
    new-instance v10, Landroid/view/MotionEvent$PointerCoords;

    .line 67
    .line 68
    invoke-direct {v10}, Landroid/view/MotionEvent$PointerCoords;-><init>()V

    .line 69
    .line 70
    .line 71
    aput-object v10, v8, v9

    .line 72
    .line 73
    add-int/lit8 v9, v9, 0x1

    .line 74
    .line 75
    goto :goto_3

    .line 76
    :cond_6
    const/4 v9, 0x0

    .line 77
    :goto_4
    if-ge v9, v2, :cond_9

    .line 78
    .line 79
    if-ltz v3, :cond_8

    .line 80
    .line 81
    if-ge v9, v3, :cond_7

    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_7
    move v10, v6

    .line 85
    goto :goto_6

    .line 86
    :cond_8
    :goto_5
    const/4 v10, 0x0

    .line 87
    :goto_6
    add-int/2addr v10, v9

    .line 88
    aget-object v11, v7, v9

    .line 89
    .line 90
    invoke-virtual {v1, v10, v11}, Landroid/view/MotionEvent;->getPointerProperties(ILandroid/view/MotionEvent$PointerProperties;)V

    .line 91
    .line 92
    .line 93
    aget-object v11, v8, v9

    .line 94
    .line 95
    invoke-virtual {v1, v10, v11}, Landroid/view/MotionEvent;->getPointerCoords(ILandroid/view/MotionEvent$PointerCoords;)V

    .line 96
    .line 97
    .line 98
    iget v10, v11, Landroid/view/MotionEvent$PointerCoords;->x:F

    .line 99
    .line 100
    iget v12, v11, Landroid/view/MotionEvent$PointerCoords;->y:F

    .line 101
    .line 102
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 103
    .line 104
    .line 105
    move-result v10

    .line 106
    int-to-long v13, v10

    .line 107
    invoke-static {v12}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 108
    .line 109
    .line 110
    move-result v10

    .line 111
    int-to-long v4, v10

    .line 112
    const/16 v10, 0x20

    .line 113
    .line 114
    shl-long/2addr v13, v10

    .line 115
    const-wide v15, 0xffffffffL

    .line 116
    .line 117
    .line 118
    .line 119
    .line 120
    and-long/2addr v4, v15

    .line 121
    or-long/2addr v4, v13

    .line 122
    invoke-virtual {v0, v4, v5}, Lw3/t;->q(J)J

    .line 123
    .line 124
    .line 125
    move-result-wide v4

    .line 126
    shr-long v13, v4, v10

    .line 127
    .line 128
    long-to-int v10, v13

    .line 129
    invoke-static {v10}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 130
    .line 131
    .line 132
    move-result v10

    .line 133
    iput v10, v11, Landroid/view/MotionEvent$PointerCoords;->x:F

    .line 134
    .line 135
    and-long/2addr v4, v15

    .line 136
    long-to-int v4, v4

    .line 137
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    iput v4, v11, Landroid/view/MotionEvent$PointerCoords;->y:F

    .line 142
    .line 143
    add-int/lit8 v9, v9, 0x1

    .line 144
    .line 145
    move/from16 v5, p2

    .line 146
    .line 147
    goto :goto_4

    .line 148
    :cond_9
    if-eqz p5, :cond_a

    .line 149
    .line 150
    const/4 v10, 0x0

    .line 151
    goto :goto_7

    .line 152
    :cond_a
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getButtonState()I

    .line 153
    .line 154
    .line 155
    move-result v4

    .line 156
    move v10, v4

    .line 157
    :goto_7
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getDownTime()J

    .line 158
    .line 159
    .line 160
    move-result-wide v3

    .line 161
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getEventTime()J

    .line 162
    .line 163
    .line 164
    move-result-wide v11

    .line 165
    cmp-long v3, v3, v11

    .line 166
    .line 167
    if-nez v3, :cond_b

    .line 168
    .line 169
    move-wide/from16 v3, p3

    .line 170
    .line 171
    goto :goto_8

    .line 172
    :cond_b
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getDownTime()J

    .line 173
    .line 174
    .line 175
    move-result-wide v3

    .line 176
    :goto_8
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getMetaState()I

    .line 177
    .line 178
    .line 179
    move-result v9

    .line 180
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getXPrecision()F

    .line 181
    .line 182
    .line 183
    move-result v11

    .line 184
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getYPrecision()F

    .line 185
    .line 186
    .line 187
    move-result v12

    .line 188
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 189
    .line 190
    .line 191
    move-result v13

    .line 192
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getEdgeFlags()I

    .line 193
    .line 194
    .line 195
    move-result v14

    .line 196
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getSource()I

    .line 197
    .line 198
    .line 199
    move-result v15

    .line 200
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getFlags()I

    .line 201
    .line 202
    .line 203
    move-result v16

    .line 204
    move/from16 v5, p2

    .line 205
    .line 206
    move v6, v2

    .line 207
    move-wide v1, v3

    .line 208
    move-wide/from16 v3, p3

    .line 209
    .line 210
    invoke-static/range {v1 .. v16}, Landroid/view/MotionEvent;->obtain(JJII[Landroid/view/MotionEvent$PointerProperties;[Landroid/view/MotionEvent$PointerCoords;IIFFIIII)Landroid/view/MotionEvent;

    .line 211
    .line 212
    .line 213
    move-result-object v1

    .line 214
    iget-object v2, v0, Lw3/t;->E:Lp3/h;

    .line 215
    .line 216
    invoke-virtual {v2, v1, v0}, Lp3/h;->a(Landroid/view/MotionEvent;Lw3/t;)Lc2/k;

    .line 217
    .line 218
    .line 219
    move-result-object v2

    .line 220
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    iget-object v3, v0, Lw3/t;->F:Lvv0/d;

    .line 224
    .line 225
    const/4 v4, 0x1

    .line 226
    invoke-virtual {v3, v2, v0, v4}, Lvv0/d;->i(Lc2/k;Lw3/t;Z)I

    .line 227
    .line 228
    .line 229
    invoke-virtual {v1}, Landroid/view/MotionEvent;->recycle()V

    .line 230
    .line 231
    .line 232
    return-void
.end method

.method public final G(Lay0/n;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p2, Lw3/s;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lw3/s;

    .line 7
    .line 8
    iget v1, v0, Lw3/s;->f:I

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
    iput v1, v0, Lw3/s;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lw3/s;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lw3/s;-><init>(Lw3/t;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lw3/s;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lw3/s;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-eq v2, v3, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    new-instance p2, Lw3/m;

    .line 52
    .line 53
    const/4 v2, 0x3

    .line 54
    invoke-direct {p2, p0, v2}, Lw3/m;-><init>(Lw3/t;I)V

    .line 55
    .line 56
    .line 57
    iput v3, v0, Lw3/s;->f:I

    .line 58
    .line 59
    new-instance v2, Lvh/j;

    .line 60
    .line 61
    const/4 v3, 0x0

    .line 62
    iget-object p0, p0, Lw3/t;->u1:Ljava/util/concurrent/atomic/AtomicReference;

    .line 63
    .line 64
    invoke-direct {v2, p2, p0, p1, v3}, Lvh/j;-><init>(Lay0/k;Ljava/util/concurrent/atomic/AtomicReference;Lay0/n;Lkotlin/coroutines/Continuation;)V

    .line 65
    .line 66
    .line 67
    invoke-static {v2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    if-ne p0, v1, :cond_3

    .line 72
    .line 73
    return-void

    .line 74
    :cond_3
    :goto_1
    new-instance p0, La8/r0;

    .line 75
    .line 76
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 77
    .line 78
    .line 79
    throw p0
.end method

.method public final H()V
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lw3/t;->T:[I

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 6
    .line 7
    .line 8
    iget-wide v2, v0, Lw3/t;->S:J

    .line 9
    .line 10
    const/16 v4, 0x20

    .line 11
    .line 12
    shr-long v5, v2, v4

    .line 13
    .line 14
    long-to-int v5, v5

    .line 15
    const-wide v6, 0xffffffffL

    .line 16
    .line 17
    .line 18
    .line 19
    .line 20
    and-long/2addr v2, v6

    .line 21
    long-to-int v2, v2

    .line 22
    const/4 v3, 0x0

    .line 23
    aget v8, v1, v3

    .line 24
    .line 25
    const/4 v9, 0x1

    .line 26
    if-ne v5, v8, :cond_0

    .line 27
    .line 28
    aget v10, v1, v9

    .line 29
    .line 30
    if-ne v2, v10, :cond_0

    .line 31
    .line 32
    iget-wide v10, v0, Lw3/t;->a0:J

    .line 33
    .line 34
    const-wide/16 v12, 0x0

    .line 35
    .line 36
    cmp-long v10, v10, v12

    .line 37
    .line 38
    if-gez v10, :cond_1

    .line 39
    .line 40
    :cond_0
    aget v1, v1, v9

    .line 41
    .line 42
    int-to-long v10, v8

    .line 43
    shl-long/2addr v10, v4

    .line 44
    int-to-long v12, v1

    .line 45
    and-long/2addr v12, v6

    .line 46
    or-long/2addr v10, v12

    .line 47
    iput-wide v10, v0, Lw3/t;->S:J

    .line 48
    .line 49
    const v1, 0x7fffffff

    .line 50
    .line 51
    .line 52
    if-eq v5, v1, :cond_1

    .line 53
    .line 54
    if-eq v2, v1, :cond_1

    .line 55
    .line 56
    invoke-virtual {v0}, Lw3/t;->getRoot()Lv3/h0;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    iget-object v1, v1, Lv3/h0;->I:Lv3/l0;

    .line 61
    .line 62
    iget-object v1, v1, Lv3/l0;->p:Lv3/y0;

    .line 63
    .line 64
    invoke-virtual {v1}, Lv3/y0;->F0()V

    .line 65
    .line 66
    .line 67
    move v1, v9

    .line 68
    goto :goto_0

    .line 69
    :cond_1
    move v1, v3

    .line 70
    :goto_0
    invoke-virtual {v0}, Lw3/t;->z()V

    .line 71
    .line 72
    .line 73
    iget-object v2, v0, Lw3/t;->R1:Landroid/view/View;

    .line 74
    .line 75
    if-nez v2, :cond_2

    .line 76
    .line 77
    invoke-virtual {v0}, Landroid/view/View;->getRootView()Landroid/view/View;

    .line 78
    .line 79
    .line 80
    move-result-object v2

    .line 81
    iput-object v2, v0, Lw3/t;->R1:Landroid/view/View;

    .line 82
    .line 83
    :cond_2
    invoke-virtual {v0}, Lw3/t;->getRectManager()Le4/a;

    .line 84
    .line 85
    .line 86
    move-result-object v5

    .line 87
    iget-wide v10, v0, Lw3/t;->S:J

    .line 88
    .line 89
    iget-wide v12, v0, Lw3/t;->c0:J

    .line 90
    .line 91
    invoke-static {v12, v13}, Lkp/d9;->b(J)J

    .line 92
    .line 93
    .line 94
    move-result-wide v12

    .line 95
    invoke-virtual {v2}, Landroid/view/View;->getWidth()I

    .line 96
    .line 97
    .line 98
    move-result v8

    .line 99
    invoke-virtual {v2}, Landroid/view/View;->getHeight()I

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 104
    .line 105
    .line 106
    iget-object v14, v0, Lw3/t;->V:[F

    .line 107
    .line 108
    invoke-static {v14}, Lkp/z;->a([F)I

    .line 109
    .line 110
    .line 111
    move-result v15

    .line 112
    iget-object v3, v5, Le4/a;->b:Le4/b;

    .line 113
    .line 114
    and-int/lit8 v15, v15, 0x2

    .line 115
    .line 116
    if-nez v15, :cond_3

    .line 117
    .line 118
    :goto_1
    move-wide/from16 v16, v6

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_3
    const/4 v14, 0x0

    .line 122
    goto :goto_1

    .line 123
    :goto_2
    iget-wide v6, v3, Le4/b;->c:J

    .line 124
    .line 125
    invoke-static {v12, v13, v6, v7}, Lt4/j;->b(JJ)Z

    .line 126
    .line 127
    .line 128
    move-result v6

    .line 129
    if-nez v6, :cond_4

    .line 130
    .line 131
    iput-wide v12, v3, Le4/b;->c:J

    .line 132
    .line 133
    move v6, v9

    .line 134
    goto :goto_3

    .line 135
    :cond_4
    const/4 v6, 0x0

    .line 136
    :goto_3
    iget-wide v12, v3, Le4/b;->d:J

    .line 137
    .line 138
    invoke-static {v10, v11, v12, v13}, Lt4/j;->b(JJ)Z

    .line 139
    .line 140
    .line 141
    move-result v7

    .line 142
    if-nez v7, :cond_5

    .line 143
    .line 144
    iput-wide v10, v3, Le4/b;->d:J

    .line 145
    .line 146
    move v6, v9

    .line 147
    :cond_5
    if-eqz v14, :cond_6

    .line 148
    .line 149
    move v6, v9

    .line 150
    :cond_6
    int-to-long v7, v8

    .line 151
    shl-long/2addr v7, v4

    .line 152
    int-to-long v10, v2

    .line 153
    and-long v10, v10, v16

    .line 154
    .line 155
    or-long/2addr v7, v10

    .line 156
    iget-wide v10, v3, Le4/b;->e:J

    .line 157
    .line 158
    cmp-long v2, v7, v10

    .line 159
    .line 160
    if-eqz v2, :cond_7

    .line 161
    .line 162
    iput-wide v7, v3, Le4/b;->e:J

    .line 163
    .line 164
    move v6, v9

    .line 165
    :cond_7
    if-nez v6, :cond_9

    .line 166
    .line 167
    iget-boolean v2, v5, Le4/a;->e:Z

    .line 168
    .line 169
    if-eqz v2, :cond_8

    .line 170
    .line 171
    goto :goto_4

    .line 172
    :cond_8
    const/4 v3, 0x0

    .line 173
    goto :goto_5

    .line 174
    :cond_9
    :goto_4
    move v3, v9

    .line 175
    :goto_5
    iput-boolean v3, v5, Le4/a;->e:Z

    .line 176
    .line 177
    iget-object v2, v0, Lw3/t;->R:Lv3/w0;

    .line 178
    .line 179
    invoke-virtual {v2, v1}, Lv3/w0;->a(Z)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v0}, Lw3/t;->getRectManager()Le4/a;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-virtual {v0}, Le4/a;->b()V

    .line 187
    .line 188
    .line 189
    return-void
.end method

.method public final I(F)V
    .locals 2

    .line 1
    iget-boolean v0, p0, Lw3/t;->i:Z

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    cmpl-float v1, p1, v0

    .line 7
    .line 8
    if-lez v1, :cond_1

    .line 9
    .line 10
    iget v0, p0, Lw3/t;->I1:F

    .line 11
    .line 12
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    iget v0, p0, Lw3/t;->I1:F

    .line 19
    .line 20
    cmpl-float v0, p1, v0

    .line 21
    .line 22
    if-lez v0, :cond_3

    .line 23
    .line 24
    :cond_0
    iput p1, p0, Lw3/t;->I1:F

    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    cmpg-float v0, p1, v0

    .line 28
    .line 29
    if-gez v0, :cond_3

    .line 30
    .line 31
    iget v0, p0, Lw3/t;->J1:F

    .line 32
    .line 33
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-nez v0, :cond_2

    .line 38
    .line 39
    iget v0, p0, Lw3/t;->J1:F

    .line 40
    .line 41
    cmpg-float v0, p1, v0

    .line 42
    .line 43
    if-gez v0, :cond_3

    .line 44
    .line 45
    :cond_2
    iput p1, p0, Lw3/t;->J1:F

    .line 46
    .line 47
    :cond_3
    return-void
.end method

.method public final addView(Landroid/view/View;)V
    .locals 1

    const/4 v0, -0x1

    .line 1
    invoke-virtual {p0, p1, v0}, Lw3/t;->addView(Landroid/view/View;I)V

    return-void
.end method

.method public final addView(Landroid/view/View;I)V
    .locals 2

    .line 2
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    invoke-virtual {p1}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    if-nez v0, :cond_0

    invoke-virtual {p0}, Landroid/view/ViewGroup;->generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    :cond_0
    const/4 v1, 0x1

    .line 3
    invoke-virtual {p0, p1, p2, v0, v1}, Landroid/view/ViewGroup;->addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)Z

    return-void
.end method

.method public final addView(Landroid/view/View;II)V
    .locals 1

    .line 4
    invoke-virtual {p0}, Landroid/view/ViewGroup;->generateDefaultLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    move-result-object v0

    .line 5
    iput p2, v0, Landroid/view/ViewGroup$LayoutParams;->width:I

    .line 6
    iput p3, v0, Landroid/view/ViewGroup$LayoutParams;->height:I

    const/4 p2, 0x1

    const/4 p3, -0x1

    .line 7
    invoke-virtual {p0, p1, p3, v0, p2}, Landroid/view/ViewGroup;->addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)Z

    return-void
.end method

.method public final addView(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;)V
    .locals 1

    const/4 v0, 0x1

    .line 8
    invoke-virtual {p0, p1, p2, p3, v0}, Landroid/view/ViewGroup;->addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)Z

    return-void
.end method

.method public final addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V
    .locals 2

    const/4 v0, -0x1

    const/4 v1, 0x1

    .line 9
    invoke-virtual {p0, p1, v0, p2, v1}, Landroid/view/ViewGroup;->addViewInLayout(Landroid/view/View;ILandroid/view/ViewGroup$LayoutParams;Z)Z

    return-void
.end method

.method public final autofill(Landroid/util/SparseArray;)V
    .locals 7

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object v1, p0, Lw3/t;->I:Ly2/b;

    .line 3
    .line 4
    if-eqz v1, :cond_5

    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    move v3, v0

    .line 11
    :goto_0
    if-ge v3, v2, :cond_5

    .line 12
    .line 13
    invoke-virtual {p1, v3}, Landroid/util/SparseArray;->keyAt(I)I

    .line 14
    .line 15
    .line 16
    move-result v4

    .line 17
    invoke-virtual {p1, v4}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    check-cast v5, Landroid/view/autofill/AutofillValue;

    .line 22
    .line 23
    invoke-virtual {v5}, Landroid/view/autofill/AutofillValue;->isText()Z

    .line 24
    .line 25
    .line 26
    move-result v6

    .line 27
    if-eqz v6, :cond_1

    .line 28
    .line 29
    iget-object v6, v1, Ly2/b;->b:Ld4/s;

    .line 30
    .line 31
    iget-object v6, v6, Ld4/s;->c:Landroidx/collection/p;

    .line 32
    .line 33
    invoke-virtual {v6, v4}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    check-cast v4, Lv3/h0;

    .line 38
    .line 39
    if-eqz v4, :cond_4

    .line 40
    .line 41
    invoke-virtual {v4}, Lv3/h0;->x()Ld4/l;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    if-eqz v4, :cond_4

    .line 46
    .line 47
    sget-object v6, Ld4/k;->g:Ld4/z;

    .line 48
    .line 49
    iget-object v4, v4, Ld4/l;->d:Landroidx/collection/q0;

    .line 50
    .line 51
    invoke-virtual {v4, v6}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object v4

    .line 55
    if-nez v4, :cond_0

    .line 56
    .line 57
    const/4 v4, 0x0

    .line 58
    :cond_0
    check-cast v4, Ld4/a;

    .line 59
    .line 60
    if-eqz v4, :cond_4

    .line 61
    .line 62
    iget-object v4, v4, Ld4/a;->b:Llx0/e;

    .line 63
    .line 64
    check-cast v4, Lay0/k;

    .line 65
    .line 66
    if-eqz v4, :cond_4

    .line 67
    .line 68
    new-instance v6, Lg4/g;

    .line 69
    .line 70
    invoke-virtual {v5}, Landroid/view/autofill/AutofillValue;->getTextValue()Ljava/lang/CharSequence;

    .line 71
    .line 72
    .line 73
    move-result-object v5

    .line 74
    invoke-virtual {v5}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    invoke-direct {v6, v5}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v4, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v4

    .line 85
    check-cast v4, Ljava/lang/Boolean;

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_1
    invoke-virtual {v5}, Landroid/view/autofill/AutofillValue;->isDate()Z

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    const-string v6, "ComposeAutofillManager"

    .line 93
    .line 94
    if-eqz v4, :cond_2

    .line 95
    .line 96
    const-string v4, "Auto filling Date fields is not yet supported."

    .line 97
    .line 98
    invoke-static {v6, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 99
    .line 100
    .line 101
    goto :goto_1

    .line 102
    :cond_2
    invoke-virtual {v5}, Landroid/view/autofill/AutofillValue;->isList()Z

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    if-eqz v4, :cond_3

    .line 107
    .line 108
    const-string v4, "Auto filling dropdown lists is not yet supported."

    .line 109
    .line 110
    invoke-static {v6, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 111
    .line 112
    .line 113
    goto :goto_1

    .line 114
    :cond_3
    invoke-virtual {v5}, Landroid/view/autofill/AutofillValue;->isToggle()Z

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    if-eqz v4, :cond_4

    .line 119
    .line 120
    const-string v4, "Auto filling toggle fields are not yet supported."

    .line 121
    .line 122
    invoke-static {v6, v4}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 123
    .line 124
    .line 125
    :cond_4
    :goto_1
    add-int/lit8 v3, v3, 0x1

    .line 126
    .line 127
    goto :goto_0

    .line 128
    :cond_5
    iget-object p0, p0, Lw3/t;->H:Lun/a;

    .line 129
    .line 130
    if-eqz p0, :cond_c

    .line 131
    .line 132
    iget-object p0, p0, Lun/a;->f:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast p0, Ly2/h;

    .line 135
    .line 136
    iget-object v1, p0, Ly2/h;->a:Ljava/util/LinkedHashMap;

    .line 137
    .line 138
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-eqz v1, :cond_6

    .line 143
    .line 144
    goto :goto_4

    .line 145
    :cond_6
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 146
    .line 147
    .line 148
    move-result v1

    .line 149
    :goto_2
    if-ge v0, v1, :cond_c

    .line 150
    .line 151
    invoke-virtual {p1, v0}, Landroid/util/SparseArray;->keyAt(I)I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    invoke-virtual {p1, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    check-cast v3, Landroid/view/autofill/AutofillValue;

    .line 160
    .line 161
    invoke-virtual {v3}, Landroid/view/autofill/AutofillValue;->isText()Z

    .line 162
    .line 163
    .line 164
    move-result v4

    .line 165
    if-eqz v4, :cond_8

    .line 166
    .line 167
    invoke-virtual {v3}, Landroid/view/autofill/AutofillValue;->getTextValue()Ljava/lang/CharSequence;

    .line 168
    .line 169
    .line 170
    move-result-object v3

    .line 171
    invoke-virtual {v3}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 172
    .line 173
    .line 174
    iget-object v3, p0, Ly2/h;->a:Ljava/util/LinkedHashMap;

    .line 175
    .line 176
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 177
    .line 178
    .line 179
    move-result-object v2

    .line 180
    invoke-virtual {v3, v2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v2

    .line 184
    if-nez v2, :cond_7

    .line 185
    .line 186
    goto :goto_3

    .line 187
    :cond_7
    new-instance p0, Ljava/lang/ClassCastException;

    .line 188
    .line 189
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 190
    .line 191
    .line 192
    throw p0

    .line 193
    :cond_8
    invoke-virtual {v3}, Landroid/view/autofill/AutofillValue;->isDate()Z

    .line 194
    .line 195
    .line 196
    move-result v2

    .line 197
    if-nez v2, :cond_b

    .line 198
    .line 199
    invoke-virtual {v3}, Landroid/view/autofill/AutofillValue;->isList()Z

    .line 200
    .line 201
    .line 202
    move-result v2

    .line 203
    if-nez v2, :cond_a

    .line 204
    .line 205
    invoke-virtual {v3}, Landroid/view/autofill/AutofillValue;->isToggle()Z

    .line 206
    .line 207
    .line 208
    move-result v2

    .line 209
    if-nez v2, :cond_9

    .line 210
    .line 211
    :goto_3
    add-int/lit8 v0, v0, 0x1

    .line 212
    .line 213
    goto :goto_2

    .line 214
    :cond_9
    new-instance p0, Llx0/k;

    .line 215
    .line 216
    const-string p1, "An operation is not implemented: b/138604541:  Add onFill() callback for toggle"

    .line 217
    .line 218
    invoke-direct {p0, p1}, Ljava/lang/Error;-><init>(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    throw p0

    .line 222
    :cond_a
    new-instance p0, Llx0/k;

    .line 223
    .line 224
    const-string p1, "An operation is not implemented: b/138604541: Add onFill() callback for list"

    .line 225
    .line 226
    invoke-direct {p0, p1}, Ljava/lang/Error;-><init>(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    throw p0

    .line 230
    :cond_b
    new-instance p0, Llx0/k;

    .line 231
    .line 232
    const-string p1, "An operation is not implemented: b/138604541: Add onFill() callback for date"

    .line 233
    .line 234
    invoke-direct {p0, p1}, Ljava/lang/Error;-><init>(Ljava/lang/String;)V

    .line 235
    .line 236
    .line 237
    throw p0

    .line 238
    :cond_c
    :goto_4
    return-void
.end method

.method public final canScrollHorizontally(I)Z
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-wide v1, p0, Lw3/t;->d:J

    .line 3
    .line 4
    iget-object p0, p0, Lw3/t;->v:Lw3/z;

    .line 5
    .line 6
    invoke-virtual {p0, v1, v2, p1, v0}, Lw3/z;->m(JIZ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final canScrollVertically(I)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    iget-wide v1, p0, Lw3/t;->d:J

    .line 3
    .line 4
    iget-object p0, p0, Lw3/t;->v:Lw3/z;

    .line 5
    .line 6
    invoke-virtual {p0, v1, v2, p1, v0}, Lw3/z;->m(JIZ)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final dispatchDraw(Landroid/graphics/Canvas;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Lw3/t;->k(Lv3/h0;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    const/4 v0, 0x1

    .line 15
    invoke-virtual {p0, v0}, Lw3/t;->r(Z)V

    .line 16
    .line 17
    .line 18
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v1}, Lv2/f;->m()V

    .line 23
    .line 24
    .line 25
    iput-boolean v0, p0, Lw3/t;->C:Z

    .line 26
    .line 27
    iget-object v0, p0, Lw3/t;->n:Laq/a;

    .line 28
    .line 29
    iget-object v1, v0, Laq/a;->e:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v1, Le3/a;

    .line 32
    .line 33
    iget-object v2, v1, Le3/a;->a:Landroid/graphics/Canvas;

    .line 34
    .line 35
    iput-object p1, v1, Le3/a;->a:Landroid/graphics/Canvas;

    .line 36
    .line 37
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    const/4 v4, 0x0

    .line 42
    invoke-virtual {v3, v1, v4}, Lv3/h0;->j(Le3/r;Lh3/c;)V

    .line 43
    .line 44
    .line 45
    iget-object v0, v0, Laq/a;->e:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v0, Le3/a;

    .line 48
    .line 49
    iput-object v2, v0, Le3/a;->a:Landroid/graphics/Canvas;

    .line 50
    .line 51
    iget-object v0, p0, Lw3/t;->A:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    .line 54
    .line 55
    .line 56
    move-result v1

    .line 57
    const/4 v2, 0x0

    .line 58
    if-nez v1, :cond_1

    .line 59
    .line 60
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    move v3, v2

    .line 65
    :goto_0
    if-ge v3, v1, :cond_1

    .line 66
    .line 67
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    check-cast v5, Lv3/n1;

    .line 72
    .line 73
    check-cast v5, Lw3/o1;

    .line 74
    .line 75
    invoke-virtual {v5}, Lw3/o1;->g()V

    .line 76
    .line 77
    .line 78
    add-int/lit8 v3, v3, 0x1

    .line 79
    .line 80
    goto :goto_0

    .line 81
    :cond_1
    sget v1, Lw3/i2;->d:I

    .line 82
    .line 83
    invoke-virtual {v0}, Ljava/util/ArrayList;->clear()V

    .line 84
    .line 85
    .line 86
    iput-boolean v2, p0, Lw3/t;->C:Z

    .line 87
    .line 88
    iget-object v1, p0, Lw3/t;->B:Ljava/util/ArrayList;

    .line 89
    .line 90
    if-eqz v1, :cond_2

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1}, Ljava/util/ArrayList;->clear()V

    .line 96
    .line 97
    .line 98
    :cond_2
    iget-boolean v0, p0, Lw3/t;->i:Z

    .line 99
    .line 100
    if-eqz v0, :cond_5

    .line 101
    .line 102
    iget v0, p0, Lw3/t;->I1:F

    .line 103
    .line 104
    invoke-static {p0, v0}, Lw3/v0;->a(Landroid/view/View;F)V

    .line 105
    .line 106
    .line 107
    iget-object v0, p0, Lw3/t;->h:Landroid/view/View;

    .line 108
    .line 109
    if-eqz v0, :cond_4

    .line 110
    .line 111
    iget v1, p0, Lw3/t;->J1:F

    .line 112
    .line 113
    invoke-static {v0, v1}, Lw3/v0;->a(Landroid/view/View;F)V

    .line 114
    .line 115
    .line 116
    iget v1, p0, Lw3/t;->J1:F

    .line 117
    .line 118
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-nez v1, :cond_3

    .line 123
    .line 124
    invoke-virtual {v0}, Landroid/view/View;->invalidate()V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p0}, Landroid/view/View;->getDrawingTime()J

    .line 128
    .line 129
    .line 130
    move-result-wide v1

    .line 131
    invoke-virtual {p0, p1, v0, v1, v2}, Landroid/view/ViewGroup;->drawChild(Landroid/graphics/Canvas;Landroid/view/View;J)Z

    .line 132
    .line 133
    .line 134
    :cond_3
    const/high16 p1, 0x7fc00000    # Float.NaN

    .line 135
    .line 136
    iput p1, p0, Lw3/t;->I1:F

    .line 137
    .line 138
    iput p1, p0, Lw3/t;->J1:F

    .line 139
    .line 140
    goto :goto_1

    .line 141
    :cond_4
    const-string p0, "frameRateCategoryView"

    .line 142
    .line 143
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 144
    .line 145
    .line 146
    throw v4

    .line 147
    :cond_5
    :goto_1
    invoke-virtual {p0}, Lw3/t;->getRectManager()Le4/a;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-virtual {p0}, Le4/a;->b()V

    .line 152
    .line 153
    .line 154
    return-void
.end method

.method public final dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z
    .locals 12

    .line 1
    iget-boolean v0, p0, Lw3/t;->M1:Z

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    iget-object v0, p0, Lw3/t;->L1:Lm8/o;

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-ne v3, v1, :cond_0

    .line 18
    .line 19
    iput-boolean v2, p0, Lw3/t;->M1:Z

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    invoke-virtual {v0}, Lm8/o;->run()V

    .line 23
    .line 24
    .line 25
    :cond_1
    :goto_0
    invoke-static {p1}, Lw3/t;->m(Landroid/view/MotionEvent;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-nez v0, :cond_40

    .line 30
    .line 31
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-nez v0, :cond_2

    .line 36
    .line 37
    goto/16 :goto_20

    .line 38
    .line 39
    :cond_2
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    const/4 v3, 0x0

    .line 44
    const/16 v4, 0x10

    .line 45
    .line 46
    const-string v5, "visitAncestors called on an unattached node"

    .line 47
    .line 48
    const/4 v6, 0x1

    .line 49
    if-ne v0, v1, :cond_33

    .line 50
    .line 51
    const/high16 v0, 0x400000

    .line 52
    .line 53
    invoke-virtual {p1, v0}, Landroid/view/InputEvent;->isFromSource(I)Z

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    if-eqz v0, :cond_31

    .line 58
    .line 59
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    invoke-static {v0}, Landroid/view/ViewConfiguration;->get(Landroid/content/Context;)Landroid/view/ViewConfiguration;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const/16 v1, 0x1a

    .line 68
    .line 69
    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getAxisValue(I)F

    .line 70
    .line 71
    .line 72
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 73
    .line 74
    .line 75
    invoke-virtual {v0}, Landroid/view/ViewConfiguration;->getScaledVerticalScrollFactor()F

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v0}, Landroid/view/ViewConfiguration;->getScaledHorizontalScrollFactor()F

    .line 82
    .line 83
    .line 84
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getEventTime()J

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getDeviceId()I

    .line 88
    .line 89
    .line 90
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    new-instance v1, La4/b;

    .line 95
    .line 96
    const/16 v7, 0xa

    .line 97
    .line 98
    invoke-direct {v1, v7, p0, p1}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 99
    .line 100
    .line 101
    check-cast v0, Lc3/l;

    .line 102
    .line 103
    iget-object p0, v0, Lc3/l;->d:Lc3/h;

    .line 104
    .line 105
    iget-boolean p0, p0, Lc3/h;->e:Z

    .line 106
    .line 107
    if-eqz p0, :cond_3

    .line 108
    .line 109
    const-string p0, "FocusRelatedWarning: Dispatching rotary event while the focus system is invalidated."

    .line 110
    .line 111
    sget-object p1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 112
    .line 113
    invoke-virtual {p1, p0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    return v2

    .line 117
    :cond_3
    iget-object p0, v0, Lc3/l;->c:Lc3/v;

    .line 118
    .line 119
    invoke-static {p0}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    if-eqz p0, :cond_10

    .line 124
    .line 125
    iget-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 126
    .line 127
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 128
    .line 129
    if-nez p1, :cond_4

    .line 130
    .line 131
    invoke-static {v5}, Ls3/a;->b(Ljava/lang/String;)V

    .line 132
    .line 133
    .line 134
    :cond_4
    iget-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 135
    .line 136
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    :goto_1
    if-eqz p0, :cond_f

    .line 141
    .line 142
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 143
    .line 144
    iget-object v0, v0, Lg1/q;->g:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v0, Lx2/r;

    .line 147
    .line 148
    iget v0, v0, Lx2/r;->g:I

    .line 149
    .line 150
    and-int/lit16 v0, v0, 0x4000

    .line 151
    .line 152
    if-eqz v0, :cond_d

    .line 153
    .line 154
    :goto_2
    if-eqz p1, :cond_d

    .line 155
    .line 156
    iget v0, p1, Lx2/r;->f:I

    .line 157
    .line 158
    and-int/lit16 v0, v0, 0x4000

    .line 159
    .line 160
    if-eqz v0, :cond_c

    .line 161
    .line 162
    move-object v0, p1

    .line 163
    move-object v7, v3

    .line 164
    :goto_3
    if-eqz v0, :cond_c

    .line 165
    .line 166
    instance-of v8, v0, Lr3/a;

    .line 167
    .line 168
    if-eqz v8, :cond_5

    .line 169
    .line 170
    goto :goto_6

    .line 171
    :cond_5
    iget v8, v0, Lx2/r;->f:I

    .line 172
    .line 173
    and-int/lit16 v8, v8, 0x4000

    .line 174
    .line 175
    if-eqz v8, :cond_b

    .line 176
    .line 177
    instance-of v8, v0, Lv3/n;

    .line 178
    .line 179
    if-eqz v8, :cond_b

    .line 180
    .line 181
    move-object v8, v0

    .line 182
    check-cast v8, Lv3/n;

    .line 183
    .line 184
    iget-object v8, v8, Lv3/n;->s:Lx2/r;

    .line 185
    .line 186
    move v9, v2

    .line 187
    :goto_4
    if-eqz v8, :cond_a

    .line 188
    .line 189
    iget v10, v8, Lx2/r;->f:I

    .line 190
    .line 191
    and-int/lit16 v10, v10, 0x4000

    .line 192
    .line 193
    if-eqz v10, :cond_9

    .line 194
    .line 195
    add-int/lit8 v9, v9, 0x1

    .line 196
    .line 197
    if-ne v9, v6, :cond_6

    .line 198
    .line 199
    move-object v0, v8

    .line 200
    goto :goto_5

    .line 201
    :cond_6
    if-nez v7, :cond_7

    .line 202
    .line 203
    new-instance v7, Ln2/b;

    .line 204
    .line 205
    new-array v10, v4, [Lx2/r;

    .line 206
    .line 207
    invoke-direct {v7, v10}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 208
    .line 209
    .line 210
    :cond_7
    if-eqz v0, :cond_8

    .line 211
    .line 212
    invoke-virtual {v7, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 213
    .line 214
    .line 215
    move-object v0, v3

    .line 216
    :cond_8
    invoke-virtual {v7, v8}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    :cond_9
    :goto_5
    iget-object v8, v8, Lx2/r;->i:Lx2/r;

    .line 220
    .line 221
    goto :goto_4

    .line 222
    :cond_a
    if-ne v9, v6, :cond_b

    .line 223
    .line 224
    goto :goto_3

    .line 225
    :cond_b
    invoke-static {v7}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 226
    .line 227
    .line 228
    move-result-object v0

    .line 229
    goto :goto_3

    .line 230
    :cond_c
    iget-object p1, p1, Lx2/r;->h:Lx2/r;

    .line 231
    .line 232
    goto :goto_2

    .line 233
    :cond_d
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 234
    .line 235
    .line 236
    move-result-object p0

    .line 237
    if-eqz p0, :cond_e

    .line 238
    .line 239
    iget-object p1, p0, Lv3/h0;->H:Lg1/q;

    .line 240
    .line 241
    if-eqz p1, :cond_e

    .line 242
    .line 243
    iget-object p1, p1, Lg1/q;->f:Ljava/lang/Object;

    .line 244
    .line 245
    check-cast p1, Lv3/z1;

    .line 246
    .line 247
    goto :goto_1

    .line 248
    :cond_e
    move-object p1, v3

    .line 249
    goto :goto_1

    .line 250
    :cond_f
    move-object v0, v3

    .line 251
    :goto_6
    check-cast v0, Lr3/a;

    .line 252
    .line 253
    goto :goto_7

    .line 254
    :cond_10
    move-object v0, v3

    .line 255
    :goto_7
    if-eqz v0, :cond_32

    .line 256
    .line 257
    move-object p0, v0

    .line 258
    check-cast p0, Lx2/r;

    .line 259
    .line 260
    iget-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 261
    .line 262
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 263
    .line 264
    if-nez p1, :cond_11

    .line 265
    .line 266
    invoke-static {v5}, Ls3/a;->b(Ljava/lang/String;)V

    .line 267
    .line 268
    .line 269
    :cond_11
    iget-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 270
    .line 271
    iget-object p1, p1, Lx2/r;->h:Lx2/r;

    .line 272
    .line 273
    invoke-static {v0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 274
    .line 275
    .line 276
    move-result-object v0

    .line 277
    move-object v5, v3

    .line 278
    :goto_8
    if-eqz v0, :cond_1d

    .line 279
    .line 280
    iget-object v7, v0, Lv3/h0;->H:Lg1/q;

    .line 281
    .line 282
    iget-object v7, v7, Lg1/q;->g:Ljava/lang/Object;

    .line 283
    .line 284
    check-cast v7, Lx2/r;

    .line 285
    .line 286
    iget v7, v7, Lx2/r;->g:I

    .line 287
    .line 288
    and-int/lit16 v7, v7, 0x4000

    .line 289
    .line 290
    if-eqz v7, :cond_1b

    .line 291
    .line 292
    :goto_9
    if-eqz p1, :cond_1b

    .line 293
    .line 294
    iget v7, p1, Lx2/r;->f:I

    .line 295
    .line 296
    and-int/lit16 v7, v7, 0x4000

    .line 297
    .line 298
    if-eqz v7, :cond_1a

    .line 299
    .line 300
    move-object v7, p1

    .line 301
    move-object v8, v3

    .line 302
    :goto_a
    if-eqz v7, :cond_1a

    .line 303
    .line 304
    instance-of v9, v7, Lr3/a;

    .line 305
    .line 306
    if-eqz v9, :cond_13

    .line 307
    .line 308
    if-nez v5, :cond_12

    .line 309
    .line 310
    new-instance v5, Ljava/util/ArrayList;

    .line 311
    .line 312
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 313
    .line 314
    .line 315
    :cond_12
    invoke-interface {v5, v7}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 316
    .line 317
    .line 318
    goto :goto_d

    .line 319
    :cond_13
    iget v9, v7, Lx2/r;->f:I

    .line 320
    .line 321
    and-int/lit16 v9, v9, 0x4000

    .line 322
    .line 323
    if-eqz v9, :cond_19

    .line 324
    .line 325
    instance-of v9, v7, Lv3/n;

    .line 326
    .line 327
    if-eqz v9, :cond_19

    .line 328
    .line 329
    move-object v9, v7

    .line 330
    check-cast v9, Lv3/n;

    .line 331
    .line 332
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 333
    .line 334
    move v10, v2

    .line 335
    :goto_b
    if-eqz v9, :cond_18

    .line 336
    .line 337
    iget v11, v9, Lx2/r;->f:I

    .line 338
    .line 339
    and-int/lit16 v11, v11, 0x4000

    .line 340
    .line 341
    if-eqz v11, :cond_17

    .line 342
    .line 343
    add-int/lit8 v10, v10, 0x1

    .line 344
    .line 345
    if-ne v10, v6, :cond_14

    .line 346
    .line 347
    move-object v7, v9

    .line 348
    goto :goto_c

    .line 349
    :cond_14
    if-nez v8, :cond_15

    .line 350
    .line 351
    new-instance v8, Ln2/b;

    .line 352
    .line 353
    new-array v11, v4, [Lx2/r;

    .line 354
    .line 355
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    :cond_15
    if-eqz v7, :cond_16

    .line 359
    .line 360
    invoke-virtual {v8, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 361
    .line 362
    .line 363
    move-object v7, v3

    .line 364
    :cond_16
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 365
    .line 366
    .line 367
    :cond_17
    :goto_c
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 368
    .line 369
    goto :goto_b

    .line 370
    :cond_18
    if-ne v10, v6, :cond_19

    .line 371
    .line 372
    goto :goto_a

    .line 373
    :cond_19
    :goto_d
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 374
    .line 375
    .line 376
    move-result-object v7

    .line 377
    goto :goto_a

    .line 378
    :cond_1a
    iget-object p1, p1, Lx2/r;->h:Lx2/r;

    .line 379
    .line 380
    goto :goto_9

    .line 381
    :cond_1b
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 382
    .line 383
    .line 384
    move-result-object v0

    .line 385
    if-eqz v0, :cond_1c

    .line 386
    .line 387
    iget-object p1, v0, Lv3/h0;->H:Lg1/q;

    .line 388
    .line 389
    if-eqz p1, :cond_1c

    .line 390
    .line 391
    iget-object p1, p1, Lg1/q;->f:Ljava/lang/Object;

    .line 392
    .line 393
    check-cast p1, Lv3/z1;

    .line 394
    .line 395
    goto :goto_8

    .line 396
    :cond_1c
    move-object p1, v3

    .line 397
    goto :goto_8

    .line 398
    :cond_1d
    if-eqz v5, :cond_1f

    .line 399
    .line 400
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 401
    .line 402
    .line 403
    move-result p1

    .line 404
    add-int/lit8 p1, p1, -0x1

    .line 405
    .line 406
    if-ltz p1, :cond_1f

    .line 407
    .line 408
    :goto_e
    add-int/lit8 v0, p1, -0x1

    .line 409
    .line 410
    invoke-interface {v5, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 411
    .line 412
    .line 413
    move-result-object p1

    .line 414
    check-cast p1, Lr3/a;

    .line 415
    .line 416
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 417
    .line 418
    .line 419
    if-gez v0, :cond_1e

    .line 420
    .line 421
    goto :goto_f

    .line 422
    :cond_1e
    move p1, v0

    .line 423
    goto :goto_e

    .line 424
    :cond_1f
    :goto_f
    iget-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 425
    .line 426
    move-object v0, v3

    .line 427
    :goto_10
    if-eqz p1, :cond_27

    .line 428
    .line 429
    instance-of v7, p1, Lr3/a;

    .line 430
    .line 431
    if-eqz v7, :cond_20

    .line 432
    .line 433
    check-cast p1, Lr3/a;

    .line 434
    .line 435
    goto :goto_13

    .line 436
    :cond_20
    iget v7, p1, Lx2/r;->f:I

    .line 437
    .line 438
    and-int/lit16 v7, v7, 0x4000

    .line 439
    .line 440
    if-eqz v7, :cond_26

    .line 441
    .line 442
    instance-of v7, p1, Lv3/n;

    .line 443
    .line 444
    if-eqz v7, :cond_26

    .line 445
    .line 446
    move-object v7, p1

    .line 447
    check-cast v7, Lv3/n;

    .line 448
    .line 449
    iget-object v7, v7, Lv3/n;->s:Lx2/r;

    .line 450
    .line 451
    move v8, v2

    .line 452
    :goto_11
    if-eqz v7, :cond_25

    .line 453
    .line 454
    iget v9, v7, Lx2/r;->f:I

    .line 455
    .line 456
    and-int/lit16 v9, v9, 0x4000

    .line 457
    .line 458
    if-eqz v9, :cond_24

    .line 459
    .line 460
    add-int/lit8 v8, v8, 0x1

    .line 461
    .line 462
    if-ne v8, v6, :cond_21

    .line 463
    .line 464
    move-object p1, v7

    .line 465
    goto :goto_12

    .line 466
    :cond_21
    if-nez v0, :cond_22

    .line 467
    .line 468
    new-instance v0, Ln2/b;

    .line 469
    .line 470
    new-array v9, v4, [Lx2/r;

    .line 471
    .line 472
    invoke-direct {v0, v9}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 473
    .line 474
    .line 475
    :cond_22
    if-eqz p1, :cond_23

    .line 476
    .line 477
    invoke-virtual {v0, p1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 478
    .line 479
    .line 480
    move-object p1, v3

    .line 481
    :cond_23
    invoke-virtual {v0, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 482
    .line 483
    .line 484
    :cond_24
    :goto_12
    iget-object v7, v7, Lx2/r;->i:Lx2/r;

    .line 485
    .line 486
    goto :goto_11

    .line 487
    :cond_25
    if-ne v8, v6, :cond_26

    .line 488
    .line 489
    goto :goto_10

    .line 490
    :cond_26
    :goto_13
    invoke-static {v0}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 491
    .line 492
    .line 493
    move-result-object p1

    .line 494
    goto :goto_10

    .line 495
    :cond_27
    invoke-virtual {v1}, La4/b;->invoke()Ljava/lang/Object;

    .line 496
    .line 497
    .line 498
    move-result-object p1

    .line 499
    check-cast p1, Ljava/lang/Boolean;

    .line 500
    .line 501
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 502
    .line 503
    .line 504
    move-result p1

    .line 505
    if-eqz p1, :cond_28

    .line 506
    .line 507
    goto/16 :goto_19

    .line 508
    .line 509
    :cond_28
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 510
    .line 511
    move-object p1, v3

    .line 512
    :goto_14
    if-eqz p0, :cond_30

    .line 513
    .line 514
    instance-of v0, p0, Lr3/a;

    .line 515
    .line 516
    if-eqz v0, :cond_29

    .line 517
    .line 518
    check-cast p0, Lr3/a;

    .line 519
    .line 520
    goto :goto_17

    .line 521
    :cond_29
    iget v0, p0, Lx2/r;->f:I

    .line 522
    .line 523
    and-int/lit16 v0, v0, 0x4000

    .line 524
    .line 525
    if-eqz v0, :cond_2f

    .line 526
    .line 527
    instance-of v0, p0, Lv3/n;

    .line 528
    .line 529
    if-eqz v0, :cond_2f

    .line 530
    .line 531
    move-object v0, p0

    .line 532
    check-cast v0, Lv3/n;

    .line 533
    .line 534
    iget-object v0, v0, Lv3/n;->s:Lx2/r;

    .line 535
    .line 536
    move v1, v2

    .line 537
    :goto_15
    if-eqz v0, :cond_2e

    .line 538
    .line 539
    iget v7, v0, Lx2/r;->f:I

    .line 540
    .line 541
    and-int/lit16 v7, v7, 0x4000

    .line 542
    .line 543
    if-eqz v7, :cond_2d

    .line 544
    .line 545
    add-int/lit8 v1, v1, 0x1

    .line 546
    .line 547
    if-ne v1, v6, :cond_2a

    .line 548
    .line 549
    move-object p0, v0

    .line 550
    goto :goto_16

    .line 551
    :cond_2a
    if-nez p1, :cond_2b

    .line 552
    .line 553
    new-instance p1, Ln2/b;

    .line 554
    .line 555
    new-array v7, v4, [Lx2/r;

    .line 556
    .line 557
    invoke-direct {p1, v7}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 558
    .line 559
    .line 560
    :cond_2b
    if-eqz p0, :cond_2c

    .line 561
    .line 562
    invoke-virtual {p1, p0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 563
    .line 564
    .line 565
    move-object p0, v3

    .line 566
    :cond_2c
    invoke-virtual {p1, v0}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 567
    .line 568
    .line 569
    :cond_2d
    :goto_16
    iget-object v0, v0, Lx2/r;->i:Lx2/r;

    .line 570
    .line 571
    goto :goto_15

    .line 572
    :cond_2e
    if-ne v1, v6, :cond_2f

    .line 573
    .line 574
    goto :goto_14

    .line 575
    :cond_2f
    :goto_17
    invoke-static {p1}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 576
    .line 577
    .line 578
    move-result-object p0

    .line 579
    goto :goto_14

    .line 580
    :cond_30
    if-eqz v5, :cond_32

    .line 581
    .line 582
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 583
    .line 584
    .line 585
    move-result p0

    .line 586
    move p1, v2

    .line 587
    :goto_18
    if-ge p1, p0, :cond_32

    .line 588
    .line 589
    invoke-interface {v5, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 590
    .line 591
    .line 592
    move-result-object v0

    .line 593
    check-cast v0, Lr3/a;

    .line 594
    .line 595
    iget-object v0, v0, Lr3/a;->r:Lw3/o;

    .line 596
    .line 597
    add-int/lit8 p1, p1, 0x1

    .line 598
    .line 599
    goto :goto_18

    .line 600
    :cond_31
    invoke-virtual {p0, p1}, Lw3/t;->j(Landroid/view/MotionEvent;)I

    .line 601
    .line 602
    .line 603
    move-result p0

    .line 604
    and-int/2addr p0, v6

    .line 605
    if-eqz p0, :cond_32

    .line 606
    .line 607
    :goto_19
    return v6

    .line 608
    :cond_32
    return v2

    .line 609
    :cond_33
    const/4 v0, 0x2

    .line 610
    invoke-virtual {p1, v0}, Landroid/view/InputEvent;->isFromSource(I)Z

    .line 611
    .line 612
    .line 613
    move-result v0

    .line 614
    if-nez v0, :cond_3f

    .line 615
    .line 616
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 617
    .line 618
    .line 619
    move-result v0

    .line 620
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 621
    .line 622
    .line 623
    move-result v1

    .line 624
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 625
    .line 626
    .line 627
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 628
    .line 629
    .line 630
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getEventTime()J

    .line 631
    .line 632
    .line 633
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 634
    .line 635
    .line 636
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 637
    .line 638
    .line 639
    move-result-object v0

    .line 640
    check-cast v0, Lc3/l;

    .line 641
    .line 642
    iget-object v1, v0, Lc3/l;->d:Lc3/h;

    .line 643
    .line 644
    iget-boolean v1, v1, Lc3/h;->e:Z

    .line 645
    .line 646
    if-eqz v1, :cond_34

    .line 647
    .line 648
    const-string v0, "FocusRelatedWarning: Dispatching indirect touch event while the focus system is invalidated."

    .line 649
    .line 650
    sget-object v1, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 651
    .line 652
    invoke-virtual {v1, v0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 653
    .line 654
    .line 655
    goto/16 :goto_1f

    .line 656
    .line 657
    :cond_34
    iget-object v0, v0, Lc3/l;->c:Lc3/v;

    .line 658
    .line 659
    invoke-static {v0}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 660
    .line 661
    .line 662
    move-result-object v0

    .line 663
    if-eqz v0, :cond_3f

    .line 664
    .line 665
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 666
    .line 667
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 668
    .line 669
    if-nez v1, :cond_35

    .line 670
    .line 671
    invoke-static {v5}, Ls3/a;->b(Ljava/lang/String;)V

    .line 672
    .line 673
    .line 674
    :cond_35
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 675
    .line 676
    invoke-static {v0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 677
    .line 678
    .line 679
    move-result-object v0

    .line 680
    :goto_1a
    if-eqz v0, :cond_3f

    .line 681
    .line 682
    iget-object v5, v0, Lv3/h0;->H:Lg1/q;

    .line 683
    .line 684
    iget-object v5, v5, Lg1/q;->g:Ljava/lang/Object;

    .line 685
    .line 686
    check-cast v5, Lx2/r;

    .line 687
    .line 688
    iget v5, v5, Lx2/r;->g:I

    .line 689
    .line 690
    const/high16 v7, 0x200000

    .line 691
    .line 692
    and-int/2addr v5, v7

    .line 693
    if-eqz v5, :cond_3d

    .line 694
    .line 695
    :goto_1b
    if-eqz v1, :cond_3d

    .line 696
    .line 697
    iget v5, v1, Lx2/r;->f:I

    .line 698
    .line 699
    and-int/2addr v5, v7

    .line 700
    if-eqz v5, :cond_3c

    .line 701
    .line 702
    move-object v5, v1

    .line 703
    move-object v8, v3

    .line 704
    :goto_1c
    if-eqz v5, :cond_3c

    .line 705
    .line 706
    iget v9, v5, Lx2/r;->f:I

    .line 707
    .line 708
    and-int/2addr v9, v7

    .line 709
    if-eqz v9, :cond_3b

    .line 710
    .line 711
    instance-of v9, v5, Lv3/n;

    .line 712
    .line 713
    if-eqz v9, :cond_3b

    .line 714
    .line 715
    move-object v9, v5

    .line 716
    check-cast v9, Lv3/n;

    .line 717
    .line 718
    iget-object v9, v9, Lv3/n;->s:Lx2/r;

    .line 719
    .line 720
    move v10, v2

    .line 721
    :goto_1d
    if-eqz v9, :cond_3a

    .line 722
    .line 723
    iget v11, v9, Lx2/r;->f:I

    .line 724
    .line 725
    and-int/2addr v11, v7

    .line 726
    if-eqz v11, :cond_39

    .line 727
    .line 728
    add-int/lit8 v10, v10, 0x1

    .line 729
    .line 730
    if-ne v10, v6, :cond_36

    .line 731
    .line 732
    move-object v5, v9

    .line 733
    goto :goto_1e

    .line 734
    :cond_36
    if-nez v8, :cond_37

    .line 735
    .line 736
    new-instance v8, Ln2/b;

    .line 737
    .line 738
    new-array v11, v4, [Lx2/r;

    .line 739
    .line 740
    invoke-direct {v8, v11}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 741
    .line 742
    .line 743
    :cond_37
    if-eqz v5, :cond_38

    .line 744
    .line 745
    invoke-virtual {v8, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 746
    .line 747
    .line 748
    move-object v5, v3

    .line 749
    :cond_38
    invoke-virtual {v8, v9}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 750
    .line 751
    .line 752
    :cond_39
    :goto_1e
    iget-object v9, v9, Lx2/r;->i:Lx2/r;

    .line 753
    .line 754
    goto :goto_1d

    .line 755
    :cond_3a
    if-ne v10, v6, :cond_3b

    .line 756
    .line 757
    goto :goto_1c

    .line 758
    :cond_3b
    invoke-static {v8}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 759
    .line 760
    .line 761
    move-result-object v5

    .line 762
    goto :goto_1c

    .line 763
    :cond_3c
    iget-object v1, v1, Lx2/r;->h:Lx2/r;

    .line 764
    .line 765
    goto :goto_1b

    .line 766
    :cond_3d
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 767
    .line 768
    .line 769
    move-result-object v0

    .line 770
    if-eqz v0, :cond_3e

    .line 771
    .line 772
    iget-object v1, v0, Lv3/h0;->H:Lg1/q;

    .line 773
    .line 774
    if-eqz v1, :cond_3e

    .line 775
    .line 776
    iget-object v1, v1, Lg1/q;->f:Ljava/lang/Object;

    .line 777
    .line 778
    check-cast v1, Lv3/z1;

    .line 779
    .line 780
    goto :goto_1a

    .line 781
    :cond_3e
    move-object v1, v3

    .line 782
    goto :goto_1a

    .line 783
    :cond_3f
    :goto_1f
    invoke-super {p0, p1}, Landroid/view/View;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    .line 784
    .line 785
    .line 786
    move-result p0

    .line 787
    return p0

    .line 788
    :cond_40
    :goto_20
    invoke-super {p0, p1}, Landroid/view/View;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    .line 789
    .line 790
    .line 791
    move-result p0

    .line 792
    return p0
.end method

.method public final dispatchHoverEvent(Landroid/view/MotionEvent;)Z
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-boolean v2, v0, Lw3/t;->M1:Z

    .line 6
    .line 7
    iget-object v3, v0, Lw3/t;->L1:Lm8/o;

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    invoke-virtual {v0, v3}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 12
    .line 13
    .line 14
    invoke-virtual {v3}, Lm8/o;->run()V

    .line 15
    .line 16
    .line 17
    :cond_0
    invoke-static {v1}, Lw3/t;->m(Landroid/view/MotionEvent;)Z

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    const/4 v4, 0x0

    .line 22
    if-nez v2, :cond_12

    .line 23
    .line 24
    invoke-virtual {v0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-nez v2, :cond_1

    .line 29
    .line 30
    goto/16 :goto_5

    .line 31
    .line 32
    :cond_1
    iget-object v2, v0, Lw3/t;->v:Lw3/z;

    .line 33
    .line 34
    iget-object v5, v2, Lw3/z;->d:Lw3/t;

    .line 35
    .line 36
    iget-object v6, v2, Lw3/z;->g:Landroid/view/accessibility/AccessibilityManager;

    .line 37
    .line 38
    invoke-virtual {v6}, Landroid/view/accessibility/AccessibilityManager;->isEnabled()Z

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    const/16 v8, 0xa

    .line 43
    .line 44
    const/4 v9, 0x7

    .line 45
    const/4 v10, 0x1

    .line 46
    if-eqz v7, :cond_c

    .line 47
    .line 48
    invoke-virtual {v6}, Landroid/view/accessibility/AccessibilityManager;->isTouchExplorationEnabled()Z

    .line 49
    .line 50
    .line 51
    move-result v6

    .line 52
    if-eqz v6, :cond_c

    .line 53
    .line 54
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getAction()I

    .line 55
    .line 56
    .line 57
    move-result v6

    .line 58
    const/16 v7, 0x100

    .line 59
    .line 60
    const/16 v11, 0x80

    .line 61
    .line 62
    const/4 v12, 0x0

    .line 63
    const/16 v13, 0xc

    .line 64
    .line 65
    const/high16 v14, -0x80000000

    .line 66
    .line 67
    if-eq v6, v9, :cond_5

    .line 68
    .line 69
    const/16 v15, 0x9

    .line 70
    .line 71
    if-eq v6, v15, :cond_5

    .line 72
    .line 73
    if-eq v6, v8, :cond_2

    .line 74
    .line 75
    goto/16 :goto_3

    .line 76
    .line 77
    :cond_2
    iget v6, v2, Lw3/z;->e:I

    .line 78
    .line 79
    if-eq v6, v14, :cond_4

    .line 80
    .line 81
    if-ne v6, v14, :cond_3

    .line 82
    .line 83
    goto/16 :goto_3

    .line 84
    .line 85
    :cond_3
    iput v14, v2, Lw3/z;->e:I

    .line 86
    .line 87
    invoke-static {v2, v14, v11, v12, v13}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {v2, v6, v7, v12, v13}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 91
    .line 92
    .line 93
    goto/16 :goto_3

    .line 94
    .line 95
    :cond_4
    invoke-virtual {v5}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 96
    .line 97
    .line 98
    move-result-object v2

    .line 99
    invoke-virtual {v2, v1}, Landroid/view/View;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    .line 100
    .line 101
    .line 102
    goto/16 :goto_3

    .line 103
    .line 104
    :cond_5
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getX()F

    .line 105
    .line 106
    .line 107
    move-result v6

    .line 108
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getY()F

    .line 109
    .line 110
    .line 111
    move-result v15

    .line 112
    invoke-virtual {v5, v10}, Lw3/t;->r(Z)V

    .line 113
    .line 114
    .line 115
    new-instance v20, Lv3/s;

    .line 116
    .line 117
    invoke-direct/range {v20 .. v20}, Lv3/s;-><init>()V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v5}, Lw3/t;->getRoot()Lv3/h0;

    .line 121
    .line 122
    .line 123
    move-result-object v14

    .line 124
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 125
    .line 126
    .line 127
    move-result v6

    .line 128
    int-to-long v8, v6

    .line 129
    invoke-static {v15}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 130
    .line 131
    .line 132
    move-result v6

    .line 133
    move-wide/from16 v16, v8

    .line 134
    .line 135
    int-to-long v7, v6

    .line 136
    const/16 v6, 0x20

    .line 137
    .line 138
    shl-long v16, v16, v6

    .line 139
    .line 140
    const-wide v18, 0xffffffffL

    .line 141
    .line 142
    .line 143
    .line 144
    .line 145
    and-long v6, v7, v18

    .line 146
    .line 147
    or-long v6, v16, v6

    .line 148
    .line 149
    iget-object v8, v14, Lv3/h0;->H:Lg1/q;

    .line 150
    .line 151
    iget-object v9, v8, Lg1/q;->e:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v9, Lv3/f1;

    .line 154
    .line 155
    sget-object v14, Lv3/f1;->N:Le3/k0;

    .line 156
    .line 157
    invoke-virtual {v9, v6, v7}, Lv3/f1;->c1(J)J

    .line 158
    .line 159
    .line 160
    move-result-wide v18

    .line 161
    iget-object v6, v8, Lg1/q;->e:Ljava/lang/Object;

    .line 162
    .line 163
    move-object/from16 v16, v6

    .line 164
    .line 165
    check-cast v16, Lv3/f1;

    .line 166
    .line 167
    sget-object v17, Lv3/f1;->R:Lv3/d;

    .line 168
    .line 169
    const/16 v21, 0x1

    .line 170
    .line 171
    const/16 v22, 0x1

    .line 172
    .line 173
    invoke-virtual/range {v16 .. v22}, Lv3/f1;->k1(Lv3/d;JLv3/s;IZ)V

    .line 174
    .line 175
    .line 176
    move-object/from16 v6, v20

    .line 177
    .line 178
    invoke-static {v6}, Ljp/k1;->h(Ljava/util/List;)I

    .line 179
    .line 180
    .line 181
    move-result v7

    .line 182
    :goto_0
    const/4 v8, -0x1

    .line 183
    if-ge v8, v7, :cond_6

    .line 184
    .line 185
    iget-object v8, v6, Lv3/s;->d:Landroidx/collection/l0;

    .line 186
    .line 187
    invoke-virtual {v8, v7}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v8

    .line 191
    const-string v9, "null cannot be cast to non-null type androidx.compose.ui.Modifier.Node"

    .line 192
    .line 193
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 194
    .line 195
    .line 196
    check-cast v8, Lx2/r;

    .line 197
    .line 198
    invoke-static {v8}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 199
    .line 200
    .line 201
    move-result-object v8

    .line 202
    invoke-virtual {v5}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 203
    .line 204
    .line 205
    move-result-object v9

    .line 206
    invoke-virtual {v9}, Lw3/t0;->getLayoutNodeToHolder()Ljava/util/HashMap;

    .line 207
    .line 208
    .line 209
    move-result-object v9

    .line 210
    invoke-virtual {v9, v8}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object v9

    .line 214
    check-cast v9, Lw4/g;

    .line 215
    .line 216
    if-eqz v9, :cond_7

    .line 217
    .line 218
    :cond_6
    const/high16 v14, -0x80000000

    .line 219
    .line 220
    goto :goto_2

    .line 221
    :cond_7
    iget-object v9, v8, Lv3/h0;->H:Lg1/q;

    .line 222
    .line 223
    const/16 v14, 0x8

    .line 224
    .line 225
    invoke-virtual {v9, v14}, Lg1/q;->i(I)Z

    .line 226
    .line 227
    .line 228
    move-result v9

    .line 229
    if-nez v9, :cond_8

    .line 230
    .line 231
    goto :goto_1

    .line 232
    :cond_8
    iget v9, v8, Lv3/h0;->e:I

    .line 233
    .line 234
    invoke-virtual {v2, v9}, Lw3/z;->A(I)I

    .line 235
    .line 236
    .line 237
    move-result v9

    .line 238
    invoke-static {v8, v4}, Ld4/t;->a(Lv3/h0;Z)Ld4/q;

    .line 239
    .line 240
    .line 241
    move-result-object v8

    .line 242
    invoke-static {v8}, Ld4/t;->f(Ld4/q;)Z

    .line 243
    .line 244
    .line 245
    move-result v14

    .line 246
    if-nez v14, :cond_9

    .line 247
    .line 248
    goto :goto_1

    .line 249
    :cond_9
    invoke-virtual {v8}, Ld4/q;->k()Ld4/l;

    .line 250
    .line 251
    .line 252
    move-result-object v8

    .line 253
    sget-object v14, Ld4/v;->z:Ld4/z;

    .line 254
    .line 255
    iget-object v8, v8, Ld4/l;->d:Landroidx/collection/q0;

    .line 256
    .line 257
    invoke-virtual {v8, v14}, Landroidx/collection/q0;->c(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v8

    .line 261
    if-eqz v8, :cond_a

    .line 262
    .line 263
    :goto_1
    add-int/lit8 v7, v7, -0x1

    .line 264
    .line 265
    goto :goto_0

    .line 266
    :cond_a
    move v14, v9

    .line 267
    :goto_2
    invoke-virtual {v5}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 268
    .line 269
    .line 270
    move-result-object v5

    .line 271
    invoke-virtual {v5, v1}, Landroid/view/View;->dispatchGenericMotionEvent(Landroid/view/MotionEvent;)Z

    .line 272
    .line 273
    .line 274
    iget v5, v2, Lw3/z;->e:I

    .line 275
    .line 276
    if-ne v5, v14, :cond_b

    .line 277
    .line 278
    goto :goto_3

    .line 279
    :cond_b
    iput v14, v2, Lw3/z;->e:I

    .line 280
    .line 281
    invoke-static {v2, v14, v11, v12, v13}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 282
    .line 283
    .line 284
    const/16 v15, 0x100

    .line 285
    .line 286
    invoke-static {v2, v5, v15, v12, v13}, Lw3/z;->E(Lw3/z;IILjava/lang/Integer;I)V

    .line 287
    .line 288
    .line 289
    :cond_c
    :goto_3
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 290
    .line 291
    .line 292
    move-result v2

    .line 293
    const/4 v5, 0x7

    .line 294
    if-eq v2, v5, :cond_10

    .line 295
    .line 296
    const/16 v5, 0xa

    .line 297
    .line 298
    if-eq v2, v5, :cond_d

    .line 299
    .line 300
    goto :goto_4

    .line 301
    :cond_d
    invoke-virtual/range {p0 .. p1}, Lw3/t;->n(Landroid/view/MotionEvent;)Z

    .line 302
    .line 303
    .line 304
    move-result v2

    .line 305
    if-eqz v2, :cond_11

    .line 306
    .line 307
    invoke-virtual {v1, v4}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 308
    .line 309
    .line 310
    move-result v2

    .line 311
    const/4 v5, 0x3

    .line 312
    if-ne v2, v5, :cond_e

    .line 313
    .line 314
    invoke-virtual {v1}, Landroid/view/MotionEvent;->getButtonState()I

    .line 315
    .line 316
    .line 317
    move-result v2

    .line 318
    if-eqz v2, :cond_e

    .line 319
    .line 320
    goto :goto_5

    .line 321
    :cond_e
    iget-object v2, v0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 322
    .line 323
    if-eqz v2, :cond_f

    .line 324
    .line 325
    invoke-virtual {v2}, Landroid/view/MotionEvent;->recycle()V

    .line 326
    .line 327
    .line 328
    :cond_f
    invoke-static {v1}, Landroid/view/MotionEvent;->obtainNoHistory(Landroid/view/MotionEvent;)Landroid/view/MotionEvent;

    .line 329
    .line 330
    .line 331
    move-result-object v1

    .line 332
    iput-object v1, v0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 333
    .line 334
    iput-boolean v10, v0, Lw3/t;->M1:Z

    .line 335
    .line 336
    const-wide/16 v1, 0x8

    .line 337
    .line 338
    invoke-virtual {v0, v3, v1, v2}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 339
    .line 340
    .line 341
    return v4

    .line 342
    :cond_10
    invoke-virtual/range {p0 .. p1}, Lw3/t;->o(Landroid/view/MotionEvent;)Z

    .line 343
    .line 344
    .line 345
    move-result v2

    .line 346
    if-nez v2, :cond_11

    .line 347
    .line 348
    goto :goto_5

    .line 349
    :cond_11
    :goto_4
    invoke-virtual/range {p0 .. p1}, Lw3/t;->j(Landroid/view/MotionEvent;)I

    .line 350
    .line 351
    .line 352
    move-result v0

    .line 353
    and-int/2addr v0, v10

    .line 354
    if-eqz v0, :cond_12

    .line 355
    .line 356
    return v10

    .line 357
    :cond_12
    :goto_5
    return v4
.end method

.method public final dispatchKeyEvent(Landroid/view/KeyEvent;)Z
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_2

    .line 6
    .line 7
    invoke-virtual {p1}, Landroid/view/KeyEvent;->getMetaState()I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget-object v1, p0, Lw3/t;->m:Lw3/r1;

    .line 12
    .line 13
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    sget-object v1, Lw3/k2;->a:Ll2/j1;

    .line 17
    .line 18
    new-instance v2, Lp3/c0;

    .line 19
    .line 20
    invoke-direct {v2, v0}, Lp3/c0;-><init>(I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1, v2}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    sget-object v1, Lc3/i;->f:Lc3/i;

    .line 31
    .line 32
    check-cast v0, Lc3/l;

    .line 33
    .line 34
    invoke-virtual {v0, p1, v1}, Lc3/l;->f(Landroid/view/KeyEvent;Lay0/a;)Z

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    if-nez v0, :cond_1

    .line 39
    .line 40
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->dispatchKeyEvent(Landroid/view/KeyEvent;)Z

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    if-eqz p0, :cond_0

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    const/4 p0, 0x0

    .line 48
    return p0

    .line 49
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 50
    return p0

    .line 51
    :cond_2
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    new-instance v1, La4/b;

    .line 56
    .line 57
    const/16 v2, 0x9

    .line 58
    .line 59
    invoke-direct {v1, v2, p0, p1}, La4/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    check-cast v0, Lc3/l;

    .line 63
    .line 64
    invoke-virtual {v0, p1, v1}, Lc3/l;->f(Landroid/view/KeyEvent;Lay0/a;)Z

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    return p0
.end method

.method public final dispatchKeyEventPreIme(Landroid/view/KeyEvent;)Z
    .locals 11

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x1

    .line 7
    if-eqz v0, :cond_b

    .line 8
    .line 9
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lc3/l;

    .line 14
    .line 15
    iget-object v3, v0, Lc3/l;->d:Lc3/h;

    .line 16
    .line 17
    iget-boolean v3, v3, Lc3/h;->e:Z

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    const-string v0, "FocusRelatedWarning: Dispatching intercepted soft keyboard event while the focus system is invalidated."

    .line 22
    .line 23
    sget-object v3, Ljava/lang/System;->out:Ljava/io/PrintStream;

    .line 24
    .line 25
    invoke-virtual {v3, v0}, Ljava/io/PrintStream;->println(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    goto/16 :goto_5

    .line 29
    .line 30
    :cond_0
    iget-object v0, v0, Lc3/l;->c:Lc3/v;

    .line 31
    .line 32
    invoke-static {v0}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 33
    .line 34
    .line 35
    move-result-object v0

    .line 36
    if-eqz v0, :cond_b

    .line 37
    .line 38
    iget-object v3, v0, Lx2/r;->d:Lx2/r;

    .line 39
    .line 40
    iget-boolean v3, v3, Lx2/r;->q:Z

    .line 41
    .line 42
    if-nez v3, :cond_1

    .line 43
    .line 44
    const-string v3, "visitAncestors called on an unattached node"

    .line 45
    .line 46
    invoke-static {v3}, Ls3/a;->b(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    :cond_1
    iget-object v3, v0, Lx2/r;->d:Lx2/r;

    .line 50
    .line 51
    invoke-static {v0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    :goto_0
    if-eqz v0, :cond_b

    .line 56
    .line 57
    iget-object v4, v0, Lv3/h0;->H:Lg1/q;

    .line 58
    .line 59
    iget-object v4, v4, Lg1/q;->g:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v4, Lx2/r;

    .line 62
    .line 63
    iget v4, v4, Lx2/r;->g:I

    .line 64
    .line 65
    const/high16 v5, 0x20000

    .line 66
    .line 67
    and-int/2addr v4, v5

    .line 68
    const/4 v6, 0x0

    .line 69
    if-eqz v4, :cond_9

    .line 70
    .line 71
    :goto_1
    if-eqz v3, :cond_9

    .line 72
    .line 73
    iget v4, v3, Lx2/r;->f:I

    .line 74
    .line 75
    and-int/2addr v4, v5

    .line 76
    if-eqz v4, :cond_8

    .line 77
    .line 78
    move-object v4, v3

    .line 79
    move-object v7, v6

    .line 80
    :goto_2
    if-eqz v4, :cond_8

    .line 81
    .line 82
    iget v8, v4, Lx2/r;->f:I

    .line 83
    .line 84
    and-int/2addr v8, v5

    .line 85
    if-eqz v8, :cond_7

    .line 86
    .line 87
    instance-of v8, v4, Lv3/n;

    .line 88
    .line 89
    if-eqz v8, :cond_7

    .line 90
    .line 91
    move-object v8, v4

    .line 92
    check-cast v8, Lv3/n;

    .line 93
    .line 94
    iget-object v8, v8, Lv3/n;->s:Lx2/r;

    .line 95
    .line 96
    move v9, v1

    .line 97
    :goto_3
    if-eqz v8, :cond_6

    .line 98
    .line 99
    iget v10, v8, Lx2/r;->f:I

    .line 100
    .line 101
    and-int/2addr v10, v5

    .line 102
    if-eqz v10, :cond_5

    .line 103
    .line 104
    add-int/lit8 v9, v9, 0x1

    .line 105
    .line 106
    if-ne v9, v2, :cond_2

    .line 107
    .line 108
    move-object v4, v8

    .line 109
    goto :goto_4

    .line 110
    :cond_2
    if-nez v7, :cond_3

    .line 111
    .line 112
    new-instance v7, Ln2/b;

    .line 113
    .line 114
    const/16 v10, 0x10

    .line 115
    .line 116
    new-array v10, v10, [Lx2/r;

    .line 117
    .line 118
    invoke-direct {v7, v10}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_3
    if-eqz v4, :cond_4

    .line 122
    .line 123
    invoke-virtual {v7, v4}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    move-object v4, v6

    .line 127
    :cond_4
    invoke-virtual {v7, v8}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :cond_5
    :goto_4
    iget-object v8, v8, Lx2/r;->i:Lx2/r;

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_6
    if-ne v9, v2, :cond_7

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_7
    invoke-static {v7}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 137
    .line 138
    .line 139
    move-result-object v4

    .line 140
    goto :goto_2

    .line 141
    :cond_8
    iget-object v3, v3, Lx2/r;->h:Lx2/r;

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_9
    invoke-virtual {v0}, Lv3/h0;->v()Lv3/h0;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    if-eqz v0, :cond_a

    .line 149
    .line 150
    iget-object v3, v0, Lv3/h0;->H:Lg1/q;

    .line 151
    .line 152
    if-eqz v3, :cond_a

    .line 153
    .line 154
    iget-object v3, v3, Lg1/q;->f:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v3, Lv3/z1;

    .line 157
    .line 158
    goto :goto_0

    .line 159
    :cond_a
    move-object v3, v6

    .line 160
    goto :goto_0

    .line 161
    :cond_b
    :goto_5
    invoke-super {p0, p1}, Landroid/view/ViewGroup;->dispatchKeyEventPreIme(Landroid/view/KeyEvent;)Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-eqz p0, :cond_c

    .line 166
    .line 167
    return v2

    .line 168
    :cond_c
    return v1
.end method

.method public final dispatchTouchEvent(Landroid/view/MotionEvent;)Z
    .locals 5

    .line 1
    iget-boolean v0, p0, Lw3/t;->M1:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    iget-object v0, p0, Lw3/t;->L1:Lm8/o;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 9
    .line 10
    .line 11
    iget-object v2, p0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 12
    .line 13
    invoke-static {v2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    if-nez v3, :cond_1

    .line 21
    .line 22
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getSource()I

    .line 23
    .line 24
    .line 25
    move-result v3

    .line 26
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getSource()I

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-ne v3, v4, :cond_1

    .line 31
    .line 32
    invoke-virtual {v2, v1}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 33
    .line 34
    .line 35
    move-result v2

    .line 36
    invoke-virtual {p1, v1}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    if-eq v2, v3, :cond_0

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    iput-boolean v1, p0, Lw3/t;->M1:Z

    .line 44
    .line 45
    goto :goto_1

    .line 46
    :cond_1
    :goto_0
    invoke-virtual {v0}, Lm8/o;->run()V

    .line 47
    .line 48
    .line 49
    :cond_2
    :goto_1
    invoke-static {p1}, Lw3/t;->m(Landroid/view/MotionEvent;)Z

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    if-nez v0, :cond_6

    .line 54
    .line 55
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    if-nez v0, :cond_3

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    const/4 v2, 0x2

    .line 67
    if-ne v0, v2, :cond_4

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Lw3/t;->o(Landroid/view/MotionEvent;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_4

    .line 74
    .line 75
    goto :goto_2

    .line 76
    :cond_4
    invoke-virtual {p0, p1}, Lw3/t;->j(Landroid/view/MotionEvent;)I

    .line 77
    .line 78
    .line 79
    move-result p1

    .line 80
    and-int/lit8 v0, p1, 0x2

    .line 81
    .line 82
    const/4 v2, 0x1

    .line 83
    if-eqz v0, :cond_5

    .line 84
    .line 85
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-interface {p0, v2}, Landroid/view/ViewParent;->requestDisallowInterceptTouchEvent(Z)V

    .line 90
    .line 91
    .line 92
    :cond_5
    and-int/lit8 p0, p1, 0x1

    .line 93
    .line 94
    if-eqz p0, :cond_6

    .line 95
    .line 96
    return v2

    .line 97
    :cond_6
    :goto_2
    return v1
.end method

.method public final findViewByAccessibilityIdTraversal(I)Landroid/view/View;
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    const-class v1, Landroid/view/View;

    .line 3
    .line 4
    const-string v2, "findViewByAccessibilityIdTraversal"

    .line 5
    .line 6
    sget-object v3, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 7
    .line 8
    filled-new-array {v3}, [Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v3

    .line 12
    invoke-virtual {v1, v2, v3}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/4 v2, 0x1

    .line 17
    invoke-virtual {v1, v2}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 18
    .line 19
    .line 20
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {v1, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    instance-of p1, p0, Landroid/view/View;

    .line 33
    .line 34
    if-eqz p1, :cond_0

    .line 35
    .line 36
    check-cast p0, Landroid/view/View;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    .line 37
    .line 38
    return-object p0

    .line 39
    :catch_0
    :cond_0
    return-object v0
.end method

.method public final focusSearch(Landroid/view/View;I)Landroid/view/View;
    .locals 7

    .line 1
    if-eqz p1, :cond_b

    .line 2
    .line 3
    iget-object v0, p0, Lw3/t;->R:Lv3/w0;

    .line 4
    .line 5
    iget-boolean v0, v0, Lv3/w0;->c:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto/16 :goto_6

    .line 10
    .line 11
    :cond_0
    sget-object v0, Lw3/m1;->f:Ley0/b;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    check-cast v0, Lw3/m1;

    .line 21
    .line 22
    invoke-virtual {v0, p2, p1, p0}, Lw3/m1;->b(ILandroid/view/View;Landroid/view/ViewGroup;)Landroid/view/View;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-ne p1, p0, :cond_2

    .line 27
    .line 28
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    check-cast v1, Lc3/l;

    .line 33
    .line 34
    iget-object v1, v1, Lc3/l;->c:Lc3/v;

    .line 35
    .line 36
    invoke-static {v1}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    if-eqz v1, :cond_1

    .line 41
    .line 42
    invoke-static {v1}, Lc3/f;->j(Lc3/v;)Ld3/c;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    goto :goto_0

    .line 47
    :cond_1
    const/4 v1, 0x0

    .line 48
    :goto_0
    if-nez v1, :cond_3

    .line 49
    .line 50
    invoke-static {p1, p0}, Lc3/f;->d(Landroid/view/View;Lw3/t;)Ld3/c;

    .line 51
    .line 52
    .line 53
    move-result-object v1

    .line 54
    goto :goto_1

    .line 55
    :cond_2
    invoke-static {p1, p0}, Lc3/f;->d(Landroid/view/View;Lw3/t;)Ld3/c;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    :cond_3
    :goto_1
    invoke-static {p2}, Lc3/f;->D(I)Lc3/d;

    .line 60
    .line 61
    .line 62
    move-result-object v2

    .line 63
    if-eqz v2, :cond_4

    .line 64
    .line 65
    iget v2, v2, Lc3/d;->a:I

    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_4
    const/4 v2, 0x6

    .line 69
    :goto_2
    new-instance v3, Lkotlin/jvm/internal/f0;

    .line 70
    .line 71
    invoke-direct {v3}, Ljava/lang/Object;-><init>()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 75
    .line 76
    .line 77
    move-result-object v4

    .line 78
    new-instance v5, Lo3/h;

    .line 79
    .line 80
    const/4 v6, 0x2

    .line 81
    invoke-direct {v5, v3, v6}, Lo3/h;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 82
    .line 83
    .line 84
    check-cast v4, Lc3/l;

    .line 85
    .line 86
    invoke-virtual {v4, v2, v1, v5}, Lc3/l;->g(ILd3/c;Lay0/k;)Ljava/lang/Boolean;

    .line 87
    .line 88
    .line 89
    move-result-object v4

    .line 90
    if-nez v4, :cond_5

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_5
    iget-object v3, v3, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 94
    .line 95
    if-nez v3, :cond_6

    .line 96
    .line 97
    if-nez v0, :cond_a

    .line 98
    .line 99
    :goto_3
    return-object p1

    .line 100
    :cond_6
    if-nez v0, :cond_7

    .line 101
    .line 102
    goto :goto_5

    .line 103
    :cond_7
    const/4 v4, 0x1

    .line 104
    if-ne v2, v4, :cond_8

    .line 105
    .line 106
    goto :goto_4

    .line 107
    :cond_8
    const/4 v4, 0x2

    .line 108
    if-ne v2, v4, :cond_9

    .line 109
    .line 110
    :goto_4
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->focusSearch(Landroid/view/View;I)Landroid/view/View;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    return-object p0

    .line 115
    :cond_9
    check-cast v3, Lc3/v;

    .line 116
    .line 117
    invoke-static {v3}, Lc3/f;->j(Lc3/v;)Ld3/c;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-static {v0, p0}, Lc3/f;->d(Landroid/view/View;Lw3/t;)Ld3/c;

    .line 122
    .line 123
    .line 124
    move-result-object p2

    .line 125
    invoke-static {p1, p2, v1, v2}, Lc3/f;->o(Ld3/c;Ld3/c;Ld3/c;I)Z

    .line 126
    .line 127
    .line 128
    move-result p1

    .line 129
    if-eqz p1, :cond_a

    .line 130
    .line 131
    :goto_5
    return-object p0

    .line 132
    :cond_a
    return-object v0

    .line 133
    :cond_b
    :goto_6
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->focusSearch(Landroid/view/View;I)Landroid/view/View;

    .line 134
    .line 135
    .line 136
    move-result-object p0

    .line 137
    return-object p0
.end method

.method public bridge synthetic getAccessibilityManager()Lw3/f;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lw3/t;->getAccessibilityManager()Lw3/g;

    move-result-object p0

    return-object p0
.end method

.method public getAccessibilityManager()Lw3/g;
    .locals 0

    .line 2
    iget-object p0, p0, Lw3/t;->x:Lw3/g;

    return-object p0
.end method

.method public final getAndroidViewsHandler$ui_release()Lw3/t0;
    .locals 2

    .line 1
    iget-object v0, p0, Lw3/t;->O:Lw3/t0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lw3/t0;

    .line 6
    .line 7
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    invoke-direct {v0, v1}, Lw3/t0;-><init>(Landroid/content/Context;)V

    .line 12
    .line 13
    .line 14
    iput-object v0, p0, Lw3/t;->O:Lw3/t0;

    .line 15
    .line 16
    const/4 v1, -0x1

    .line 17
    invoke-virtual {p0, v0, v1}, Lw3/t;->addView(Landroid/view/View;I)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 21
    .line 22
    .line 23
    :cond_0
    iget-object p0, p0, Lw3/t;->O:Lw3/t0;

    .line 24
    .line 25
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    return-object p0
.end method

.method public getAutofill()Ly2/e;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->H:Lun/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public getAutofillManager()Ly2/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->I:Ly2/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public getAutofillTree()Ly2/h;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->z:Ly2/h;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getClipboard()Lw3/c1;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lw3/t;->getClipboard()Lw3/h;

    move-result-object p0

    return-object p0
.end method

.method public getClipboard()Lw3/h;
    .locals 0

    .line 2
    iget-object p0, p0, Lw3/t;->L:Lw3/h;

    return-object p0
.end method

.method public bridge synthetic getClipboardManager()Lw3/d1;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lw3/t;->getClipboardManager()Lw3/i;

    move-result-object p0

    return-object p0
.end method

.method public getClipboardManager()Lw3/i;
    .locals 0

    .line 2
    iget-object p0, p0, Lw3/t;->K:Lw3/i;

    return-object p0
.end method

.method public final getConfigurationChangeObserver()Lay0/k;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lay0/k;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lw3/t;->G:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getContentCaptureManager$ui_release()Lz2/e;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->w:Lz2/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public getCoroutineContext()Lpx0/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->k:Lpx0/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDensity()Lt4/c;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt4/c;

    .line 8
    .line 9
    return-object p0
.end method

.method public getDragAndDropManager()La3/a;
    .locals 0

    .line 2
    iget-object p0, p0, Lw3/t;->l:La3/a;

    return-object p0
.end method

.method public bridge synthetic getDragAndDropManager()La3/c;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lw3/t;->getDragAndDropManager()La3/a;

    move-result-object p0

    return-object p0
.end method

.method public getEmbeddedViewFocusRect()Ld3/c;
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    check-cast p0, Lc3/l;

    .line 13
    .line 14
    iget-object p0, p0, Lc3/l;->c:Lc3/v;

    .line 15
    .line 16
    invoke-static {p0}, Lc3/f;->g(Lc3/v;)Lc3/v;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    invoke-static {p0}, Lc3/f;->j(Lc3/v;)Ld3/c;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    return-object p0

    .line 27
    :cond_0
    return-object v1

    .line 28
    :cond_1
    invoke-virtual {p0}, Landroid/view/View;->findFocus()Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    if-eqz v0, :cond_2

    .line 33
    .line 34
    invoke-static {v0, p0}, Lc3/f;->d(Landroid/view/View;Lw3/t;)Ld3/c;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0

    .line 39
    :cond_2
    return-object v1
.end method

.method public getFocusOwner()Lc3/j;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->j:Lc3/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getFocusedRect(Landroid/graphics/Rect;)V
    .locals 4

    .line 1
    invoke-virtual {p0}, Lw3/t;->getEmbeddedViewFocusRect()Ld3/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget p0, v0, Ld3/c;->a:F

    .line 8
    .line 9
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    iput p0, p1, Landroid/graphics/Rect;->left:I

    .line 14
    .line 15
    iget p0, v0, Ld3/c;->b:F

    .line 16
    .line 17
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    iput p0, p1, Landroid/graphics/Rect;->top:I

    .line 22
    .line 23
    iget p0, v0, Ld3/c;->c:F

    .line 24
    .line 25
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    iput p0, p1, Landroid/graphics/Rect;->right:I

    .line 30
    .line 31
    iget p0, v0, Ld3/c;->d:F

    .line 32
    .line 33
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    iput p0, p1, Landroid/graphics/Rect;->bottom:I

    .line 38
    .line 39
    return-void

    .line 40
    :cond_0
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    sget-object v1, Lw3/o;->h:Lw3/o;

    .line 45
    .line 46
    check-cast v0, Lc3/l;

    .line 47
    .line 48
    const/4 v2, 0x6

    .line 49
    const/4 v3, 0x0

    .line 50
    invoke-virtual {v0, v2, v3, v1}, Lc3/l;->g(ILd3/c;Lay0/k;)Ljava/lang/Boolean;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 55
    .line 56
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    if-nez v0, :cond_1

    .line 61
    .line 62
    const/high16 p0, -0x80000000

    .line 63
    .line 64
    invoke-virtual {p1, p0, p0, p0, p0}, Landroid/graphics/Rect;->set(IIII)V

    .line 65
    .line 66
    .line 67
    return-void

    .line 68
    :cond_1
    invoke-super {p0, p1}, Landroid/view/View;->getFocusedRect(Landroid/graphics/Rect;)V

    .line 69
    .line 70
    .line 71
    return-void
.end method

.method public getFontFamilyResolver()Lk4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->x1:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk4/m;

    .line 8
    .line 9
    return-object p0
.end method

.method public getFontLoader()Lk4/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->w1:Lw3/x0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getGraphicsContext()Le3/w;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->y:Le3/e;

    .line 2
    .line 3
    return-object p0
.end method

.method public getHapticFeedBack()Ll3/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->A1:Ll3/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public getHasPendingMeasureOrLayout()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    iget-object p0, p0, Lv3/w0;->b:Lrn/i;

    .line 4
    .line 5
    invoke-virtual {p0}, Lrn/i;->w()Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getImportantForAutofill()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public getInputModeManager()Lm3/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->B1:Lm3/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getInsetsListener()Lt3/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->p:Lt3/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLastMatrixRecalculationAnimationTime$ui_release()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lw3/t;->a0:J

    .line 2
    .line 3
    return-wide v0
.end method

.method public getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->z1:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt4/m;

    .line 8
    .line 9
    return-object p0
.end method

.method public getLayoutNodes()Landroidx/collection/b0;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Landroidx/collection/b0;"
        }
    .end annotation

    .line 2
    iget-object p0, p0, Lw3/t;->r:Landroidx/collection/b0;

    return-object p0
.end method

.method public bridge synthetic getLayoutNodes()Landroidx/collection/p;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lw3/t;->getLayoutNodes()Landroidx/collection/b0;

    move-result-object p0

    return-object p0
.end method

.method public getMeasureIteration()J
    .locals 2

    .line 1
    iget-object p0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    iget-boolean v0, p0, Lv3/w0;->c:Z

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const-string v0, "measureIteration should be only used during the measure/layout pass"

    .line 8
    .line 9
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-wide v0, p0, Lv3/w0;->g:J

    .line 13
    .line 14
    return-wide v0
.end method

.method public getModifierLocalManager()Lu3/d;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->C1:Lu3/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getOutOfFrameExecutor()Lv3/m1;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lw3/t;->getOutOfFrameExecutor()Lw3/t;

    move-result-object p0

    return-object p0
.end method

.method public getOutOfFrameExecutor()Lw3/t;
    .locals 1

    .line 2
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    move-result v0

    if-eqz v0, :cond_0

    return-object p0

    :cond_0
    const/4 p0, 0x0

    return-object p0
.end method

.method public getPlacementScope()Lt3/d1;
    .locals 2

    .line 1
    sget v0, Lt3/g1;->b:I

    .line 2
    .line 3
    new-instance v0, Lt3/n0;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-direct {v0, p0, v1}, Lt3/n0;-><init>(Ljava/lang/Object;I)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public getPointerIconService()Lp3/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->S1:Lw3/r;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRectManager()Le4/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->s:Le4/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRoot()Lv3/h0;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->q:Lv3/h0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRootForTest()Lv3/w1;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->t:Lw3/t;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getScrollCaptureInProgress$ui_release()Z
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1f

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lw3/t;->Q1:Laq/a;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Laq/a;->e:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast p0, Ll2/j1;

    .line 14
    .line 15
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Ljava/lang/Boolean;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    return p0

    .line 26
    :cond_0
    const/4 p0, 0x0

    .line 27
    return p0
.end method

.method public getSemanticsOwner()Ld4/s;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->u:Ld4/s;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSharedDrawScope()Lv3/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->f:Lv3/j0;

    .line 2
    .line 3
    return-object p0
.end method

.method public getShowLayoutBounds()Z
    .locals 2

    .line 1
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v1, 0x1e

    .line 4
    .line 5
    if-lt v0, v1, :cond_0

    .line 6
    .line 7
    sget-object v0, Lw3/u0;->a:Lw3/u0;

    .line 8
    .line 9
    invoke-virtual {v0, p0}, Lw3/u0;->a(Landroid/view/View;)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    iget-boolean p0, p0, Lw3/t;->N:Z

    .line 15
    .line 16
    return p0
.end method

.method public getSnapshotObserver()Lv3/q1;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->M:Lv3/q1;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSoftwareKeyboardController()Lw3/b2;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->v1:Lw3/i1;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTextInputService()Ll4/w;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->t1:Ll4/w;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTextToolbar()Lw3/d2;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->D1:Lw3/n0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getUncaughtExceptionHandler$ui_release()Lv3/v1;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public getView()Landroid/view/View;
    .locals 0

    .line 1
    return-object p0
.end method

.method public getViewConfiguration()Lw3/h2;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->o:Lw3/s0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getViewTreeOwners()Lw3/l;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->e0:Ll2/h0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/h0;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lw3/l;

    .line 8
    .line 9
    return-object p0
.end method

.method public getWindowInfo()Lw3/j2;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->m:Lw3/r1;

    .line 2
    .line 3
    return-object p0
.end method

.method public final get_autofillManager$ui_release()Ly2/b;
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->I:Ly2/b;

    .line 2
    .line 3
    return-object p0
.end method

.method public final h(Lay0/n;Lv3/c1;Lh3/c;)Lv3/n1;
    .locals 7

    .line 1
    if-eqz p3, :cond_0

    .line 2
    .line 3
    new-instance v0, Lw3/o1;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    move-object v3, p0

    .line 7
    move-object v4, p1

    .line 8
    move-object v5, p2

    .line 9
    move-object v1, p3

    .line 10
    invoke-direct/range {v0 .. v5}, Lw3/o1;-><init>(Lh3/c;Le3/w;Lw3/t;Lay0/n;Lay0/a;)V

    .line 11
    .line 12
    .line 13
    return-object v0

    .line 14
    :cond_0
    move-object v3, p0

    .line 15
    move-object v4, p1

    .line 16
    move-object v5, p2

    .line 17
    :cond_1
    iget-object p0, v3, Lw3/t;->G1:Lb81/b;

    .line 18
    .line 19
    iget-object p1, p0, Lb81/b;->f:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p1, Ljava/lang/ref/ReferenceQueue;

    .line 22
    .line 23
    iget-object p0, p0, Lb81/b;->e:Ljava/lang/Object;

    .line 24
    .line 25
    check-cast p0, Ln2/b;

    .line 26
    .line 27
    invoke-virtual {p1}, Ljava/lang/ref/ReferenceQueue;->poll()Ljava/lang/ref/Reference;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    if-eqz p1, :cond_2

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Ln2/b;->l(Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    :cond_2
    if-nez p1, :cond_1

    .line 37
    .line 38
    :cond_3
    iget p1, p0, Ln2/b;->f:I

    .line 39
    .line 40
    const/4 p2, 0x0

    .line 41
    if-eqz p1, :cond_4

    .line 42
    .line 43
    add-int/lit8 p1, p1, -0x1

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 46
    .line 47
    .line 48
    move-result-object p1

    .line 49
    check-cast p1, Ljava/lang/ref/Reference;

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    if-eqz p1, :cond_3

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_4
    move-object p1, p2

    .line 59
    :goto_0
    check-cast p1, Lv3/n1;

    .line 60
    .line 61
    if-eqz p1, :cond_8

    .line 62
    .line 63
    move-object p0, p1

    .line 64
    check-cast p0, Lw3/o1;

    .line 65
    .line 66
    iget-object p3, p0, Lw3/o1;->e:Le3/w;

    .line 67
    .line 68
    if-eqz p3, :cond_7

    .line 69
    .line 70
    iget-object v0, p0, Lw3/o1;->d:Lh3/c;

    .line 71
    .line 72
    iget-boolean v0, v0, Lh3/c;->s:Z

    .line 73
    .line 74
    if-nez v0, :cond_5

    .line 75
    .line 76
    const-string v0, "layer should have been released before reuse"

    .line 77
    .line 78
    invoke-static {v0}, Ls3/a;->a(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    :cond_5
    invoke-interface {p3}, Le3/w;->a()Lh3/c;

    .line 82
    .line 83
    .line 84
    move-result-object p3

    .line 85
    iput-object p3, p0, Lw3/o1;->d:Lh3/c;

    .line 86
    .line 87
    const/4 p3, 0x0

    .line 88
    iput-boolean p3, p0, Lw3/o1;->j:Z

    .line 89
    .line 90
    iput-object v4, p0, Lw3/o1;->g:Lay0/n;

    .line 91
    .line 92
    iput-object v5, p0, Lw3/o1;->h:Lay0/a;

    .line 93
    .line 94
    iput-boolean p3, p0, Lw3/o1;->t:Z

    .line 95
    .line 96
    iput-boolean p3, p0, Lw3/o1;->u:Z

    .line 97
    .line 98
    const/4 v0, 0x1

    .line 99
    iput-boolean v0, p0, Lw3/o1;->v:Z

    .line 100
    .line 101
    iget-object v0, p0, Lw3/o1;->k:[F

    .line 102
    .line 103
    invoke-static {v0}, Le3/c0;->d([F)V

    .line 104
    .line 105
    .line 106
    iget-object v0, p0, Lw3/o1;->l:[F

    .line 107
    .line 108
    if-eqz v0, :cond_6

    .line 109
    .line 110
    invoke-static {v0}, Le3/c0;->d([F)V

    .line 111
    .line 112
    .line 113
    :cond_6
    sget-wide v0, Le3/q0;->b:J

    .line 114
    .line 115
    iput-wide v0, p0, Lw3/o1;->r:J

    .line 116
    .line 117
    iput-boolean p3, p0, Lw3/o1;->w:Z

    .line 118
    .line 119
    const v0, 0x7fffffff

    .line 120
    .line 121
    .line 122
    int-to-long v0, v0

    .line 123
    const/16 v2, 0x20

    .line 124
    .line 125
    shl-long v2, v0, v2

    .line 126
    .line 127
    const-wide v4, 0xffffffffL

    .line 128
    .line 129
    .line 130
    .line 131
    .line 132
    and-long/2addr v0, v4

    .line 133
    or-long/2addr v0, v2

    .line 134
    iput-wide v0, p0, Lw3/o1;->i:J

    .line 135
    .line 136
    iput-object p2, p0, Lw3/o1;->s:Le3/g0;

    .line 137
    .line 138
    iput p3, p0, Lw3/o1;->q:I

    .line 139
    .line 140
    return-object p1

    .line 141
    :cond_7
    const-string p0, "currently reuse is only supported when we manage the layer lifecycle"

    .line 142
    .line 143
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    throw p0

    .line 148
    :cond_8
    new-instance v1, Lw3/o1;

    .line 149
    .line 150
    invoke-virtual {v3}, Lw3/t;->getGraphicsContext()Le3/w;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-interface {p0}, Le3/w;->a()Lh3/c;

    .line 155
    .line 156
    .line 157
    move-result-object v2

    .line 158
    move-object v6, v5

    .line 159
    move-object v5, v4

    .line 160
    move-object v4, v3

    .line 161
    invoke-virtual {v4}, Lw3/t;->getGraphicsContext()Le3/w;

    .line 162
    .line 163
    .line 164
    move-result-object v3

    .line 165
    invoke-direct/range {v1 .. v6}, Lw3/o1;-><init>(Lh3/c;Le3/w;Lw3/t;Lay0/n;Lay0/a;)V

    .line 166
    .line 167
    .line 168
    return-object v1
.end method

.method public final i(Lv3/h0;Z)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lv3/w0;->f(Lv3/h0;Z)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final j(Landroid/view/MotionEvent;)I
    .locals 16

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    iget-object v2, v1, Lw3/t;->K1:Lvp/g4;

    .line 6
    .line 7
    invoke-virtual {v1, v2}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 8
    .line 9
    .line 10
    const/4 v7, 0x0

    .line 11
    :try_start_0
    invoke-virtual/range {p0 .. p1}, Lw3/t;->A(Landroid/view/MotionEvent;)V

    .line 12
    .line 13
    .line 14
    const/4 v8, 0x1

    .line 15
    iput-boolean v8, v1, Lw3/t;->b0:Z

    .line 16
    .line 17
    invoke-virtual {v1, v7}, Lw3/t;->r(Z)V

    .line 18
    .line 19
    .line 20
    const-string v2, "AndroidOwner:onTouch"

    .line 21
    .line 22
    invoke-static {v2}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_2

    .line 23
    .line 24
    .line 25
    :try_start_1
    invoke-virtual {v0}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 26
    .line 27
    .line 28
    move-result v9

    .line 29
    iget-object v2, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 30
    .line 31
    const/4 v10, 0x3

    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    invoke-virtual {v2, v7}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 35
    .line 36
    .line 37
    move-result v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 38
    if-ne v3, v10, :cond_0

    .line 39
    .line 40
    move v11, v8

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    move v11, v7

    .line 43
    goto :goto_0

    .line 44
    :catchall_0
    move-exception v0

    .line 45
    goto/16 :goto_d

    .line 46
    .line 47
    :goto_0
    const/16 v12, 0xa

    .line 48
    .line 49
    iget-object v13, v1, Lw3/t;->F:Lvv0/d;

    .line 50
    .line 51
    if-eqz v2, :cond_5

    .line 52
    .line 53
    :try_start_2
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getSource()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    invoke-virtual {v0}, Landroid/view/MotionEvent;->getSource()I

    .line 58
    .line 59
    .line 60
    move-result v4

    .line 61
    if-ne v3, v4, :cond_2

    .line 62
    .line 63
    invoke-virtual {v2, v7}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    invoke-virtual {v0, v7}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 68
    .line 69
    .line 70
    move-result v4

    .line 71
    if-eq v3, v4, :cond_1

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    move v3, v7

    .line 75
    goto :goto_2

    .line 76
    :cond_2
    :goto_1
    move v3, v8

    .line 77
    :goto_2
    if-eqz v3, :cond_5

    .line 78
    .line 79
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getButtonState()I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-eqz v3, :cond_4

    .line 84
    .line 85
    :cond_3
    move-object v14, v2

    .line 86
    goto :goto_3

    .line 87
    :cond_4
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    if-eqz v3, :cond_3

    .line 92
    .line 93
    const/4 v4, 0x2

    .line 94
    if-eq v3, v4, :cond_3

    .line 95
    .line 96
    const/4 v4, 0x6

    .line 97
    if-eq v3, v4, :cond_3

    .line 98
    .line 99
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getActionMasked()I

    .line 100
    .line 101
    .line 102
    move-result v3

    .line 103
    if-eq v3, v12, :cond_5

    .line 104
    .line 105
    if-eqz v11, :cond_5

    .line 106
    .line 107
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getEventTime()J

    .line 108
    .line 109
    .line 110
    move-result-wide v4

    .line 111
    const/4 v6, 0x1

    .line 112
    const/16 v3, 0xa

    .line 113
    .line 114
    invoke-virtual/range {v1 .. v6}, Lw3/t;->F(Landroid/view/MotionEvent;IJZ)V

    .line 115
    .line 116
    .line 117
    move-object v14, v2

    .line 118
    goto :goto_4

    .line 119
    :catchall_1
    move-exception v0

    .line 120
    move-object/from16 v1, p0

    .line 121
    .line 122
    goto/16 :goto_d

    .line 123
    .line 124
    :cond_5
    move-object v14, v2

    .line 125
    goto :goto_4

    .line 126
    :goto_3
    iget-boolean v1, v13, Lvv0/d;->a:Z

    .line 127
    .line 128
    if-nez v1, :cond_6

    .line 129
    .line 130
    iget-object v1, v13, Lvv0/d;->d:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v1, Lhu/q;

    .line 133
    .line 134
    iget-object v1, v1, Lhu/q;->e:Ljava/lang/Object;

    .line 135
    .line 136
    check-cast v1, Landroidx/collection/u;

    .line 137
    .line 138
    invoke-virtual {v1}, Landroidx/collection/u;->a()V

    .line 139
    .line 140
    .line 141
    iget-object v1, v13, Lvv0/d;->c:Ljava/lang/Object;

    .line 142
    .line 143
    check-cast v1, Lp3/d;

    .line 144
    .line 145
    invoke-virtual {v1}, Lp3/d;->c()V

    .line 146
    .line 147
    .line 148
    :cond_6
    :goto_4
    invoke-virtual {v0, v7}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 149
    .line 150
    .line 151
    move-result v1

    .line 152
    if-ne v1, v10, :cond_7

    .line 153
    .line 154
    move v1, v8

    .line 155
    goto :goto_5

    .line 156
    :cond_7
    move v1, v7

    .line 157
    :goto_5
    const/16 v15, 0x9

    .line 158
    .line 159
    if-nez v11, :cond_8

    .line 160
    .line 161
    if-eqz v1, :cond_8

    .line 162
    .line 163
    if-eq v9, v10, :cond_8

    .line 164
    .line 165
    if-eq v9, v15, :cond_8

    .line 166
    .line 167
    invoke-virtual/range {p0 .. p1}, Lw3/t;->n(Landroid/view/MotionEvent;)Z

    .line 168
    .line 169
    .line 170
    move-result v1

    .line 171
    if-eqz v1, :cond_8

    .line 172
    .line 173
    invoke-virtual {v0}, Landroid/view/MotionEvent;->getEventTime()J

    .line 174
    .line 175
    .line 176
    move-result-wide v4
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 177
    const/4 v6, 0x1

    .line 178
    const/16 v3, 0x9

    .line 179
    .line 180
    move-object/from16 v1, p0

    .line 181
    .line 182
    move-object v2, v0

    .line 183
    :try_start_3
    invoke-virtual/range {v1 .. v6}, Lw3/t;->F(Landroid/view/MotionEvent;IJZ)V

    .line 184
    .line 185
    .line 186
    goto :goto_6

    .line 187
    :cond_8
    move-object/from16 v1, p0

    .line 188
    .line 189
    :goto_6
    if-eqz v14, :cond_9

    .line 190
    .line 191
    invoke-virtual {v14}, Landroid/view/MotionEvent;->recycle()V

    .line 192
    .line 193
    .line 194
    :cond_9
    iget-object v0, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 195
    .line 196
    if-eqz v0, :cond_14

    .line 197
    .line 198
    invoke-virtual {v0}, Landroid/view/MotionEvent;->getAction()I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    if-ne v0, v12, :cond_14

    .line 203
    .line 204
    iget-object v0, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 205
    .line 206
    if-eqz v0, :cond_a

    .line 207
    .line 208
    invoke-virtual {v0, v7}, Landroid/view/MotionEvent;->getPointerId(I)I

    .line 209
    .line 210
    .line 211
    move-result v0

    .line 212
    goto :goto_7

    .line 213
    :cond_a
    const/4 v0, -0x1

    .line 214
    :goto_7
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getAction()I

    .line 215
    .line 216
    .line 217
    move-result v2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 218
    iget-object v3, v1, Lw3/t;->E:Lp3/h;

    .line 219
    .line 220
    if-ne v2, v15, :cond_b

    .line 221
    .line 222
    :try_start_4
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getHistorySize()I

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    if-nez v2, :cond_b

    .line 227
    .line 228
    if-ltz v0, :cond_14

    .line 229
    .line 230
    iget-object v2, v3, Lp3/h;->e:Ljava/lang/Object;

    .line 231
    .line 232
    check-cast v2, Landroid/util/SparseBooleanArray;

    .line 233
    .line 234
    invoke-virtual {v2, v0}, Landroid/util/SparseBooleanArray;->delete(I)V

    .line 235
    .line 236
    .line 237
    iget-object v2, v3, Lp3/h;->d:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v2, Landroid/util/SparseLongArray;

    .line 240
    .line 241
    invoke-virtual {v2, v0}, Landroid/util/SparseLongArray;->delete(I)V

    .line 242
    .line 243
    .line 244
    goto/16 :goto_c

    .line 245
    .line 246
    :cond_b
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getAction()I

    .line 247
    .line 248
    .line 249
    move-result v2

    .line 250
    if-nez v2, :cond_14

    .line 251
    .line 252
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getHistorySize()I

    .line 253
    .line 254
    .line 255
    move-result v2

    .line 256
    if-nez v2, :cond_14

    .line 257
    .line 258
    iget-object v2, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 259
    .line 260
    const/high16 v4, 0x7fc00000    # Float.NaN

    .line 261
    .line 262
    if-eqz v2, :cond_c

    .line 263
    .line 264
    invoke-virtual {v2}, Landroid/view/MotionEvent;->getX()F

    .line 265
    .line 266
    .line 267
    move-result v2

    .line 268
    goto :goto_8

    .line 269
    :cond_c
    move v2, v4

    .line 270
    :goto_8
    iget-object v5, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 271
    .line 272
    if-eqz v5, :cond_d

    .line 273
    .line 274
    invoke-virtual {v5}, Landroid/view/MotionEvent;->getY()F

    .line 275
    .line 276
    .line 277
    move-result v4

    .line 278
    :cond_d
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getX()F

    .line 279
    .line 280
    .line 281
    move-result v5

    .line 282
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getY()F

    .line 283
    .line 284
    .line 285
    move-result v6

    .line 286
    cmpg-float v2, v2, v5

    .line 287
    .line 288
    if-nez v2, :cond_e

    .line 289
    .line 290
    cmpg-float v2, v4, v6

    .line 291
    .line 292
    if-nez v2, :cond_e

    .line 293
    .line 294
    move v2, v7

    .line 295
    goto :goto_9

    .line 296
    :cond_e
    move v2, v8

    .line 297
    :goto_9
    iget-object v4, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 298
    .line 299
    if-eqz v4, :cond_f

    .line 300
    .line 301
    invoke-virtual {v4}, Landroid/view/MotionEvent;->getEventTime()J

    .line 302
    .line 303
    .line 304
    move-result-wide v4

    .line 305
    goto :goto_a

    .line 306
    :cond_f
    const-wide/16 v4, -0x1

    .line 307
    .line 308
    :goto_a
    invoke-virtual/range {p1 .. p1}, Landroid/view/MotionEvent;->getEventTime()J

    .line 309
    .line 310
    .line 311
    move-result-wide v9

    .line 312
    cmp-long v4, v4, v9

    .line 313
    .line 314
    if-eqz v4, :cond_10

    .line 315
    .line 316
    move v4, v8

    .line 317
    goto :goto_b

    .line 318
    :cond_10
    move v4, v7

    .line 319
    :goto_b
    if-nez v2, :cond_11

    .line 320
    .line 321
    if-eqz v4, :cond_14

    .line 322
    .line 323
    :cond_11
    if-ltz v0, :cond_12

    .line 324
    .line 325
    iget-object v2, v3, Lp3/h;->e:Ljava/lang/Object;

    .line 326
    .line 327
    check-cast v2, Landroid/util/SparseBooleanArray;

    .line 328
    .line 329
    invoke-virtual {v2, v0}, Landroid/util/SparseBooleanArray;->delete(I)V

    .line 330
    .line 331
    .line 332
    iget-object v2, v3, Lp3/h;->d:Ljava/lang/Object;

    .line 333
    .line 334
    check-cast v2, Landroid/util/SparseLongArray;

    .line 335
    .line 336
    invoke-virtual {v2, v0}, Landroid/util/SparseLongArray;->delete(I)V

    .line 337
    .line 338
    .line 339
    :cond_12
    iget-object v0, v13, Lvv0/d;->c:Ljava/lang/Object;

    .line 340
    .line 341
    check-cast v0, Lp3/d;

    .line 342
    .line 343
    iget-boolean v2, v0, Lp3/d;->d:Z

    .line 344
    .line 345
    if-eqz v2, :cond_13

    .line 346
    .line 347
    iput-boolean v8, v0, Lp3/d;->d:Z

    .line 348
    .line 349
    goto :goto_c

    .line 350
    :cond_13
    iget-object v0, v0, Lp3/d;->g:Lp3/j;

    .line 351
    .line 352
    iget-object v0, v0, Lp3/j;->a:Ln2/b;

    .line 353
    .line 354
    invoke-virtual {v0}, Ln2/b;->i()V

    .line 355
    .line 356
    .line 357
    :cond_14
    :goto_c
    invoke-static/range {p1 .. p1}, Landroid/view/MotionEvent;->obtainNoHistory(Landroid/view/MotionEvent;)Landroid/view/MotionEvent;

    .line 358
    .line 359
    .line 360
    move-result-object v0

    .line 361
    iput-object v0, v1, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 362
    .line 363
    invoke-virtual/range {p0 .. p1}, Lw3/t;->E(Landroid/view/MotionEvent;)I

    .line 364
    .line 365
    .line 366
    move-result v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 367
    :try_start_5
    invoke-static {}, Landroid/os/Trace;->endSection()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    .line 368
    .line 369
    .line 370
    iput-boolean v7, v1, Lw3/t;->b0:Z

    .line 371
    .line 372
    return v0

    .line 373
    :catchall_2
    move-exception v0

    .line 374
    goto :goto_e

    .line 375
    :goto_d
    :try_start_6
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 376
    .line 377
    .line 378
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_2

    .line 379
    :goto_e
    iput-boolean v7, v1, Lw3/t;->b0:Z

    .line 380
    .line 381
    throw v0
.end method

.method public final l(Lv3/h0;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, p1, v1}, Lv3/w0;->p(Lv3/h0;Z)Z

    .line 5
    .line 6
    .line 7
    invoke-virtual {p1}, Lv3/h0;->z()Ln2/b;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    iget-object v0, p1, Ln2/b;->d:[Ljava/lang/Object;

    .line 12
    .line 13
    iget p1, p1, Ln2/b;->f:I

    .line 14
    .line 15
    :goto_0
    if-ge v1, p1, :cond_0

    .line 16
    .line 17
    aget-object v2, v0, v1

    .line 18
    .line 19
    check-cast v2, Lv3/h0;

    .line 20
    .line 21
    invoke-virtual {p0, v2}, Lw3/t;->l(Lv3/h0;)V

    .line 22
    .line 23
    .line 24
    add-int/lit8 v1, v1, 0x1

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    return-void
.end method

.method public final n(Landroid/view/MotionEvent;)Z
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getX()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getY()F

    .line 6
    .line 7
    .line 8
    move-result p1

    .line 9
    const/4 v1, 0x0

    .line 10
    cmpg-float v2, v1, v0

    .line 11
    .line 12
    if-gtz v2, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/view/View;->getWidth()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    int-to-float v2, v2

    .line 19
    cmpg-float v0, v0, v2

    .line 20
    .line 21
    if-gtz v0, :cond_0

    .line 22
    .line 23
    cmpg-float v0, v1, p1

    .line 24
    .line 25
    if-gtz v0, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getHeight()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-float p0, p0

    .line 32
    cmpg-float p0, p1, p0

    .line 33
    .line 34
    if-gtz p0, :cond_0

    .line 35
    .line 36
    const/4 p0, 0x1

    .line 37
    return p0

    .line 38
    :cond_0
    const/4 p0, 0x0

    .line 39
    return p0
.end method

.method public final o(Landroid/view/MotionEvent;)Z
    .locals 3

    .line 1
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    if-eq v0, v1, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    iget-object p0, p0, Lw3/t;->E1:Landroid/view/MotionEvent;

    .line 10
    .line 11
    if-eqz p0, :cond_1

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getPointerCount()I

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    if-ne v0, v2, :cond_1

    .line 22
    .line 23
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawX()F

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getRawX()F

    .line 28
    .line 29
    .line 30
    move-result v2

    .line 31
    cmpg-float v0, v0, v2

    .line 32
    .line 33
    if-nez v0, :cond_1

    .line 34
    .line 35
    invoke-virtual {p1}, Landroid/view/MotionEvent;->getRawY()F

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    invoke-virtual {p0}, Landroid/view/MotionEvent;->getRawY()F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    cmpg-float p0, p1, p0

    .line 44
    .line 45
    if-nez p0, :cond_1

    .line 46
    .line 47
    const/4 p0, 0x0

    .line 48
    return p0

    .line 49
    :cond_1
    :goto_0
    return v1
.end method

.method public final onAttachedToWindow()V
    .locals 7

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->onAttachedToWindow()V

    .line 2
    .line 3
    .line 4
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 5
    .line 6
    const/16 v1, 0x1e

    .line 7
    .line 8
    if-ge v0, v1, :cond_0

    .line 9
    .line 10
    invoke-static {}, Lw3/h0;->u()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    invoke-virtual {p0, v0}, Lw3/t;->setShowLayoutBounds(Z)V

    .line 15
    .line 16
    .line 17
    :cond_0
    iget-object v0, p0, Lw3/t;->p:Lt3/s;

    .line 18
    .line 19
    invoke-virtual {v0, p0}, Lt3/s;->onViewAttachedToWindow(Landroid/view/View;)V

    .line 20
    .line 21
    .line 22
    sget-object v0, Lw3/t;->X1:Lu/g;

    .line 23
    .line 24
    const/4 v1, 0x1

    .line 25
    const/4 v2, 0x0

    .line 26
    if-nez v0, :cond_5

    .line 27
    .line 28
    new-instance v0, Lu/g;

    .line 29
    .line 30
    invoke-direct {v0, v1}, Lu/g;-><init>(I)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lw3/t;->X1:Lu/g;

    .line 34
    .line 35
    invoke-static {}, Landroid/os/StrictMode;->getVmPolicy()Landroid/os/StrictMode$VmPolicy;

    .line 36
    .line 37
    .line 38
    move-result-object v3

    .line 39
    :try_start_0
    sget-object v4, Lw3/t;->T1:Ljava/lang/Class;

    .line 40
    .line 41
    if-nez v4, :cond_1

    .line 42
    .line 43
    const-string v4, "android.os.SystemProperties"

    .line 44
    .line 45
    invoke-static {v4}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    sput-object v4, Lw3/t;->T1:Ljava/lang/Class;

    .line 50
    .line 51
    :cond_1
    sget-object v4, Lw3/t;->V1:Ljava/lang/reflect/Method;

    .line 52
    .line 53
    if-nez v4, :cond_3

    .line 54
    .line 55
    sget-object v4, Landroid/os/StrictMode$VmPolicy;->LAX:Landroid/os/StrictMode$VmPolicy;

    .line 56
    .line 57
    invoke-static {v4}, Landroid/os/StrictMode;->setVmPolicy(Landroid/os/StrictMode$VmPolicy;)V

    .line 58
    .line 59
    .line 60
    sget-object v4, Lw3/t;->T1:Ljava/lang/Class;

    .line 61
    .line 62
    if-eqz v4, :cond_2

    .line 63
    .line 64
    const-string v5, "addChangeCallback"

    .line 65
    .line 66
    const-class v6, Ljava/lang/Runnable;

    .line 67
    .line 68
    filled-new-array {v6}, [Ljava/lang/Class;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    invoke-virtual {v4, v5, v6}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    goto :goto_0

    .line 77
    :cond_2
    move-object v4, v2

    .line 78
    :goto_0
    sput-object v4, Lw3/t;->V1:Ljava/lang/reflect/Method;

    .line 79
    .line 80
    :cond_3
    sget-object v4, Lw3/t;->V1:Ljava/lang/reflect/Method;

    .line 81
    .line 82
    if-eqz v4, :cond_4

    .line 83
    .line 84
    filled-new-array {v0}, [Ljava/lang/Object;

    .line 85
    .line 86
    .line 87
    move-result-object v0

    .line 88
    invoke-virtual {v4, v2, v0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 89
    .line 90
    .line 91
    :catchall_0
    :cond_4
    invoke-static {v3}, Landroid/os/StrictMode;->setVmPolicy(Landroid/os/StrictMode$VmPolicy;)V

    .line 92
    .line 93
    .line 94
    :cond_5
    sget-object v0, Lw3/t;->W1:Landroidx/collection/l0;

    .line 95
    .line 96
    monitor-enter v0

    .line 97
    :try_start_1
    invoke-virtual {v0, p0}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 98
    .line 99
    .line 100
    monitor-exit v0

    .line 101
    iget-object v0, p0, Lw3/t;->m:Lw3/r1;

    .line 102
    .line 103
    invoke-virtual {p0}, Landroid/view/View;->hasWindowFocus()Z

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    iget-object v0, v0, Lw3/r1;->c:Ll2/j1;

    .line 108
    .line 109
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 110
    .line 111
    .line 112
    move-result-object v3

    .line 113
    invoke-virtual {v0, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 114
    .line 115
    .line 116
    iget-object v0, p0, Lw3/t;->m:Lw3/r1;

    .line 117
    .line 118
    new-instance v3, Lw3/q;

    .line 119
    .line 120
    const/4 v4, 0x0

    .line 121
    invoke-direct {v3, p0, v4}, Lw3/q;-><init>(Lw3/t;I)V

    .line 122
    .line 123
    .line 124
    iget-object v4, v0, Lw3/r1;->b:Ll2/j1;

    .line 125
    .line 126
    if-nez v4, :cond_6

    .line 127
    .line 128
    iput-object v3, v0, Lw3/r1;->a:Lay0/a;

    .line 129
    .line 130
    :cond_6
    if-eqz v4, :cond_7

    .line 131
    .line 132
    invoke-static {p0}, Lw3/h0;->l(Lw3/t;)J

    .line 133
    .line 134
    .line 135
    move-result-wide v5

    .line 136
    new-instance v0, Lt4/l;

    .line 137
    .line 138
    invoke-direct {v0, v5, v6}, Lt4/l;-><init>(J)V

    .line 139
    .line 140
    .line 141
    invoke-virtual {v4, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 142
    .line 143
    .line 144
    :cond_7
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 145
    .line 146
    .line 147
    move-result-object v0

    .line 148
    invoke-virtual {p0, v0}, Lw3/t;->l(Lv3/h0;)V

    .line 149
    .line 150
    .line 151
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 152
    .line 153
    .line 154
    move-result-object v0

    .line 155
    invoke-static {v0}, Lw3/t;->k(Lv3/h0;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 159
    .line 160
    .line 161
    move-result-object v0

    .line 162
    iget-object v0, v0, Lv3/q1;->a:Lv2/r;

    .line 163
    .line 164
    invoke-virtual {v0}, Lv2/r;->e()V

    .line 165
    .line 166
    .line 167
    iget-object v0, p0, Lw3/t;->H:Lun/a;

    .line 168
    .line 169
    if-eqz v0, :cond_8

    .line 170
    .line 171
    sget-object v3, Ly2/f;->a:Ly2/f;

    .line 172
    .line 173
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 174
    .line 175
    .line 176
    iget-object v0, v0, Lun/a;->g:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v0, Landroid/view/autofill/AutofillManager;

    .line 179
    .line 180
    invoke-virtual {v0, v3}, Landroid/view/autofill/AutofillManager;->registerCallback(Landroid/view/autofill/AutofillManager$AutofillCallback;)V

    .line 181
    .line 182
    .line 183
    :cond_8
    invoke-static {p0}, Landroidx/lifecycle/v0;->d(Landroid/view/View;)Landroidx/lifecycle/x;

    .line 184
    .line 185
    .line 186
    move-result-object v0

    .line 187
    invoke-static {p0}, Lkp/w;->b(Landroid/view/View;)Lra/f;

    .line 188
    .line 189
    .line 190
    move-result-object v3

    .line 191
    invoke-virtual {p0}, Lw3/t;->getViewTreeOwners()Lw3/l;

    .line 192
    .line 193
    .line 194
    move-result-object v4

    .line 195
    if-eqz v4, :cond_9

    .line 196
    .line 197
    if-eqz v0, :cond_c

    .line 198
    .line 199
    if-eqz v3, :cond_c

    .line 200
    .line 201
    iget-object v5, v4, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 202
    .line 203
    if-ne v0, v5, :cond_9

    .line 204
    .line 205
    if-eq v3, v5, :cond_c

    .line 206
    .line 207
    :cond_9
    if-eqz v0, :cond_13

    .line 208
    .line 209
    if-eqz v3, :cond_12

    .line 210
    .line 211
    if-eqz v4, :cond_a

    .line 212
    .line 213
    iget-object v4, v4, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 214
    .line 215
    invoke-interface {v4}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 216
    .line 217
    .line 218
    move-result-object v4

    .line 219
    if-eqz v4, :cond_a

    .line 220
    .line 221
    invoke-virtual {v4, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 222
    .line 223
    .line 224
    :cond_a
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 225
    .line 226
    .line 227
    move-result-object v4

    .line 228
    invoke-virtual {v4, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 229
    .line 230
    .line 231
    new-instance v4, Lw3/l;

    .line 232
    .line 233
    invoke-direct {v4, v0, v3}, Lw3/l;-><init>(Landroidx/lifecycle/x;Lra/f;)V

    .line 234
    .line 235
    .line 236
    invoke-direct {p0, v4}, Lw3/t;->set_viewTreeOwners(Lw3/l;)V

    .line 237
    .line 238
    .line 239
    iget-object v0, p0, Lw3/t;->f0:Lay0/k;

    .line 240
    .line 241
    if-eqz v0, :cond_b

    .line 242
    .line 243
    invoke-interface {v0, v4}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    :cond_b
    iput-object v2, p0, Lw3/t;->f0:Lay0/k;

    .line 247
    .line 248
    :cond_c
    iget-object v0, p0, Lw3/t;->B1:Lm3/c;

    .line 249
    .line 250
    invoke-virtual {p0}, Landroid/view/View;->isInTouchMode()Z

    .line 251
    .line 252
    .line 253
    move-result v3

    .line 254
    if-eqz v3, :cond_d

    .line 255
    .line 256
    goto :goto_1

    .line 257
    :cond_d
    const/4 v1, 0x2

    .line 258
    :goto_1
    iget-object v0, v0, Lm3/c;->a:Ll2/j1;

    .line 259
    .line 260
    new-instance v3, Lm3/a;

    .line 261
    .line 262
    invoke-direct {v3, v1}, Lm3/a;-><init>(I)V

    .line 263
    .line 264
    .line 265
    invoke-virtual {v0, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    invoke-virtual {p0}, Lw3/t;->getViewTreeOwners()Lw3/l;

    .line 269
    .line 270
    .line 271
    move-result-object v0

    .line 272
    if-eqz v0, :cond_e

    .line 273
    .line 274
    iget-object v0, v0, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 275
    .line 276
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 277
    .line 278
    .line 279
    move-result-object v2

    .line 280
    :cond_e
    if-eqz v2, :cond_11

    .line 281
    .line 282
    invoke-virtual {v2, p0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 283
    .line 284
    .line 285
    iget-object v0, p0, Lw3/t;->w:Lz2/e;

    .line 286
    .line 287
    invoke-virtual {v2, v0}, Landroidx/lifecycle/r;->a(Landroidx/lifecycle/w;)V

    .line 288
    .line 289
    .line 290
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 291
    .line 292
    .line 293
    move-result-object v0

    .line 294
    iget-object v1, p0, Lw3/t;->g0:Lq61/l;

    .line 295
    .line 296
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->addOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 297
    .line 298
    .line 299
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 300
    .line 301
    .line 302
    move-result-object v0

    .line 303
    iget-object v1, p0, Lw3/t;->q1:Lw3/j;

    .line 304
    .line 305
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->addOnScrollChangedListener(Landroid/view/ViewTreeObserver$OnScrollChangedListener;)V

    .line 306
    .line 307
    .line 308
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 309
    .line 310
    .line 311
    move-result-object v0

    .line 312
    iget-object v1, p0, Lw3/t;->r1:Lw3/k;

    .line 313
    .line 314
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->addOnTouchModeChangeListener(Landroid/view/ViewTreeObserver$OnTouchModeChangeListener;)V

    .line 315
    .line 316
    .line 317
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 318
    .line 319
    const/16 v1, 0x1f

    .line 320
    .line 321
    if-lt v0, v1, :cond_f

    .line 322
    .line 323
    sget-object v0, Lw3/e0;->a:Lw3/e0;

    .line 324
    .line 325
    invoke-virtual {v0, p0}, Lw3/e0;->b(Landroid/view/View;)V

    .line 326
    .line 327
    .line 328
    :cond_f
    iget-object v0, p0, Lw3/t;->I:Ly2/b;

    .line 329
    .line 330
    if-eqz v0, :cond_10

    .line 331
    .line 332
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 333
    .line 334
    .line 335
    move-result-object v1

    .line 336
    check-cast v1, Lc3/l;

    .line 337
    .line 338
    iget-object v1, v1, Lc3/l;->g:Landroidx/collection/l0;

    .line 339
    .line 340
    invoke-virtual {v1, v0}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 341
    .line 342
    .line 343
    invoke-virtual {p0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 344
    .line 345
    .line 346
    move-result-object p0

    .line 347
    iget-object p0, p0, Ld4/s;->d:Landroidx/collection/l0;

    .line 348
    .line 349
    invoke-virtual {p0, v0}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 350
    .line 351
    .line 352
    :cond_10
    return-void

    .line 353
    :cond_11
    const-string p0, "No lifecycle owner exists"

    .line 354
    .line 355
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 356
    .line 357
    .line 358
    move-result-object p0

    .line 359
    throw p0

    .line 360
    :cond_12
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 361
    .line 362
    const-string v0, "Composed into the View which doesn\'t propagateViewTreeSavedStateRegistryOwner!"

    .line 363
    .line 364
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    throw p0

    .line 368
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 369
    .line 370
    const-string v0, "Composed into the View which doesn\'t propagate ViewTreeLifecycleOwner!"

    .line 371
    .line 372
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 373
    .line 374
    .line 375
    throw p0

    .line 376
    :catchall_1
    move-exception p0

    .line 377
    monitor-exit v0

    .line 378
    throw p0
.end method

.method public final onCheckIsTextEditor()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lw3/t;->u1:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lx2/u;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, v0, Lx2/u;->b:Ljava/lang/Object;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v1

    .line 16
    :goto_0
    check-cast v0, Lw3/m0;

    .line 17
    .line 18
    if-nez v0, :cond_1

    .line 19
    .line 20
    iget-object p0, p0, Lw3/t;->s1:Ll4/y;

    .line 21
    .line 22
    iget-boolean p0, p0, Ll4/y;->d:Z

    .line 23
    .line 24
    return p0

    .line 25
    :cond_1
    iget-object p0, v0, Lw3/m0;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 26
    .line 27
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lx2/u;

    .line 32
    .line 33
    if-eqz p0, :cond_2

    .line 34
    .line 35
    iget-object v1, p0, Lx2/u;->b:Ljava/lang/Object;

    .line 36
    .line 37
    :cond_2
    check-cast v1, Lw3/p1;

    .line 38
    .line 39
    if-eqz v1, :cond_3

    .line 40
    .line 41
    iget-boolean p0, v1, Lw3/p1;->e:Z

    .line 42
    .line 43
    const/4 v0, 0x1

    .line 44
    xor-int/2addr p0, v0

    .line 45
    if-ne p0, v0, :cond_3

    .line 46
    .line 47
    return v0

    .line 48
    :cond_3
    const/4 p0, 0x0

    .line 49
    return p0
.end method

.method public final onConfigurationChanged(Landroid/content/res/Configuration;)V
    .locals 5

    .line 1
    invoke-super {p0, p1}, Landroid/view/View;->onConfigurationChanged(Landroid/content/res/Configuration;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    invoke-static {v0}, Lkp/z8;->a(Landroid/content/Context;)Lt4/e;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-direct {p0, v0}, Lw3/t;->setDensity(Lt4/c;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, p0, Lw3/t;->m:Lw3/r1;

    .line 16
    .line 17
    iget-object v0, v0, Lw3/r1;->b:Ll2/j1;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-static {p0}, Lw3/h0;->l(Lw3/t;)J

    .line 22
    .line 23
    .line 24
    move-result-wide v1

    .line 25
    new-instance v3, Lt4/l;

    .line 26
    .line 27
    invoke-direct {v3, v1, v2}, Lt4/l;-><init>(J)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0, v3}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    :cond_0
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    const/16 v2, 0x1f

    .line 37
    .line 38
    if-lt v0, v2, :cond_1

    .line 39
    .line 40
    invoke-static {p1}, Lh4/b;->a(Landroid/content/res/Configuration;)I

    .line 41
    .line 42
    .line 43
    move-result v3

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    move v3, v1

    .line 46
    :goto_0
    iget v4, p0, Lw3/t;->y1:I

    .line 47
    .line 48
    if-eq v3, v4, :cond_3

    .line 49
    .line 50
    if-lt v0, v2, :cond_2

    .line 51
    .line 52
    invoke-static {p1}, Lh4/b;->a(Landroid/content/res/Configuration;)I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    :cond_2
    iput v1, p0, Lw3/t;->y1:I

    .line 57
    .line 58
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-static {v0}, Llp/wc;->a(Landroid/content/Context;)Lk4/o;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-direct {p0, v0}, Lw3/t;->setFontFamilyResolver(Lk4/m;)V

    .line 67
    .line 68
    .line 69
    :cond_3
    iget-object p0, p0, Lw3/t;->G:Lay0/k;

    .line 70
    .line 71
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    return-void
.end method

.method public final onCreateInputConnection(Landroid/view/inputmethod/EditorInfo;)Landroid/view/inputmethod/InputConnection;
    .locals 13

    .line 1
    iget-object v0, p0, Lw3/t;->u1:Ljava/util/concurrent/atomic/AtomicReference;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lx2/u;

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    iget-object v0, v0, Lx2/u;->b:Ljava/lang/Object;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    move-object v0, v1

    .line 16
    :goto_0
    check-cast v0, Lw3/m0;

    .line 17
    .line 18
    const/4 v2, 0x5

    .line 19
    if-nez v0, :cond_1a

    .line 20
    .line 21
    iget-object p0, p0, Lw3/t;->s1:Ll4/y;

    .line 22
    .line 23
    iget-boolean v0, p0, Ll4/y;->d:Z

    .line 24
    .line 25
    if-nez v0, :cond_1

    .line 26
    .line 27
    goto/16 :goto_8

    .line 28
    .line 29
    :cond_1
    iget-object v0, p0, Ll4/y;->h:Ll4/j;

    .line 30
    .line 31
    iget-object v1, p0, Ll4/y;->g:Ll4/v;

    .line 32
    .line 33
    iget v3, v0, Ll4/j;->e:I

    .line 34
    .line 35
    iget-boolean v4, v0, Ll4/j;->a:Z

    .line 36
    .line 37
    const/4 v5, 0x1

    .line 38
    const/4 v6, 0x4

    .line 39
    const/4 v7, 0x7

    .line 40
    const/4 v8, 0x6

    .line 41
    const/4 v9, 0x3

    .line 42
    const/4 v10, 0x2

    .line 43
    if-ne v3, v5, :cond_3

    .line 44
    .line 45
    if-eqz v4, :cond_2

    .line 46
    .line 47
    :goto_1
    move v11, v8

    .line 48
    goto :goto_2

    .line 49
    :cond_2
    const/4 v11, 0x0

    .line 50
    goto :goto_2

    .line 51
    :cond_3
    if-nez v3, :cond_4

    .line 52
    .line 53
    move v11, v5

    .line 54
    goto :goto_2

    .line 55
    :cond_4
    if-ne v3, v10, :cond_5

    .line 56
    .line 57
    move v11, v10

    .line 58
    goto :goto_2

    .line 59
    :cond_5
    if-ne v3, v8, :cond_6

    .line 60
    .line 61
    move v11, v2

    .line 62
    goto :goto_2

    .line 63
    :cond_6
    if-ne v3, v2, :cond_7

    .line 64
    .line 65
    move v11, v7

    .line 66
    goto :goto_2

    .line 67
    :cond_7
    if-ne v3, v9, :cond_8

    .line 68
    .line 69
    move v11, v9

    .line 70
    goto :goto_2

    .line 71
    :cond_8
    if-ne v3, v6, :cond_9

    .line 72
    .line 73
    move v11, v6

    .line 74
    goto :goto_2

    .line 75
    :cond_9
    if-ne v3, v7, :cond_19

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :goto_2
    iput v11, p1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    .line 79
    .line 80
    iget v12, v0, Ll4/j;->d:I

    .line 81
    .line 82
    if-ne v12, v5, :cond_a

    .line 83
    .line 84
    iput v5, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_a
    if-ne v12, v10, :cond_b

    .line 88
    .line 89
    iput v5, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 90
    .line 91
    const/high16 v2, -0x80000000

    .line 92
    .line 93
    or-int/2addr v2, v11

    .line 94
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    .line 95
    .line 96
    goto :goto_3

    .line 97
    :cond_b
    if-ne v12, v9, :cond_c

    .line 98
    .line 99
    iput v10, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 100
    .line 101
    goto :goto_3

    .line 102
    :cond_c
    if-ne v12, v6, :cond_d

    .line 103
    .line 104
    iput v9, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 105
    .line 106
    goto :goto_3

    .line 107
    :cond_d
    if-ne v12, v2, :cond_e

    .line 108
    .line 109
    const/16 v2, 0x11

    .line 110
    .line 111
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_e
    if-ne v12, v8, :cond_f

    .line 115
    .line 116
    const/16 v2, 0x21

    .line 117
    .line 118
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_f
    if-ne v12, v7, :cond_10

    .line 122
    .line 123
    const/16 v2, 0x81

    .line 124
    .line 125
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 126
    .line 127
    goto :goto_3

    .line 128
    :cond_10
    const/16 v2, 0x8

    .line 129
    .line 130
    if-ne v12, v2, :cond_11

    .line 131
    .line 132
    const/16 v2, 0x12

    .line 133
    .line 134
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 135
    .line 136
    goto :goto_3

    .line 137
    :cond_11
    const/16 v2, 0x9

    .line 138
    .line 139
    if-ne v12, v2, :cond_18

    .line 140
    .line 141
    const/16 v2, 0x2002

    .line 142
    .line 143
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 144
    .line 145
    :goto_3
    if-nez v4, :cond_12

    .line 146
    .line 147
    iget v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 148
    .line 149
    and-int/lit8 v4, v2, 0x1

    .line 150
    .line 151
    if-ne v4, v5, :cond_12

    .line 152
    .line 153
    const/high16 v4, 0x20000

    .line 154
    .line 155
    or-int/2addr v2, v4

    .line 156
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 157
    .line 158
    if-ne v3, v5, :cond_12

    .line 159
    .line 160
    iget v2, p1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    .line 161
    .line 162
    const/high16 v3, 0x40000000    # 2.0f

    .line 163
    .line 164
    or-int/2addr v2, v3

    .line 165
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    .line 166
    .line 167
    :cond_12
    iget v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 168
    .line 169
    and-int/lit8 v3, v2, 0x1

    .line 170
    .line 171
    if-ne v3, v5, :cond_16

    .line 172
    .line 173
    iget v3, v0, Ll4/j;->b:I

    .line 174
    .line 175
    if-ne v3, v5, :cond_13

    .line 176
    .line 177
    or-int/lit16 v2, v2, 0x1000

    .line 178
    .line 179
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 180
    .line 181
    goto :goto_4

    .line 182
    :cond_13
    if-ne v3, v10, :cond_14

    .line 183
    .line 184
    or-int/lit16 v2, v2, 0x2000

    .line 185
    .line 186
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 187
    .line 188
    goto :goto_4

    .line 189
    :cond_14
    if-ne v3, v9, :cond_15

    .line 190
    .line 191
    or-int/lit16 v2, v2, 0x4000

    .line 192
    .line 193
    iput v2, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 194
    .line 195
    :cond_15
    :goto_4
    iget-boolean v0, v0, Ll4/j;->c:Z

    .line 196
    .line 197
    if-eqz v0, :cond_16

    .line 198
    .line 199
    iget v0, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 200
    .line 201
    const v2, 0x8000

    .line 202
    .line 203
    .line 204
    or-int/2addr v0, v2

    .line 205
    iput v0, p1, Landroid/view/inputmethod/EditorInfo;->inputType:I

    .line 206
    .line 207
    :cond_16
    iget-wide v2, v1, Ll4/v;->b:J

    .line 208
    .line 209
    sget v0, Lg4/o0;->c:I

    .line 210
    .line 211
    const/16 v0, 0x20

    .line 212
    .line 213
    shr-long v4, v2, v0

    .line 214
    .line 215
    long-to-int v0, v4

    .line 216
    iput v0, p1, Landroid/view/inputmethod/EditorInfo;->initialSelStart:I

    .line 217
    .line 218
    const-wide v4, 0xffffffffL

    .line 219
    .line 220
    .line 221
    .line 222
    .line 223
    and-long/2addr v2, v4

    .line 224
    long-to-int v0, v2

    .line 225
    iput v0, p1, Landroid/view/inputmethod/EditorInfo;->initialSelEnd:I

    .line 226
    .line 227
    iget-object v0, v1, Ll4/v;->a:Lg4/g;

    .line 228
    .line 229
    iget-object v0, v0, Lg4/g;->e:Ljava/lang/String;

    .line 230
    .line 231
    invoke-static {p1, v0}, Lkp/i7;->b(Landroid/view/inputmethod/EditorInfo;Ljava/lang/CharSequence;)V

    .line 232
    .line 233
    .line 234
    iget v0, p1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    .line 235
    .line 236
    const/high16 v1, 0x2000000

    .line 237
    .line 238
    or-int/2addr v0, v1

    .line 239
    iput v0, p1, Landroid/view/inputmethod/EditorInfo;->imeOptions:I

    .line 240
    .line 241
    invoke-static {}, Ls6/h;->d()Z

    .line 242
    .line 243
    .line 244
    move-result v0

    .line 245
    if-nez v0, :cond_17

    .line 246
    .line 247
    goto :goto_5

    .line 248
    :cond_17
    invoke-static {}, Ls6/h;->a()Ls6/h;

    .line 249
    .line 250
    .line 251
    move-result-object v0

    .line 252
    invoke-virtual {v0, p1}, Ls6/h;->i(Landroid/view/inputmethod/EditorInfo;)V

    .line 253
    .line 254
    .line 255
    :goto_5
    iget-object p1, p0, Ll4/y;->g:Ll4/v;

    .line 256
    .line 257
    iget-object v0, p0, Ll4/y;->h:Ll4/j;

    .line 258
    .line 259
    iget-boolean v0, v0, Ll4/j;->c:Z

    .line 260
    .line 261
    new-instance v1, Lj1/a;

    .line 262
    .line 263
    const/16 v2, 0xa

    .line 264
    .line 265
    invoke-direct {v1, p0, v2}, Lj1/a;-><init>(Ljava/lang/Object;I)V

    .line 266
    .line 267
    .line 268
    new-instance v2, Ll4/r;

    .line 269
    .line 270
    invoke-direct {v2, p1, v1, v0}, Ll4/r;-><init>(Ll4/v;Lj1/a;Z)V

    .line 271
    .line 272
    .line 273
    iget-object p0, p0, Ll4/y;->i:Ljava/util/ArrayList;

    .line 274
    .line 275
    new-instance p1, Ljava/lang/ref/WeakReference;

    .line 276
    .line 277
    invoke-direct {p1, v2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    return-object v2

    .line 284
    :cond_18
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 285
    .line 286
    const-string p1, "Invalid Keyboard Type"

    .line 287
    .line 288
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 289
    .line 290
    .line 291
    throw p0

    .line 292
    :cond_19
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 293
    .line 294
    const-string p1, "invalid ImeAction"

    .line 295
    .line 296
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    throw p0

    .line 300
    :cond_1a
    iget-object p0, v0, Lw3/m0;->g:Ljava/util/concurrent/atomic/AtomicReference;

    .line 301
    .line 302
    invoke-virtual {p0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    check-cast p0, Lx2/u;

    .line 307
    .line 308
    if-eqz p0, :cond_1b

    .line 309
    .line 310
    iget-object p0, p0, Lx2/u;->b:Ljava/lang/Object;

    .line 311
    .line 312
    goto :goto_6

    .line 313
    :cond_1b
    move-object p0, v1

    .line 314
    :goto_6
    check-cast p0, Lw3/p1;

    .line 315
    .line 316
    if-eqz p0, :cond_1e

    .line 317
    .line 318
    iget-object v0, p0, Lw3/p1;->c:Ljava/lang/Object;

    .line 319
    .line 320
    monitor-enter v0

    .line 321
    :try_start_0
    iget-boolean v3, p0, Lw3/p1;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 322
    .line 323
    if-eqz v3, :cond_1c

    .line 324
    .line 325
    monitor-exit v0

    .line 326
    return-object v1

    .line 327
    :cond_1c
    :try_start_1
    iget-object v1, p0, Lw3/p1;->a:Lc2/p;

    .line 328
    .line 329
    invoke-virtual {v1, p1}, Lc2/p;->a(Landroid/view/inputmethod/EditorInfo;)Lc2/q;

    .line 330
    .line 331
    .line 332
    move-result-object p1

    .line 333
    new-instance v1, Lw3/a0;

    .line 334
    .line 335
    invoke-direct {v1, p0, v2}, Lw3/a0;-><init>(Ljava/lang/Object;I)V

    .line 336
    .line 337
    .line 338
    sget v2, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 339
    .line 340
    const/16 v3, 0x22

    .line 341
    .line 342
    if-lt v2, v3, :cond_1d

    .line 343
    .line 344
    new-instance v2, Ll4/n;

    .line 345
    .line 346
    invoke-direct {v2, p1, v1}, Ll4/m;-><init>(Lc2/q;Lw3/a0;)V

    .line 347
    .line 348
    .line 349
    goto :goto_7

    .line 350
    :cond_1d
    new-instance v2, Ll4/m;

    .line 351
    .line 352
    invoke-direct {v2, p1, v1}, Ll4/m;-><init>(Lc2/q;Lw3/a0;)V

    .line 353
    .line 354
    .line 355
    :goto_7
    iget-object p0, p0, Lw3/p1;->d:Ln2/b;

    .line 356
    .line 357
    new-instance p1, Lv3/e2;

    .line 358
    .line 359
    invoke-direct {p1, v2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 360
    .line 361
    .line 362
    invoke-virtual {p0, p1}, Ln2/b;->c(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 363
    .line 364
    .line 365
    monitor-exit v0

    .line 366
    return-object v2

    .line 367
    :catchall_0
    move-exception p0

    .line 368
    monitor-exit v0

    .line 369
    throw p0

    .line 370
    :cond_1e
    :goto_8
    return-object v1
.end method

.method public final onCreateVirtualViewTranslationRequests([J[ILjava/util/function/Consumer;)V
    .locals 6

    .line 1
    iget-object p0, p0, Lw3/t;->w:Lz2/e;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    array-length p2, p1

    .line 7
    const/4 v0, 0x0

    .line 8
    :goto_0
    if-ge v0, p2, :cond_3

    .line 9
    .line 10
    aget-wide v1, p1, v0

    .line 11
    .line 12
    invoke-virtual {p0}, Lz2/e;->d()Landroidx/collection/p;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    long-to-int v1, v1

    .line 17
    invoke-virtual {v3, v1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    check-cast v1, Ld4/r;

    .line 22
    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    iget-object v1, v1, Ld4/r;->a:Ld4/q;

    .line 26
    .line 27
    if-nez v1, :cond_0

    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
    invoke-static {}, Lh4/b;->o()V

    .line 31
    .line 32
    .line 33
    iget-object v2, p0, Lz2/e;->d:Lw3/t;

    .line 34
    .line 35
    invoke-virtual {v2}, Landroid/view/View;->getAutofillId()Landroid/view/autofill/AutofillId;

    .line 36
    .line 37
    .line 38
    move-result-object v2

    .line 39
    iget v3, v1, Ld4/q;->g:I

    .line 40
    .line 41
    int-to-long v3, v3

    .line 42
    invoke-static {v2, v3, v4}, Lh4/b;->l(Landroid/view/autofill/AutofillId;J)Landroid/view/translation/ViewTranslationRequest$Builder;

    .line 43
    .line 44
    .line 45
    move-result-object v2

    .line 46
    iget-object v1, v1, Ld4/q;->d:Ld4/l;

    .line 47
    .line 48
    sget-object v3, Ld4/v;->A:Ld4/z;

    .line 49
    .line 50
    iget-object v1, v1, Ld4/l;->d:Landroidx/collection/q0;

    .line 51
    .line 52
    invoke-virtual {v1, v3}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    const/4 v3, 0x0

    .line 57
    if-nez v1, :cond_1

    .line 58
    .line 59
    move-object v1, v3

    .line 60
    :cond_1
    check-cast v1, Ljava/util/List;

    .line 61
    .line 62
    if-eqz v1, :cond_2

    .line 63
    .line 64
    const-string v4, "\n"

    .line 65
    .line 66
    const/16 v5, 0x3e

    .line 67
    .line 68
    invoke-static {v1, v4, v3, v5}, Lv4/a;->a(Ljava/util/List;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    if-eqz v1, :cond_2

    .line 73
    .line 74
    new-instance v3, Lg4/g;

    .line 75
    .line 76
    invoke-direct {v3, v1}, Lg4/g;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    invoke-static {v3}, Lh4/b;->k(Lg4/g;)Landroid/view/translation/TranslationRequestValue;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    invoke-static {v2, v1}, Lz2/c;->e(Landroid/view/translation/ViewTranslationRequest$Builder;Landroid/view/translation/TranslationRequestValue;)V

    .line 84
    .line 85
    .line 86
    invoke-static {v2}, Lz2/c;->b(Landroid/view/translation/ViewTranslationRequest$Builder;)Landroid/view/translation/ViewTranslationRequest;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-interface {p3, v1}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    :cond_2
    :goto_1
    add-int/lit8 v0, v0, 0x1

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_3
    return-void
.end method

.method public final onDetachedFromWindow()V
    .locals 3

    .line 1
    invoke-super {p0}, Landroid/view/ViewGroup;->onDetachedFromWindow()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lw3/t;->p:Lt3/s;

    .line 5
    .line 6
    invoke-virtual {v0, p0}, Lt3/s;->onViewDetachedFromWindow(Landroid/view/View;)V

    .line 7
    .line 8
    .line 9
    iget-boolean v0, p0, Lw3/t;->i:Z

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object v0, p0, Lw3/t;->h:Landroid/view/View;

    .line 15
    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    invoke-virtual {p0, v0}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const-string p0, "frameRateCategoryView"

    .line 23
    .line 24
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw v1

    .line 28
    :cond_1
    :goto_0
    sget-object v0, Lw3/t;->W1:Landroidx/collection/l0;

    .line 29
    .line 30
    monitor-enter v0

    .line 31
    :try_start_0
    invoke-virtual {v0, p0}, Landroidx/collection/l0;->i(Ljava/lang/Object;)Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 32
    .line 33
    .line 34
    monitor-exit v0

    .line 35
    invoke-virtual {p0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    iget-object v0, v0, Lv3/q1;->a:Lv2/r;

    .line 40
    .line 41
    iget-object v2, v0, Lv2/r;->h:Lrx/b;

    .line 42
    .line 43
    if-eqz v2, :cond_2

    .line 44
    .line 45
    invoke-virtual {v2}, Lrx/b;->d()V

    .line 46
    .line 47
    .line 48
    :cond_2
    invoke-virtual {v0}, Lv2/r;->a()V

    .line 49
    .line 50
    .line 51
    iget-object v0, p0, Lw3/t;->m:Lw3/r1;

    .line 52
    .line 53
    iget-object v2, v0, Lw3/r1;->b:Ll2/j1;

    .line 54
    .line 55
    if-nez v2, :cond_3

    .line 56
    .line 57
    iput-object v1, v0, Lw3/r1;->a:Lay0/a;

    .line 58
    .line 59
    :cond_3
    invoke-virtual {p0}, Lw3/t;->getViewTreeOwners()Lw3/l;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-eqz v0, :cond_4

    .line 64
    .line 65
    iget-object v0, v0, Lw3/l;->a:Landroidx/lifecycle/x;

    .line 66
    .line 67
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    :cond_4
    if-eqz v1, :cond_8

    .line 72
    .line 73
    iget-object v0, p0, Lw3/t;->w:Lz2/e;

    .line 74
    .line 75
    invoke-virtual {v1, v0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {v1, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 79
    .line 80
    .line 81
    iget-object v0, p0, Lw3/t;->H:Lun/a;

    .line 82
    .line 83
    if-eqz v0, :cond_5

    .line 84
    .line 85
    sget-object v1, Ly2/f;->a:Ly2/f;

    .line 86
    .line 87
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 88
    .line 89
    .line 90
    iget-object v0, v0, Lun/a;->g:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v0, Landroid/view/autofill/AutofillManager;

    .line 93
    .line 94
    invoke-virtual {v0, v1}, Landroid/view/autofill/AutofillManager;->unregisterCallback(Landroid/view/autofill/AutofillManager$AutofillCallback;)V

    .line 95
    .line 96
    .line 97
    :cond_5
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    iget-object v1, p0, Lw3/t;->g0:Lq61/l;

    .line 102
    .line 103
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeOnGlobalLayoutListener(Landroid/view/ViewTreeObserver$OnGlobalLayoutListener;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    iget-object v1, p0, Lw3/t;->q1:Lw3/j;

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeOnScrollChangedListener(Landroid/view/ViewTreeObserver$OnScrollChangedListener;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    iget-object v1, p0, Lw3/t;->r1:Lw3/k;

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Landroid/view/ViewTreeObserver;->removeOnTouchModeChangeListener(Landroid/view/ViewTreeObserver$OnTouchModeChangeListener;)V

    .line 122
    .line 123
    .line 124
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 125
    .line 126
    const/16 v1, 0x1f

    .line 127
    .line 128
    if-lt v0, v1, :cond_6

    .line 129
    .line 130
    sget-object v0, Lw3/e0;->a:Lw3/e0;

    .line 131
    .line 132
    invoke-virtual {v0, p0}, Lw3/e0;->a(Landroid/view/View;)V

    .line 133
    .line 134
    .line 135
    :cond_6
    iget-object v0, p0, Lw3/t;->I:Ly2/b;

    .line 136
    .line 137
    if-eqz v0, :cond_7

    .line 138
    .line 139
    invoke-virtual {p0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 140
    .line 141
    .line 142
    move-result-object v1

    .line 143
    iget-object v1, v1, Ld4/s;->d:Landroidx/collection/l0;

    .line 144
    .line 145
    invoke-virtual {v1, v0}, Landroidx/collection/l0;->i(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 149
    .line 150
    .line 151
    move-result-object p0

    .line 152
    check-cast p0, Lc3/l;

    .line 153
    .line 154
    iget-object p0, p0, Lc3/l;->g:Landroidx/collection/l0;

    .line 155
    .line 156
    invoke-virtual {p0, v0}, Landroidx/collection/l0;->i(Ljava/lang/Object;)Z

    .line 157
    .line 158
    .line 159
    :cond_7
    return-void

    .line 160
    :cond_8
    const-string p0, "No lifecycle owner exists"

    .line 161
    .line 162
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 163
    .line 164
    .line 165
    move-result-object p0

    .line 166
    throw p0

    .line 167
    :catchall_0
    move-exception p0

    .line 168
    monitor-exit v0

    .line 169
    throw p0
.end method

.method public final onDraw(Landroid/graphics/Canvas;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onFocusChanged(ZILandroid/graphics/Rect;)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2, p3}, Landroid/view/View;->onFocusChanged(ZILandroid/graphics/Rect;)V

    .line 2
    .line 3
    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    invoke-virtual {p0}, Landroid/view/View;->hasFocus()Z

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lc3/l;

    .line 17
    .line 18
    iget-object p0, p0, Lc3/l;->c:Lc3/v;

    .line 19
    .line 20
    const/4 p1, 0x1

    .line 21
    invoke-static {p0, p1}, Lc3/f;->e(Lc3/v;Z)Z

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lw3/t;->a0:J

    .line 4
    .line 5
    iget-object p1, p0, Lw3/t;->R:Lv3/w0;

    .line 6
    .line 7
    iget-object v0, p0, Lw3/t;->N1:Lw3/q;

    .line 8
    .line 9
    invoke-virtual {p1, v0}, Lv3/w0;->j(Lw3/q;)Z

    .line 10
    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    iput-object p1, p0, Lw3/t;->P:Lt4/a;

    .line 14
    .line 15
    invoke-virtual {p0}, Lw3/t;->H()V

    .line 16
    .line 17
    .line 18
    iget-object p1, p0, Lw3/t;->O:Lw3/t0;

    .line 19
    .line 20
    if-eqz p1, :cond_0

    .line 21
    .line 22
    invoke-virtual {p0}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    sub-int/2addr p4, p2

    .line 27
    sub-int/2addr p5, p3

    .line 28
    const/4 p1, 0x0

    .line 29
    invoke-virtual {p0, p1, p1, p4, p5}, Landroid/view/View;->layout(IIII)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method public final onMeasure(II)V
    .locals 8

    .line 1
    iget-object v0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    const-string v1, "AndroidOwner:onMeasure"

    .line 4
    .line 5
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :try_start_0
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-nez v1, :cond_0

    .line 13
    .line 14
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {p0, v1}, Lw3/t;->l(Lv3/h0;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    invoke-static {p1}, Lw3/t;->g(I)J

    .line 22
    .line 23
    .line 24
    move-result-wide v1

    .line 25
    const/16 p1, 0x20

    .line 26
    .line 27
    ushr-long v3, v1, p1

    .line 28
    .line 29
    long-to-int v3, v3

    .line 30
    const-wide v4, 0xffffffffL

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    and-long/2addr v1, v4

    .line 36
    long-to-int v1, v1

    .line 37
    invoke-static {p2}, Lw3/t;->g(I)J

    .line 38
    .line 39
    .line 40
    move-result-wide v6

    .line 41
    ushr-long p1, v6, p1

    .line 42
    .line 43
    long-to-int p1, p1

    .line 44
    and-long/2addr v4, v6

    .line 45
    long-to-int p2, v4

    .line 46
    invoke-static {v3, v1, p1, p2}, Lkp/a9;->a(IIII)J

    .line 47
    .line 48
    .line 49
    move-result-wide p1

    .line 50
    iget-object v1, p0, Lw3/t;->P:Lt4/a;

    .line 51
    .line 52
    if-nez v1, :cond_1

    .line 53
    .line 54
    new-instance v1, Lt4/a;

    .line 55
    .line 56
    invoke-direct {v1, p1, p2}, Lt4/a;-><init>(J)V

    .line 57
    .line 58
    .line 59
    iput-object v1, p0, Lw3/t;->P:Lt4/a;

    .line 60
    .line 61
    const/4 v1, 0x0

    .line 62
    iput-boolean v1, p0, Lw3/t;->Q:Z

    .line 63
    .line 64
    goto :goto_0

    .line 65
    :cond_1
    iget-wide v1, v1, Lt4/a;->a:J

    .line 66
    .line 67
    invoke-static {v1, v2, p1, p2}, Lt4/a;->b(JJ)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_2

    .line 72
    .line 73
    const/4 v1, 0x1

    .line 74
    iput-boolean v1, p0, Lw3/t;->Q:Z

    .line 75
    .line 76
    :cond_2
    :goto_0
    invoke-virtual {v0, p1, p2}, Lv3/w0;->q(J)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Lv3/w0;->l()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 83
    .line 84
    .line 85
    move-result-object p1

    .line 86
    iget-object p1, p1, Lv3/h0;->I:Lv3/l0;

    .line 87
    .line 88
    iget-object p1, p1, Lv3/l0;->p:Lv3/y0;

    .line 89
    .line 90
    iget p1, p1, Lt3/e1;->d:I

    .line 91
    .line 92
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    iget-object p2, p2, Lv3/h0;->I:Lv3/l0;

    .line 97
    .line 98
    iget-object p2, p2, Lv3/l0;->p:Lv3/y0;

    .line 99
    .line 100
    iget p2, p2, Lt3/e1;->e:I

    .line 101
    .line 102
    invoke-virtual {p0, p1, p2}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 103
    .line 104
    .line 105
    iget-object p1, p0, Lw3/t;->O:Lw3/t0;

    .line 106
    .line 107
    if-eqz p1, :cond_3

    .line 108
    .line 109
    invoke-virtual {p0}, Lw3/t;->getAndroidViewsHandler$ui_release()Lw3/t0;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 114
    .line 115
    .line 116
    move-result-object p2

    .line 117
    iget-object p2, p2, Lv3/h0;->I:Lv3/l0;

    .line 118
    .line 119
    iget-object p2, p2, Lv3/l0;->p:Lv3/y0;

    .line 120
    .line 121
    iget p2, p2, Lt3/e1;->d:I

    .line 122
    .line 123
    const/high16 v0, 0x40000000    # 2.0f

    .line 124
    .line 125
    invoke-static {p2, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 126
    .line 127
    .line 128
    move-result p2

    .line 129
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 134
    .line 135
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 136
    .line 137
    iget p0, p0, Lt3/e1;->e:I

    .line 138
    .line 139
    invoke-static {p0, v0}, Landroid/view/View$MeasureSpec;->makeMeasureSpec(II)I

    .line 140
    .line 141
    .line 142
    move-result p0

    .line 143
    invoke-virtual {p1, p2, p0}, Landroid/view/View;->measure(II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 144
    .line 145
    .line 146
    :cond_3
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 147
    .line 148
    .line 149
    return-void

    .line 150
    :catchall_0
    move-exception p0

    .line 151
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 152
    .line 153
    .line 154
    throw p0
.end method

.method public final onProvideAutofillVirtualStructure(Landroid/view/ViewStructure;I)V
    .locals 11

    .line 1
    if-eqz p1, :cond_9

    .line 2
    .line 3
    const/4 p2, 0x1

    .line 4
    iget-object v0, p0, Lw3/t;->I:Ly2/b;

    .line 5
    .line 6
    if-eqz v0, :cond_5

    .line 7
    .line 8
    iget-object v1, v0, Ly2/b;->b:Ld4/s;

    .line 9
    .line 10
    iget-object v1, v1, Ld4/s;->a:Lv3/h0;

    .line 11
    .line 12
    iget-object v2, v0, Ly2/b;->g:Landroid/view/autofill/AutofillId;

    .line 13
    .line 14
    iget-object v3, v0, Ly2/b;->e:Ljava/lang/String;

    .line 15
    .line 16
    iget-object v0, v0, Ly2/b;->d:Le4/a;

    .line 17
    .line 18
    invoke-static {p1, v1, v2, v3, v0}, Llp/sf;->d(Landroid/view/ViewStructure;Lv3/h0;Landroid/view/autofill/AutofillId;Ljava/lang/String;Le4/a;)V

    .line 19
    .line 20
    .line 21
    sget-object v4, Landroidx/collection/w0;->a:[Ljava/lang/Object;

    .line 22
    .line 23
    new-instance v4, Landroidx/collection/l0;

    .line 24
    .line 25
    const/4 v5, 0x2

    .line 26
    invoke-direct {v4, v5}, Landroidx/collection/l0;-><init>(I)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v4, v1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v4, p1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    :cond_0
    invoke-virtual {v4}, Landroidx/collection/l0;->h()Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_5

    .line 40
    .line 41
    iget v1, v4, Landroidx/collection/l0;->b:I

    .line 42
    .line 43
    sub-int/2addr v1, p2

    .line 44
    invoke-virtual {v4, v1}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    const-string v5, "null cannot be cast to non-null type android.view.ViewStructure"

    .line 49
    .line 50
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    check-cast v1, Landroid/view/ViewStructure;

    .line 54
    .line 55
    iget v5, v4, Landroidx/collection/l0;->b:I

    .line 56
    .line 57
    sub-int/2addr v5, p2

    .line 58
    invoke-virtual {v4, v5}, Landroidx/collection/l0;->j(I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v5

    .line 62
    const-string v6, "null cannot be cast to non-null type androidx.compose.ui.semantics.SemanticsInfo"

    .line 63
    .line 64
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    check-cast v5, Lv3/h0;

    .line 68
    .line 69
    invoke-virtual {v5}, Lv3/h0;->o()Ljava/util/List;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    const/4 v7, 0x0

    .line 78
    :goto_0
    if-ge v7, v6, :cond_0

    .line 79
    .line 80
    move-object v8, v5

    .line 81
    check-cast v8, Landroidx/collection/j0;

    .line 82
    .line 83
    invoke-virtual {v8, v7}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v8

    .line 87
    check-cast v8, Lv3/h0;

    .line 88
    .line 89
    iget-boolean v9, v8, Lv3/h0;->S:Z

    .line 90
    .line 91
    if-nez v9, :cond_4

    .line 92
    .line 93
    invoke-virtual {v8}, Lv3/h0;->I()Z

    .line 94
    .line 95
    .line 96
    move-result v9

    .line 97
    if-eqz v9, :cond_4

    .line 98
    .line 99
    invoke-virtual {v8}, Lv3/h0;->J()Z

    .line 100
    .line 101
    .line 102
    move-result v9

    .line 103
    if-nez v9, :cond_1

    .line 104
    .line 105
    goto :goto_1

    .line 106
    :cond_1
    invoke-virtual {v8}, Lv3/h0;->x()Ld4/l;

    .line 107
    .line 108
    .line 109
    move-result-object v9

    .line 110
    if-eqz v9, :cond_3

    .line 111
    .line 112
    iget-object v9, v9, Ld4/l;->d:Landroidx/collection/q0;

    .line 113
    .line 114
    sget-object v10, Ld4/k;->g:Ld4/z;

    .line 115
    .line 116
    invoke-virtual {v9, v10}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v10

    .line 120
    if-nez v10, :cond_2

    .line 121
    .line 122
    sget-object v10, Ld4/v;->q:Ld4/z;

    .line 123
    .line 124
    invoke-virtual {v9, v10}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v10

    .line 128
    if-nez v10, :cond_2

    .line 129
    .line 130
    sget-object v10, Ld4/v;->r:Ld4/z;

    .line 131
    .line 132
    invoke-virtual {v9, v10}, Landroidx/collection/q0;->b(Ljava/lang/Object;)Z

    .line 133
    .line 134
    .line 135
    move-result v9

    .line 136
    if-eqz v9, :cond_3

    .line 137
    .line 138
    :cond_2
    invoke-virtual {v1, p2}, Landroid/view/ViewStructure;->addChildCount(I)I

    .line 139
    .line 140
    .line 141
    move-result v9

    .line 142
    invoke-virtual {v1, v9}, Landroid/view/ViewStructure;->newChild(I)Landroid/view/ViewStructure;

    .line 143
    .line 144
    .line 145
    move-result-object v9

    .line 146
    invoke-static {v9, v8, v2, v3, v0}, Llp/sf;->d(Landroid/view/ViewStructure;Lv3/h0;Landroid/view/autofill/AutofillId;Ljava/lang/String;Le4/a;)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v4, v8}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    invoke-virtual {v4, v9}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 153
    .line 154
    .line 155
    goto :goto_1

    .line 156
    :cond_3
    invoke-virtual {v4, v8}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {v4, v1}, Landroidx/collection/l0;->a(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    :cond_4
    :goto_1
    add-int/lit8 v7, v7, 0x1

    .line 163
    .line 164
    goto :goto_0

    .line 165
    :cond_5
    iget-object p0, p0, Lw3/t;->H:Lun/a;

    .line 166
    .line 167
    if-eqz p0, :cond_9

    .line 168
    .line 169
    iget-object v0, p0, Lun/a;->f:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v0, Ly2/h;

    .line 172
    .line 173
    iget-object v1, v0, Ly2/h;->a:Ljava/util/LinkedHashMap;

    .line 174
    .line 175
    iget-object v0, v0, Ly2/h;->a:Ljava/util/LinkedHashMap;

    .line 176
    .line 177
    invoke-interface {v1}, Ljava/util/Map;->isEmpty()Z

    .line 178
    .line 179
    .line 180
    move-result v1

    .line 181
    if-eqz v1, :cond_6

    .line 182
    .line 183
    goto :goto_2

    .line 184
    :cond_6
    invoke-interface {v0}, Ljava/util/Map;->size()I

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    invoke-virtual {p1, v1}, Landroid/view/ViewStructure;->addChildCount(I)I

    .line 189
    .line 190
    .line 191
    move-result v1

    .line 192
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 193
    .line 194
    .line 195
    move-result-object v0

    .line 196
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 197
    .line 198
    .line 199
    move-result-object v0

    .line 200
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 201
    .line 202
    .line 203
    move-result v2

    .line 204
    if-nez v2, :cond_7

    .line 205
    .line 206
    goto :goto_2

    .line 207
    :cond_7
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v0

    .line 211
    check-cast v0, Ljava/util/Map$Entry;

    .line 212
    .line 213
    invoke-interface {v0}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v2

    .line 217
    check-cast v2, Ljava/lang/Number;

    .line 218
    .line 219
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 220
    .line 221
    .line 222
    move-result v2

    .line 223
    invoke-interface {v0}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v0

    .line 227
    if-nez v0, :cond_8

    .line 228
    .line 229
    invoke-virtual {p1, v1}, Landroid/view/ViewStructure;->newChild(I)Landroid/view/ViewStructure;

    .line 230
    .line 231
    .line 232
    move-result-object p1

    .line 233
    iget-object v0, p0, Lun/a;->h:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast v0, Landroid/view/autofill/AutofillId;

    .line 236
    .line 237
    invoke-virtual {p1, v0, v2}, Landroid/view/ViewStructure;->setAutofillId(Landroid/view/autofill/AutofillId;I)V

    .line 238
    .line 239
    .line 240
    iget-object p0, p0, Lun/a;->e:Ljava/lang/Object;

    .line 241
    .line 242
    check-cast p0, Lw3/t;

    .line 243
    .line 244
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 245
    .line 246
    .line 247
    move-result-object p0

    .line 248
    invoke-virtual {p0}, Landroid/content/Context;->getPackageName()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    const/4 v0, 0x0

    .line 253
    invoke-virtual {p1, v2, p0, v0, v0}, Landroid/view/ViewStructure;->setId(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 254
    .line 255
    .line 256
    invoke-virtual {p1, p2}, Landroid/view/ViewStructure;->setAutofillType(I)V

    .line 257
    .line 258
    .line 259
    throw v0

    .line 260
    :cond_8
    new-instance p0, Ljava/lang/ClassCastException;

    .line 261
    .line 262
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 263
    .line 264
    .line 265
    throw p0

    .line 266
    :cond_9
    :goto_2
    return-void
.end method

.method public final onResolvePointerIcon(Landroid/view/MotionEvent;I)Landroid/view/PointerIcon;
    .locals 2

    .line 1
    invoke-virtual {p1, p2}, Landroid/view/MotionEvent;->getToolType(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/16 v1, 0x2002

    .line 6
    .line 7
    invoke-virtual {p1, v1}, Landroid/view/InputEvent;->isFromSource(I)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_2

    .line 12
    .line 13
    const/16 v1, 0x4002

    .line 14
    .line 15
    invoke-virtual {p1, v1}, Landroid/view/InputEvent;->isFromSource(I)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    const/4 v1, 0x2

    .line 22
    if-eq v0, v1, :cond_0

    .line 23
    .line 24
    const/4 v1, 0x4

    .line 25
    if-ne v0, v1, :cond_2

    .line 26
    .line 27
    :cond_0
    invoke-virtual {p0}, Lw3/t;->getPointerIconService()Lp3/r;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    check-cast v0, Lw3/r;

    .line 32
    .line 33
    iget-object v0, v0, Lw3/r;->a:Lp3/q;

    .line 34
    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    invoke-virtual {p0}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    instance-of p1, v0, Lp3/a;

    .line 42
    .line 43
    if-eqz p1, :cond_1

    .line 44
    .line 45
    check-cast v0, Lp3/a;

    .line 46
    .line 47
    iget p1, v0, Lp3/a;->b:I

    .line 48
    .line 49
    invoke-static {p0, p1}, Landroid/view/PointerIcon;->getSystemIcon(Landroid/content/Context;I)Landroid/view/PointerIcon;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0

    .line 54
    :cond_1
    const/16 p1, 0x3e8

    .line 55
    .line 56
    invoke-static {p0, p1}, Landroid/view/PointerIcon;->getSystemIcon(Landroid/content/Context;I)Landroid/view/PointerIcon;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :cond_2
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->onResolvePointerIcon(Landroid/view/MotionEvent;I)Landroid/view/PointerIcon;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0
.end method

.method public final onResume(Landroidx/lifecycle/x;)V
    .locals 1

    .line 1
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v0, 0x1e

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    invoke-static {}, Lw3/h0;->u()Z

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    invoke-virtual {p0, p1}, Lw3/t;->setShowLayoutBounds(Z)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final onRtlPropertiesChanged(I)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lw3/t;->e:Z

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    if-eqz p1, :cond_1

    .line 6
    .line 7
    const/4 v0, 0x1

    .line 8
    if-eq p1, v0, :cond_0

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    sget-object p1, Lt4/m;->e:Lt4/m;

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_1
    sget-object p1, Lt4/m;->d:Lt4/m;

    .line 16
    .line 17
    :goto_0
    if-nez p1, :cond_2

    .line 18
    .line 19
    sget-object p1, Lt4/m;->d:Lt4/m;

    .line 20
    .line 21
    :cond_2
    invoke-direct {p0, p1}, Lw3/t;->setLayoutDirection(Lt4/m;)V

    .line 22
    .line 23
    .line 24
    :cond_3
    return-void
.end method

.method public final onScrollCaptureSearch(Landroid/graphics/Rect;Landroid/graphics/Point;Ljava/util/function/Consumer;)V
    .locals 14

    .line 1
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 2
    .line 3
    const/16 v0, 0x1f

    .line 4
    .line 5
    if-lt p1, v0, :cond_2

    .line 6
    .line 7
    iget-object v5, p0, Lw3/t;->Q1:Laq/a;

    .line 8
    .line 9
    if-eqz v5, :cond_2

    .line 10
    .line 11
    invoke-virtual {p0}, Lw3/t;->getSemanticsOwner()Ld4/s;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0}, Lw3/t;->getCoroutineContext()Lpx0/g;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-instance v8, Ln2/b;

    .line 20
    .line 21
    const/16 v1, 0x10

    .line 22
    .line 23
    new-array v1, v1, [Lc4/j;

    .line 24
    .line 25
    invoke-direct {v8, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Ld4/s;->a()Ld4/q;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    new-instance v6, Lc4/i;

    .line 33
    .line 34
    const/16 v12, 0x8

    .line 35
    .line 36
    const/4 v13, 0x0

    .line 37
    const/4 v7, 0x1

    .line 38
    const-class v9, Ln2/b;

    .line 39
    .line 40
    const-string v10, "add"

    .line 41
    .line 42
    const-string v11, "add(Ljava/lang/Object;)Z"

    .line 43
    .line 44
    invoke-direct/range {v6 .. v13}, Lc4/i;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 45
    .line 46
    .line 47
    const/4 v1, 0x0

    .line 48
    invoke-static {p1, v1, v6}, Ljp/qc;->d(Ld4/q;ILc4/i;)V

    .line 49
    .line 50
    .line 51
    const/4 p1, 0x2

    .line 52
    new-array p1, p1, [Lay0/k;

    .line 53
    .line 54
    sget-object v2, Lc4/c;->h:Lc4/c;

    .line 55
    .line 56
    aput-object v2, p1, v1

    .line 57
    .line 58
    sget-object v2, Lc4/c;->i:Lc4/c;

    .line 59
    .line 60
    aput-object v2, p1, v7

    .line 61
    .line 62
    invoke-static {p1}, Ljp/vc;->b([Lay0/k;)Ld4/a0;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    iget-object v2, v8, Ln2/b;->d:[Ljava/lang/Object;

    .line 67
    .line 68
    iget v3, v8, Ln2/b;->f:I

    .line 69
    .line 70
    invoke-static {v2, p1, v1, v3}, Lmx0/n;->T([Ljava/lang/Object;Ljava/util/Comparator;II)V

    .line 71
    .line 72
    .line 73
    iget p1, v8, Ln2/b;->f:I

    .line 74
    .line 75
    if-nez p1, :cond_0

    .line 76
    .line 77
    const/4 p1, 0x0

    .line 78
    goto :goto_0

    .line 79
    :cond_0
    sub-int/2addr p1, v7

    .line 80
    iget-object v1, v8, Ln2/b;->d:[Ljava/lang/Object;

    .line 81
    .line 82
    aget-object p1, v1, p1

    .line 83
    .line 84
    :goto_0
    check-cast p1, Lc4/j;

    .line 85
    .line 86
    if-nez p1, :cond_1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_1
    iget-object v3, p1, Lc4/j;->c:Lt4/k;

    .line 90
    .line 91
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    new-instance v1, Lc4/e;

    .line 96
    .line 97
    iget-object v2, p1, Lc4/j;->a:Ld4/q;

    .line 98
    .line 99
    move-object v6, p0

    .line 100
    invoke-direct/range {v1 .. v6}, Lc4/e;-><init>(Ld4/q;Lt4/k;Lpw0/a;Laq/a;Lw3/t;)V

    .line 101
    .line 102
    .line 103
    iget-object p1, p1, Lc4/j;->d:Lv3/f1;

    .line 104
    .line 105
    invoke-static {p1}, Lt3/k1;->i(Lt3/y;)Lt3/y;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    invoke-interface {v0, p1, v7}, Lt3/y;->P(Lt3/y;Z)Ld3/c;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    invoke-virtual {v3}, Lt4/k;->c()J

    .line 114
    .line 115
    .line 116
    move-result-wide v4

    .line 117
    invoke-static {p1}, Lkp/e9;->b(Ld3/c;)Lt4/k;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-static {p1}, Le3/j0;->w(Lt4/k;)Landroid/graphics/Rect;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    new-instance v0, Landroid/graphics/Point;

    .line 126
    .line 127
    const/16 v2, 0x20

    .line 128
    .line 129
    shr-long v7, v4, v2

    .line 130
    .line 131
    long-to-int v2, v7

    .line 132
    const-wide v7, 0xffffffffL

    .line 133
    .line 134
    .line 135
    .line 136
    .line 137
    and-long/2addr v4, v7

    .line 138
    long-to-int v4, v4

    .line 139
    invoke-direct {v0, v2, v4}, Landroid/graphics/Point;-><init>(II)V

    .line 140
    .line 141
    .line 142
    invoke-static {p0, p1, v0, v1}, Lc4/a;->o(Lw3/t;Landroid/graphics/Rect;Landroid/graphics/Point;Landroid/view/ScrollCaptureCallback;)Landroid/view/ScrollCaptureTarget;

    .line 143
    .line 144
    .line 145
    move-result-object p0

    .line 146
    invoke-static {v3}, Le3/j0;->w(Lt4/k;)Landroid/graphics/Rect;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    invoke-static {p0, p1}, Lc4/a;->y(Landroid/view/ScrollCaptureTarget;Landroid/graphics/Rect;)V

    .line 151
    .line 152
    .line 153
    move-object/from16 p1, p3

    .line 154
    .line 155
    invoke-interface {p1, p0}, Ljava/util/function/Consumer;->accept(Ljava/lang/Object;)V

    .line 156
    .line 157
    .line 158
    :cond_2
    :goto_1
    return-void
.end method

.method public final onVirtualViewTranslationResponses(Landroid/util/LongSparseArray;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lw3/t;->w:Lz2/e;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    const/16 v1, 0x1f

    .line 9
    .line 10
    if-ge v0, v1, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-virtual {v0}, Landroid/os/Looper;->getThread()Ljava/lang/Thread;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-static {p0, p1}, Lfb/w;->c(Lz2/e;Landroid/util/LongSparseArray;)V

    .line 32
    .line 33
    .line 34
    return-void

    .line 35
    :cond_1
    iget-object v0, p0, Lz2/e;->d:Lw3/t;

    .line 36
    .line 37
    new-instance v1, Lyt/g;

    .line 38
    .line 39
    const/4 v2, 0x1

    .line 40
    invoke-direct {v1, v2, p0, p1}, Lyt/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v1}, Landroid/view/View;->post(Ljava/lang/Runnable;)Z

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final onWindowFocusChanged(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw3/t;->m:Lw3/r1;

    .line 2
    .line 3
    iget-object v0, v0, Lw3/r1;->c:Ll2/j1;

    .line 4
    .line 5
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {v0, v1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    const/4 v0, 0x1

    .line 13
    iput-boolean v0, p0, Lw3/t;->P1:Z

    .line 14
    .line 15
    invoke-super {p0, p1}, Landroid/view/View;->onWindowFocusChanged(Z)V

    .line 16
    .line 17
    .line 18
    if-eqz p1, :cond_0

    .line 19
    .line 20
    sget p1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 21
    .line 22
    const/16 v0, 0x1e

    .line 23
    .line 24
    if-ge p1, v0, :cond_0

    .line 25
    .line 26
    invoke-static {}, Lw3/h0;->u()Z

    .line 27
    .line 28
    .line 29
    move-result p1

    .line 30
    invoke-virtual {p0}, Lw3/t;->getShowLayoutBounds()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eq v0, p1, :cond_0

    .line 35
    .line 36
    invoke-virtual {p0, p1}, Lw3/t;->setShowLayoutBounds(Z)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    invoke-static {p0}, Lw3/t;->k(Lv3/h0;)V

    .line 44
    .line 45
    .line 46
    :cond_0
    return-void
.end method

.method public final p([F)V
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    invoke-virtual {v0}, Lw3/t;->z()V

    .line 6
    .line 7
    .line 8
    iget-object v2, v0, Lw3/t;->V:[F

    .line 9
    .line 10
    invoke-static {v1, v2}, Le3/c0;->e([F[F)V

    .line 11
    .line 12
    .line 13
    iget-wide v2, v0, Lw3/t;->c0:J

    .line 14
    .line 15
    const/16 v4, 0x20

    .line 16
    .line 17
    shr-long/2addr v2, v4

    .line 18
    long-to-int v2, v2

    .line 19
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    iget-wide v3, v0, Lw3/t;->c0:J

    .line 24
    .line 25
    const-wide v5, 0xffffffffL

    .line 26
    .line 27
    .line 28
    .line 29
    .line 30
    and-long/2addr v3, v5

    .line 31
    long-to-int v3, v3

    .line 32
    invoke-static {v3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 33
    .line 34
    .line 35
    move-result v3

    .line 36
    iget-object v0, v0, Lw3/t;->U:[F

    .line 37
    .line 38
    invoke-static {v0}, Le3/c0;->d([F)V

    .line 39
    .line 40
    .line 41
    invoke-static {v0, v2, v3}, Le3/c0;->f([FFF)V

    .line 42
    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    invoke-static {v2, v2, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 46
    .line 47
    .line 48
    move-result v3

    .line 49
    const/4 v4, 0x1

    .line 50
    invoke-static {v2, v4, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 51
    .line 52
    .line 53
    move-result v5

    .line 54
    const/4 v6, 0x2

    .line 55
    invoke-static {v2, v6, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 56
    .line 57
    .line 58
    move-result v7

    .line 59
    const/4 v8, 0x3

    .line 60
    invoke-static {v2, v8, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 61
    .line 62
    .line 63
    move-result v9

    .line 64
    invoke-static {v4, v2, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 65
    .line 66
    .line 67
    move-result v10

    .line 68
    invoke-static {v4, v4, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 69
    .line 70
    .line 71
    move-result v11

    .line 72
    invoke-static {v4, v6, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 73
    .line 74
    .line 75
    move-result v12

    .line 76
    invoke-static {v4, v8, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 77
    .line 78
    .line 79
    move-result v13

    .line 80
    invoke-static {v6, v2, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 81
    .line 82
    .line 83
    move-result v14

    .line 84
    invoke-static {v6, v4, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 85
    .line 86
    .line 87
    move-result v15

    .line 88
    invoke-static {v6, v6, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 89
    .line 90
    .line 91
    move-result v16

    .line 92
    invoke-static {v6, v8, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 93
    .line 94
    .line 95
    move-result v17

    .line 96
    invoke-static {v8, v2, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 97
    .line 98
    .line 99
    move-result v18

    .line 100
    invoke-static {v8, v4, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 101
    .line 102
    .line 103
    move-result v19

    .line 104
    invoke-static {v8, v6, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 105
    .line 106
    .line 107
    move-result v20

    .line 108
    invoke-static {v8, v8, v0, v1}, Lw3/h0;->o(II[F[F)F

    .line 109
    .line 110
    .line 111
    move-result v0

    .line 112
    aput v3, v1, v2

    .line 113
    .line 114
    aput v5, v1, v4

    .line 115
    .line 116
    aput v7, v1, v6

    .line 117
    .line 118
    aput v9, v1, v8

    .line 119
    .line 120
    const/4 v2, 0x4

    .line 121
    aput v10, v1, v2

    .line 122
    .line 123
    const/4 v2, 0x5

    .line 124
    aput v11, v1, v2

    .line 125
    .line 126
    const/4 v2, 0x6

    .line 127
    aput v12, v1, v2

    .line 128
    .line 129
    const/4 v2, 0x7

    .line 130
    aput v13, v1, v2

    .line 131
    .line 132
    const/16 v2, 0x8

    .line 133
    .line 134
    aput v14, v1, v2

    .line 135
    .line 136
    const/16 v2, 0x9

    .line 137
    .line 138
    aput v15, v1, v2

    .line 139
    .line 140
    const/16 v2, 0xa

    .line 141
    .line 142
    aput v16, v1, v2

    .line 143
    .line 144
    const/16 v2, 0xb

    .line 145
    .line 146
    aput v17, v1, v2

    .line 147
    .line 148
    const/16 v2, 0xc

    .line 149
    .line 150
    aput v18, v1, v2

    .line 151
    .line 152
    const/16 v2, 0xd

    .line 153
    .line 154
    aput v19, v1, v2

    .line 155
    .line 156
    const/16 v2, 0xe

    .line 157
    .line 158
    aput v20, v1, v2

    .line 159
    .line 160
    const/16 v2, 0xf

    .line 161
    .line 162
    aput v0, v1, v2

    .line 163
    .line 164
    return-void
.end method

.method public final q(J)J
    .locals 7

    .line 1
    invoke-virtual {p0}, Lw3/t;->z()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p0, Lw3/t;->V:[F

    .line 5
    .line 6
    invoke-static {p1, p2, v0}, Le3/c0;->b(J[F)J

    .line 7
    .line 8
    .line 9
    move-result-wide p1

    .line 10
    const/16 v0, 0x20

    .line 11
    .line 12
    shr-long v1, p1, v0

    .line 13
    .line 14
    long-to-int v1, v1

    .line 15
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget-wide v2, p0, Lw3/t;->c0:J

    .line 20
    .line 21
    shr-long/2addr v2, v0

    .line 22
    long-to-int v2, v2

    .line 23
    invoke-static {v2}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    add-float/2addr v2, v1

    .line 28
    const-wide v3, 0xffffffffL

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr p1, v3

    .line 34
    long-to-int p1, p1

    .line 35
    invoke-static {p1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 36
    .line 37
    .line 38
    move-result p1

    .line 39
    iget-wide v5, p0, Lw3/t;->c0:J

    .line 40
    .line 41
    and-long/2addr v5, v3

    .line 42
    long-to-int p0, v5

    .line 43
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    add-float/2addr p0, p1

    .line 48
    invoke-static {v2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    int-to-long p1, p1

    .line 53
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    int-to-long v1, p0

    .line 58
    shl-long p0, p1, v0

    .line 59
    .line 60
    and-long v0, v1, v3

    .line 61
    .line 62
    or-long/2addr p0, v0

    .line 63
    return-wide p0
.end method

.method public final r(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    iget-object v1, v0, Lv3/w0;->b:Lrn/i;

    .line 4
    .line 5
    invoke-virtual {v1}, Lrn/i;->w()Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_1

    .line 10
    .line 11
    iget-object v1, v0, Lv3/w0;->e:Lvp/y1;

    .line 12
    .line 13
    iget-object v1, v1, Lvp/y1;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v1, Ln2/b;

    .line 16
    .line 17
    iget v1, v1, Ln2/b;->f:I

    .line 18
    .line 19
    if-eqz v1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-void

    .line 23
    :cond_1
    :goto_0
    const-string v1, "AndroidOwner:measureAndLayout"

    .line 24
    .line 25
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    if-eqz p1, :cond_2

    .line 29
    .line 30
    :try_start_0
    iget-object p1, p0, Lw3/t;->N1:Lw3/q;

    .line 31
    .line 32
    goto :goto_1

    .line 33
    :cond_2
    const/4 p1, 0x0

    .line 34
    :goto_1
    invoke-virtual {v0, p1}, Lv3/w0;->j(Lw3/q;)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_3

    .line 39
    .line 40
    invoke-virtual {p0}, Landroid/view/View;->requestLayout()V

    .line 41
    .line 42
    .line 43
    :cond_3
    const/4 p1, 0x0

    .line 44
    invoke-virtual {v0, p1}, Lv3/w0;->a(Z)V

    .line 45
    .line 46
    .line 47
    iget-boolean v0, p0, Lw3/t;->D:Z

    .line 48
    .line 49
    if-eqz v0, :cond_4

    .line 50
    .line 51
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {v0}, Landroid/view/ViewTreeObserver;->dispatchOnGlobalLayout()V

    .line 56
    .line 57
    .line 58
    iput-boolean p1, p0, Lw3/t;->D:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 59
    .line 60
    :cond_4
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 66
    .line 67
    .line 68
    throw p0
.end method

.method public final requestFocus(ILandroid/graphics/Rect;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isFocused()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    check-cast v0, Lc3/l;

    .line 14
    .line 15
    iget-object v0, v0, Lc3/l;->c:Lc3/v;

    .line 16
    .line 17
    invoke-virtual {v0}, Lc3/v;->Z0()Lc3/u;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-virtual {v0}, Lc3/u;->a()Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    invoke-super {p0, p1, p2}, Landroid/view/ViewGroup;->requestFocus(ILandroid/graphics/Rect;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    :cond_1
    invoke-static {p1}, Lc3/f;->D(I)Lc3/d;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    if-eqz p1, :cond_2

    .line 37
    .line 38
    iget p1, p1, Lc3/d;->a:I

    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    const/4 p1, 0x7

    .line 42
    :goto_0
    invoke-virtual {p0}, Lw3/t;->getFocusOwner()Lc3/j;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-eqz p2, :cond_3

    .line 47
    .line 48
    invoke-static {p2}, Le3/j0;->B(Landroid/graphics/Rect;)Ld3/c;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    goto :goto_1

    .line 53
    :cond_3
    const/4 p2, 0x0

    .line 54
    :goto_1
    new-instance v0, Lc3/k;

    .line 55
    .line 56
    const/4 v1, 0x1

    .line 57
    invoke-direct {v0, p1, v1}, Lc3/k;-><init>(II)V

    .line 58
    .line 59
    .line 60
    check-cast p0, Lc3/l;

    .line 61
    .line 62
    invoke-virtual {p0, p1, p2, v0}, Lc3/l;->g(ILd3/c;Lay0/k;)Ljava/lang/Boolean;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 67
    .line 68
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 69
    .line 70
    .line 71
    move-result p0

    .line 72
    return p0
.end method

.method public final s(Lv3/h0;J)V
    .locals 2

    .line 1
    iget-object v0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    const-string v1, "AndroidOwner:measureAndLayout"

    .line 4
    .line 5
    invoke-static {v1}, Landroid/os/Trace;->beginSection(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :try_start_0
    invoke-virtual {v0, p1, p2, p3}, Lv3/w0;->k(Lv3/h0;J)V

    .line 9
    .line 10
    .line 11
    iget-object p1, v0, Lv3/w0;->b:Lrn/i;

    .line 12
    .line 13
    invoke-virtual {p1}, Lrn/i;->w()Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-nez p1, :cond_0

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    invoke-virtual {v0, p1}, Lv3/w0;->a(Z)V

    .line 21
    .line 22
    .line 23
    iget-boolean p2, p0, Lw3/t;->D:Z

    .line 24
    .line 25
    if-eqz p2, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0}, Landroid/view/View;->getViewTreeObserver()Landroid/view/ViewTreeObserver;

    .line 28
    .line 29
    .line 30
    move-result-object p2

    .line 31
    invoke-virtual {p2}, Landroid/view/ViewTreeObserver;->dispatchOnGlobalLayout()V

    .line 32
    .line 33
    .line 34
    iput-boolean p1, p0, Lw3/t;->D:Z

    .line 35
    .line 36
    :cond_0
    invoke-virtual {p0}, Lw3/t;->getRectManager()Le4/a;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    invoke-virtual {p0}, Le4/a;->b()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 41
    .line 42
    .line 43
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :catchall_0
    move-exception p0

    .line 48
    invoke-static {}, Landroid/os/Trace;->endSection()V

    .line 49
    .line 50
    .line 51
    throw p0
.end method

.method public setAccessibilityEventBatchIntervalMillis(J)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->v:Lw3/z;

    .line 2
    .line 3
    iput-wide p1, p0, Lw3/z;->h:J

    .line 4
    .line 5
    return-void
.end method

.method public final setConfigurationChangeObserver(Lay0/k;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    iput-object p1, p0, Lw3/t;->G:Lay0/k;

    .line 2
    .line 3
    return-void
.end method

.method public final setContentCaptureManager$ui_release(Lz2/e;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lw3/t;->w:Lz2/e;

    .line 2
    .line 3
    return-void
.end method

.method public setCoroutineContext(Lpx0/g;)V
    .locals 9

    .line 1
    iput-object p1, p0, Lw3/t;->k:Lpx0/g;

    .line 2
    .line 3
    invoke-virtual {p0}, Lw3/t;->getRoot()Lv3/h0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 8
    .line 9
    iget-object p0, p0, Lg1/q;->g:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Lx2/r;

    .line 12
    .line 13
    instance-of p1, p0, Lp3/j0;

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    move-object p1, p0

    .line 18
    check-cast p1, Lp3/j0;

    .line 19
    .line 20
    invoke-virtual {p1}, Lp3/j0;->Z0()V

    .line 21
    .line 22
    .line 23
    :cond_0
    iget-object p1, p0, Lx2/r;->d:Lx2/r;

    .line 24
    .line 25
    iget-boolean p1, p1, Lx2/r;->q:Z

    .line 26
    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    const-string p1, "visitSubtreeIf called on an unattached node"

    .line 30
    .line 31
    invoke-static {p1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    :cond_1
    new-instance p1, Ln2/b;

    .line 35
    .line 36
    const/16 v0, 0x10

    .line 37
    .line 38
    new-array v1, v0, [Lx2/r;

    .line 39
    .line 40
    invoke-direct {p1, v1}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 44
    .line 45
    iget-object v1, p0, Lx2/r;->i:Lx2/r;

    .line 46
    .line 47
    if-nez v1, :cond_2

    .line 48
    .line 49
    invoke-static {p1, p0}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    invoke-virtual {p1, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    :goto_0
    iget p0, p1, Ln2/b;->f:I

    .line 57
    .line 58
    if-eqz p0, :cond_c

    .line 59
    .line 60
    add-int/lit8 p0, p0, -0x1

    .line 61
    .line 62
    invoke-virtual {p1, p0}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Lx2/r;

    .line 67
    .line 68
    iget v1, p0, Lx2/r;->g:I

    .line 69
    .line 70
    and-int/2addr v1, v0

    .line 71
    if-eqz v1, :cond_b

    .line 72
    .line 73
    move-object v1, p0

    .line 74
    :goto_1
    if-eqz v1, :cond_b

    .line 75
    .line 76
    iget v2, v1, Lx2/r;->f:I

    .line 77
    .line 78
    and-int/2addr v2, v0

    .line 79
    if-eqz v2, :cond_a

    .line 80
    .line 81
    const/4 v2, 0x0

    .line 82
    move-object v3, v1

    .line 83
    move-object v4, v2

    .line 84
    :goto_2
    if-eqz v3, :cond_a

    .line 85
    .line 86
    instance-of v5, v3, Lv3/t1;

    .line 87
    .line 88
    if-eqz v5, :cond_3

    .line 89
    .line 90
    check-cast v3, Lv3/t1;

    .line 91
    .line 92
    instance-of v5, v3, Lp3/j0;

    .line 93
    .line 94
    if-eqz v5, :cond_9

    .line 95
    .line 96
    check-cast v3, Lp3/j0;

    .line 97
    .line 98
    invoke-virtual {v3}, Lp3/j0;->Z0()V

    .line 99
    .line 100
    .line 101
    goto :goto_5

    .line 102
    :cond_3
    iget v5, v3, Lx2/r;->f:I

    .line 103
    .line 104
    and-int/2addr v5, v0

    .line 105
    if-eqz v5, :cond_9

    .line 106
    .line 107
    instance-of v5, v3, Lv3/n;

    .line 108
    .line 109
    if-eqz v5, :cond_9

    .line 110
    .line 111
    move-object v5, v3

    .line 112
    check-cast v5, Lv3/n;

    .line 113
    .line 114
    iget-object v5, v5, Lv3/n;->s:Lx2/r;

    .line 115
    .line 116
    const/4 v6, 0x0

    .line 117
    :goto_3
    const/4 v7, 0x1

    .line 118
    if-eqz v5, :cond_8

    .line 119
    .line 120
    iget v8, v5, Lx2/r;->f:I

    .line 121
    .line 122
    and-int/2addr v8, v0

    .line 123
    if-eqz v8, :cond_7

    .line 124
    .line 125
    add-int/lit8 v6, v6, 0x1

    .line 126
    .line 127
    if-ne v6, v7, :cond_4

    .line 128
    .line 129
    move-object v3, v5

    .line 130
    goto :goto_4

    .line 131
    :cond_4
    if-nez v4, :cond_5

    .line 132
    .line 133
    new-instance v4, Ln2/b;

    .line 134
    .line 135
    new-array v7, v0, [Lx2/r;

    .line 136
    .line 137
    invoke-direct {v4, v7}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    :cond_5
    if-eqz v3, :cond_6

    .line 141
    .line 142
    invoke-virtual {v4, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    move-object v3, v2

    .line 146
    :cond_6
    invoke-virtual {v4, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 147
    .line 148
    .line 149
    :cond_7
    :goto_4
    iget-object v5, v5, Lx2/r;->i:Lx2/r;

    .line 150
    .line 151
    goto :goto_3

    .line 152
    :cond_8
    if-ne v6, v7, :cond_9

    .line 153
    .line 154
    goto :goto_2

    .line 155
    :cond_9
    :goto_5
    invoke-static {v4}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 156
    .line 157
    .line 158
    move-result-object v3

    .line 159
    goto :goto_2

    .line 160
    :cond_a
    iget-object v1, v1, Lx2/r;->i:Lx2/r;

    .line 161
    .line 162
    goto :goto_1

    .line 163
    :cond_b
    invoke-static {p1, p0}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 164
    .line 165
    .line 166
    goto :goto_0

    .line 167
    :cond_c
    return-void
.end method

.method public final setLastMatrixRecalculationAnimationTime$ui_release(J)V
    .locals 0

    .line 1
    iput-wide p1, p0, Lw3/t;->a0:J

    .line 2
    .line 3
    return-void
.end method

.method public final setOnViewTreeOwnersAvailable(Lay0/k;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-virtual {p0}, Lw3/t;->getViewTreeOwners()Lw3/l;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {p1, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    iput-object p1, p0, Lw3/t;->f0:Lay0/k;

    .line 17
    .line 18
    :cond_1
    return-void
.end method

.method public setShowLayoutBounds(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lw3/t;->N:Z

    .line 2
    .line 3
    return-void
.end method

.method public setUncaughtExceptionHandler(Lv3/v1;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final setUncaughtExceptionHandler$ui_release(Lv3/v1;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final shouldDelayChildPressedState()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final t(Lv3/n1;Z)V
    .locals 1

    .line 1
    iget-object v0, p0, Lw3/t;->A:Ljava/util/ArrayList;

    .line 2
    .line 3
    if-nez p2, :cond_1

    .line 4
    .line 5
    iget-boolean p2, p0, Lw3/t;->C:Z

    .line 6
    .line 7
    if-nez p2, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lw3/t;->B:Ljava/util/ArrayList;

    .line 13
    .line 14
    if-eqz p0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 17
    .line 18
    .line 19
    :cond_0
    return-void

    .line 20
    :cond_1
    iget-boolean p2, p0, Lw3/t;->C:Z

    .line 21
    .line 22
    if-nez p2, :cond_2

    .line 23
    .line 24
    invoke-interface {v0, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :cond_2
    iget-object p2, p0, Lw3/t;->B:Ljava/util/ArrayList;

    .line 29
    .line 30
    if-nez p2, :cond_3

    .line 31
    .line 32
    new-instance p2, Ljava/util/ArrayList;

    .line 33
    .line 34
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object p2, p0, Lw3/t;->B:Ljava/util/ArrayList;

    .line 38
    .line 39
    :cond_3
    invoke-interface {p2, p1}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public final u()V
    .locals 10

    .line 1
    iget-boolean v0, p0, Lw3/t;->J:Z

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x0

    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    invoke-virtual {p0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object v0, v0, Lv3/q1;->a:Lv2/r;

    .line 12
    .line 13
    iget-object v3, v0, Lv2/r;->g:Ljava/lang/Object;

    .line 14
    .line 15
    monitor-enter v3

    .line 16
    :try_start_0
    iget-object v0, v0, Lv2/r;->f:Ln2/b;

    .line 17
    .line 18
    iget v4, v0, Ln2/b;->f:I

    .line 19
    .line 20
    move v5, v2

    .line 21
    move v6, v5

    .line 22
    :goto_0
    if-ge v5, v4, :cond_2

    .line 23
    .line 24
    iget-object v7, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 25
    .line 26
    aget-object v7, v7, v5

    .line 27
    .line 28
    check-cast v7, Lv2/q;

    .line 29
    .line 30
    invoke-virtual {v7}, Lv2/q;->e()V

    .line 31
    .line 32
    .line 33
    iget-object v7, v7, Lv2/q;->f:Landroidx/collection/q0;

    .line 34
    .line 35
    invoke-virtual {v7}, Landroidx/collection/q0;->j()Z

    .line 36
    .line 37
    .line 38
    move-result v7

    .line 39
    if-nez v7, :cond_0

    .line 40
    .line 41
    add-int/lit8 v6, v6, 0x1

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_0
    if-lez v6, :cond_1

    .line 45
    .line 46
    iget-object v7, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 47
    .line 48
    sub-int v8, v5, v6

    .line 49
    .line 50
    aget-object v9, v7, v5

    .line 51
    .line 52
    aput-object v9, v7, v8

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :catchall_0
    move-exception p0

    .line 56
    goto :goto_2

    .line 57
    :cond_1
    :goto_1
    add-int/lit8 v5, v5, 0x1

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_2
    iget-object v5, v0, Ln2/b;->d:[Ljava/lang/Object;

    .line 61
    .line 62
    sub-int v6, v4, v6

    .line 63
    .line 64
    invoke-static {v5, v6, v4, v1}, Ljava/util/Arrays;->fill([Ljava/lang/Object;IILjava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iput v6, v0, Ln2/b;->f:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 68
    .line 69
    monitor-exit v3

    .line 70
    iput-boolean v2, p0, Lw3/t;->J:Z

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :goto_2
    monitor-exit v3

    .line 74
    throw p0

    .line 75
    :cond_3
    :goto_3
    iget-object v0, p0, Lw3/t;->O:Lw3/t0;

    .line 76
    .line 77
    if-eqz v0, :cond_4

    .line 78
    .line 79
    invoke-static {v0}, Lw3/t;->e(Landroid/view/ViewGroup;)V

    .line 80
    .line 81
    .line 82
    :cond_4
    iget-object v0, p0, Lw3/t;->I:Ly2/b;

    .line 83
    .line 84
    if-eqz v0, :cond_6

    .line 85
    .line 86
    iget-object v3, v0, Ly2/b;->h:Landroidx/collection/c0;

    .line 87
    .line 88
    iget v4, v3, Landroidx/collection/c0;->d:I

    .line 89
    .line 90
    if-nez v4, :cond_5

    .line 91
    .line 92
    iget-boolean v4, v0, Ly2/b;->i:Z

    .line 93
    .line 94
    if-eqz v4, :cond_5

    .line 95
    .line 96
    iget-object v4, v0, Ly2/b;->a:Lpv/g;

    .line 97
    .line 98
    iget-object v4, v4, Lpv/g;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v4, Landroid/view/autofill/AutofillManager;

    .line 101
    .line 102
    invoke-virtual {v4}, Landroid/view/autofill/AutofillManager;->commit()V

    .line 103
    .line 104
    .line 105
    iput-boolean v2, v0, Ly2/b;->i:Z

    .line 106
    .line 107
    :cond_5
    iget v3, v3, Landroidx/collection/c0;->d:I

    .line 108
    .line 109
    if-eqz v3, :cond_6

    .line 110
    .line 111
    const/4 v3, 0x1

    .line 112
    iput-boolean v3, v0, Ly2/b;->i:Z

    .line 113
    .line 114
    :cond_6
    :goto_4
    iget-object v0, p0, Lw3/t;->H1:Landroidx/collection/l0;

    .line 115
    .line 116
    invoke-virtual {v0}, Landroidx/collection/l0;->h()Z

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    if-eqz v0, :cond_a

    .line 121
    .line 122
    iget-object v0, p0, Lw3/t;->H1:Landroidx/collection/l0;

    .line 123
    .line 124
    invoke-virtual {v0, v2}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v0

    .line 128
    if-eqz v0, :cond_a

    .line 129
    .line 130
    iget-object v0, p0, Lw3/t;->H1:Landroidx/collection/l0;

    .line 131
    .line 132
    iget v0, v0, Landroidx/collection/l0;->b:I

    .line 133
    .line 134
    move v3, v2

    .line 135
    :goto_5
    if-ge v3, v0, :cond_9

    .line 136
    .line 137
    iget-object v4, p0, Lw3/t;->H1:Landroidx/collection/l0;

    .line 138
    .line 139
    invoke-virtual {v4, v3}, Landroidx/collection/l0;->e(I)Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v4

    .line 143
    check-cast v4, Lay0/a;

    .line 144
    .line 145
    iget-object v5, p0, Lw3/t;->H1:Landroidx/collection/l0;

    .line 146
    .line 147
    if-ltz v3, :cond_8

    .line 148
    .line 149
    iget v6, v5, Landroidx/collection/l0;->b:I

    .line 150
    .line 151
    if-ge v3, v6, :cond_8

    .line 152
    .line 153
    iget-object v5, v5, Landroidx/collection/l0;->a:[Ljava/lang/Object;

    .line 154
    .line 155
    aget-object v6, v5, v3

    .line 156
    .line 157
    aput-object v1, v5, v3

    .line 158
    .line 159
    if-eqz v4, :cond_7

    .line 160
    .line 161
    invoke-interface {v4}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 162
    .line 163
    .line 164
    :cond_7
    add-int/lit8 v3, v3, 0x1

    .line 165
    .line 166
    goto :goto_5

    .line 167
    :cond_8
    invoke-virtual {v5, v3}, Landroidx/collection/l0;->m(I)V

    .line 168
    .line 169
    .line 170
    throw v1

    .line 171
    :cond_9
    iget-object v3, p0, Lw3/t;->H1:Landroidx/collection/l0;

    .line 172
    .line 173
    invoke-virtual {v3, v2, v0}, Landroidx/collection/l0;->k(II)V

    .line 174
    .line 175
    .line 176
    goto :goto_4

    .line 177
    :cond_a
    return-void
.end method

.method public final v(Lv3/h0;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lw3/t;->v:Lw3/z;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iput-boolean v1, v0, Lw3/z;->A:Z

    .line 5
    .line 6
    invoke-virtual {v0}, Lw3/z;->v()Z

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    if-nez v2, :cond_0

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    invoke-virtual {v0, p1}, Lw3/z;->w(Lv3/h0;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    iget-object p0, p0, Lw3/t;->w:Lz2/e;

    .line 17
    .line 18
    iput-boolean v1, p0, Lz2/e;->j:Z

    .line 19
    .line 20
    invoke-virtual {p0}, Lz2/e;->e()Z

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    if-eqz p1, :cond_1

    .line 25
    .line 26
    iget-object p0, p0, Lz2/e;->k:Lxy0/j;

    .line 27
    .line 28
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-interface {p0, p1}, Lxy0/a0;->e(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    :cond_1
    return-void
.end method

.method public final w(Lv3/h0;ZZZ)V
    .locals 5

    .line 1
    iget-object v0, p0, Lw3/t;->R:Lv3/w0;

    .line 2
    .line 3
    if-eqz p2, :cond_b

    .line 4
    .line 5
    iget-object p2, v0, Lv3/w0;->b:Lrn/i;

    .line 6
    .line 7
    iget-object v1, p1, Lv3/h0;->j:Lv3/h0;

    .line 8
    .line 9
    iget-object v2, p1, Lv3/h0;->I:Lv3/l0;

    .line 10
    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const-string v1, "Error: requestLookaheadRemeasure cannot be called on a node outside LookaheadScope"

    .line 15
    .line 16
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    :goto_0
    iget-object v1, v2, Lv3/l0;->d:Lv3/d0;

    .line 20
    .line 21
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    const/4 v3, 0x1

    .line 26
    if-eqz v1, :cond_a

    .line 27
    .line 28
    if-eq v1, v3, :cond_c

    .line 29
    .line 30
    const/4 v4, 0x2

    .line 31
    if-eq v1, v4, :cond_a

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    if-eq v1, v4, :cond_a

    .line 35
    .line 36
    const/4 v4, 0x4

    .line 37
    if-ne v1, v4, :cond_9

    .line 38
    .line 39
    iget-boolean v1, v2, Lv3/l0;->e:Z

    .line 40
    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    if-nez p3, :cond_1

    .line 44
    .line 45
    goto/16 :goto_2

    .line 46
    .line 47
    :cond_1
    iput-boolean v3, v2, Lv3/l0;->e:Z

    .line 48
    .line 49
    iget-object p3, v2, Lv3/l0;->p:Lv3/y0;

    .line 50
    .line 51
    iput-boolean v3, p3, Lv3/y0;->y:Z

    .line 52
    .line 53
    iget-boolean p3, p1, Lv3/h0;->S:Z

    .line 54
    .line 55
    if-eqz p3, :cond_2

    .line 56
    .line 57
    goto :goto_2

    .line 58
    :cond_2
    invoke-virtual {p1}, Lv3/h0;->K()Ljava/lang/Boolean;

    .line 59
    .line 60
    .line 61
    move-result-object p3

    .line 62
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 63
    .line 64
    invoke-static {p3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result p3

    .line 68
    if-nez p3, :cond_3

    .line 69
    .line 70
    invoke-static {p1}, Lv3/w0;->h(Lv3/h0;)Z

    .line 71
    .line 72
    .line 73
    move-result p3

    .line 74
    if-eqz p3, :cond_4

    .line 75
    .line 76
    :cond_3
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 77
    .line 78
    .line 79
    move-result-object p3

    .line 80
    if-eqz p3, :cond_7

    .line 81
    .line 82
    iget-object p3, p3, Lv3/h0;->I:Lv3/l0;

    .line 83
    .line 84
    iget-boolean p3, p3, Lv3/l0;->e:Z

    .line 85
    .line 86
    if-ne p3, v3, :cond_7

    .line 87
    .line 88
    :cond_4
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 89
    .line 90
    .line 91
    move-result p3

    .line 92
    if-nez p3, :cond_5

    .line 93
    .line 94
    invoke-static {p1}, Lv3/w0;->i(Lv3/h0;)Z

    .line 95
    .line 96
    .line 97
    move-result p3

    .line 98
    if-eqz p3, :cond_8

    .line 99
    .line 100
    :cond_5
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 101
    .line 102
    .line 103
    move-result-object p3

    .line 104
    if-eqz p3, :cond_6

    .line 105
    .line 106
    invoke-virtual {p3}, Lv3/h0;->r()Z

    .line 107
    .line 108
    .line 109
    move-result p3

    .line 110
    if-ne p3, v3, :cond_6

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_6
    sget-object p3, Lv3/v;->f:Lv3/v;

    .line 114
    .line 115
    invoke-virtual {p2, p1, p3}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 116
    .line 117
    .line 118
    goto :goto_1

    .line 119
    :cond_7
    sget-object p3, Lv3/v;->d:Lv3/v;

    .line 120
    .line 121
    invoke-virtual {p2, p1, p3}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 122
    .line 123
    .line 124
    :cond_8
    :goto_1
    iget-boolean p2, v0, Lv3/w0;->d:Z

    .line 125
    .line 126
    if-nez p2, :cond_c

    .line 127
    .line 128
    if-eqz p4, :cond_c

    .line 129
    .line 130
    invoke-virtual {p0, p1}, Lw3/t;->C(Lv3/h0;)V

    .line 131
    .line 132
    .line 133
    return-void

    .line 134
    :cond_9
    new-instance p0, La8/r0;

    .line 135
    .line 136
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 137
    .line 138
    .line 139
    throw p0

    .line 140
    :cond_a
    iget-object p0, v0, Lv3/w0;->h:Ln2/b;

    .line 141
    .line 142
    new-instance p2, Lv3/v0;

    .line 143
    .line 144
    invoke-direct {p2, p1, v3, p3}, Lv3/v0;-><init>(Lv3/h0;ZZ)V

    .line 145
    .line 146
    .line 147
    invoke-virtual {p0, p2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    return-void

    .line 151
    :cond_b
    invoke-virtual {v0, p1, p3}, Lv3/w0;->p(Lv3/h0;Z)Z

    .line 152
    .line 153
    .line 154
    move-result p2

    .line 155
    if-eqz p2, :cond_c

    .line 156
    .line 157
    if-eqz p4, :cond_c

    .line 158
    .line 159
    invoke-virtual {p0, p1}, Lw3/t;->C(Lv3/h0;)V

    .line 160
    .line 161
    .line 162
    :cond_c
    :goto_2
    return-void
.end method

.method public final x(Lv3/h0;ZZ)V
    .locals 8

    .line 1
    iget-object v0, p1, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x4

    .line 5
    const/4 v3, 0x3

    .line 6
    const/4 v4, 0x2

    .line 7
    iget-object v5, p0, Lw3/t;->R:Lv3/w0;

    .line 8
    .line 9
    const/4 v6, 0x1

    .line 10
    if-eqz p2, :cond_b

    .line 11
    .line 12
    iget-object p2, v5, Lv3/w0;->b:Lrn/i;

    .line 13
    .line 14
    iget-object v7, v0, Lv3/l0;->d:Lv3/d0;

    .line 15
    .line 16
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    .line 17
    .line 18
    .line 19
    move-result v7

    .line 20
    if-eqz v7, :cond_1

    .line 21
    .line 22
    if-eq v7, v6, :cond_13

    .line 23
    .line 24
    if-eq v7, v4, :cond_1

    .line 25
    .line 26
    if-eq v7, v3, :cond_13

    .line 27
    .line 28
    if-ne v7, v2, :cond_0

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :cond_0
    new-instance p0, La8/r0;

    .line 32
    .line 33
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_1
    :goto_0
    iget-boolean v2, v0, Lv3/l0;->e:Z

    .line 38
    .line 39
    if-nez v2, :cond_2

    .line 40
    .line 41
    iget-boolean v2, v0, Lv3/l0;->f:Z

    .line 42
    .line 43
    if-eqz v2, :cond_3

    .line 44
    .line 45
    :cond_2
    if-nez p3, :cond_3

    .line 46
    .line 47
    goto/16 :goto_6

    .line 48
    .line 49
    :cond_3
    iput-boolean v6, v0, Lv3/l0;->f:Z

    .line 50
    .line 51
    iput-boolean v6, v0, Lv3/l0;->g:Z

    .line 52
    .line 53
    iget-object p3, v0, Lv3/l0;->p:Lv3/y0;

    .line 54
    .line 55
    iput-boolean v6, p3, Lv3/y0;->z:Z

    .line 56
    .line 57
    iput-boolean v6, p3, Lv3/y0;->A:Z

    .line 58
    .line 59
    iget-boolean p3, p1, Lv3/h0;->S:Z

    .line 60
    .line 61
    if-eqz p3, :cond_4

    .line 62
    .line 63
    goto/16 :goto_6

    .line 64
    .line 65
    :cond_4
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 66
    .line 67
    .line 68
    move-result-object p3

    .line 69
    invoke-virtual {p1}, Lv3/h0;->K()Ljava/lang/Boolean;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    sget-object v2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 74
    .line 75
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    if-eqz v0, :cond_7

    .line 80
    .line 81
    if-eqz p3, :cond_5

    .line 82
    .line 83
    iget-object v0, p3, Lv3/h0;->I:Lv3/l0;

    .line 84
    .line 85
    iget-boolean v0, v0, Lv3/l0;->e:Z

    .line 86
    .line 87
    if-ne v0, v6, :cond_5

    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_5
    if-eqz p3, :cond_6

    .line 91
    .line 92
    iget-object v0, p3, Lv3/h0;->I:Lv3/l0;

    .line 93
    .line 94
    iget-boolean v0, v0, Lv3/l0;->f:Z

    .line 95
    .line 96
    if-ne v0, v6, :cond_6

    .line 97
    .line 98
    goto :goto_1

    .line 99
    :cond_6
    sget-object p3, Lv3/v;->e:Lv3/v;

    .line 100
    .line 101
    invoke-virtual {p2, p1, p3}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 102
    .line 103
    .line 104
    goto :goto_2

    .line 105
    :cond_7
    :goto_1
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 106
    .line 107
    .line 108
    move-result v0

    .line 109
    if-eqz v0, :cond_a

    .line 110
    .line 111
    if-eqz p3, :cond_8

    .line 112
    .line 113
    invoke-virtual {p3}, Lv3/h0;->q()Z

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    if-ne v0, v6, :cond_8

    .line 118
    .line 119
    goto :goto_2

    .line 120
    :cond_8
    if-eqz p3, :cond_9

    .line 121
    .line 122
    invoke-virtual {p3}, Lv3/h0;->r()Z

    .line 123
    .line 124
    .line 125
    move-result p3

    .line 126
    if-ne p3, v6, :cond_9

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_9
    sget-object p3, Lv3/v;->g:Lv3/v;

    .line 130
    .line 131
    invoke-virtual {p2, p1, p3}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 132
    .line 133
    .line 134
    :cond_a
    :goto_2
    iget-boolean p1, v5, Lv3/w0;->d:Z

    .line 135
    .line 136
    if-nez p1, :cond_13

    .line 137
    .line 138
    invoke-virtual {p0, v1}, Lw3/t;->C(Lv3/h0;)V

    .line 139
    .line 140
    .line 141
    return-void

    .line 142
    :cond_b
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 143
    .line 144
    .line 145
    iget-object p2, v0, Lv3/l0;->d:Lv3/d0;

    .line 146
    .line 147
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 148
    .line 149
    .line 150
    move-result p2

    .line 151
    if-eqz p2, :cond_13

    .line 152
    .line 153
    if-eq p2, v6, :cond_13

    .line 154
    .line 155
    if-eq p2, v4, :cond_13

    .line 156
    .line 157
    if-eq p2, v3, :cond_13

    .line 158
    .line 159
    if-ne p2, v2, :cond_12

    .line 160
    .line 161
    invoke-virtual {p1}, Lv3/h0;->v()Lv3/h0;

    .line 162
    .line 163
    .line 164
    move-result-object p2

    .line 165
    if-eqz p2, :cond_d

    .line 166
    .line 167
    invoke-virtual {p2}, Lv3/h0;->J()Z

    .line 168
    .line 169
    .line 170
    move-result v2

    .line 171
    if-eqz v2, :cond_c

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_c
    const/4 v2, 0x0

    .line 175
    goto :goto_4

    .line 176
    :cond_d
    :goto_3
    move v2, v6

    .line 177
    :goto_4
    if-nez p3, :cond_e

    .line 178
    .line 179
    invoke-virtual {p1}, Lv3/h0;->r()Z

    .line 180
    .line 181
    .line 182
    move-result p3

    .line 183
    if-nez p3, :cond_13

    .line 184
    .line 185
    invoke-virtual {p1}, Lv3/h0;->q()Z

    .line 186
    .line 187
    .line 188
    move-result p3

    .line 189
    if-eqz p3, :cond_e

    .line 190
    .line 191
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 192
    .line 193
    .line 194
    move-result p3

    .line 195
    if-ne p3, v2, :cond_e

    .line 196
    .line 197
    invoke-virtual {p1}, Lv3/h0;->J()Z

    .line 198
    .line 199
    .line 200
    move-result p3

    .line 201
    iget-object v3, v0, Lv3/l0;->p:Lv3/y0;

    .line 202
    .line 203
    iget-boolean v3, v3, Lv3/y0;->x:Z

    .line 204
    .line 205
    if-ne p3, v3, :cond_e

    .line 206
    .line 207
    goto :goto_6

    .line 208
    :cond_e
    iget-object p3, v0, Lv3/l0;->p:Lv3/y0;

    .line 209
    .line 210
    iput-boolean v6, p3, Lv3/y0;->z:Z

    .line 211
    .line 212
    iput-boolean v6, p3, Lv3/y0;->A:Z

    .line 213
    .line 214
    iget-boolean v0, p1, Lv3/h0;->S:Z

    .line 215
    .line 216
    if-eqz v0, :cond_f

    .line 217
    .line 218
    goto :goto_6

    .line 219
    :cond_f
    iget-boolean p3, p3, Lv3/y0;->x:Z

    .line 220
    .line 221
    if-eqz p3, :cond_13

    .line 222
    .line 223
    if-eqz v2, :cond_13

    .line 224
    .line 225
    if-eqz p2, :cond_10

    .line 226
    .line 227
    invoke-virtual {p2}, Lv3/h0;->q()Z

    .line 228
    .line 229
    .line 230
    move-result p3

    .line 231
    if-ne p3, v6, :cond_10

    .line 232
    .line 233
    goto :goto_5

    .line 234
    :cond_10
    if-eqz p2, :cond_11

    .line 235
    .line 236
    invoke-virtual {p2}, Lv3/h0;->r()Z

    .line 237
    .line 238
    .line 239
    move-result p2

    .line 240
    if-ne p2, v6, :cond_11

    .line 241
    .line 242
    goto :goto_5

    .line 243
    :cond_11
    iget-object p2, v5, Lv3/w0;->b:Lrn/i;

    .line 244
    .line 245
    sget-object p3, Lv3/v;->g:Lv3/v;

    .line 246
    .line 247
    invoke-virtual {p2, p1, p3}, Lrn/i;->n(Lv3/h0;Lv3/v;)V

    .line 248
    .line 249
    .line 250
    :goto_5
    iget-boolean p1, v5, Lv3/w0;->d:Z

    .line 251
    .line 252
    if-nez p1, :cond_13

    .line 253
    .line 254
    invoke-virtual {p0, v1}, Lw3/t;->C(Lv3/h0;)V

    .line 255
    .line 256
    .line 257
    return-void

    .line 258
    :cond_12
    new-instance p0, La8/r0;

    .line 259
    .line 260
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 261
    .line 262
    .line 263
    throw p0

    .line 264
    :cond_13
    :goto_6
    return-void
.end method

.method public final y()V
    .locals 3

    .line 1
    iget-object v0, p0, Lw3/t;->v:Lw3/z;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    iput-boolean v1, v0, Lw3/z;->A:Z

    .line 5
    .line 6
    invoke-virtual {v0}, Lw3/z;->v()Z

    .line 7
    .line 8
    .line 9
    move-result v2

    .line 10
    if-eqz v2, :cond_0

    .line 11
    .line 12
    iget-boolean v2, v0, Lw3/z;->L:Z

    .line 13
    .line 14
    if-nez v2, :cond_0

    .line 15
    .line 16
    iput-boolean v1, v0, Lw3/z;->L:Z

    .line 17
    .line 18
    iget-object v2, v0, Lw3/z;->l:Landroid/os/Handler;

    .line 19
    .line 20
    iget-object v0, v0, Lw3/z;->N:Lm8/o;

    .line 21
    .line 22
    invoke-virtual {v2, v0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 23
    .line 24
    .line 25
    :cond_0
    iget-object p0, p0, Lw3/t;->w:Lz2/e;

    .line 26
    .line 27
    iput-boolean v1, p0, Lz2/e;->j:Z

    .line 28
    .line 29
    invoke-virtual {p0}, Lz2/e;->e()Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-eqz v0, :cond_1

    .line 34
    .line 35
    iget-boolean v0, p0, Lz2/e;->q:Z

    .line 36
    .line 37
    if-nez v0, :cond_1

    .line 38
    .line 39
    iput-boolean v1, p0, Lz2/e;->q:Z

    .line 40
    .line 41
    iget-object v0, p0, Lz2/e;->l:Landroid/os/Handler;

    .line 42
    .line 43
    iget-object p0, p0, Lz2/e;->r:Lz2/a;

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Landroid/os/Handler;->post(Ljava/lang/Runnable;)Z

    .line 46
    .line 47
    .line 48
    :cond_1
    return-void
.end method

.method public final z()V
    .locals 6

    .line 1
    iget-boolean v0, p0, Lw3/t;->b0:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-wide v2, p0, Lw3/t;->a0:J

    .line 10
    .line 11
    cmp-long v2, v0, v2

    .line 12
    .line 13
    if-eqz v2, :cond_1

    .line 14
    .line 15
    iput-wide v0, p0, Lw3/t;->a0:J

    .line 16
    .line 17
    iget-object v0, p0, Lw3/t;->O1:Lw3/a1;

    .line 18
    .line 19
    iget-object v1, p0, Lw3/t;->V:[F

    .line 20
    .line 21
    invoke-virtual {v0, p0, v1}, Lw3/a1;->a(Landroid/view/View;[F)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lw3/t;->W:[F

    .line 25
    .line 26
    invoke-static {v1, v0}, Lw3/h0;->w([F[F)Z

    .line 27
    .line 28
    .line 29
    invoke-virtual {p0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 30
    .line 31
    .line 32
    move-result-object v0

    .line 33
    move-object v1, p0

    .line 34
    :goto_0
    instance-of v2, v0, Landroid/view/ViewGroup;

    .line 35
    .line 36
    if-eqz v2, :cond_0

    .line 37
    .line 38
    move-object v1, v0

    .line 39
    check-cast v1, Landroid/view/View;

    .line 40
    .line 41
    move-object v0, v1

    .line 42
    check-cast v0, Landroid/view/ViewGroup;

    .line 43
    .line 44
    invoke-virtual {v0}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    goto :goto_0

    .line 49
    :cond_0
    iget-object v0, p0, Lw3/t;->T:[I

    .line 50
    .line 51
    invoke-virtual {v1, v0}, Landroid/view/View;->getLocationOnScreen([I)V

    .line 52
    .line 53
    .line 54
    const/4 v2, 0x0

    .line 55
    aget v3, v0, v2

    .line 56
    .line 57
    int-to-float v3, v3

    .line 58
    const/4 v4, 0x1

    .line 59
    aget v5, v0, v4

    .line 60
    .line 61
    int-to-float v5, v5

    .line 62
    invoke-virtual {v1, v0}, Landroid/view/View;->getLocationInWindow([I)V

    .line 63
    .line 64
    .line 65
    aget v1, v0, v2

    .line 66
    .line 67
    int-to-float v1, v1

    .line 68
    aget v0, v0, v4

    .line 69
    .line 70
    int-to-float v0, v0

    .line 71
    sub-float/2addr v3, v1

    .line 72
    sub-float/2addr v5, v0

    .line 73
    invoke-static {v3}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    int-to-long v0, v0

    .line 78
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    int-to-long v2, v2

    .line 83
    const/16 v4, 0x20

    .line 84
    .line 85
    shl-long/2addr v0, v4

    .line 86
    const-wide v4, 0xffffffffL

    .line 87
    .line 88
    .line 89
    .line 90
    .line 91
    and-long/2addr v2, v4

    .line 92
    or-long/2addr v0, v2

    .line 93
    iput-wide v0, p0, Lw3/t;->c0:J

    .line 94
    .line 95
    :cond_1
    return-void
.end method

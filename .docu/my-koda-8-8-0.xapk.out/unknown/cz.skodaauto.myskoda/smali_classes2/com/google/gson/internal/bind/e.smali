.class public abstract Lcom/google/gson/internal/bind/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final A:Lcom/google/gson/z;

.field public static final B:Lcom/google/gson/z;

.field public static final a:Lcom/google/gson/z;

.field public static final b:Lcom/google/gson/z;

.field public static final c:Lcom/google/gson/y;

.field public static final d:Lcom/google/gson/z;

.field public static final e:Lcom/google/gson/z;

.field public static final f:Lcom/google/gson/z;

.field public static final g:Lcom/google/gson/z;

.field public static final h:Lcom/google/gson/z;

.field public static final i:Lcom/google/gson/z;

.field public static final j:Lcom/google/gson/z;

.field public static final k:Lcom/google/gson/y;

.field public static final l:Lcom/google/gson/z;

.field public static final m:Lcom/google/gson/y;

.field public static final n:Lcom/google/gson/y;

.field public static final o:Lcom/google/gson/y;

.field public static final p:Lcom/google/gson/z;

.field public static final q:Lcom/google/gson/z;

.field public static final r:Lcom/google/gson/z;

.field public static final s:Lcom/google/gson/z;

.field public static final t:Lcom/google/gson/z;

.field public static final u:Lcom/google/gson/z;

.field public static final v:Lcom/google/gson/z;

.field public static final w:Lcom/google/gson/z;

.field public static final x:Lcom/google/gson/z;

.field public static final y:Lcom/google/gson/z;

.field public static final z:Lcom/google/gson/y;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$1;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$1;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 11
    .line 12
    const-class v2, Ljava/lang/Class;

    .line 13
    .line 14
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 15
    .line 16
    .line 17
    sput-object v1, Lcom/google/gson/internal/bind/e;->a:Lcom/google/gson/z;

    .line 18
    .line 19
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$2;

    .line 20
    .line 21
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$2;-><init>()V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 29
    .line 30
    const-class v2, Ljava/util/BitSet;

    .line 31
    .line 32
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 33
    .line 34
    .line 35
    sput-object v1, Lcom/google/gson/internal/bind/e;->b:Lcom/google/gson/z;

    .line 36
    .line 37
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$3;

    .line 38
    .line 39
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$3;-><init>()V

    .line 40
    .line 41
    .line 42
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$4;

    .line 43
    .line 44
    invoke-direct {v1}, Lcom/google/gson/internal/bind/TypeAdapters$4;-><init>()V

    .line 45
    .line 46
    .line 47
    sput-object v1, Lcom/google/gson/internal/bind/e;->c:Lcom/google/gson/y;

    .line 48
    .line 49
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$30;

    .line 50
    .line 51
    sget-object v2, Ljava/lang/Boolean;->TYPE:Ljava/lang/Class;

    .line 52
    .line 53
    const-class v3, Ljava/lang/Boolean;

    .line 54
    .line 55
    invoke-direct {v1, v2, v3, v0}, Lcom/google/gson/internal/bind/TypeAdapters$30;-><init>(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 56
    .line 57
    .line 58
    sput-object v1, Lcom/google/gson/internal/bind/e;->d:Lcom/google/gson/z;

    .line 59
    .line 60
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$5;

    .line 61
    .line 62
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$5;-><init>()V

    .line 63
    .line 64
    .line 65
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$30;

    .line 66
    .line 67
    sget-object v2, Ljava/lang/Byte;->TYPE:Ljava/lang/Class;

    .line 68
    .line 69
    const-class v3, Ljava/lang/Byte;

    .line 70
    .line 71
    invoke-direct {v1, v2, v3, v0}, Lcom/google/gson/internal/bind/TypeAdapters$30;-><init>(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 72
    .line 73
    .line 74
    sput-object v1, Lcom/google/gson/internal/bind/e;->e:Lcom/google/gson/z;

    .line 75
    .line 76
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$6;

    .line 77
    .line 78
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$6;-><init>()V

    .line 79
    .line 80
    .line 81
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$30;

    .line 82
    .line 83
    sget-object v2, Ljava/lang/Short;->TYPE:Ljava/lang/Class;

    .line 84
    .line 85
    const-class v3, Ljava/lang/Short;

    .line 86
    .line 87
    invoke-direct {v1, v2, v3, v0}, Lcom/google/gson/internal/bind/TypeAdapters$30;-><init>(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 88
    .line 89
    .line 90
    sput-object v1, Lcom/google/gson/internal/bind/e;->f:Lcom/google/gson/z;

    .line 91
    .line 92
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$7;

    .line 93
    .line 94
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$7;-><init>()V

    .line 95
    .line 96
    .line 97
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$30;

    .line 98
    .line 99
    sget-object v2, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 100
    .line 101
    const-class v3, Ljava/lang/Integer;

    .line 102
    .line 103
    invoke-direct {v1, v2, v3, v0}, Lcom/google/gson/internal/bind/TypeAdapters$30;-><init>(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 104
    .line 105
    .line 106
    sput-object v1, Lcom/google/gson/internal/bind/e;->g:Lcom/google/gson/z;

    .line 107
    .line 108
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$8;

    .line 109
    .line 110
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$8;-><init>()V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v0}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 114
    .line 115
    .line 116
    move-result-object v0

    .line 117
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 118
    .line 119
    const-class v2, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 120
    .line 121
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 122
    .line 123
    .line 124
    sput-object v1, Lcom/google/gson/internal/bind/e;->h:Lcom/google/gson/z;

    .line 125
    .line 126
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$9;

    .line 127
    .line 128
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$9;-><init>()V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 136
    .line 137
    const-class v2, Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 138
    .line 139
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 140
    .line 141
    .line 142
    sput-object v1, Lcom/google/gson/internal/bind/e;->i:Lcom/google/gson/z;

    .line 143
    .line 144
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$10;

    .line 145
    .line 146
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$10;-><init>()V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v0}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 154
    .line 155
    const-class v2, Ljava/util/concurrent/atomic/AtomicIntegerArray;

    .line 156
    .line 157
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 158
    .line 159
    .line 160
    sput-object v1, Lcom/google/gson/internal/bind/e;->j:Lcom/google/gson/z;

    .line 161
    .line 162
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$11;

    .line 163
    .line 164
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$11;-><init>()V

    .line 165
    .line 166
    .line 167
    sput-object v0, Lcom/google/gson/internal/bind/e;->k:Lcom/google/gson/y;

    .line 168
    .line 169
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$12;

    .line 170
    .line 171
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$12;-><init>()V

    .line 172
    .line 173
    .line 174
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$13;

    .line 175
    .line 176
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$13;-><init>()V

    .line 177
    .line 178
    .line 179
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$14;

    .line 180
    .line 181
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$14;-><init>()V

    .line 182
    .line 183
    .line 184
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$30;

    .line 185
    .line 186
    sget-object v2, Ljava/lang/Character;->TYPE:Ljava/lang/Class;

    .line 187
    .line 188
    const-class v3, Ljava/lang/Character;

    .line 189
    .line 190
    invoke-direct {v1, v2, v3, v0}, Lcom/google/gson/internal/bind/TypeAdapters$30;-><init>(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 191
    .line 192
    .line 193
    sput-object v1, Lcom/google/gson/internal/bind/e;->l:Lcom/google/gson/z;

    .line 194
    .line 195
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$15;

    .line 196
    .line 197
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$15;-><init>()V

    .line 198
    .line 199
    .line 200
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$16;

    .line 201
    .line 202
    invoke-direct {v1}, Lcom/google/gson/internal/bind/TypeAdapters$16;-><init>()V

    .line 203
    .line 204
    .line 205
    sput-object v1, Lcom/google/gson/internal/bind/e;->m:Lcom/google/gson/y;

    .line 206
    .line 207
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$17;

    .line 208
    .line 209
    invoke-direct {v1}, Lcom/google/gson/internal/bind/TypeAdapters$17;-><init>()V

    .line 210
    .line 211
    .line 212
    sput-object v1, Lcom/google/gson/internal/bind/e;->n:Lcom/google/gson/y;

    .line 213
    .line 214
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$18;

    .line 215
    .line 216
    invoke-direct {v1}, Lcom/google/gson/internal/bind/TypeAdapters$18;-><init>()V

    .line 217
    .line 218
    .line 219
    sput-object v1, Lcom/google/gson/internal/bind/e;->o:Lcom/google/gson/y;

    .line 220
    .line 221
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 222
    .line 223
    const-class v2, Ljava/lang/String;

    .line 224
    .line 225
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 226
    .line 227
    .line 228
    sput-object v1, Lcom/google/gson/internal/bind/e;->p:Lcom/google/gson/z;

    .line 229
    .line 230
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$19;

    .line 231
    .line 232
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$19;-><init>()V

    .line 233
    .line 234
    .line 235
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 236
    .line 237
    const-class v2, Ljava/lang/StringBuilder;

    .line 238
    .line 239
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 240
    .line 241
    .line 242
    sput-object v1, Lcom/google/gson/internal/bind/e;->q:Lcom/google/gson/z;

    .line 243
    .line 244
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$20;

    .line 245
    .line 246
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$20;-><init>()V

    .line 247
    .line 248
    .line 249
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 250
    .line 251
    const-class v2, Ljava/lang/StringBuffer;

    .line 252
    .line 253
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 254
    .line 255
    .line 256
    sput-object v1, Lcom/google/gson/internal/bind/e;->r:Lcom/google/gson/z;

    .line 257
    .line 258
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$21;

    .line 259
    .line 260
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$21;-><init>()V

    .line 261
    .line 262
    .line 263
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 264
    .line 265
    const-class v2, Ljava/net/URL;

    .line 266
    .line 267
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 268
    .line 269
    .line 270
    sput-object v1, Lcom/google/gson/internal/bind/e;->s:Lcom/google/gson/z;

    .line 271
    .line 272
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$22;

    .line 273
    .line 274
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$22;-><init>()V

    .line 275
    .line 276
    .line 277
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 278
    .line 279
    const-class v2, Ljava/net/URI;

    .line 280
    .line 281
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 282
    .line 283
    .line 284
    sput-object v1, Lcom/google/gson/internal/bind/e;->t:Lcom/google/gson/z;

    .line 285
    .line 286
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$23;

    .line 287
    .line 288
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$23;-><init>()V

    .line 289
    .line 290
    .line 291
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$32;

    .line 292
    .line 293
    const-class v2, Ljava/net/InetAddress;

    .line 294
    .line 295
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$32;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 296
    .line 297
    .line 298
    sput-object v1, Lcom/google/gson/internal/bind/e;->u:Lcom/google/gson/z;

    .line 299
    .line 300
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$24;

    .line 301
    .line 302
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$24;-><init>()V

    .line 303
    .line 304
    .line 305
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 306
    .line 307
    const-class v2, Ljava/util/UUID;

    .line 308
    .line 309
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 310
    .line 311
    .line 312
    sput-object v1, Lcom/google/gson/internal/bind/e;->v:Lcom/google/gson/z;

    .line 313
    .line 314
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$25;

    .line 315
    .line 316
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$25;-><init>()V

    .line 317
    .line 318
    .line 319
    invoke-virtual {v0}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 320
    .line 321
    .line 322
    move-result-object v0

    .line 323
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 324
    .line 325
    const-class v2, Ljava/util/Currency;

    .line 326
    .line 327
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 328
    .line 329
    .line 330
    sput-object v1, Lcom/google/gson/internal/bind/e;->w:Lcom/google/gson/z;

    .line 331
    .line 332
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$26;

    .line 333
    .line 334
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$26;-><init>()V

    .line 335
    .line 336
    .line 337
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$31;

    .line 338
    .line 339
    invoke-direct {v1, v0}, Lcom/google/gson/internal/bind/TypeAdapters$31;-><init>(Lcom/google/gson/y;)V

    .line 340
    .line 341
    .line 342
    sput-object v1, Lcom/google/gson/internal/bind/e;->x:Lcom/google/gson/z;

    .line 343
    .line 344
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$27;

    .line 345
    .line 346
    invoke-direct {v0}, Lcom/google/gson/internal/bind/TypeAdapters$27;-><init>()V

    .line 347
    .line 348
    .line 349
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 350
    .line 351
    const-class v2, Ljava/util/Locale;

    .line 352
    .line 353
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 354
    .line 355
    .line 356
    sput-object v1, Lcom/google/gson/internal/bind/e;->y:Lcom/google/gson/z;

    .line 357
    .line 358
    sget-object v0, Lcom/google/gson/internal/bind/JsonElementTypeAdapter;->a:Lcom/google/gson/internal/bind/JsonElementTypeAdapter;

    .line 359
    .line 360
    sput-object v0, Lcom/google/gson/internal/bind/e;->z:Lcom/google/gson/y;

    .line 361
    .line 362
    new-instance v1, Lcom/google/gson/internal/bind/TypeAdapters$32;

    .line 363
    .line 364
    const-class v2, Lcom/google/gson/n;

    .line 365
    .line 366
    invoke-direct {v1, v2, v0}, Lcom/google/gson/internal/bind/TypeAdapters$32;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 367
    .line 368
    .line 369
    sput-object v1, Lcom/google/gson/internal/bind/e;->A:Lcom/google/gson/z;

    .line 370
    .line 371
    sget-object v0, Lcom/google/gson/internal/bind/EnumTypeAdapter;->d:Lcom/google/gson/z;

    .line 372
    .line 373
    sput-object v0, Lcom/google/gson/internal/bind/e;->B:Lcom/google/gson/z;

    .line 374
    .line 375
    return-void
.end method

.method public static a(Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/y;)Lcom/google/gson/z;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$28;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lcom/google/gson/internal/bind/TypeAdapters$28;-><init>(Lcom/google/gson/reflect/TypeToken;Lcom/google/gson/y;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static b(Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$29;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lcom/google/gson/internal/bind/TypeAdapters$29;-><init>(Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public static c(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;
    .locals 1

    .line 1
    new-instance v0, Lcom/google/gson/internal/bind/TypeAdapters$30;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1, p2}, Lcom/google/gson/internal/bind/TypeAdapters$30;-><init>(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

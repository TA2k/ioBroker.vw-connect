.class public final Lcom/google/gson/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final k:Lcom/google/gson/i;

.field public static final l:Lcom/google/gson/a;

.field public static final m:Lcom/google/gson/t;

.field public static final n:Lcom/google/gson/u;


# instance fields
.field public final a:Ljava/lang/ThreadLocal;

.field public final b:Ljava/util/concurrent/ConcurrentHashMap;

.field public final c:Lcom/google/android/gms/internal/measurement/i4;

.field public final d:Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

.field public final e:Ljava/util/List;

.field public final f:Z

.field public final g:Lcom/google/gson/i;

.field public final h:Ljava/util/List;

.field public final i:Ljava/util/List;

.field public final j:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    sget-object v0, Lcom/google/gson/i;->d:Lcom/google/gson/i;

    .line 2
    .line 3
    sput-object v0, Lcom/google/gson/j;->k:Lcom/google/gson/i;

    .line 4
    .line 5
    sget-object v0, Lcom/google/gson/h;->d:Lcom/google/gson/a;

    .line 6
    .line 7
    sput-object v0, Lcom/google/gson/j;->l:Lcom/google/gson/a;

    .line 8
    .line 9
    sget-object v0, Lcom/google/gson/x;->d:Lcom/google/gson/t;

    .line 10
    .line 11
    sput-object v0, Lcom/google/gson/j;->m:Lcom/google/gson/t;

    .line 12
    .line 13
    sget-object v0, Lcom/google/gson/x;->e:Lcom/google/gson/u;

    .line 14
    .line 15
    sput-object v0, Lcom/google/gson/j;->n:Lcom/google/gson/u;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Lcom/google/gson/internal/Excluder;Lcom/google/gson/h;Ljava/util/Map;ZLcom/google/gson/i;ZILjava/util/List;Ljava/util/List;Ljava/util/List;Lcom/google/gson/x;Lcom/google/gson/x;Ljava/util/List;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/ThreadLocal;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/google/gson/j;->a:Ljava/lang/ThreadLocal;

    .line 10
    .line 11
    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lcom/google/gson/j;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 17
    .line 18
    move-object v0, p3

    .line 19
    move-object p3, p2

    .line 20
    new-instance p2, Lcom/google/android/gms/internal/measurement/i4;

    .line 21
    .line 22
    invoke-direct {p2, p13, v0, p6}, Lcom/google/android/gms/internal/measurement/i4;-><init>(Ljava/util/List;Ljava/util/Map;Z)V

    .line 23
    .line 24
    .line 25
    iput-object p2, p0, Lcom/google/gson/j;->c:Lcom/google/android/gms/internal/measurement/i4;

    .line 26
    .line 27
    iput-boolean p4, p0, Lcom/google/gson/j;->f:Z

    .line 28
    .line 29
    iput-object p5, p0, Lcom/google/gson/j;->g:Lcom/google/gson/i;

    .line 30
    .line 31
    iput-object p8, p0, Lcom/google/gson/j;->h:Ljava/util/List;

    .line 32
    .line 33
    iput-object p9, p0, Lcom/google/gson/j;->i:Ljava/util/List;

    .line 34
    .line 35
    iput-object p13, p0, Lcom/google/gson/j;->j:Ljava/util/List;

    .line 36
    .line 37
    new-instance p8, Ljava/util/ArrayList;

    .line 38
    .line 39
    invoke-direct {p8}, Ljava/util/ArrayList;-><init>()V

    .line 40
    .line 41
    .line 42
    sget-object p4, Lcom/google/gson/internal/bind/e;->A:Lcom/google/gson/z;

    .line 43
    .line 44
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    invoke-static {p11}, Lcom/google/gson/internal/bind/ObjectTypeAdapter;->d(Lcom/google/gson/x;)Lcom/google/gson/z;

    .line 48
    .line 49
    .line 50
    move-result-object p4

    .line 51
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    invoke-virtual {p8, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 55
    .line 56
    .line 57
    invoke-virtual {p8, p10}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 58
    .line 59
    .line 60
    sget-object p4, Lcom/google/gson/internal/bind/e;->p:Lcom/google/gson/z;

    .line 61
    .line 62
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    sget-object p4, Lcom/google/gson/internal/bind/e;->g:Lcom/google/gson/z;

    .line 66
    .line 67
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    sget-object p4, Lcom/google/gson/internal/bind/e;->d:Lcom/google/gson/z;

    .line 71
    .line 72
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    sget-object p4, Lcom/google/gson/internal/bind/e;->e:Lcom/google/gson/z;

    .line 76
    .line 77
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    sget-object p4, Lcom/google/gson/internal/bind/e;->f:Lcom/google/gson/z;

    .line 81
    .line 82
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 83
    .line 84
    .line 85
    const/4 p4, 0x1

    .line 86
    if-ne p7, p4, :cond_0

    .line 87
    .line 88
    sget-object p4, Lcom/google/gson/internal/bind/e;->k:Lcom/google/gson/y;

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_0
    new-instance p4, Lcom/google/gson/Gson$3;

    .line 92
    .line 93
    invoke-direct {p4}, Lcom/google/gson/Gson$3;-><init>()V

    .line 94
    .line 95
    .line 96
    :goto_0
    sget-object p5, Ljava/lang/Long;->TYPE:Ljava/lang/Class;

    .line 97
    .line 98
    const-class p6, Ljava/lang/Long;

    .line 99
    .line 100
    invoke-static {p5, p6, p4}, Lcom/google/gson/internal/bind/e;->c(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 101
    .line 102
    .line 103
    move-result-object p5

    .line 104
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    new-instance p5, Lcom/google/gson/Gson$1;

    .line 108
    .line 109
    invoke-direct {p5}, Ljava/lang/Object;-><init>()V

    .line 110
    .line 111
    .line 112
    sget-object p6, Ljava/lang/Double;->TYPE:Ljava/lang/Class;

    .line 113
    .line 114
    const-class p7, Ljava/lang/Double;

    .line 115
    .line 116
    invoke-static {p6, p7, p5}, Lcom/google/gson/internal/bind/e;->c(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 117
    .line 118
    .line 119
    move-result-object p5

    .line 120
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    new-instance p5, Lcom/google/gson/Gson$2;

    .line 124
    .line 125
    invoke-direct {p5}, Ljava/lang/Object;-><init>()V

    .line 126
    .line 127
    .line 128
    sget-object p6, Ljava/lang/Float;->TYPE:Ljava/lang/Class;

    .line 129
    .line 130
    const-class p7, Ljava/lang/Float;

    .line 131
    .line 132
    invoke-static {p6, p7, p5}, Lcom/google/gson/internal/bind/e;->c(Ljava/lang/Class;Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 133
    .line 134
    .line 135
    move-result-object p5

    .line 136
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 137
    .line 138
    .line 139
    sget-object p5, Lcom/google/gson/x;->e:Lcom/google/gson/u;

    .line 140
    .line 141
    if-ne p12, p5, :cond_1

    .line 142
    .line 143
    sget-object p5, Lcom/google/gson/internal/bind/NumberTypeAdapter;->b:Lcom/google/gson/z;

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_1
    invoke-static {p12}, Lcom/google/gson/internal/bind/NumberTypeAdapter;->d(Lcom/google/gson/x;)Lcom/google/gson/z;

    .line 147
    .line 148
    .line 149
    move-result-object p5

    .line 150
    :goto_1
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    sget-object p5, Lcom/google/gson/internal/bind/e;->h:Lcom/google/gson/z;

    .line 154
    .line 155
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    sget-object p5, Lcom/google/gson/internal/bind/e;->i:Lcom/google/gson/z;

    .line 159
    .line 160
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    new-instance p5, Lcom/google/gson/Gson$4;

    .line 164
    .line 165
    invoke-direct {p5, p4}, Lcom/google/gson/Gson$4;-><init>(Lcom/google/gson/y;)V

    .line 166
    .line 167
    .line 168
    invoke-virtual {p5}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 169
    .line 170
    .line 171
    move-result-object p5

    .line 172
    const-class p6, Ljava/util/concurrent/atomic/AtomicLong;

    .line 173
    .line 174
    invoke-static {p6, p5}, Lcom/google/gson/internal/bind/e;->b(Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 175
    .line 176
    .line 177
    move-result-object p5

    .line 178
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    new-instance p5, Lcom/google/gson/Gson$5;

    .line 182
    .line 183
    invoke-direct {p5, p4}, Lcom/google/gson/Gson$5;-><init>(Lcom/google/gson/y;)V

    .line 184
    .line 185
    .line 186
    invoke-virtual {p5}, Lcom/google/gson/y;->a()Lcom/google/gson/y;

    .line 187
    .line 188
    .line 189
    move-result-object p4

    .line 190
    const-class p5, Ljava/util/concurrent/atomic/AtomicLongArray;

    .line 191
    .line 192
    invoke-static {p5, p4}, Lcom/google/gson/internal/bind/e;->b(Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 193
    .line 194
    .line 195
    move-result-object p4

    .line 196
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 197
    .line 198
    .line 199
    sget-object p4, Lcom/google/gson/internal/bind/e;->j:Lcom/google/gson/z;

    .line 200
    .line 201
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 202
    .line 203
    .line 204
    sget-object p4, Lcom/google/gson/internal/bind/e;->l:Lcom/google/gson/z;

    .line 205
    .line 206
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    sget-object p4, Lcom/google/gson/internal/bind/e;->q:Lcom/google/gson/z;

    .line 210
    .line 211
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    sget-object p4, Lcom/google/gson/internal/bind/e;->r:Lcom/google/gson/z;

    .line 215
    .line 216
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    const-class p4, Ljava/math/BigDecimal;

    .line 220
    .line 221
    sget-object p5, Lcom/google/gson/internal/bind/e;->m:Lcom/google/gson/y;

    .line 222
    .line 223
    invoke-static {p4, p5}, Lcom/google/gson/internal/bind/e;->b(Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 224
    .line 225
    .line 226
    move-result-object p4

    .line 227
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 228
    .line 229
    .line 230
    const-class p4, Ljava/math/BigInteger;

    .line 231
    .line 232
    sget-object p5, Lcom/google/gson/internal/bind/e;->n:Lcom/google/gson/y;

    .line 233
    .line 234
    invoke-static {p4, p5}, Lcom/google/gson/internal/bind/e;->b(Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 235
    .line 236
    .line 237
    move-result-object p4

    .line 238
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 239
    .line 240
    .line 241
    const-class p4, Lcom/google/gson/internal/h;

    .line 242
    .line 243
    sget-object p5, Lcom/google/gson/internal/bind/e;->o:Lcom/google/gson/y;

    .line 244
    .line 245
    invoke-static {p4, p5}, Lcom/google/gson/internal/bind/e;->b(Ljava/lang/Class;Lcom/google/gson/y;)Lcom/google/gson/z;

    .line 246
    .line 247
    .line 248
    move-result-object p4

    .line 249
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 250
    .line 251
    .line 252
    sget-object p4, Lcom/google/gson/internal/bind/e;->s:Lcom/google/gson/z;

    .line 253
    .line 254
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 255
    .line 256
    .line 257
    sget-object p4, Lcom/google/gson/internal/bind/e;->t:Lcom/google/gson/z;

    .line 258
    .line 259
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 260
    .line 261
    .line 262
    sget-object p4, Lcom/google/gson/internal/bind/e;->v:Lcom/google/gson/z;

    .line 263
    .line 264
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 265
    .line 266
    .line 267
    sget-object p4, Lcom/google/gson/internal/bind/e;->w:Lcom/google/gson/z;

    .line 268
    .line 269
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 270
    .line 271
    .line 272
    sget-object p4, Lcom/google/gson/internal/bind/e;->y:Lcom/google/gson/z;

    .line 273
    .line 274
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 275
    .line 276
    .line 277
    sget-object p4, Lcom/google/gson/internal/bind/e;->u:Lcom/google/gson/z;

    .line 278
    .line 279
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 280
    .line 281
    .line 282
    sget-object p4, Lcom/google/gson/internal/bind/e;->b:Lcom/google/gson/z;

    .line 283
    .line 284
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    sget-object p4, Lcom/google/gson/internal/bind/DefaultDateTypeAdapter;->c:Lcom/google/gson/z;

    .line 288
    .line 289
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 290
    .line 291
    .line 292
    sget-object p4, Lcom/google/gson/internal/bind/e;->x:Lcom/google/gson/z;

    .line 293
    .line 294
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 295
    .line 296
    .line 297
    sget-boolean p4, Lcom/google/gson/internal/sql/b;->a:Z

    .line 298
    .line 299
    if-eqz p4, :cond_2

    .line 300
    .line 301
    sget-object p4, Lcom/google/gson/internal/sql/b;->e:Lcom/google/gson/z;

    .line 302
    .line 303
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 304
    .line 305
    .line 306
    sget-object p4, Lcom/google/gson/internal/sql/b;->d:Lcom/google/gson/z;

    .line 307
    .line 308
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 309
    .line 310
    .line 311
    sget-object p4, Lcom/google/gson/internal/sql/b;->f:Lcom/google/gson/z;

    .line 312
    .line 313
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 314
    .line 315
    .line 316
    :cond_2
    sget-object p4, Lcom/google/gson/internal/bind/ArrayTypeAdapter;->c:Lcom/google/gson/z;

    .line 317
    .line 318
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 319
    .line 320
    .line 321
    sget-object p4, Lcom/google/gson/internal/bind/e;->a:Lcom/google/gson/z;

    .line 322
    .line 323
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 324
    .line 325
    .line 326
    new-instance p4, Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory;

    .line 327
    .line 328
    invoke-direct {p4, p2}, Lcom/google/gson/internal/bind/CollectionTypeAdapterFactory;-><init>(Lcom/google/android/gms/internal/measurement/i4;)V

    .line 329
    .line 330
    .line 331
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 332
    .line 333
    .line 334
    new-instance p4, Lcom/google/gson/internal/bind/MapTypeAdapterFactory;

    .line 335
    .line 336
    invoke-direct {p4, p2}, Lcom/google/gson/internal/bind/MapTypeAdapterFactory;-><init>(Lcom/google/android/gms/internal/measurement/i4;)V

    .line 337
    .line 338
    .line 339
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 340
    .line 341
    .line 342
    new-instance p5, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

    .line 343
    .line 344
    invoke-direct {p5, p2}, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;-><init>(Lcom/google/android/gms/internal/measurement/i4;)V

    .line 345
    .line 346
    .line 347
    iput-object p5, p0, Lcom/google/gson/j;->d:Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

    .line 348
    .line 349
    invoke-virtual {p8, p5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 350
    .line 351
    .line 352
    sget-object p4, Lcom/google/gson/internal/bind/e;->B:Lcom/google/gson/z;

    .line 353
    .line 354
    invoke-virtual {p8, p4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 355
    .line 356
    .line 357
    move-object p4, p1

    .line 358
    new-instance p1, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;

    .line 359
    .line 360
    move-object p6, p13

    .line 361
    invoke-direct/range {p1 .. p6}, Lcom/google/gson/internal/bind/ReflectiveTypeAdapterFactory;-><init>(Lcom/google/android/gms/internal/measurement/i4;Lcom/google/gson/h;Lcom/google/gson/internal/Excluder;Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;Ljava/util/List;)V

    .line 362
    .line 363
    .line 364
    invoke-virtual {p8, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 365
    .line 366
    .line 367
    invoke-static {p8}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 368
    .line 369
    .line 370
    move-result-object p1

    .line 371
    iput-object p1, p0, Lcom/google/gson/j;->e:Ljava/util/List;

    .line 372
    .line 373
    return-void
.end method

.method public static a(D)V
    .locals 2

    .line 1
    invoke-static {p0, p1}, Ljava/lang/Double;->isNaN(D)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-static {p0, p1}, Ljava/lang/Double;->isInfinite(D)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 15
    .line 16
    new-instance v1, Ljava/lang/StringBuilder;

    .line 17
    .line 18
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v1, p0, p1}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p0, " is not a valid double value as per JSON specification. To override this behavior, use GsonBuilder.serializeSpecialFloatingPointValues() method."

    .line 25
    .line 26
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0
.end method


# virtual methods
.method public final b(Ljava/lang/String;Lcom/google/gson/reflect/TypeToken;)Ljava/lang/Object;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-nez p1, :cond_0

    .line 3
    .line 4
    return-object v0

    .line 5
    :cond_0
    new-instance v1, Ljava/io/StringReader;

    .line 6
    .line 7
    invoke-direct {v1, p1}, Ljava/io/StringReader;-><init>(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance p1, Lpu/a;

    .line 11
    .line 12
    invoke-direct {p1, v1}, Lpu/a;-><init>(Ljava/io/Reader;)V

    .line 13
    .line 14
    .line 15
    const/4 v1, 0x2

    .line 16
    iput v1, p1, Lpu/a;->r:I

    .line 17
    .line 18
    const-string v2, "AssertionError (GSON 2.13.1): "

    .line 19
    .line 20
    const-string v3, "Type adapter \'"

    .line 21
    .line 22
    const/4 v4, 0x1

    .line 23
    iput v4, p1, Lpu/a;->r:I

    .line 24
    .line 25
    :try_start_0
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 26
    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    invoke-virtual {p0, p2}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {p0, p1}, Lcom/google/gson/y;->b(Lpu/a;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 38
    .line 39
    .line 40
    move-result-object v6

    .line 41
    invoke-static {v6}, Lcom/google/gson/internal/f;->l(Ljava/lang/Class;)Ljava/lang/Class;

    .line 42
    .line 43
    .line 44
    move-result-object v6

    .line 45
    if-eqz v5, :cond_2

    .line 46
    .line 47
    invoke-virtual {v6, v5}, Ljava/lang/Class;->isInstance(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v6

    .line 51
    if-eqz v6, :cond_1

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_1
    new-instance v6, Ljava/lang/ClassCastException;

    .line 55
    .line 56
    new-instance v7, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    invoke-direct {v7, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v7, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    const-string p0, "\' returned wrong type; requested "

    .line 65
    .line 66
    invoke-virtual {v7, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    invoke-virtual {v7, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string p0, " but got instance of "

    .line 77
    .line 78
    invoke-virtual {v7, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    invoke-virtual {v7, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    const-string p0, "\nVerify that the adapter was registered for the correct type."

    .line 89
    .line 90
    invoke-virtual {v7, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-direct {v6, p0}, Ljava/lang/ClassCastException;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    throw v6
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    :catchall_0
    move-exception p0

    .line 102
    goto :goto_7

    .line 103
    :catch_0
    move-exception p0

    .line 104
    goto :goto_1

    .line 105
    :catch_1
    move-exception p0

    .line 106
    goto :goto_2

    .line 107
    :catch_2
    move-exception p0

    .line 108
    goto :goto_3

    .line 109
    :catch_3
    move-exception p0

    .line 110
    goto :goto_4

    .line 111
    :cond_2
    :goto_0
    iput v1, p1, Lpu/a;->r:I

    .line 112
    .line 113
    move-object v0, v5

    .line 114
    goto :goto_5

    .line 115
    :goto_1
    :try_start_1
    new-instance p2, Ljava/lang/AssertionError;

    .line 116
    .line 117
    new-instance v0, Ljava/lang/StringBuilder;

    .line 118
    .line 119
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v2

    .line 126
    invoke-virtual {v0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    invoke-direct {p2, v0, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 134
    .line 135
    .line 136
    throw p2

    .line 137
    :goto_2
    new-instance p2, Lcom/google/gson/o;

    .line 138
    .line 139
    invoke-direct {p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 140
    .line 141
    .line 142
    throw p2

    .line 143
    :goto_3
    new-instance p2, Lcom/google/gson/o;

    .line 144
    .line 145
    invoke-direct {p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 146
    .line 147
    .line 148
    throw p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 149
    :goto_4
    if-eqz v4, :cond_5

    .line 150
    .line 151
    iput v1, p1, Lpu/a;->r:I

    .line 152
    .line 153
    :goto_5
    if-eqz v0, :cond_4

    .line 154
    .line 155
    :try_start_2
    invoke-virtual {p1}, Lpu/a;->l0()I

    .line 156
    .line 157
    .line 158
    move-result p0

    .line 159
    const/16 p1, 0xa

    .line 160
    .line 161
    if-ne p0, p1, :cond_3

    .line 162
    .line 163
    goto :goto_6

    .line 164
    :cond_3
    new-instance p0, Lcom/google/gson/o;

    .line 165
    .line 166
    const-string p1, "JSON document was not fully consumed."

    .line 167
    .line 168
    invoke-direct {p0, p1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 169
    .line 170
    .line 171
    throw p0
    :try_end_2
    .catch Lpu/c; {:try_start_2 .. :try_end_2} :catch_5
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_4

    .line 172
    :catch_4
    move-exception p0

    .line 173
    new-instance p1, Lcom/google/gson/o;

    .line 174
    .line 175
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 176
    .line 177
    .line 178
    throw p1

    .line 179
    :catch_5
    move-exception p0

    .line 180
    new-instance p1, Lcom/google/gson/o;

    .line 181
    .line 182
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 183
    .line 184
    .line 185
    throw p1

    .line 186
    :cond_4
    :goto_6
    return-object v0

    .line 187
    :cond_5
    :try_start_3
    new-instance p2, Lcom/google/gson/o;

    .line 188
    .line 189
    invoke-direct {p2, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 190
    .line 191
    .line 192
    throw p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 193
    :goto_7
    iput v1, p1, Lpu/a;->r:I

    .line 194
    .line 195
    throw p0
.end method

.method public final c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 8

    .line 1
    const-string v0, "type must not be null"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/google/gson/j;->b:Ljava/util/concurrent/ConcurrentHashMap;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    check-cast v1, Lcom/google/gson/y;

    .line 13
    .line 14
    if-eqz v1, :cond_0

    .line 15
    .line 16
    return-object v1

    .line 17
    :cond_0
    iget-object v1, p0, Lcom/google/gson/j;->a:Ljava/lang/ThreadLocal;

    .line 18
    .line 19
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->get()Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v2

    .line 23
    check-cast v2, Ljava/util/Map;

    .line 24
    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    new-instance v2, Ljava/util/HashMap;

    .line 28
    .line 29
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, v2}, Ljava/lang/ThreadLocal;->set(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    const/4 v3, 0x1

    .line 36
    goto :goto_0

    .line 37
    :cond_1
    invoke-interface {v2, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v3

    .line 41
    check-cast v3, Lcom/google/gson/y;

    .line 42
    .line 43
    if-eqz v3, :cond_2

    .line 44
    .line 45
    return-object v3

    .line 46
    :cond_2
    const/4 v3, 0x0

    .line 47
    :goto_0
    :try_start_0
    new-instance v4, Lcom/google/gson/Gson$FutureTypeAdapter;

    .line 48
    .line 49
    invoke-direct {v4}, Lcom/google/gson/Gson$FutureTypeAdapter;-><init>()V

    .line 50
    .line 51
    .line 52
    invoke-interface {v2, p1, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    iget-object v5, p0, Lcom/google/gson/j;->e:Ljava/util/List;

    .line 56
    .line 57
    invoke-interface {v5}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    const/4 v6, 0x0

    .line 62
    :cond_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 63
    .line 64
    .line 65
    move-result v7

    .line 66
    if-eqz v7, :cond_5

    .line 67
    .line 68
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object v6

    .line 72
    check-cast v6, Lcom/google/gson/z;

    .line 73
    .line 74
    invoke-interface {v6, p0, p1}, Lcom/google/gson/z;->a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 75
    .line 76
    .line 77
    move-result-object v6

    .line 78
    if-eqz v6, :cond_3

    .line 79
    .line 80
    iget-object p0, v4, Lcom/google/gson/Gson$FutureTypeAdapter;->a:Lcom/google/gson/y;

    .line 81
    .line 82
    if-nez p0, :cond_4

    .line 83
    .line 84
    iput-object v6, v4, Lcom/google/gson/Gson$FutureTypeAdapter;->a:Lcom/google/gson/y;

    .line 85
    .line 86
    invoke-interface {v2, p1, v6}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :catchall_0
    move-exception p0

    .line 91
    goto :goto_2

    .line 92
    :cond_4
    new-instance p0, Ljava/lang/AssertionError;

    .line 93
    .line 94
    const-string p1, "Delegate is already set"

    .line 95
    .line 96
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    throw p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 100
    :cond_5
    :goto_1
    if-eqz v3, :cond_6

    .line 101
    .line 102
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->remove()V

    .line 103
    .line 104
    .line 105
    :cond_6
    if-eqz v6, :cond_8

    .line 106
    .line 107
    if-eqz v3, :cond_7

    .line 108
    .line 109
    invoke-virtual {v0, v2}, Ljava/util/concurrent/ConcurrentHashMap;->putAll(Ljava/util/Map;)V

    .line 110
    .line 111
    .line 112
    :cond_7
    return-object v6

    .line 113
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 114
    .line 115
    new-instance v0, Ljava/lang/StringBuilder;

    .line 116
    .line 117
    const-string v1, "GSON (2.13.1) cannot handle "

    .line 118
    .line 119
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 130
    .line 131
    .line 132
    throw p0

    .line 133
    :goto_2
    if-eqz v3, :cond_9

    .line 134
    .line 135
    invoke-virtual {v1}, Ljava/lang/ThreadLocal;->remove()V

    .line 136
    .line 137
    .line 138
    :cond_9
    throw p0
.end method

.method public final d(Lcom/google/gson/z;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;
    .locals 6

    .line 1
    const-string v0, "skipPast must not be null"

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    const-string v0, "type must not be null"

    .line 7
    .line 8
    invoke-static {p2, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lcom/google/gson/j;->d:Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    iget-object v1, v0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->e:Ljava/util/concurrent/ConcurrentHashMap;

    .line 17
    .line 18
    sget-object v2, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->f:Lcom/google/gson/z;

    .line 19
    .line 20
    const/4 v3, 0x1

    .line 21
    if-ne p1, v2, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    invoke-virtual {p2}, Lcom/google/gson/reflect/TypeToken;->getRawType()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v1, v2}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v4

    .line 32
    check-cast v4, Lcom/google/gson/z;

    .line 33
    .line 34
    if-eqz v4, :cond_1

    .line 35
    .line 36
    if-ne v4, p1, :cond_5

    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_1
    const-class v4, Lmu/a;

    .line 40
    .line 41
    invoke-virtual {v2, v4}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    check-cast v4, Lmu/a;

    .line 46
    .line 47
    if-nez v4, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    invoke-interface {v4}, Lmu/a;->value()Ljava/lang/Class;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    const-class v5, Lcom/google/gson/z;

    .line 55
    .line 56
    invoke-virtual {v5, v4}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-nez v5, :cond_3

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    iget-object v5, v0, Lcom/google/gson/internal/bind/JsonAdapterAnnotationTypeAdapterFactory;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 64
    .line 65
    invoke-static {v4}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/Class;)Lcom/google/gson/reflect/TypeToken;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    invoke-virtual {v5, v4, v3}, Lcom/google/android/gms/internal/measurement/i4;->r(Lcom/google/gson/reflect/TypeToken;Z)Lcom/google/gson/internal/m;

    .line 70
    .line 71
    .line 72
    move-result-object v4

    .line 73
    invoke-interface {v4}, Lcom/google/gson/internal/m;->a()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    check-cast v4, Lcom/google/gson/z;

    .line 78
    .line 79
    invoke-virtual {v1, v2, v4}, Ljava/util/concurrent/ConcurrentHashMap;->putIfAbsent(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v1

    .line 83
    check-cast v1, Lcom/google/gson/z;

    .line 84
    .line 85
    if-eqz v1, :cond_4

    .line 86
    .line 87
    move-object v4, v1

    .line 88
    :cond_4
    if-ne v4, p1, :cond_5

    .line 89
    .line 90
    :goto_0
    move-object p1, v0

    .line 91
    :cond_5
    :goto_1
    iget-object v0, p0, Lcom/google/gson/j;->e:Ljava/util/List;

    .line 92
    .line 93
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    const/4 v1, 0x0

    .line 98
    :cond_6
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    if-eqz v2, :cond_8

    .line 103
    .line 104
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Lcom/google/gson/z;

    .line 109
    .line 110
    if-nez v1, :cond_7

    .line 111
    .line 112
    if-ne v2, p1, :cond_6

    .line 113
    .line 114
    move v1, v3

    .line 115
    goto :goto_2

    .line 116
    :cond_7
    invoke-interface {v2, p0, p2}, Lcom/google/gson/z;->a(Lcom/google/gson/j;Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 117
    .line 118
    .line 119
    move-result-object v2

    .line 120
    if-eqz v2, :cond_6

    .line 121
    .line 122
    return-object v2

    .line 123
    :cond_8
    if-nez v1, :cond_9

    .line 124
    .line 125
    invoke-virtual {p0, p2}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 126
    .line 127
    .line 128
    move-result-object p0

    .line 129
    return-object p0

    .line 130
    :cond_9
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 131
    .line 132
    new-instance p1, Ljava/lang/StringBuilder;

    .line 133
    .line 134
    const-string v0, "GSON cannot serialize or deserialize "

    .line 135
    .line 136
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    throw p0
.end method

.method public final e(Lcom/wultra/android/sslpinning/model/CachedData;Ljava/lang/Class;Lpu/b;)V
    .locals 4

    .line 1
    const-string v0, "AssertionError (GSON 2.13.1): "

    .line 2
    .line 3
    invoke-static {p2}, Lcom/google/gson/reflect/TypeToken;->get(Ljava/lang/reflect/Type;)Lcom/google/gson/reflect/TypeToken;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-virtual {p0, p2}, Lcom/google/gson/j;->c(Lcom/google/gson/reflect/TypeToken;)Lcom/google/gson/y;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    iget v1, p3, Lpu/b;->k:I

    .line 12
    .line 13
    const/4 v2, 0x2

    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    const/4 v2, 0x1

    .line 17
    iput v2, p3, Lpu/b;->k:I

    .line 18
    .line 19
    :cond_0
    iget-boolean v2, p3, Lpu/b;->l:Z

    .line 20
    .line 21
    iget-boolean v3, p3, Lpu/b;->n:Z

    .line 22
    .line 23
    iget-boolean p0, p0, Lcom/google/gson/j;->f:Z

    .line 24
    .line 25
    iput-boolean p0, p3, Lpu/b;->l:Z

    .line 26
    .line 27
    const/4 p0, 0x0

    .line 28
    iput-boolean p0, p3, Lpu/b;->n:Z

    .line 29
    .line 30
    :try_start_0
    invoke-virtual {p2, p3, p1}, Lcom/google/gson/y;->c(Lpu/b;Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/AssertionError; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    .line 33
    invoke-virtual {p3, v1}, Lpu/b;->E(I)V

    .line 34
    .line 35
    .line 36
    iput-boolean v2, p3, Lpu/b;->l:Z

    .line 37
    .line 38
    iput-boolean v3, p3, Lpu/b;->n:Z

    .line 39
    .line 40
    return-void

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    goto :goto_0

    .line 43
    :catch_0
    move-exception p0

    .line 44
    :try_start_1
    new-instance p1, Ljava/lang/AssertionError;

    .line 45
    .line 46
    new-instance p2, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    invoke-direct {p1, p2, p0}, Ljava/lang/AssertionError;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    throw p1

    .line 66
    :catch_1
    move-exception p0

    .line 67
    new-instance p1, Lcom/google/gson/o;

    .line 68
    .line 69
    invoke-direct {p1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 70
    .line 71
    .line 72
    throw p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    :goto_0
    invoke-virtual {p3, v1}, Lpu/b;->E(I)V

    .line 74
    .line 75
    .line 76
    iput-boolean v2, p3, Lpu/b;->l:Z

    .line 77
    .line 78
    iput-boolean v3, p3, Lpu/b;->n:Z

    .line 79
    .line 80
    throw p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "{serializeNulls:false,factories:"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lcom/google/gson/j;->e:Ljava/util/List;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ",instanceCreators:"

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lcom/google/gson/j;->c:Lcom/google/android/gms/internal/measurement/i4;

    .line 19
    .line 20
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, "}"

    .line 24
    .line 25
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

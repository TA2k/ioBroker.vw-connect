.class public abstract Luz0/b1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:[Lsz0/g;

.field public static final b:[Lqz0/a;

.field public static final c:Ljava/lang/Object;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Lsz0/g;

    .line 3
    .line 4
    sput-object v0, Luz0/b1;->a:[Lsz0/g;

    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    new-array v0, v0, [Lqz0/a;

    .line 8
    .line 9
    sput-object v0, Luz0/b1;->b:[Lqz0/a;

    .line 10
    .line 11
    new-instance v0, Ljava/lang/Object;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 14
    .line 15
    .line 16
    sput-object v0, Luz0/b1;->c:Ljava/lang/Object;

    .line 17
    .line 18
    return-void
.end method

.method public static final a(Ljava/lang/String;Lqz0/a;)Luz0/f0;
    .locals 2

    .line 1
    new-instance v0, Luz0/f0;

    .line 2
    .line 3
    new-instance v1, Luz0/g0;

    .line 4
    .line 5
    invoke-direct {v1, p1}, Luz0/g0;-><init>(Lqz0/a;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {v0, p0, v1}, Luz0/f0;-><init>(Ljava/lang/String;Luz0/c0;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static final b(Lsz0/g;)Ljava/util/Set;
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    instance-of v0, p0, Luz0/l;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    check-cast p0, Luz0/l;

    .line 11
    .line 12
    invoke-interface {p0}, Luz0/l;->a()Ljava/util/Set;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0

    .line 17
    :cond_0
    new-instance v0, Ljava/util/HashSet;

    .line 18
    .line 19
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-direct {v0, v1}, Ljava/util/HashSet;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    const/4 v2, 0x0

    .line 31
    :goto_0
    if-ge v2, v1, :cond_1

    .line 32
    .line 33
    invoke-interface {p0, v2}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v3

    .line 37
    invoke-virtual {v0, v3}, Ljava/util/HashSet;->add(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    add-int/lit8 v2, v2, 0x1

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_1
    return-object v0
.end method

.method public static final c(Ljava/util/List;)[Lsz0/g;
    .locals 1

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Ljava/util/Collection;

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-interface {v0}, Ljava/util/Collection;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :cond_1
    if-eqz p0, :cond_3

    .line 14
    .line 15
    check-cast p0, Ljava/util/Collection;

    .line 16
    .line 17
    const/4 v0, 0x0

    .line 18
    new-array v0, v0, [Lsz0/g;

    .line 19
    .line 20
    invoke-interface {p0, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, [Lsz0/g;

    .line 25
    .line 26
    if-nez p0, :cond_2

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_2
    return-object p0

    .line 30
    :cond_3
    :goto_0
    sget-object p0, Luz0/b1;->a:[Lsz0/g;

    .line 31
    .line 32
    return-object p0
.end method

.method public static final varargs d(Ljava/lang/Class;[Lqz0/a;)Lqz0/a;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    const-string v2, "args"

    .line 11
    .line 12
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v0}, Ljava/lang/Class;->isEnum()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    const-class v3, Lqz0/c;

    .line 20
    .line 21
    const-class v4, Lqz0/g;

    .line 22
    .line 23
    if-eqz v2, :cond_0

    .line 24
    .line 25
    invoke-virtual {v0, v4}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    if-nez v2, :cond_0

    .line 30
    .line 31
    invoke-virtual {v0, v3}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    if-nez v2, :cond_0

    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/Class;->getEnumConstants()[Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    new-instance v2, Luz0/y;

    .line 42
    .line 43
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    const-string v3, "getCanonicalName(...)"

    .line 48
    .line 49
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const-string v3, "null cannot be cast to non-null type kotlin.Array<out kotlin.Enum<*>>"

    .line 53
    .line 54
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    check-cast v1, [Ljava/lang/Enum;

    .line 58
    .line 59
    invoke-direct {v2, v0, v1}, Luz0/y;-><init>(Ljava/lang/String;[Ljava/lang/Enum;)V

    .line 60
    .line 61
    .line 62
    return-object v2

    .line 63
    :cond_0
    array-length v2, v1

    .line 64
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v2

    .line 68
    check-cast v2, [Lqz0/a;

    .line 69
    .line 70
    const-string v5, "Companion"

    .line 71
    .line 72
    const/4 v6, 0x1

    .line 73
    const/4 v7, 0x0

    .line 74
    :try_start_0
    invoke-virtual {v0, v5}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 75
    .line 76
    .line 77
    move-result-object v5

    .line 78
    invoke-virtual {v5, v6}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 79
    .line 80
    .line 81
    invoke-virtual {v5, v7}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v5
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 85
    goto :goto_0

    .line 86
    :catchall_0
    move-object v5, v7

    .line 87
    :goto_0
    if-nez v5, :cond_1

    .line 88
    .line 89
    move-object v2, v7

    .line 90
    goto :goto_1

    .line 91
    :cond_1
    array-length v8, v2

    .line 92
    invoke-static {v2, v8}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v2

    .line 96
    check-cast v2, [Lqz0/a;

    .line 97
    .line 98
    invoke-static {v5, v2}, Luz0/b1;->h(Ljava/lang/Object;[Lqz0/a;)Lqz0/a;

    .line 99
    .line 100
    .line 101
    move-result-object v2

    .line 102
    :goto_1
    if-eqz v2, :cond_2

    .line 103
    .line 104
    return-object v2

    .line 105
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v2

    .line 109
    const-string v5, "INSTANCE"

    .line 110
    .line 111
    const/4 v8, 0x0

    .line 112
    if-eqz v2, :cond_8

    .line 113
    .line 114
    const-string v9, "java."

    .line 115
    .line 116
    invoke-static {v2, v9, v8}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 117
    .line 118
    .line 119
    move-result v9

    .line 120
    if-nez v9, :cond_8

    .line 121
    .line 122
    const-string v9, "kotlin."

    .line 123
    .line 124
    invoke-static {v2, v9, v8}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 125
    .line 126
    .line 127
    move-result v2

    .line 128
    if-eqz v2, :cond_3

    .line 129
    .line 130
    goto :goto_5

    .line 131
    :cond_3
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 132
    .line 133
    .line 134
    move-result-object v2

    .line 135
    const-string v9, "getDeclaredFields(...)"

    .line 136
    .line 137
    invoke-static {v2, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    array-length v9, v2

    .line 141
    move-object v12, v7

    .line 142
    move v10, v8

    .line 143
    move v11, v10

    .line 144
    :goto_2
    if-ge v10, v9, :cond_6

    .line 145
    .line 146
    aget-object v13, v2, v10

    .line 147
    .line 148
    invoke-virtual {v13}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 149
    .line 150
    .line 151
    move-result-object v14

    .line 152
    invoke-static {v14, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v14

    .line 156
    if-eqz v14, :cond_5

    .line 157
    .line 158
    invoke-virtual {v13}, Ljava/lang/reflect/Field;->getType()Ljava/lang/Class;

    .line 159
    .line 160
    .line 161
    move-result-object v14

    .line 162
    invoke-static {v14, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result v14

    .line 166
    if-eqz v14, :cond_5

    .line 167
    .line 168
    invoke-virtual {v13}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 169
    .line 170
    .line 171
    move-result v14

    .line 172
    invoke-static {v14}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 173
    .line 174
    .line 175
    move-result v14

    .line 176
    if-eqz v14, :cond_5

    .line 177
    .line 178
    if-eqz v11, :cond_4

    .line 179
    .line 180
    :goto_3
    move-object v12, v7

    .line 181
    goto :goto_4

    .line 182
    :cond_4
    move v11, v6

    .line 183
    move-object v12, v13

    .line 184
    :cond_5
    add-int/lit8 v10, v10, 0x1

    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_6
    if-nez v11, :cond_7

    .line 188
    .line 189
    goto :goto_3

    .line 190
    :cond_7
    :goto_4
    if-nez v12, :cond_9

    .line 191
    .line 192
    :cond_8
    :goto_5
    move-object v2, v7

    .line 193
    goto :goto_9

    .line 194
    :cond_9
    invoke-virtual {v12, v7}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v2

    .line 198
    invoke-virtual {v0}, Ljava/lang/Class;->getMethods()[Ljava/lang/reflect/Method;

    .line 199
    .line 200
    .line 201
    move-result-object v9

    .line 202
    const-string v10, "getMethods(...)"

    .line 203
    .line 204
    invoke-static {v9, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    array-length v10, v9

    .line 208
    move-object v13, v7

    .line 209
    move v11, v8

    .line 210
    move v12, v11

    .line 211
    :goto_6
    if-ge v11, v10, :cond_c

    .line 212
    .line 213
    aget-object v14, v9, v11

    .line 214
    .line 215
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getName()Ljava/lang/String;

    .line 216
    .line 217
    .line 218
    move-result-object v15

    .line 219
    const-string v8, "serializer"

    .line 220
    .line 221
    invoke-static {v15, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 222
    .line 223
    .line 224
    move-result v8

    .line 225
    if-eqz v8, :cond_b

    .line 226
    .line 227
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getParameterTypes()[Ljava/lang/Class;

    .line 228
    .line 229
    .line 230
    move-result-object v8

    .line 231
    const-string v15, "getParameterTypes(...)"

    .line 232
    .line 233
    invoke-static {v8, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 234
    .line 235
    .line 236
    array-length v8, v8

    .line 237
    if-nez v8, :cond_b

    .line 238
    .line 239
    invoke-virtual {v14}, Ljava/lang/reflect/Method;->getReturnType()Ljava/lang/Class;

    .line 240
    .line 241
    .line 242
    move-result-object v8

    .line 243
    const-class v15, Lqz0/a;

    .line 244
    .line 245
    invoke-static {v8, v15}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v8

    .line 249
    if-eqz v8, :cond_b

    .line 250
    .line 251
    if-eqz v12, :cond_a

    .line 252
    .line 253
    :goto_7
    move-object v13, v7

    .line 254
    goto :goto_8

    .line 255
    :cond_a
    move v12, v6

    .line 256
    move-object v13, v14

    .line 257
    :cond_b
    add-int/lit8 v11, v11, 0x1

    .line 258
    .line 259
    const/4 v8, 0x0

    .line 260
    goto :goto_6

    .line 261
    :cond_c
    if-nez v12, :cond_d

    .line 262
    .line 263
    goto :goto_7

    .line 264
    :cond_d
    :goto_8
    if-nez v13, :cond_e

    .line 265
    .line 266
    goto :goto_5

    .line 267
    :cond_e
    invoke-virtual {v13, v2, v7}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 268
    .line 269
    .line 270
    move-result-object v2

    .line 271
    instance-of v8, v2, Lqz0/a;

    .line 272
    .line 273
    if-eqz v8, :cond_8

    .line 274
    .line 275
    check-cast v2, Lqz0/a;

    .line 276
    .line 277
    :goto_9
    if-eqz v2, :cond_f

    .line 278
    .line 279
    return-object v2

    .line 280
    :cond_f
    array-length v2, v1

    .line 281
    invoke-static {v1, v2}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v1

    .line 285
    check-cast v1, [Lqz0/a;

    .line 286
    .line 287
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredClasses()[Ljava/lang/Class;

    .line 288
    .line 289
    .line 290
    move-result-object v2

    .line 291
    const-string v8, "getDeclaredClasses(...)"

    .line 292
    .line 293
    invoke-static {v2, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 294
    .line 295
    .line 296
    array-length v9, v2

    .line 297
    const/4 v10, 0x0

    .line 298
    :goto_a
    if-ge v10, v9, :cond_11

    .line 299
    .line 300
    aget-object v11, v2, v10

    .line 301
    .line 302
    const-class v12, Luz0/v0;

    .line 303
    .line 304
    invoke-virtual {v11, v12}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 305
    .line 306
    .line 307
    move-result-object v12

    .line 308
    if-eqz v12, :cond_10

    .line 309
    .line 310
    goto :goto_b

    .line 311
    :cond_10
    add-int/lit8 v10, v10, 0x1

    .line 312
    .line 313
    goto :goto_a

    .line 314
    :cond_11
    move-object v11, v7

    .line 315
    :goto_b
    if-nez v11, :cond_12

    .line 316
    .line 317
    :catchall_1
    move-object v2, v7

    .line 318
    goto :goto_c

    .line 319
    :cond_12
    invoke-virtual {v11}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 320
    .line 321
    .line 322
    move-result-object v2

    .line 323
    :try_start_1
    invoke-virtual {v0, v2}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 324
    .line 325
    .line 326
    move-result-object v2

    .line 327
    invoke-virtual {v2, v6}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 328
    .line 329
    .line 330
    invoke-virtual {v2, v7}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 334
    :goto_c
    if-eqz v2, :cond_13

    .line 335
    .line 336
    array-length v9, v1

    .line 337
    invoke-static {v1, v9}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object v1

    .line 341
    check-cast v1, [Lqz0/a;

    .line 342
    .line 343
    invoke-static {v2, v1}, Luz0/b1;->h(Ljava/lang/Object;[Lqz0/a;)Lqz0/a;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    if-eqz v1, :cond_13

    .line 348
    .line 349
    goto :goto_11

    .line 350
    :cond_13
    :try_start_2
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredClasses()[Ljava/lang/Class;

    .line 351
    .line 352
    .line 353
    move-result-object v1

    .line 354
    invoke-static {v1, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 355
    .line 356
    .line 357
    array-length v2, v1

    .line 358
    move-object v9, v7

    .line 359
    const/4 v8, 0x0

    .line 360
    const/16 v16, 0x0

    .line 361
    .line 362
    :goto_d
    if-ge v8, v2, :cond_16

    .line 363
    .line 364
    aget-object v10, v1, v8

    .line 365
    .line 366
    invoke-virtual {v10}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 367
    .line 368
    .line 369
    move-result-object v11

    .line 370
    const-string v12, "$serializer"

    .line 371
    .line 372
    invoke-virtual {v11, v12}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 373
    .line 374
    .line 375
    move-result v11

    .line 376
    if-eqz v11, :cond_15

    .line 377
    .line 378
    if-eqz v16, :cond_14

    .line 379
    .line 380
    :goto_e
    move-object v9, v7

    .line 381
    goto :goto_f

    .line 382
    :cond_14
    move/from16 v16, v6

    .line 383
    .line 384
    move-object v9, v10

    .line 385
    :cond_15
    add-int/lit8 v8, v8, 0x1

    .line 386
    .line 387
    goto :goto_d

    .line 388
    :cond_16
    if-nez v16, :cond_17

    .line 389
    .line 390
    goto :goto_e

    .line 391
    :cond_17
    :goto_f
    if-eqz v9, :cond_18

    .line 392
    .line 393
    invoke-virtual {v9, v5}, Ljava/lang/Class;->getField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 394
    .line 395
    .line 396
    move-result-object v1

    .line 397
    if-eqz v1, :cond_18

    .line 398
    .line 399
    invoke-virtual {v1, v7}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 400
    .line 401
    .line 402
    move-result-object v1

    .line 403
    goto :goto_10

    .line 404
    :cond_18
    move-object v1, v7

    .line 405
    :goto_10
    instance-of v2, v1, Lqz0/a;

    .line 406
    .line 407
    if-eqz v2, :cond_19

    .line 408
    .line 409
    check-cast v1, Lqz0/a;
    :try_end_2
    .catch Ljava/lang/NoSuchFieldException; {:try_start_2 .. :try_end_2} :catch_0

    .line 410
    .line 411
    goto :goto_11

    .line 412
    :catch_0
    :cond_19
    move-object v1, v7

    .line 413
    :goto_11
    if-eqz v1, :cond_1a

    .line 414
    .line 415
    return-object v1

    .line 416
    :cond_1a
    invoke-virtual {v0, v3}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 417
    .line 418
    .line 419
    move-result-object v1

    .line 420
    if-eqz v1, :cond_1b

    .line 421
    .line 422
    goto :goto_12

    .line 423
    :cond_1b
    invoke-virtual {v0, v4}, Ljava/lang/Class;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 424
    .line 425
    .line 426
    move-result-object v1

    .line 427
    check-cast v1, Lqz0/g;

    .line 428
    .line 429
    if-eqz v1, :cond_1c

    .line 430
    .line 431
    invoke-interface {v1}, Lqz0/g;->with()Ljava/lang/Class;

    .line 432
    .line 433
    .line 434
    move-result-object v1

    .line 435
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 436
    .line 437
    invoke-virtual {v2, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 438
    .line 439
    .line 440
    move-result-object v1

    .line 441
    const-class v3, Lqz0/d;

    .line 442
    .line 443
    invoke-virtual {v2, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 444
    .line 445
    .line 446
    move-result-object v2

    .line 447
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 448
    .line 449
    .line 450
    move-result v1

    .line 451
    if-eqz v1, :cond_1c

    .line 452
    .line 453
    :goto_12
    new-instance v7, Lqz0/d;

    .line 454
    .line 455
    invoke-static {v0}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 456
    .line 457
    .line 458
    move-result-object v0

    .line 459
    invoke-direct {v7, v0}, Lqz0/d;-><init>(Lhy0/d;)V

    .line 460
    .line 461
    .line 462
    :cond_1c
    return-object v7
.end method

.method public static final e(Ljava/lang/String;[Ljava/lang/Enum;[Ljava/lang/String;[[Ljava/lang/annotation/Annotation;)Luz0/y;
    .locals 12

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Luz0/x;

    .line 7
    .line 8
    array-length v1, p1

    .line 9
    invoke-direct {v0, p0, v1}, Luz0/x;-><init>(Ljava/lang/String;I)V

    .line 10
    .line 11
    .line 12
    array-length v1, p1

    .line 13
    const/4 v2, 0x0

    .line 14
    move v3, v2

    .line 15
    move v4, v3

    .line 16
    :goto_0
    if-ge v3, v1, :cond_3

    .line 17
    .line 18
    aget-object v5, p1, v3

    .line 19
    .line 20
    add-int/lit8 v6, v4, 0x1

    .line 21
    .line 22
    invoke-static {v4, p2}, Lmx0/n;->C(I[Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v7

    .line 26
    check-cast v7, Ljava/lang/String;

    .line 27
    .line 28
    if-nez v7, :cond_0

    .line 29
    .line 30
    invoke-virtual {v5}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v7

    .line 34
    :cond_0
    invoke-virtual {v0, v7, v2}, Luz0/d1;->j(Ljava/lang/String;Z)V

    .line 35
    .line 36
    .line 37
    invoke-static {v4, p3}, Lmx0/n;->C(I[Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    check-cast v4, [Ljava/lang/annotation/Annotation;

    .line 42
    .line 43
    if-eqz v4, :cond_2

    .line 44
    .line 45
    array-length v5, v4

    .line 46
    move v7, v2

    .line 47
    :goto_1
    if-ge v7, v5, :cond_2

    .line 48
    .line 49
    aget-object v8, v4, v7

    .line 50
    .line 51
    const-string v9, "annotation"

    .line 52
    .line 53
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget v9, v0, Luz0/d1;->d:I

    .line 57
    .line 58
    iget-object v10, v0, Luz0/d1;->f:[Ljava/util/List;

    .line 59
    .line 60
    aget-object v9, v10, v9

    .line 61
    .line 62
    if-nez v9, :cond_1

    .line 63
    .line 64
    new-instance v9, Ljava/util/ArrayList;

    .line 65
    .line 66
    const/4 v11, 0x1

    .line 67
    invoke-direct {v9, v11}, Ljava/util/ArrayList;-><init>(I)V

    .line 68
    .line 69
    .line 70
    iget v11, v0, Luz0/d1;->d:I

    .line 71
    .line 72
    aput-object v9, v10, v11

    .line 73
    .line 74
    :cond_1
    invoke-interface {v9, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    add-int/lit8 v7, v7, 0x1

    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_2
    add-int/lit8 v3, v3, 0x1

    .line 81
    .line 82
    move v4, v6

    .line 83
    goto :goto_0

    .line 84
    :cond_3
    new-instance p2, Luz0/y;

    .line 85
    .line 86
    invoke-direct {p2, p0, p1}, Luz0/y;-><init>(Ljava/lang/String;[Ljava/lang/Enum;)V

    .line 87
    .line 88
    .line 89
    iput-object v0, p2, Luz0/y;->c:Ljava/lang/Object;

    .line 90
    .line 91
    return-object p2
.end method

.method public static final f(Ljava/lang/String;[Ljava/lang/Enum;)Luz0/y;
    .locals 1

    .line 1
    const-string v0, "values"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Luz0/y;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Luz0/y;-><init>(Ljava/lang/String;[Ljava/lang/Enum;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public static final g(Lsz0/g;[Lsz0/g;)I
    .locals 7

    .line 1
    const-string v0, "typeParams"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    mul-int/lit8 v0, v0, 0x1f

    .line 15
    .line 16
    invoke-static {p1}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    add-int/2addr v0, p1

    .line 21
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 22
    .line 23
    .line 24
    move-result p1

    .line 25
    const/4 v1, 0x1

    .line 26
    move v2, v1

    .line 27
    :goto_0
    const/4 v3, 0x0

    .line 28
    if-lez p1, :cond_0

    .line 29
    .line 30
    move v4, v1

    .line 31
    goto :goto_1

    .line 32
    :cond_0
    move v4, v3

    .line 33
    :goto_1
    if-eqz v4, :cond_2

    .line 34
    .line 35
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    add-int/lit8 v5, p1, -0x1

    .line 40
    .line 41
    sub-int/2addr v4, p1

    .line 42
    invoke-interface {p0, v4}, Lsz0/g;->g(I)Lsz0/g;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    mul-int/lit8 v2, v2, 0x1f

    .line 47
    .line 48
    invoke-interface {p1}, Lsz0/g;->h()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    if-eqz p1, :cond_1

    .line 53
    .line 54
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    .line 55
    .line 56
    .line 57
    move-result v3

    .line 58
    :cond_1
    add-int/2addr v2, v3

    .line 59
    move p1, v5

    .line 60
    goto :goto_0

    .line 61
    :cond_2
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 62
    .line 63
    .line 64
    move-result p1

    .line 65
    move v4, v1

    .line 66
    :goto_2
    if-lez p1, :cond_3

    .line 67
    .line 68
    move v5, v1

    .line 69
    goto :goto_3

    .line 70
    :cond_3
    move v5, v3

    .line 71
    :goto_3
    if-eqz v5, :cond_5

    .line 72
    .line 73
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 74
    .line 75
    .line 76
    move-result v5

    .line 77
    add-int/lit8 v6, p1, -0x1

    .line 78
    .line 79
    sub-int/2addr v5, p1

    .line 80
    invoke-interface {p0, v5}, Lsz0/g;->g(I)Lsz0/g;

    .line 81
    .line 82
    .line 83
    move-result-object p1

    .line 84
    mul-int/lit8 v4, v4, 0x1f

    .line 85
    .line 86
    invoke-interface {p1}, Lsz0/g;->getKind()Lkp/y8;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    if-eqz p1, :cond_4

    .line 91
    .line 92
    invoke-virtual {p1}, Lkp/y8;->hashCode()I

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    goto :goto_4

    .line 97
    :cond_4
    move p1, v3

    .line 98
    :goto_4
    add-int/2addr v4, p1

    .line 99
    move p1, v6

    .line 100
    goto :goto_2

    .line 101
    :cond_5
    mul-int/lit8 v0, v0, 0x1f

    .line 102
    .line 103
    add-int/2addr v0, v2

    .line 104
    mul-int/lit8 v0, v0, 0x1f

    .line 105
    .line 106
    add-int/2addr v0, v4

    .line 107
    return v0
.end method

.method public static final varargs h(Ljava/lang/Object;[Lqz0/a;)Lqz0/a;
    .locals 4

    .line 1
    :try_start_0
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-array v0, v1, [Ljava/lang/Class;

    .line 6
    .line 7
    goto :goto_1

    .line 8
    :cond_0
    array-length v0, p1

    .line 9
    new-array v2, v0, [Ljava/lang/Class;

    .line 10
    .line 11
    :goto_0
    if-ge v1, v0, :cond_1

    .line 12
    .line 13
    const-class v3, Lqz0/a;

    .line 14
    .line 15
    aput-object v3, v2, v1

    .line 16
    .line 17
    add-int/lit8 v1, v1, 0x1

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_1
    move-object v0, v2

    .line 21
    :goto_1
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    const-string v2, "serializer"

    .line 26
    .line 27
    array-length v3, v0

    .line 28
    invoke-static {v0, v3}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, [Ljava/lang/Class;

    .line 33
    .line 34
    invoke-virtual {v1, v2, v0}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    array-length v1, p1

    .line 39
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    invoke-virtual {v0, p0, p1}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    instance-of p1, p0, Lqz0/a;

    .line 48
    .line 49
    if-eqz p1, :cond_4

    .line 50
    .line 51
    check-cast p0, Lqz0/a;
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_0 .. :try_end_0} :catch_0

    .line 52
    .line 53
    return-object p0

    .line 54
    :catch_0
    move-exception p0

    .line 55
    invoke-virtual {p0}, Ljava/lang/reflect/InvocationTargetException;->getCause()Ljava/lang/Throwable;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-eqz p1, :cond_3

    .line 60
    .line 61
    new-instance v0, Ljava/lang/reflect/InvocationTargetException;

    .line 62
    .line 63
    invoke-virtual {p1}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    if-nez v1, :cond_2

    .line 68
    .line 69
    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    :cond_2
    invoke-direct {v0, p1, v1}, Ljava/lang/reflect/InvocationTargetException;-><init>(Ljava/lang/Throwable;Ljava/lang/String;)V

    .line 74
    .line 75
    .line 76
    throw v0

    .line 77
    :cond_3
    throw p0

    .line 78
    :catch_1
    :cond_4
    const/4 p0, 0x0

    .line 79
    return-object p0
.end method

.method public static final i(Lhy0/d;)Z
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Class;->isInterface()Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public static final j(Lhy0/a0;)Lhy0/d;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    instance-of v0, p0, Lhy0/d;

    .line 11
    .line 12
    if-eqz v0, :cond_0

    .line 13
    .line 14
    check-cast p0, Lhy0/d;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    instance-of v0, p0, Lhy0/b0;

    .line 18
    .line 19
    if-eqz v0, :cond_1

    .line 20
    .line 21
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 22
    .line 23
    new-instance v1, Ljava/lang/StringBuilder;

    .line 24
    .line 25
    const-string v2, "Captured type parameter "

    .line 26
    .line 27
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v2, " from generic non-reified function. Such functionality cannot be supported because "

    .line 34
    .line 35
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v2, " is erased, either specify serializer explicitly or make calling function inline with reified "

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const/16 p0, 0x2e

    .line 50
    .line 51
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    throw v0

    .line 62
    :cond_1
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 63
    .line 64
    new-instance v1, Ljava/lang/StringBuilder;

    .line 65
    .line 66
    const-string v2, "Only KClass supported as classifier, got "

    .line 67
    .line 68
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 79
    .line 80
    .line 81
    throw v0
.end method

.method public static final k(Lhy0/d;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    if-nez p0, :cond_0

    .line 11
    .line 12
    const-string p0, "<local class name not available>"

    .line 13
    .line 14
    :cond_0
    const-string v0, "Serializer for class \'"

    .line 15
    .line 16
    const-string v1, "\' is not found.\nPlease ensure that class is marked as \'@Serializable\' and that the serialization compiler plugin is applied.\n"

    .line 17
    .line 18
    invoke-static {v0, p0, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public static final l(IILsz0/g;)V
    .locals 4

    .line 1
    const-string v0, "descriptor"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    not-int p0, p0

    .line 12
    and-int/2addr p0, p1

    .line 13
    const/4 p1, 0x0

    .line 14
    move v1, p1

    .line 15
    :goto_0
    const/16 v2, 0x20

    .line 16
    .line 17
    if-ge v1, v2, :cond_1

    .line 18
    .line 19
    and-int/lit8 v2, p0, 0x1

    .line 20
    .line 21
    if-eqz v2, :cond_0

    .line 22
    .line 23
    invoke-interface {p2, v1}, Lsz0/g;->e(I)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    :cond_0
    ushr-int/lit8 p0, p0, 0x1

    .line 31
    .line 32
    add-int/lit8 v1, v1, 0x1

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    new-instance p0, Lqz0/b;

    .line 36
    .line 37
    invoke-interface {p2}, Lsz0/g;->h()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p2

    .line 41
    const-string v1, "serialName"

    .line 42
    .line 43
    invoke-static {p2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    const/4 v2, 0x1

    .line 51
    if-ne v1, v2, :cond_2

    .line 52
    .line 53
    new-instance v1, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    const-string v2, "Field \'"

    .line 56
    .line 57
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p1

    .line 64
    check-cast p1, Ljava/lang/String;

    .line 65
    .line 66
    const-string v2, "\' is required for type with serial name \'"

    .line 67
    .line 68
    const-string v3, "\', but it was missing"

    .line 69
    .line 70
    invoke-static {v1, p1, v2, p2, v3}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    goto :goto_1

    .line 75
    :cond_2
    new-instance p1, Ljava/lang/StringBuilder;

    .line 76
    .line 77
    const-string v1, "Fields "

    .line 78
    .line 79
    invoke-direct {p1, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, " are required for type with serial name \'"

    .line 86
    .line 87
    invoke-virtual {p1, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string p2, "\', but they were missing"

    .line 94
    .line 95
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    :goto_1
    const/4 p2, 0x0

    .line 103
    invoke-direct {p0, v0, p1, p2}, Lqz0/b;-><init>(Ljava/util/List;Ljava/lang/String;Lqz0/b;)V

    .line 104
    .line 105
    .line 106
    throw p0
.end method

.method public static final m(Lhy0/d;Ljava/lang/String;)V
    .locals 5

    .line 1
    const-string v0, "baseClass"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Ljava/lang/StringBuilder;

    .line 7
    .line 8
    const-string v1, "in the polymorphic scope of \'"

    .line 9
    .line 10
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const/16 v1, 0x27

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    new-instance v1, Lqz0/h;

    .line 30
    .line 31
    if-nez p1, :cond_0

    .line 32
    .line 33
    const-string p0, "Class discriminator was missing and no default serializers were registered "

    .line 34
    .line 35
    const/16 p1, 0x2e

    .line 36
    .line 37
    invoke-static {p1, p0, v0}, Lvj/b;->f(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    const-string v2, "\' is not found "

    .line 43
    .line 44
    const-string v3, ".\nCheck if class with serial name \'"

    .line 45
    .line 46
    const-string v4, "Serializer for subclass \'"

    .line 47
    .line 48
    invoke-static {v4, p1, v2, v0, v3}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    const-string v2, "\' exists and serializer is registered in a corresponding SerializersModule.\nTo be registered automatically, class \'"

    .line 53
    .line 54
    const-string v3, "\' has to be \'@Serializable\', and the base class \'"

    .line 55
    .line 56
    invoke-static {v0, p1, v2, p1, v3}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-interface {p0}, Lhy0/d;->getSimpleName()Ljava/lang/String;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string p0, "\' has to be sealed and \'@Serializable\'."

    .line 67
    .line 68
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    :goto_0
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw v1
.end method

.method public static final n(Lsz0/g;)Ljava/lang/String;
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-interface {p0}, Lsz0/g;->d()I

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    invoke-static {v0, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 7
    .line 8
    .line 9
    move-result-object v2

    .line 10
    new-instance v0, Ljava/lang/StringBuilder;

    .line 11
    .line 12
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 13
    .line 14
    .line 15
    invoke-interface {p0}, Lsz0/g;->h()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const/16 v1, 0x28

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    new-instance v6, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;

    .line 32
    .line 33
    const/16 v0, 0xb

    .line 34
    .line 35
    invoke-direct {v6, p0, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/k;-><init>(Ljava/lang/Object;I)V

    .line 36
    .line 37
    .line 38
    const/16 v7, 0x18

    .line 39
    .line 40
    const-string v3, ", "

    .line 41
    .line 42
    const-string v5, ")"

    .line 43
    .line 44
    invoke-static/range {v2 .. v7}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0
.end method

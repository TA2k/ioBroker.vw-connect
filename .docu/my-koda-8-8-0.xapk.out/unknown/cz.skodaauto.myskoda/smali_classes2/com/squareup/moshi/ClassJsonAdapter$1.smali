.class Lcom/squareup/moshi/ClassJsonAdapter$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/squareup/moshi/JsonAdapter$Factory;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/squareup/moshi/ClassJsonAdapter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static b(Ljava/lang/reflect/Type;Ljava/lang/Class;)V
    .locals 4

    .line 1
    invoke-static {p0}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-nez v1, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 13
    .line 14
    new-instance v2, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v3, "No JsonAdapter for "

    .line 17
    .line 18
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p0, ", you should probably use "

    .line 25
    .line 26
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string p0, " instead of "

    .line 37
    .line 38
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Ljava/lang/Class;->getSimpleName()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    const-string p0, " (Moshi only supports the collection interfaces by default) or else register a custom JsonAdapter."

    .line 49
    .line 50
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    invoke-direct {v1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v1
.end method


# virtual methods
.method public final a(Ljava/lang/reflect/Type;Ljava/util/Set;Lcom/squareup/moshi/Moshi;)Lcom/squareup/moshi/JsonAdapter;
    .locals 12

    .line 1
    const-class p0, Ljava/lang/Object;

    .line 2
    .line 3
    instance-of v0, p1, Ljava/lang/Class;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-nez v0, :cond_0

    .line 7
    .line 8
    instance-of v0, p1, Ljava/lang/reflect/ParameterizedType;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    goto/16 :goto_8

    .line 13
    .line 14
    :cond_0
    invoke-static {p1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {v0}, Ljava/lang/Class;->isInterface()Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-nez v2, :cond_15

    .line 23
    .line 24
    invoke-virtual {v0}, Ljava/lang/Class;->isEnum()Z

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz v2, :cond_1

    .line 29
    .line 30
    goto/16 :goto_8

    .line 31
    .line 32
    :cond_1
    invoke-interface {p2}, Ljava/util/Set;->isEmpty()Z

    .line 33
    .line 34
    .line 35
    move-result p2

    .line 36
    if-nez p2, :cond_2

    .line 37
    .line 38
    goto/16 :goto_8

    .line 39
    .line 40
    :cond_2
    invoke-static {v0}, Lax/b;->e(Ljava/lang/Class;)Z

    .line 41
    .line 42
    .line 43
    move-result p2

    .line 44
    if-eqz p2, :cond_4

    .line 45
    .line 46
    const-class p0, Ljava/util/List;

    .line 47
    .line 48
    invoke-static {p1, p0}, Lcom/squareup/moshi/ClassJsonAdapter$1;->b(Ljava/lang/reflect/Type;Ljava/lang/Class;)V

    .line 49
    .line 50
    .line 51
    const-class p0, Ljava/util/Set;

    .line 52
    .line 53
    invoke-static {p1, p0}, Lcom/squareup/moshi/ClassJsonAdapter$1;->b(Ljava/lang/reflect/Type;Ljava/lang/Class;)V

    .line 54
    .line 55
    .line 56
    const-class p0, Ljava/util/Map;

    .line 57
    .line 58
    invoke-static {p1, p0}, Lcom/squareup/moshi/ClassJsonAdapter$1;->b(Ljava/lang/reflect/Type;Ljava/lang/Class;)V

    .line 59
    .line 60
    .line 61
    const-class p0, Ljava/util/Collection;

    .line 62
    .line 63
    invoke-static {p1, p0}, Lcom/squareup/moshi/ClassJsonAdapter$1;->b(Ljava/lang/reflect/Type;Ljava/lang/Class;)V

    .line 64
    .line 65
    .line 66
    new-instance p0, Ljava/lang/StringBuilder;

    .line 67
    .line 68
    const-string p2, "Platform "

    .line 69
    .line 70
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 77
    .line 78
    .line 79
    move-result-object p0

    .line 80
    instance-of p2, p1, Ljava/lang/reflect/ParameterizedType;

    .line 81
    .line 82
    if-eqz p2, :cond_3

    .line 83
    .line 84
    new-instance p2, Ljava/lang/StringBuilder;

    .line 85
    .line 86
    invoke-direct {p2}, Ljava/lang/StringBuilder;-><init>()V

    .line 87
    .line 88
    .line 89
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 90
    .line 91
    .line 92
    const-string p0, " in "

    .line 93
    .line 94
    invoke-virtual {p2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    :cond_3
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 105
    .line 106
    const-string p2, " requires explicit JsonAdapter to be registered"

    .line 107
    .line 108
    invoke-static {p0, p2}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p1

    .line 116
    :cond_4
    invoke-virtual {v0}, Ljava/lang/Class;->isAnonymousClass()Z

    .line 117
    .line 118
    .line 119
    move-result p2

    .line 120
    if-nez p2, :cond_14

    .line 121
    .line 122
    invoke-virtual {v0}, Ljava/lang/Class;->isLocalClass()Z

    .line 123
    .line 124
    .line 125
    move-result p2

    .line 126
    if-nez p2, :cond_13

    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/Class;->getEnclosingClass()Ljava/lang/Class;

    .line 129
    .line 130
    .line 131
    move-result-object p2

    .line 132
    if-eqz p2, :cond_6

    .line 133
    .line 134
    invoke-virtual {v0}, Ljava/lang/Class;->getModifiers()I

    .line 135
    .line 136
    .line 137
    move-result p2

    .line 138
    invoke-static {p2}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 139
    .line 140
    .line 141
    move-result p2

    .line 142
    if-eqz p2, :cond_5

    .line 143
    .line 144
    goto :goto_0

    .line 145
    :cond_5
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 146
    .line 147
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    const-string p2, "Cannot serialize non-static nested class "

    .line 152
    .line 153
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw p0

    .line 161
    :cond_6
    :goto_0
    invoke-virtual {v0}, Ljava/lang/Class;->getModifiers()I

    .line 162
    .line 163
    .line 164
    move-result p2

    .line 165
    invoke-static {p2}, Ljava/lang/reflect/Modifier;->isAbstract(I)Z

    .line 166
    .line 167
    .line 168
    move-result p2

    .line 169
    if-nez p2, :cond_12

    .line 170
    .line 171
    sget-object p2, Lax/b;->c:Ljava/lang/Class;

    .line 172
    .line 173
    if-eqz p2, :cond_8

    .line 174
    .line 175
    invoke-virtual {v0, p2}, Ljava/lang/Class;->isAnnotationPresent(Ljava/lang/Class;)Z

    .line 176
    .line 177
    .line 178
    move-result p2

    .line 179
    if-nez p2, :cond_7

    .line 180
    .line 181
    goto :goto_1

    .line 182
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 183
    .line 184
    new-instance p1, Ljava/lang/StringBuilder;

    .line 185
    .line 186
    const-string p2, "Cannot serialize Kotlin type "

    .line 187
    .line 188
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object p2

    .line 195
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    const-string p2, ". Reflective serialization of Kotlin classes without using kotlin-reflect has undefined and unexpected behavior. Please use KotlinJsonAdapterFactory from the moshi-kotlin artifact or use code gen from the moshi-kotlin-codegen artifact."

    .line 199
    .line 200
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object p1

    .line 207
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    throw p0

    .line 211
    :cond_8
    :goto_1
    const-string p2, "newInstance"

    .line 212
    .line 213
    const-class v2, Ljava/io/ObjectStreamClass;

    .line 214
    .line 215
    const-class v3, Ljava/lang/Class;

    .line 216
    .line 217
    const/4 v4, 0x1

    .line 218
    :try_start_0
    invoke-virtual {v0, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 219
    .line 220
    .line 221
    move-result-object v5

    .line 222
    invoke-virtual {v5, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 223
    .line 224
    .line 225
    new-instance v6, Lcom/squareup/moshi/ClassFactory$1;

    .line 226
    .line 227
    invoke-direct {v6, v5, v0}, Lcom/squareup/moshi/ClassFactory$1;-><init>(Ljava/lang/reflect/Constructor;Ljava/lang/Class;)V
    :try_end_0
    .catch Ljava/lang/NoSuchMethodException; {:try_start_0 .. :try_end_0} :catch_0

    .line 228
    .line 229
    .line 230
    goto :goto_2

    .line 231
    :catch_0
    :try_start_1
    const-string v5, "sun.misc.Unsafe"

    .line 232
    .line 233
    invoke-static {v5}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 234
    .line 235
    .line 236
    move-result-object v5

    .line 237
    const-string v6, "theUnsafe"

    .line 238
    .line 239
    invoke-virtual {v5, v6}, Ljava/lang/Class;->getDeclaredField(Ljava/lang/String;)Ljava/lang/reflect/Field;

    .line 240
    .line 241
    .line 242
    move-result-object v6

    .line 243
    invoke-virtual {v6, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 244
    .line 245
    .line 246
    invoke-virtual {v6, v1}, Ljava/lang/reflect/Field;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v6

    .line 250
    const-string v7, "allocateInstance"

    .line 251
    .line 252
    filled-new-array {v3}, [Ljava/lang/Class;

    .line 253
    .line 254
    .line 255
    move-result-object v8

    .line 256
    invoke-virtual {v5, v7, v8}, Ljava/lang/Class;->getMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 257
    .line 258
    .line 259
    move-result-object v5

    .line 260
    new-instance v7, Lcom/squareup/moshi/ClassFactory$2;

    .line 261
    .line 262
    invoke-direct {v7, v5, v6, v0}, Lcom/squareup/moshi/ClassFactory$2;-><init>(Ljava/lang/reflect/Method;Ljava/lang/Object;Ljava/lang/Class;)V
    :try_end_1
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_6
    .catch Ljava/lang/ClassNotFoundException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/NoSuchMethodException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/NoSuchFieldException; {:try_start_1 .. :try_end_1} :catch_1

    .line 263
    .line 264
    .line 265
    move-object v6, v7

    .line 266
    goto :goto_2

    .line 267
    :catch_1
    :try_start_2
    const-string v5, "getConstructorId"

    .line 268
    .line 269
    filled-new-array {v3}, [Ljava/lang/Class;

    .line 270
    .line 271
    .line 272
    move-result-object v6

    .line 273
    invoke-virtual {v2, v5, v6}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    invoke-virtual {v5, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 278
    .line 279
    .line 280
    filled-new-array {p0}, [Ljava/lang/Object;

    .line 281
    .line 282
    .line 283
    move-result-object v6

    .line 284
    invoke-virtual {v5, v1, v6}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v5

    .line 288
    check-cast v5, Ljava/lang/Integer;

    .line 289
    .line 290
    invoke-virtual {v5}, Ljava/lang/Integer;->intValue()I

    .line 291
    .line 292
    .line 293
    move-result v5

    .line 294
    sget-object v6, Ljava/lang/Integer;->TYPE:Ljava/lang/Class;

    .line 295
    .line 296
    filled-new-array {v3, v6}, [Ljava/lang/Class;

    .line 297
    .line 298
    .line 299
    move-result-object v6

    .line 300
    invoke-virtual {v2, p2, v6}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    invoke-virtual {v2, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 305
    .line 306
    .line 307
    new-instance v6, Lcom/squareup/moshi/ClassFactory$3;

    .line 308
    .line 309
    invoke-direct {v6, v2, v0, v5}, Lcom/squareup/moshi/ClassFactory$3;-><init>(Ljava/lang/reflect/Method;Ljava/lang/Class;I)V
    :try_end_2
    .catch Ljava/lang/IllegalAccessException; {:try_start_2 .. :try_end_2} :catch_5
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_2 .. :try_end_2} :catch_2
    .catch Ljava/lang/NoSuchMethodException; {:try_start_2 .. :try_end_2} :catch_3

    .line 310
    .line 311
    .line 312
    goto :goto_2

    .line 313
    :catch_2
    move-exception p0

    .line 314
    goto/16 :goto_7

    .line 315
    .line 316
    :catch_3
    :try_start_3
    const-class v1, Ljava/io/ObjectInputStream;

    .line 317
    .line 318
    filled-new-array {v3, v3}, [Ljava/lang/Class;

    .line 319
    .line 320
    .line 321
    move-result-object v2

    .line 322
    invoke-virtual {v1, p2, v2}, Ljava/lang/Class;->getDeclaredMethod(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;

    .line 323
    .line 324
    .line 325
    move-result-object p2

    .line 326
    invoke-virtual {p2, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 327
    .line 328
    .line 329
    new-instance v6, Lcom/squareup/moshi/ClassFactory$4;

    .line 330
    .line 331
    invoke-direct {v6, p2, v0}, Lcom/squareup/moshi/ClassFactory$4;-><init>(Ljava/lang/reflect/Method;Ljava/lang/Class;)V
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_4

    .line 332
    .line 333
    .line 334
    :goto_2
    new-instance p2, Ljava/util/TreeMap;

    .line 335
    .line 336
    invoke-direct {p2}, Ljava/util/TreeMap;-><init>()V

    .line 337
    .line 338
    .line 339
    :goto_3
    if-eq p1, p0, :cond_11

    .line 340
    .line 341
    invoke-static {p1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 342
    .line 343
    .line 344
    move-result-object v0

    .line 345
    invoke-static {v0}, Lax/b;->e(Ljava/lang/Class;)Z

    .line 346
    .line 347
    .line 348
    move-result v1

    .line 349
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredFields()[Ljava/lang/reflect/Field;

    .line 350
    .line 351
    .line 352
    move-result-object v2

    .line 353
    array-length v3, v2

    .line 354
    const/4 v5, 0x0

    .line 355
    :goto_4
    if-ge v5, v3, :cond_10

    .line 356
    .line 357
    aget-object v7, v2, v5

    .line 358
    .line 359
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getModifiers()I

    .line 360
    .line 361
    .line 362
    move-result v8

    .line 363
    invoke-static {v8}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 364
    .line 365
    .line 366
    move-result v9

    .line 367
    if-nez v9, :cond_f

    .line 368
    .line 369
    invoke-static {v8}, Ljava/lang/reflect/Modifier;->isTransient(I)Z

    .line 370
    .line 371
    .line 372
    move-result v9

    .line 373
    if-eqz v9, :cond_9

    .line 374
    .line 375
    goto/16 :goto_6

    .line 376
    .line 377
    :cond_9
    invoke-static {v8}, Ljava/lang/reflect/Modifier;->isPublic(I)Z

    .line 378
    .line 379
    .line 380
    move-result v9

    .line 381
    if-nez v9, :cond_a

    .line 382
    .line 383
    invoke-static {v8}, Ljava/lang/reflect/Modifier;->isProtected(I)Z

    .line 384
    .line 385
    .line 386
    move-result v8

    .line 387
    if-nez v8, :cond_a

    .line 388
    .line 389
    if-nez v1, :cond_f

    .line 390
    .line 391
    :cond_a
    const-class v8, Lcom/squareup/moshi/Json;

    .line 392
    .line 393
    invoke-virtual {v7, v8}, Ljava/lang/reflect/Field;->getAnnotation(Ljava/lang/Class;)Ljava/lang/annotation/Annotation;

    .line 394
    .line 395
    .line 396
    move-result-object v8

    .line 397
    check-cast v8, Lcom/squareup/moshi/Json;

    .line 398
    .line 399
    if-eqz v8, :cond_b

    .line 400
    .line 401
    invoke-interface {v8}, Lcom/squareup/moshi/Json;->ignore()Z

    .line 402
    .line 403
    .line 404
    move-result v9

    .line 405
    if-eqz v9, :cond_b

    .line 406
    .line 407
    goto :goto_6

    .line 408
    :cond_b
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getGenericType()Ljava/lang/reflect/Type;

    .line 409
    .line 410
    .line 411
    move-result-object v9

    .line 412
    new-instance v10, Ljava/util/LinkedHashSet;

    .line 413
    .line 414
    invoke-direct {v10}, Ljava/util/LinkedHashSet;-><init>()V

    .line 415
    .line 416
    .line 417
    invoke-static {p1, v0, v9, v10}, Lax/b;->h(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/LinkedHashSet;)Ljava/lang/reflect/Type;

    .line 418
    .line 419
    .line 420
    move-result-object v9

    .line 421
    invoke-interface {v7}, Ljava/lang/reflect/AnnotatedElement;->getAnnotations()[Ljava/lang/annotation/Annotation;

    .line 422
    .line 423
    .line 424
    move-result-object v10

    .line 425
    invoke-static {v10}, Lax/b;->f([Ljava/lang/annotation/Annotation;)Ljava/util/Set;

    .line 426
    .line 427
    .line 428
    move-result-object v10

    .line 429
    invoke-virtual {v7}, Ljava/lang/reflect/Field;->getName()Ljava/lang/String;

    .line 430
    .line 431
    .line 432
    move-result-object v11

    .line 433
    invoke-virtual {p3, v9, v10, v11}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 434
    .line 435
    .line 436
    move-result-object v9

    .line 437
    invoke-virtual {v7, v4}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 438
    .line 439
    .line 440
    if-nez v8, :cond_c

    .line 441
    .line 442
    goto :goto_5

    .line 443
    :cond_c
    invoke-interface {v8}, Lcom/squareup/moshi/Json;->name()Ljava/lang/String;

    .line 444
    .line 445
    .line 446
    move-result-object v8

    .line 447
    const-string v10, "\u0000"

    .line 448
    .line 449
    invoke-virtual {v10, v8}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 450
    .line 451
    .line 452
    move-result v10

    .line 453
    if-eqz v10, :cond_d

    .line 454
    .line 455
    goto :goto_5

    .line 456
    :cond_d
    move-object v11, v8

    .line 457
    :goto_5
    new-instance v8, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;

    .line 458
    .line 459
    invoke-direct {v8, v11, v7, v9}, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;-><init>(Ljava/lang/String;Ljava/lang/reflect/Field;Lcom/squareup/moshi/JsonAdapter;)V

    .line 460
    .line 461
    .line 462
    invoke-virtual {p2, v11, v8}, Ljava/util/TreeMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 463
    .line 464
    .line 465
    move-result-object v8

    .line 466
    check-cast v8, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;

    .line 467
    .line 468
    if-nez v8, :cond_e

    .line 469
    .line 470
    goto :goto_6

    .line 471
    :cond_e
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 472
    .line 473
    new-instance p1, Ljava/lang/StringBuilder;

    .line 474
    .line 475
    const-string p2, "Conflicting fields:\n    "

    .line 476
    .line 477
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 478
    .line 479
    .line 480
    iget-object p2, v8, Lcom/squareup/moshi/ClassJsonAdapter$FieldBinding;->b:Ljava/lang/reflect/Field;

    .line 481
    .line 482
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 483
    .line 484
    .line 485
    const-string p2, "\n    "

    .line 486
    .line 487
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 488
    .line 489
    .line 490
    invoke-virtual {p1, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 491
    .line 492
    .line 493
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 494
    .line 495
    .line 496
    move-result-object p1

    .line 497
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    throw p0

    .line 501
    :cond_f
    :goto_6
    add-int/lit8 v5, v5, 0x1

    .line 502
    .line 503
    goto/16 :goto_4

    .line 504
    .line 505
    :cond_10
    invoke-static {p1}, Lcom/squareup/moshi/Types;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 506
    .line 507
    .line 508
    move-result-object v0

    .line 509
    invoke-virtual {v0}, Ljava/lang/Class;->getGenericSuperclass()Ljava/lang/reflect/Type;

    .line 510
    .line 511
    .line 512
    move-result-object v1

    .line 513
    new-instance v2, Ljava/util/LinkedHashSet;

    .line 514
    .line 515
    invoke-direct {v2}, Ljava/util/LinkedHashSet;-><init>()V

    .line 516
    .line 517
    .line 518
    invoke-static {p1, v0, v1, v2}, Lax/b;->h(Ljava/lang/reflect/Type;Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/LinkedHashSet;)Ljava/lang/reflect/Type;

    .line 519
    .line 520
    .line 521
    move-result-object p1

    .line 522
    goto/16 :goto_3

    .line 523
    .line 524
    :cond_11
    new-instance p0, Lcom/squareup/moshi/ClassJsonAdapter;

    .line 525
    .line 526
    invoke-direct {p0, v6, p2}, Lcom/squareup/moshi/ClassJsonAdapter;-><init>(Lcom/squareup/moshi/ClassFactory;Ljava/util/TreeMap;)V

    .line 527
    .line 528
    .line 529
    invoke-virtual {p0}, Lcom/squareup/moshi/JsonAdapter;->d()Lax/a;

    .line 530
    .line 531
    .line 532
    move-result-object p0

    .line 533
    return-object p0

    .line 534
    :catch_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 535
    .line 536
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 537
    .line 538
    .line 539
    move-result-object p1

    .line 540
    const-string p2, "cannot construct instances of "

    .line 541
    .line 542
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 543
    .line 544
    .line 545
    move-result-object p1

    .line 546
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 547
    .line 548
    .line 549
    throw p0

    .line 550
    :goto_7
    invoke-static {p0}, Lax/b;->i(Ljava/lang/reflect/InvocationTargetException;)V

    .line 551
    .line 552
    .line 553
    throw v1

    .line 554
    :catch_5
    new-instance p0, Ljava/lang/AssertionError;

    .line 555
    .line 556
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 557
    .line 558
    .line 559
    throw p0

    .line 560
    :catch_6
    new-instance p0, Ljava/lang/AssertionError;

    .line 561
    .line 562
    invoke-direct {p0}, Ljava/lang/AssertionError;-><init>()V

    .line 563
    .line 564
    .line 565
    throw p0

    .line 566
    :cond_12
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 567
    .line 568
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 569
    .line 570
    .line 571
    move-result-object p1

    .line 572
    const-string p2, "Cannot serialize abstract class "

    .line 573
    .line 574
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 575
    .line 576
    .line 577
    move-result-object p1

    .line 578
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 579
    .line 580
    .line 581
    throw p0

    .line 582
    :cond_13
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 583
    .line 584
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 585
    .line 586
    .line 587
    move-result-object p1

    .line 588
    const-string p2, "Cannot serialize local class "

    .line 589
    .line 590
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 591
    .line 592
    .line 593
    move-result-object p1

    .line 594
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 595
    .line 596
    .line 597
    throw p0

    .line 598
    :cond_14
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 599
    .line 600
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 601
    .line 602
    .line 603
    move-result-object p1

    .line 604
    const-string p2, "Cannot serialize anonymous class "

    .line 605
    .line 606
    invoke-virtual {p2, p1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 607
    .line 608
    .line 609
    move-result-object p1

    .line 610
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 611
    .line 612
    .line 613
    throw p0

    .line 614
    :cond_15
    :goto_8
    return-object v1
.end method

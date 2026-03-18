.class public final Lkotlin/reflect/jvm/internal/impl/types/TypeParameterUpperBoundEraser$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lkotlin/reflect/jvm/internal/impl/types/TypeParameterUpperBoundEraser;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lkotlin/reflect/jvm/internal/impl/types/TypeParameterUpperBoundEraser$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final replaceArgumentsOfUpperBound(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutor;Ljava/util/Set;Z)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;
    .locals 16
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lkotlin/reflect/jvm/internal/impl/types/KotlinType;",
            "Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutor;",
            "Ljava/util/Set<",
            "+",
            "Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;",
            ">;Z)",
            "Lkotlin/reflect/jvm/internal/impl/types/KotlinType;"
        }
    .end annotation

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    const-string v2, "<this>"

    .line 6
    .line 7
    move-object/from16 v3, p1

    .line 8
    .line 9
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    const-string v2, "substitutor"

    .line 13
    .line 14
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->unwrap()Lkotlin/reflect/jvm/internal/impl/types/UnwrappedType;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    instance-of v4, v2, Lkotlin/reflect/jvm/internal/impl/types/FlexibleType;

    .line 22
    .line 23
    const/4 v5, 0x2

    .line 24
    const-string v6, "getType(...)"

    .line 25
    .line 26
    const/16 v9, 0xa

    .line 27
    .line 28
    const-string v10, "getParameters(...)"

    .line 29
    .line 30
    const/4 v11, 0x0

    .line 31
    if-eqz v4, :cond_e

    .line 32
    .line 33
    move-object v4, v2

    .line 34
    check-cast v4, Lkotlin/reflect/jvm/internal/impl/types/FlexibleType;

    .line 35
    .line 36
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/FlexibleType;->getLowerBound()Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 37
    .line 38
    .line 39
    move-result-object v12

    .line 40
    invoke-virtual {v12}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 41
    .line 42
    .line 43
    move-result-object v13

    .line 44
    invoke-interface {v13}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getParameters()Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object v13

    .line 48
    invoke-interface {v13}, Ljava/util/List;->isEmpty()Z

    .line 49
    .line 50
    .line 51
    move-result v13

    .line 52
    if-nez v13, :cond_6

    .line 53
    .line 54
    invoke-virtual {v12}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 55
    .line 56
    .line 57
    move-result-object v13

    .line 58
    invoke-interface {v13}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getDeclarationDescriptor()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptor;

    .line 59
    .line 60
    .line 61
    move-result-object v13

    .line 62
    if-nez v13, :cond_0

    .line 63
    .line 64
    goto/16 :goto_3

    .line 65
    .line 66
    :cond_0
    invoke-virtual {v12}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 67
    .line 68
    .line 69
    move-result-object v13

    .line 70
    invoke-interface {v13}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getParameters()Ljava/util/List;

    .line 71
    .line 72
    .line 73
    move-result-object v13

    .line 74
    invoke-static {v13, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    check-cast v13, Ljava/lang/Iterable;

    .line 78
    .line 79
    new-instance v14, Ljava/util/ArrayList;

    .line 80
    .line 81
    invoke-static {v13, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 82
    .line 83
    .line 84
    move-result v15

    .line 85
    invoke-direct {v14, v15}, Ljava/util/ArrayList;-><init>(I)V

    .line 86
    .line 87
    .line 88
    invoke-interface {v13}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 89
    .line 90
    .line 91
    move-result-object v13

    .line 92
    :goto_0
    invoke-interface {v13}, Ljava/util/Iterator;->hasNext()Z

    .line 93
    .line 94
    .line 95
    move-result v15

    .line 96
    if-eqz v15, :cond_5

    .line 97
    .line 98
    invoke-interface {v13}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v15

    .line 102
    check-cast v15, Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;

    .line 103
    .line 104
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getArguments()Ljava/util/List;

    .line 105
    .line 106
    .line 107
    move-result-object v7

    .line 108
    invoke-interface {v15}, Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;->getIndex()I

    .line 109
    .line 110
    .line 111
    move-result v8

    .line 112
    invoke-static {v8, v7}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object v7

    .line 116
    check-cast v7, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;

    .line 117
    .line 118
    if-eqz p4, :cond_1

    .line 119
    .line 120
    if-eqz v7, :cond_1

    .line 121
    .line 122
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 123
    .line 124
    .line 125
    move-result-object v8

    .line 126
    if-eqz v8, :cond_1

    .line 127
    .line 128
    invoke-static {v8}, Lkotlin/reflect/jvm/internal/impl/types/typeUtil/TypeUtilsKt;->containsTypeParameter(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Z

    .line 129
    .line 130
    .line 131
    move-result v8

    .line 132
    if-nez v8, :cond_1

    .line 133
    .line 134
    goto :goto_2

    .line 135
    :cond_1
    if-eqz v1, :cond_2

    .line 136
    .line 137
    invoke-interface {v1, v15}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v8

    .line 141
    if-eqz v8, :cond_2

    .line 142
    .line 143
    const/4 v8, 0x1

    .line 144
    goto :goto_1

    .line 145
    :cond_2
    const/4 v8, 0x0

    .line 146
    :goto_1
    if-eqz v7, :cond_3

    .line 147
    .line 148
    if-nez v8, :cond_3

    .line 149
    .line 150
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutor;->getSubstitution()Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;

    .line 151
    .line 152
    .line 153
    move-result-object v8

    .line 154
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 155
    .line 156
    .line 157
    move-result-object v9

    .line 158
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 159
    .line 160
    .line 161
    invoke-virtual {v8, v9}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;->get(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;

    .line 162
    .line 163
    .line 164
    move-result-object v8

    .line 165
    if-nez v8, :cond_4

    .line 166
    .line 167
    :cond_3
    new-instance v7, Lkotlin/reflect/jvm/internal/impl/types/StarProjectionImpl;

    .line 168
    .line 169
    invoke-direct {v7, v15}, Lkotlin/reflect/jvm/internal/impl/types/StarProjectionImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;)V

    .line 170
    .line 171
    .line 172
    :cond_4
    :goto_2
    invoke-interface {v14, v7}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    const/16 v9, 0xa

    .line 176
    .line 177
    goto :goto_0

    .line 178
    :cond_5
    invoke-static {v12, v14, v11, v5, v11}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutionKt;->replace$default(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;Ljava/util/List;Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;ILjava/lang/Object;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 179
    .line 180
    .line 181
    move-result-object v12

    .line 182
    :cond_6
    :goto_3
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/FlexibleType;->getUpperBound()Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 183
    .line 184
    .line 185
    move-result-object v4

    .line 186
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 187
    .line 188
    .line 189
    move-result-object v7

    .line 190
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getParameters()Ljava/util/List;

    .line 191
    .line 192
    .line 193
    move-result-object v7

    .line 194
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 195
    .line 196
    .line 197
    move-result v7

    .line 198
    if-nez v7, :cond_d

    .line 199
    .line 200
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 201
    .line 202
    .line 203
    move-result-object v7

    .line 204
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getDeclarationDescriptor()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptor;

    .line 205
    .line 206
    .line 207
    move-result-object v7

    .line 208
    if-nez v7, :cond_7

    .line 209
    .line 210
    goto/16 :goto_7

    .line 211
    .line 212
    :cond_7
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 213
    .line 214
    .line 215
    move-result-object v7

    .line 216
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getParameters()Ljava/util/List;

    .line 217
    .line 218
    .line 219
    move-result-object v7

    .line 220
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 221
    .line 222
    .line 223
    check-cast v7, Ljava/lang/Iterable;

    .line 224
    .line 225
    new-instance v8, Ljava/util/ArrayList;

    .line 226
    .line 227
    const/16 v9, 0xa

    .line 228
    .line 229
    invoke-static {v7, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 230
    .line 231
    .line 232
    move-result v9

    .line 233
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 234
    .line 235
    .line 236
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 237
    .line 238
    .line 239
    move-result-object v7

    .line 240
    :goto_4
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 241
    .line 242
    .line 243
    move-result v9

    .line 244
    if-eqz v9, :cond_c

    .line 245
    .line 246
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 247
    .line 248
    .line 249
    move-result-object v9

    .line 250
    check-cast v9, Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;

    .line 251
    .line 252
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getArguments()Ljava/util/List;

    .line 253
    .line 254
    .line 255
    move-result-object v10

    .line 256
    invoke-interface {v9}, Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;->getIndex()I

    .line 257
    .line 258
    .line 259
    move-result v13

    .line 260
    invoke-static {v13, v10}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 261
    .line 262
    .line 263
    move-result-object v10

    .line 264
    check-cast v10, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;

    .line 265
    .line 266
    if-eqz p4, :cond_8

    .line 267
    .line 268
    if-eqz v10, :cond_8

    .line 269
    .line 270
    invoke-interface {v10}, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 271
    .line 272
    .line 273
    move-result-object v13

    .line 274
    if-eqz v13, :cond_8

    .line 275
    .line 276
    invoke-static {v13}, Lkotlin/reflect/jvm/internal/impl/types/typeUtil/TypeUtilsKt;->containsTypeParameter(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Z

    .line 277
    .line 278
    .line 279
    move-result v13

    .line 280
    if-nez v13, :cond_8

    .line 281
    .line 282
    goto :goto_6

    .line 283
    :cond_8
    if-eqz v1, :cond_9

    .line 284
    .line 285
    invoke-interface {v1, v9}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 286
    .line 287
    .line 288
    move-result v13

    .line 289
    if-eqz v13, :cond_9

    .line 290
    .line 291
    const/4 v13, 0x1

    .line 292
    goto :goto_5

    .line 293
    :cond_9
    const/4 v13, 0x0

    .line 294
    :goto_5
    if-eqz v10, :cond_a

    .line 295
    .line 296
    if-nez v13, :cond_a

    .line 297
    .line 298
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutor;->getSubstitution()Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;

    .line 299
    .line 300
    .line 301
    move-result-object v13

    .line 302
    invoke-interface {v10}, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 303
    .line 304
    .line 305
    move-result-object v14

    .line 306
    invoke-static {v14, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    invoke-virtual {v13, v14}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;->get(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;

    .line 310
    .line 311
    .line 312
    move-result-object v13

    .line 313
    if-nez v13, :cond_b

    .line 314
    .line 315
    :cond_a
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/types/StarProjectionImpl;

    .line 316
    .line 317
    invoke-direct {v10, v9}, Lkotlin/reflect/jvm/internal/impl/types/StarProjectionImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;)V

    .line 318
    .line 319
    .line 320
    :cond_b
    :goto_6
    invoke-interface {v8, v10}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 321
    .line 322
    .line 323
    goto :goto_4

    .line 324
    :cond_c
    invoke-static {v4, v8, v11, v5, v11}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutionKt;->replace$default(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;Ljava/util/List;Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;ILjava/lang/Object;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 325
    .line 326
    .line 327
    move-result-object v4

    .line 328
    :cond_d
    :goto_7
    invoke-static {v12, v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinTypeFactory;->flexibleType(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;Lkotlin/reflect/jvm/internal/impl/types/SimpleType;)Lkotlin/reflect/jvm/internal/impl/types/UnwrappedType;

    .line 329
    .line 330
    .line 331
    move-result-object v1

    .line 332
    goto/16 :goto_c

    .line 333
    .line 334
    :cond_e
    instance-of v4, v2, Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 335
    .line 336
    if-eqz v4, :cond_16

    .line 337
    .line 338
    move-object v4, v2

    .line 339
    check-cast v4, Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 340
    .line 341
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 342
    .line 343
    .line 344
    move-result-object v7

    .line 345
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getParameters()Ljava/util/List;

    .line 346
    .line 347
    .line 348
    move-result-object v7

    .line 349
    invoke-interface {v7}, Ljava/util/List;->isEmpty()Z

    .line 350
    .line 351
    .line 352
    move-result v7

    .line 353
    if-nez v7, :cond_15

    .line 354
    .line 355
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 356
    .line 357
    .line 358
    move-result-object v7

    .line 359
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getDeclarationDescriptor()Lkotlin/reflect/jvm/internal/impl/descriptors/ClassifierDescriptor;

    .line 360
    .line 361
    .line 362
    move-result-object v7

    .line 363
    if-nez v7, :cond_f

    .line 364
    .line 365
    goto/16 :goto_b

    .line 366
    .line 367
    :cond_f
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getConstructor()Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;

    .line 368
    .line 369
    .line 370
    move-result-object v7

    .line 371
    invoke-interface {v7}, Lkotlin/reflect/jvm/internal/impl/types/TypeConstructor;->getParameters()Ljava/util/List;

    .line 372
    .line 373
    .line 374
    move-result-object v7

    .line 375
    invoke-static {v7, v10}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 376
    .line 377
    .line 378
    check-cast v7, Ljava/lang/Iterable;

    .line 379
    .line 380
    new-instance v8, Ljava/util/ArrayList;

    .line 381
    .line 382
    const/16 v9, 0xa

    .line 383
    .line 384
    invoke-static {v7, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 385
    .line 386
    .line 387
    move-result v9

    .line 388
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 389
    .line 390
    .line 391
    invoke-interface {v7}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 392
    .line 393
    .line 394
    move-result-object v7

    .line 395
    :goto_8
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 396
    .line 397
    .line 398
    move-result v9

    .line 399
    if-eqz v9, :cond_14

    .line 400
    .line 401
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 402
    .line 403
    .line 404
    move-result-object v9

    .line 405
    check-cast v9, Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;

    .line 406
    .line 407
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/types/KotlinType;->getArguments()Ljava/util/List;

    .line 408
    .line 409
    .line 410
    move-result-object v10

    .line 411
    invoke-interface {v9}, Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;->getIndex()I

    .line 412
    .line 413
    .line 414
    move-result v12

    .line 415
    invoke-static {v12, v10}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object v10

    .line 419
    check-cast v10, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;

    .line 420
    .line 421
    if-eqz p4, :cond_10

    .line 422
    .line 423
    if-eqz v10, :cond_10

    .line 424
    .line 425
    invoke-interface {v10}, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 426
    .line 427
    .line 428
    move-result-object v12

    .line 429
    if-eqz v12, :cond_10

    .line 430
    .line 431
    invoke-static {v12}, Lkotlin/reflect/jvm/internal/impl/types/typeUtil/TypeUtilsKt;->containsTypeParameter(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Z

    .line 432
    .line 433
    .line 434
    move-result v12

    .line 435
    if-nez v12, :cond_10

    .line 436
    .line 437
    goto :goto_a

    .line 438
    :cond_10
    if-eqz v1, :cond_11

    .line 439
    .line 440
    invoke-interface {v1, v9}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 441
    .line 442
    .line 443
    move-result v12

    .line 444
    if-eqz v12, :cond_11

    .line 445
    .line 446
    const/4 v12, 0x1

    .line 447
    goto :goto_9

    .line 448
    :cond_11
    const/4 v12, 0x0

    .line 449
    :goto_9
    if-eqz v10, :cond_12

    .line 450
    .line 451
    if-nez v12, :cond_12

    .line 452
    .line 453
    invoke-virtual {v0}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutor;->getSubstitution()Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;

    .line 454
    .line 455
    .line 456
    move-result-object v12

    .line 457
    invoke-interface {v10}, Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;->getType()Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 458
    .line 459
    .line 460
    move-result-object v13

    .line 461
    invoke-static {v13, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 462
    .line 463
    .line 464
    invoke-virtual {v12, v13}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitution;->get(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/TypeProjection;

    .line 465
    .line 466
    .line 467
    move-result-object v12

    .line 468
    if-nez v12, :cond_13

    .line 469
    .line 470
    :cond_12
    new-instance v10, Lkotlin/reflect/jvm/internal/impl/types/StarProjectionImpl;

    .line 471
    .line 472
    invoke-direct {v10, v9}, Lkotlin/reflect/jvm/internal/impl/types/StarProjectionImpl;-><init>(Lkotlin/reflect/jvm/internal/impl/descriptors/TypeParameterDescriptor;)V

    .line 473
    .line 474
    .line 475
    :cond_13
    :goto_a
    invoke-interface {v8, v10}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 476
    .line 477
    .line 478
    goto :goto_8

    .line 479
    :cond_14
    invoke-static {v4, v8, v11, v5, v11}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutionKt;->replace$default(Lkotlin/reflect/jvm/internal/impl/types/SimpleType;Ljava/util/List;Lkotlin/reflect/jvm/internal/impl/types/TypeAttributes;ILjava/lang/Object;)Lkotlin/reflect/jvm/internal/impl/types/SimpleType;

    .line 480
    .line 481
    .line 482
    move-result-object v1

    .line 483
    goto :goto_c

    .line 484
    :cond_15
    :goto_b
    move-object v1, v4

    .line 485
    :goto_c
    invoke-static {v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeWithEnhancementKt;->inheritEnhancement(Lkotlin/reflect/jvm/internal/impl/types/UnwrappedType;Lkotlin/reflect/jvm/internal/impl/types/KotlinType;)Lkotlin/reflect/jvm/internal/impl/types/UnwrappedType;

    .line 486
    .line 487
    .line 488
    move-result-object v1

    .line 489
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/types/Variance;->OUT_VARIANCE:Lkotlin/reflect/jvm/internal/impl/types/Variance;

    .line 490
    .line 491
    invoke-virtual {v0, v1, v2}, Lkotlin/reflect/jvm/internal/impl/types/TypeSubstitutor;->safeSubstitute(Lkotlin/reflect/jvm/internal/impl/types/KotlinType;Lkotlin/reflect/jvm/internal/impl/types/Variance;)Lkotlin/reflect/jvm/internal/impl/types/KotlinType;

    .line 492
    .line 493
    .line 494
    move-result-object v0

    .line 495
    const-string v1, "safeSubstitute(...)"

    .line 496
    .line 497
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    return-object v0

    .line 501
    :cond_16
    new-instance v0, La8/r0;

    .line 502
    .line 503
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 504
    .line 505
    .line 506
    throw v0
.end method

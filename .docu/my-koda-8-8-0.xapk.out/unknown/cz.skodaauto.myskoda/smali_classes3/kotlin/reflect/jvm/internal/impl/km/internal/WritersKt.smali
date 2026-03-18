.class public final Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$WhenMappings;
    }
.end annotation


# direct methods
.method public static synthetic accessor$WritersKt$lambda0(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeVersionRequirement$lambda$1(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static synthetic accessor$WritersKt$lambda1(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeVersionRequirement$lambda$2(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;I)Llx0/b0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public static final writeProperty(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmProperty;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;
    .locals 5

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "kmProperty"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getTypeParameters()Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    check-cast v1, Ljava/lang/Iterable;

    .line 20
    .line 21
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 26
    .line 27
    .line 28
    move-result v2

    .line 29
    if-eqz v2, :cond_0

    .line 30
    .line 31
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;

    .line 36
    .line 37
    invoke-static {p0, v2}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeTypeParameter(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter;

    .line 42
    .line 43
    .line 44
    move-result-object v2

    .line 45
    invoke-virtual {v0, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->addTypeParameter(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 46
    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getReceiverParameterType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    if-eqz v1, :cond_1

    .line 54
    .line 55
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setReceiverType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 64
    .line 65
    .line 66
    :cond_1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getContextParameters()Ljava/util/List;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    check-cast v1, Ljava/lang/Iterable;

    .line 71
    .line 72
    new-instance v2, Ljava/util/ArrayList;

    .line 73
    .line 74
    const/16 v3, 0xa

    .line 75
    .line 76
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 77
    .line 78
    .line 79
    move-result v4

    .line 80
    invoke-direct {v2, v4}, Ljava/util/ArrayList;-><init>(I)V

    .line 81
    .line 82
    .line 83
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 84
    .line 85
    .line 86
    move-result-object v1

    .line 87
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 88
    .line 89
    .line 90
    move-result v4

    .line 91
    if-eqz v4, :cond_2

    .line 92
    .line 93
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v4

    .line 97
    check-cast v4, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;

    .line 98
    .line 99
    invoke-static {p0, v4}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeValueParameter(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 100
    .line 101
    .line 102
    move-result-object v4

    .line 103
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;

    .line 104
    .line 105
    .line 106
    move-result-object v4

    .line 107
    invoke-interface {v2, v4}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_2
    invoke-virtual {v0, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->addAllContextParameter(Ljava/lang/Iterable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getContextParameters()Ljava/util/List;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    check-cast v1, Ljava/lang/Iterable;

    .line 119
    .line 120
    new-instance v2, Ljava/util/ArrayList;

    .line 121
    .line 122
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    invoke-direct {v2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 127
    .line 128
    .line 129
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 130
    .line 131
    .line 132
    move-result-object v1

    .line 133
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v3

    .line 137
    if-eqz v3, :cond_3

    .line 138
    .line 139
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;

    .line 144
    .line 145
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    invoke-static {p0, v3}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 150
    .line 151
    .line 152
    move-result-object v3

    .line 153
    invoke-virtual {v3}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 154
    .line 155
    .line 156
    move-result-object v3

    .line 157
    invoke-interface {v2, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 158
    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_3
    invoke-virtual {v0, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->addAllContextReceiverType(Ljava/lang/Iterable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 162
    .line 163
    .line 164
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getSetterParameter()Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;

    .line 165
    .line 166
    .line 167
    move-result-object v1

    .line 168
    if-eqz v1, :cond_4

    .line 169
    .line 170
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeValueParameter(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;

    .line 175
    .line 176
    .line 177
    move-result-object v1

    .line 178
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setSetterValueParameter(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 179
    .line 180
    .line 181
    :cond_4
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getReturnType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 182
    .line 183
    .line 184
    move-result-object v1

    .line 185
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 186
    .line 187
    .line 188
    move-result-object v1

    .line 189
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 190
    .line 191
    .line 192
    move-result-object v1

    .line 193
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setReturnType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 194
    .line 195
    .line 196
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getVersionRequirements()Ljava/util/List;

    .line 197
    .line 198
    .line 199
    move-result-object v1

    .line 200
    check-cast v1, Ljava/lang/Iterable;

    .line 201
    .line 202
    new-instance v2, Ljava/util/ArrayList;

    .line 203
    .line 204
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 205
    .line 206
    .line 207
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    :cond_5
    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 212
    .line 213
    .line 214
    move-result v3

    .line 215
    if-eqz v3, :cond_6

    .line 216
    .line 217
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v3

    .line 221
    check-cast v3, Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;

    .line 222
    .line 223
    invoke-static {p0, v3}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeVersionRequirement(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;)Ljava/lang/Integer;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    if-eqz v3, :cond_5

    .line 228
    .line 229
    invoke-interface {v2, v3}, Ljava/util/Collection;->add(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    goto :goto_3

    .line 233
    :cond_6
    invoke-virtual {v0, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->addAllVersionRequirement(Ljava/lang/Iterable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 234
    .line 235
    .line 236
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getExtensions$kotlin_metadata()Ljava/util/List;

    .line 237
    .line 238
    .line 239
    move-result-object v1

    .line 240
    check-cast v1, Ljava/lang/Iterable;

    .line 241
    .line 242
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 247
    .line 248
    .line 249
    move-result v2

    .line 250
    if-eqz v2, :cond_7

    .line 251
    .line 252
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v2

    .line 256
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 257
    .line 258
    invoke-interface {v2, p1, v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->writePropertyExtensions(Lkotlin/reflect/jvm/internal/impl/km/KmProperty;Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;)V

    .line 259
    .line 260
    .line 261
    goto :goto_4

    .line 262
    :cond_7
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getName()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v1

    .line 266
    invoke-virtual {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->get(Ljava/lang/String;)I

    .line 267
    .line 268
    .line 269
    move-result p0

    .line 270
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setName(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 271
    .line 272
    .line 273
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getFlags$kotlin_metadata()I

    .line 274
    .line 275
    .line 276
    move-result p0

    .line 277
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->HAS_ANNOTATIONS:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 278
    .line 279
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getAnnotations()Ljava/util/List;

    .line 280
    .line 281
    .line 282
    move-result-object v2

    .line 283
    check-cast v2, Ljava/util/Collection;

    .line 284
    .line 285
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 286
    .line 287
    .line 288
    move-result v2

    .line 289
    xor-int/lit8 v2, v2, 0x1

    .line 290
    .line 291
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 292
    .line 293
    .line 294
    move-result-object v2

    .line 295
    invoke-virtual {v1, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 296
    .line 297
    .line 298
    move-result v2

    .line 299
    or-int/2addr p0, v2

    .line 300
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;->getDefaultInstance()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;

    .line 301
    .line 302
    .line 303
    move-result-object v2

    .line 304
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property;->getFlags()I

    .line 305
    .line 306
    .line 307
    move-result v2

    .line 308
    if-eq p0, v2, :cond_8

    .line 309
    .line 310
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 311
    .line 312
    .line 313
    :cond_8
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getGetter()Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 314
    .line 315
    .line 316
    move-result-object p0

    .line 317
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;->getFlags$kotlin_metadata()I

    .line 318
    .line 319
    .line 320
    move-result p0

    .line 321
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getGetter()Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 322
    .line 323
    .line 324
    move-result-object v2

    .line 325
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;->getAnnotations()Ljava/util/List;

    .line 326
    .line 327
    .line 328
    move-result-object v2

    .line 329
    check-cast v2, Ljava/util/Collection;

    .line 330
    .line 331
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 332
    .line 333
    .line 334
    move-result v2

    .line 335
    xor-int/lit8 v2, v2, 0x1

    .line 336
    .line 337
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 338
    .line 339
    .line 340
    move-result-object v2

    .line 341
    invoke-virtual {v1, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 342
    .line 343
    .line 344
    move-result v2

    .line 345
    or-int/2addr p0, v2

    .line 346
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setGetterFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 347
    .line 348
    .line 349
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmProperty;->getSetter()Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;

    .line 350
    .line 351
    .line 352
    move-result-object p0

    .line 353
    if-eqz p0, :cond_9

    .line 354
    .line 355
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;->getFlags$kotlin_metadata()I

    .line 356
    .line 357
    .line 358
    move-result p1

    .line 359
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/KmPropertyAccessorAttributes;->getAnnotations()Ljava/util/List;

    .line 360
    .line 361
    .line 362
    move-result-object p0

    .line 363
    check-cast p0, Ljava/util/Collection;

    .line 364
    .line 365
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 366
    .line 367
    .line 368
    move-result p0

    .line 369
    xor-int/lit8 p0, p0, 0x1

    .line 370
    .line 371
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 372
    .line 373
    .line 374
    move-result-object p0

    .line 375
    invoke-virtual {v1, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 376
    .line 377
    .line 378
    move-result p0

    .line 379
    or-int/2addr p0, p1

    .line 380
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;->setSetterFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Property$Builder;

    .line 381
    .line 382
    .line 383
    :cond_9
    return-object v0
.end method

.method private static final writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;
    .locals 3

    .line 1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getClassifier()Lkotlin/reflect/jvm/internal/impl/km/KmClassifier;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    instance-of v2, v1, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$Class;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$Class;

    .line 14
    .line 15
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$Class;->getName()Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    invoke-virtual {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getClassName$kotlin_metadata(Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setClassName(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    instance-of v2, v1, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$TypeAlias;

    .line 28
    .line 29
    if-eqz v2, :cond_1

    .line 30
    .line 31
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$TypeAlias;

    .line 32
    .line 33
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$TypeAlias;->getName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    invoke-virtual {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getClassName$kotlin_metadata(Ljava/lang/String;)I

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setTypeAliasName(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_1
    instance-of v2, v1, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$TypeParameter;

    .line 46
    .line 47
    if-eqz v2, :cond_a

    .line 48
    .line 49
    check-cast v1, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$TypeParameter;

    .line 50
    .line 51
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/km/KmClassifier$TypeParameter;->getId()I

    .line 52
    .line 53
    .line 54
    move-result v1

    .line 55
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setTypeParameter(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 56
    .line 57
    .line 58
    :goto_0
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getArguments()Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Ljava/lang/Iterable;

    .line 63
    .line 64
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_2

    .line 73
    .line 74
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;

    .line 79
    .line 80
    invoke-static {p0, v2}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeTypeProjection(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-virtual {v0, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->addArgument(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 85
    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_2
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getAbbreviatedType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    if-eqz v1, :cond_3

    .line 93
    .line 94
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 95
    .line 96
    .line 97
    move-result-object v1

    .line 98
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setAbbreviatedType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 103
    .line 104
    .line 105
    :cond_3
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getOuterType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 106
    .line 107
    .line 108
    move-result-object v1

    .line 109
    if-eqz v1, :cond_4

    .line 110
    .line 111
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 112
    .line 113
    .line 114
    move-result-object v1

    .line 115
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setOuterType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 120
    .line 121
    .line 122
    :cond_4
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getFlexibleTypeUpperBound()Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;

    .line 123
    .line 124
    .line 125
    move-result-object v1

    .line 126
    if-eqz v1, :cond_6

    .line 127
    .line 128
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;->getType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 129
    .line 130
    .line 131
    move-result-object v2

    .line 132
    invoke-static {p0, v2}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 133
    .line 134
    .line 135
    move-result-object v2

    .line 136
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/km/KmFlexibleTypeUpperBound;->getTypeFlexibilityId()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object v1

    .line 140
    if-eqz v1, :cond_5

    .line 141
    .line 142
    invoke-virtual {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->get(Ljava/lang/String;)I

    .line 143
    .line 144
    .line 145
    move-result v1

    .line 146
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setFlexibleTypeCapabilitiesId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 147
    .line 148
    .line 149
    :cond_5
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setFlexibleUpperBound(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 154
    .line 155
    .line 156
    :cond_6
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getExtensions$kotlin_metadata()Ljava/util/List;

    .line 157
    .line 158
    .line 159
    move-result-object v1

    .line 160
    check-cast v1, Ljava/lang/Iterable;

    .line 161
    .line 162
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 163
    .line 164
    .line 165
    move-result-object v1

    .line 166
    :goto_2
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    if-eqz v2, :cond_7

    .line 171
    .line 172
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v2

    .line 176
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 177
    .line 178
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 179
    .line 180
    .line 181
    invoke-interface {v2, p1, v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->writeTypeExtensions(Lkotlin/reflect/jvm/internal/impl/km/KmType;Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;)V

    .line 182
    .line 183
    .line 184
    goto :goto_2

    .line 185
    :cond_7
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/km/Attributes;->isNullable(Lkotlin/reflect/jvm/internal/impl/km/KmType;)Z

    .line 186
    .line 187
    .line 188
    move-result p0

    .line 189
    const/4 v1, 0x1

    .line 190
    if-eqz p0, :cond_8

    .line 191
    .line 192
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setNullable(Z)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 193
    .line 194
    .line 195
    :cond_8
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmType;->getFlags$kotlin_metadata()I

    .line 196
    .line 197
    .line 198
    move-result p0

    .line 199
    shr-int/2addr p0, v1

    .line 200
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;->getDefaultInstance()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;->getFlags()I

    .line 205
    .line 206
    .line 207
    move-result p1

    .line 208
    if-eq p0, p1, :cond_9

    .line 209
    .line 210
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 211
    .line 212
    .line 213
    :cond_9
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    return-object v0

    .line 217
    :cond_a
    new-instance p0, La8/r0;

    .line 218
    .line 219
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 220
    .line 221
    .line 222
    throw p0
.end method

.method private static final writeTypeParameter(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;
    .locals 3

    .line 1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->getUpperBounds()Ljava/util/List;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    check-cast v1, Ljava/lang/Iterable;

    .line 10
    .line 11
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_0

    .line 20
    .line 21
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 26
    .line 27
    invoke-static {p0, v2}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 28
    .line 29
    .line 30
    move-result-object v2

    .line 31
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 32
    .line 33
    .line 34
    move-result-object v2

    .line 35
    invoke-virtual {v0, v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->addUpperBound(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 36
    .line 37
    .line 38
    goto :goto_0

    .line 39
    :cond_0
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getExtensions$kotlin_metadata()Ljava/util/List;

    .line 40
    .line 41
    .line 42
    move-result-object v1

    .line 43
    check-cast v1, Ljava/lang/Iterable;

    .line 44
    .line 45
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v1

    .line 49
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    if-eqz v2, :cond_1

    .line 54
    .line 55
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 60
    .line 61
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-interface {v2, p1, v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->writeTypeParameterExtensions(Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->getName()Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object v1

    .line 72
    invoke-virtual {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->get(Ljava/lang/String;)I

    .line 73
    .line 74
    .line 75
    move-result p0

    .line 76
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->setName(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->getId()I

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->setId(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 84
    .line 85
    .line 86
    invoke-static {p1}, Lkotlin/reflect/jvm/internal/impl/km/Attributes;->isReified(Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;)Z

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter;->getDefaultInstance()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter;->getReified()Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-eq p0, v1, :cond_2

    .line 99
    .line 100
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->setReified(Z)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 101
    .line 102
    .line 103
    :cond_2
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->getVariance()Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/km/KmVariance;->IN:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 108
    .line 109
    if-ne p0, v1, :cond_3

    .line 110
    .line 111
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Variance;->IN:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Variance;

    .line 112
    .line 113
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->setVariance(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Variance;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 114
    .line 115
    .line 116
    return-object v0

    .line 117
    :cond_3
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeParameter;->getVariance()Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 118
    .line 119
    .line 120
    move-result-object p0

    .line 121
    sget-object p1, Lkotlin/reflect/jvm/internal/impl/km/KmVariance;->OUT:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 122
    .line 123
    if-ne p0, p1, :cond_4

    .line 124
    .line 125
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Variance;->OUT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Variance;

    .line 126
    .line 127
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;->setVariance(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Variance;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$TypeParameter$Builder;

    .line 128
    .line 129
    .line 130
    :cond_4
    return-object v0
.end method

.method private static final writeTypeProjection(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;
    .locals 3

    .line 1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;->STAR:Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;

    .line 6
    .line 7
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    sget-object p0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;->STAR:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;->setProjection(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;

    .line 16
    .line 17
    .line 18
    goto :goto_1

    .line 19
    :cond_0
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;->component1()Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmTypeProjection;->component2()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    if-eqz v1, :cond_3

    .line 28
    .line 29
    if-eqz p1, :cond_3

    .line 30
    .line 31
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/km/KmVariance;->IN:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 32
    .line 33
    if-ne v1, v2, :cond_1

    .line 34
    .line 35
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;->IN:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;->setProjection(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_1
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/km/KmVariance;->OUT:Lkotlin/reflect/jvm/internal/impl/km/KmVariance;

    .line 42
    .line 43
    if-ne v1, v2, :cond_2

    .line 44
    .line 45
    sget-object v1, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;->OUT:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;->setProjection(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Projection;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;

    .line 48
    .line 49
    .line 50
    :cond_2
    :goto_0
    invoke-static {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Argument$Builder;

    .line 59
    .line 60
    .line 61
    :goto_1
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    return-object v0

    .line 65
    :cond_3
    new-instance p0, Lkotlin/reflect/jvm/internal/impl/km/InconsistentKotlinMetadataException;

    .line 66
    .line 67
    const-string p1, "Variance and type must be set for non-star type projection"

    .line 68
    .line 69
    const/4 v0, 0x2

    .line 70
    const/4 v1, 0x0

    .line 71
    invoke-direct {p0, p1, v1, v0, v1}, Lkotlin/reflect/jvm/internal/impl/km/InconsistentKotlinMetadataException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;ILkotlin/jvm/internal/g;)V

    .line 72
    .line 73
    .line 74
    throw p0
.end method

.method private static final writeValueParameter(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;
    .locals 4

    .line 1
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->setType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getVarargElementType()Lkotlin/reflect/jvm/internal/impl/km/KmType;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    if-eqz v1, :cond_0

    .line 25
    .line 26
    invoke-static {p0, v1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt;->writeType(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmType;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->setVarargElementType(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Type;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 35
    .line 36
    .line 37
    :cond_0
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getAnnotationParameterDefaultValue()Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    if-eqz v1, :cond_1

    .line 42
    .line 43
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getStrings()Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;

    .line 44
    .line 45
    .line 46
    move-result-object v2

    .line 47
    invoke-static {v1, v2}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteUtilsKt;->writeAnnotationArgument(Lkotlin/reflect/jvm/internal/impl/km/KmAnnotationArgument;Lkotlin/reflect/jvm/internal/impl/metadata/serialization/StringTable;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value$Builder;->build()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->setAnnotationParameterDefaultValue(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$Annotation$Argument$Value;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 56
    .line 57
    .line 58
    :cond_1
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getExtensions$kotlin_metadata()Ljava/util/List;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    check-cast v1, Ljava/lang/Iterable;

    .line 63
    .line 64
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 65
    .line 66
    .line 67
    move-result-object v1

    .line 68
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    if-eqz v2, :cond_2

    .line 73
    .line 74
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;

    .line 79
    .line 80
    invoke-interface {v2, p1, v0, p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/extensions/MetadataExtensions;->writeValueParameterExtensions(Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;)V

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_2
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getFlags$kotlin_metadata()I

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    sget-object v2, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags;->HAS_ANNOTATIONS:Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;

    .line 89
    .line 90
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getAnnotations()Ljava/util/List;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    check-cast v3, Ljava/util/Collection;

    .line 95
    .line 96
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 97
    .line 98
    .line 99
    move-result v3

    .line 100
    xor-int/lit8 v3, v3, 0x1

    .line 101
    .line 102
    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 103
    .line 104
    .line 105
    move-result-object v3

    .line 106
    invoke-virtual {v2, v3}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/Flags$BooleanFlagField;->toFlags(Ljava/lang/Boolean;)I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    or-int/2addr v1, v2

    .line 111
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;->getDefaultInstance()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;

    .line 112
    .line 113
    .line 114
    move-result-object v2

    .line 115
    invoke-virtual {v2}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter;->getFlags()I

    .line 116
    .line 117
    .line 118
    move-result v2

    .line 119
    if-eq v1, v2, :cond_3

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->setFlags(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 122
    .line 123
    .line 124
    :cond_3
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmValueParameter;->getName()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p1

    .line 128
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->get(Ljava/lang/String;)I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    invoke-virtual {v0, p0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;->setName(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$ValueParameter$Builder;

    .line 133
    .line 134
    .line 135
    return-object v0
.end method

.method private static final writeVersionRequirement(Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;)Ljava/lang/Integer;
    .locals 9

    .line 1
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;->getKind()Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirementVersionKind;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;->getLevel()Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirementLevel;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;->getErrorCode()Ljava/lang/Integer;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;->getMessage()Ljava/lang/String;

    .line 14
    .line 15
    .line 16
    move-result-object v3

    .line 17
    invoke-static {}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement;->newBuilder()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 18
    .line 19
    .line 20
    move-result-object v4

    .line 21
    sget-object v5, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    aget v0, v5, v0

    .line 28
    .line 29
    const/4 v5, 0x3

    .line 30
    const/4 v6, 0x2

    .line 31
    const/4 v7, 0x1

    .line 32
    if-eq v0, v7, :cond_3

    .line 33
    .line 34
    if-eq v0, v6, :cond_2

    .line 35
    .line 36
    if-eq v0, v5, :cond_1

    .line 37
    .line 38
    const/4 p0, 0x4

    .line 39
    if-ne v0, p0, :cond_0

    .line 40
    .line 41
    const/4 p0, 0x0

    .line 42
    return-object p0

    .line 43
    :cond_0
    new-instance p0, La8/r0;

    .line 44
    .line 45
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 46
    .line 47
    .line 48
    throw p0

    .line 49
    :cond_1
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;->API_VERSION:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;->COMPILER_VERSION:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_3
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;->LANGUAGE_VERSION:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;

    .line 56
    .line 57
    :goto_0
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->getDefaultInstanceForType()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement;

    .line 58
    .line 59
    .line 60
    move-result-object v8

    .line 61
    invoke-virtual {v8}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement;->getVersionKind()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    if-eq v0, v8, :cond_4

    .line 66
    .line 67
    invoke-virtual {v4, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->setVersionKind(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$VersionKind;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 68
    .line 69
    .line 70
    :cond_4
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$WhenMappings;->$EnumSwitchMapping$1:[I

    .line 71
    .line 72
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    aget v0, v0, v1

    .line 77
    .line 78
    if-eq v0, v7, :cond_7

    .line 79
    .line 80
    if-eq v0, v6, :cond_6

    .line 81
    .line 82
    if-ne v0, v5, :cond_5

    .line 83
    .line 84
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;->HIDDEN:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;

    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_5
    new-instance p0, La8/r0;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :cond_6
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;->ERROR:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_7
    sget-object v0, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;->WARNING:Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;

    .line 97
    .line 98
    :goto_1
    invoke-virtual {v4}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->getDefaultInstanceForType()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement;

    .line 99
    .line 100
    .line 101
    move-result-object v1

    .line 102
    invoke-virtual {v1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement;->getLevel()Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;

    .line 103
    .line 104
    .line 105
    move-result-object v1

    .line 106
    if-eq v0, v1, :cond_8

    .line 107
    .line 108
    invoke-virtual {v4, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->setLevel(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Level;)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 109
    .line 110
    .line 111
    :cond_8
    if-eqz v2, :cond_9

    .line 112
    .line 113
    invoke-virtual {v2}, Ljava/lang/Integer;->intValue()I

    .line 114
    .line 115
    .line 116
    move-result v0

    .line 117
    invoke-virtual {v4, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->setErrorCode(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 118
    .line 119
    .line 120
    :cond_9
    if-eqz v3, :cond_a

    .line 121
    .line 122
    invoke-virtual {p0, v3}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->get(Ljava/lang/String;)I

    .line 123
    .line 124
    .line 125
    move-result v0

    .line 126
    invoke-virtual {v4, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->setMessage(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 127
    .line 128
    .line 129
    :cond_a
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersionRequirement;->getVersion()Lkotlin/reflect/jvm/internal/impl/km/KmVersion;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersion;->component1()I

    .line 134
    .line 135
    .line 136
    move-result v0

    .line 137
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersion;->component2()I

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    invoke-virtual {p1}, Lkotlin/reflect/jvm/internal/impl/km/KmVersion;->component3()I

    .line 142
    .line 143
    .line 144
    move-result p1

    .line 145
    new-instance v2, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/VersionRequirement$Version;

    .line 146
    .line 147
    invoke-direct {v2, v0, v1, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/VersionRequirement$Version;-><init>(III)V

    .line 148
    .line 149
    .line 150
    new-instance p1, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$$Lambda$0;

    .line 151
    .line 152
    invoke-direct {p1, v4}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$$Lambda$0;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;)V

    .line 153
    .line 154
    .line 155
    new-instance v0, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$$Lambda$1;

    .line 156
    .line 157
    invoke-direct {v0, v4}, Lkotlin/reflect/jvm/internal/impl/km/internal/WritersKt$$Lambda$1;-><init>(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v2, p1, v0}, Lkotlin/reflect/jvm/internal/impl/metadata/deserialization/VersionRequirement$Version;->encode(Lay0/k;Lay0/k;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/impl/km/internal/WriteContext;->getVersionRequirements$kotlin_metadata()Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableVersionRequirementTable;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    invoke-virtual {p0, v4}, Lkotlin/reflect/jvm/internal/impl/metadata/serialization/MutableTable;->get(Lkotlin/reflect/jvm/internal/impl/protobuf/GeneratedMessageLite$Builder;)I

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 172
    .line 173
    .line 174
    move-result-object p0

    .line 175
    return-object p0
.end method

.method private static final writeVersionRequirement$lambda$1(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->setVersion(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 5
    .line 6
    .line 7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    return-object p0
.end method

.method private static final writeVersionRequirement$lambda$2(Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;I)Llx0/b0;
    .locals 0

    .line 1
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0, p1}, Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;->setVersionFull(I)Lkotlin/reflect/jvm/internal/impl/metadata/ProtoBuf$VersionRequirement$Builder;

    .line 5
    .line 6
    .line 7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 8
    .line 9
    return-object p0
.end method

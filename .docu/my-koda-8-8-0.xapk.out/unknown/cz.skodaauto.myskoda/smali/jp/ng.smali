.class public abstract Ljp/ng;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final c(Ljava/lang/reflect/Type;)Ljava/lang/Class;
    .locals 3

    .line 1
    instance-of v0, p0, Ljava/lang/Class;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p0, Ljava/lang/Class;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    instance-of v0, p0, Ljava/lang/reflect/ParameterizedType;

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    check-cast p0, Ljava/lang/reflect/ParameterizedType;

    .line 13
    .line 14
    invoke-interface {p0}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    const-string v0, "getRawType(...)"

    .line 19
    .line 20
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0}, Ljp/ng;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_1
    instance-of v0, p0, Ljava/lang/reflect/WildcardType;

    .line 29
    .line 30
    if-eqz v0, :cond_2

    .line 31
    .line 32
    check-cast p0, Ljava/lang/reflect/WildcardType;

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    const-string v0, "getUpperBounds(...)"

    .line 39
    .line 40
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-static {p0}, Lmx0/n;->u([Ljava/lang/Object;)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const-string v0, "first(...)"

    .line 48
    .line 49
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    check-cast p0, Ljava/lang/reflect/Type;

    .line 53
    .line 54
    invoke-static {p0}, Ljp/ng;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    return-object p0

    .line 59
    :cond_2
    instance-of v0, p0, Ljava/lang/reflect/GenericArrayType;

    .line 60
    .line 61
    if-eqz v0, :cond_3

    .line 62
    .line 63
    check-cast p0, Ljava/lang/reflect/GenericArrayType;

    .line 64
    .line 65
    invoke-interface {p0}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    const-string v0, "getGenericComponentType(...)"

    .line 70
    .line 71
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {p0}, Ljp/ng;->c(Ljava/lang/reflect/Type;)Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    return-object p0

    .line 79
    :cond_3
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 80
    .line 81
    new-instance v1, Ljava/lang/StringBuilder;

    .line 82
    .line 83
    const-string v2, "type should be an instance of Class<?>, GenericArrayType, ParametrizedType or WildcardType, but actual argument "

    .line 84
    .line 85
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    const-string v2, " has type "

    .line 92
    .line 93
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 94
    .line 95
    .line 96
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 97
    .line 98
    .line 99
    move-result-object p0

    .line 100
    sget-object v2, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 101
    .line 102
    invoke-static {v2, p0, v1}, Lia/b;->i(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p0

    .line 106
    invoke-direct {v0, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    throw v0
.end method

.method public static final d(Lwq/f;Ljava/lang/Class;Ljava/util/List;)Lqz0/a;
    .locals 1

    .line 1
    check-cast p2, Ljava/util/Collection;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    new-array v0, v0, [Lqz0/a;

    .line 5
    .line 6
    invoke-interface {p2, v0}, Ljava/util/Collection;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    check-cast p2, [Lqz0/a;

    .line 11
    .line 12
    array-length v0, p2

    .line 13
    invoke-static {p2, v0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    check-cast p2, [Lqz0/a;

    .line 18
    .line 19
    invoke-static {p1, p2}, Luz0/b1;->d(Ljava/lang/Class;[Lqz0/a;)Lqz0/a;

    .line 20
    .line 21
    .line 22
    move-result-object p2

    .line 23
    if-eqz p2, :cond_0

    .line 24
    .line 25
    return-object p2

    .line 26
    :cond_0
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 27
    .line 28
    .line 29
    move-result-object p2

    .line 30
    sget-object v0, Luz0/i1;->a:Lnx0/f;

    .line 31
    .line 32
    const-string v0, "<this>"

    .line 33
    .line 34
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    sget-object v0, Luz0/i1;->a:Lnx0/f;

    .line 38
    .line 39
    invoke-virtual {v0, p2}, Lnx0/f;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p2

    .line 43
    check-cast p2, Lqz0/a;

    .line 44
    .line 45
    if-nez p2, :cond_2

    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 48
    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/Class;->isInterface()Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-eqz p0, :cond_1

    .line 55
    .line 56
    new-instance p0, Lqz0/d;

    .line 57
    .line 58
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    invoke-direct {p0, p1}, Lqz0/d;-><init>(Lhy0/d;)V

    .line 63
    .line 64
    .line 65
    return-object p0

    .line 66
    :cond_1
    const/4 p0, 0x0

    .line 67
    return-object p0

    .line 68
    :cond_2
    return-object p2
.end method

.method public static final e(Lwq/f;Ljava/lang/reflect/Type;Z)Lqz0/a;
    .locals 7

    .line 1
    instance-of v0, p1, Ljava/lang/reflect/GenericArrayType;

    .line 2
    .line 3
    const-string v1, "<this>"

    .line 4
    .line 5
    const-string v2, "null cannot be cast to non-null type kotlin.reflect.KClass<kotlin.Any>"

    .line 6
    .line 7
    const-string v3, "null cannot be cast to non-null type java.lang.Class<*>"

    .line 8
    .line 9
    const-string v4, "getUpperBounds(...)"

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    if-eqz v0, :cond_5

    .line 13
    .line 14
    check-cast p1, Ljava/lang/reflect/GenericArrayType;

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/lang/reflect/GenericArrayType;->getGenericComponentType()Ljava/lang/reflect/Type;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    instance-of v0, p1, Ljava/lang/reflect/WildcardType;

    .line 21
    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    check-cast p1, Ljava/lang/reflect/WildcardType;

    .line 25
    .line 26
    invoke-interface {p1}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {p1}, Lmx0/n;->u([Ljava/lang/Object;)Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object p1

    .line 37
    check-cast p1, Ljava/lang/reflect/Type;

    .line 38
    .line 39
    :cond_0
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    if-eqz p2, :cond_1

    .line 43
    .line 44
    invoke-static {p0, p1}, Ljp/mg;->e(Lwq/f;Ljava/lang/reflect/Type;)Lqz0/a;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    goto :goto_0

    .line 49
    :cond_1
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-static {p0, p1, v5}, Ljp/ng;->e(Lwq/f;Ljava/lang/reflect/Type;Z)Lqz0/a;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    if-nez p0, :cond_2

    .line 57
    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :cond_2
    :goto_0
    instance-of p2, p1, Ljava/lang/reflect/ParameterizedType;

    .line 61
    .line 62
    if-eqz p2, :cond_3

    .line 63
    .line 64
    check-cast p1, Ljava/lang/reflect/ParameterizedType;

    .line 65
    .line 66
    invoke-interface {p1}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    .line 67
    .line 68
    .line 69
    move-result-object p1

    .line 70
    invoke-static {p1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    check-cast p1, Ljava/lang/Class;

    .line 74
    .line 75
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    goto :goto_1

    .line 80
    :cond_3
    instance-of p2, p1, Lhy0/d;

    .line 81
    .line 82
    if-eqz p2, :cond_4

    .line 83
    .line 84
    check-cast p1, Lhy0/d;

    .line 85
    .line 86
    :goto_1
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 87
    .line 88
    .line 89
    new-instance p2, Luz0/j1;

    .line 90
    .line 91
    invoke-direct {p2, p1, p0}, Luz0/j1;-><init>(Lhy0/d;Lqz0/a;)V

    .line 92
    .line 93
    .line 94
    return-object p2

    .line 95
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 96
    .line 97
    new-instance p2, Ljava/lang/StringBuilder;

    .line 98
    .line 99
    const-string v0, "unsupported type in GenericArray: "

    .line 100
    .line 101
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 109
    .line 110
    invoke-static {v0, p1, p2}, Lia/b;->i(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p1

    .line 114
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 115
    .line 116
    .line 117
    throw p0

    .line 118
    :cond_5
    instance-of v0, p1, Ljava/lang/Class;

    .line 119
    .line 120
    if-eqz v0, :cond_9

    .line 121
    .line 122
    check-cast p1, Ljava/lang/Class;

    .line 123
    .line 124
    invoke-virtual {p1}, Ljava/lang/Class;->isArray()Z

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    if-eqz v0, :cond_8

    .line 129
    .line 130
    invoke-virtual {p1}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    invoke-virtual {v0}, Ljava/lang/Class;->isPrimitive()Z

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    if-nez v0, :cond_8

    .line 139
    .line 140
    invoke-virtual {p1}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    const-string v0, "getComponentType(...)"

    .line 145
    .line 146
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 147
    .line 148
    .line 149
    if-eqz p2, :cond_6

    .line 150
    .line 151
    invoke-static {p0, p1}, Ljp/mg;->e(Lwq/f;Ljava/lang/reflect/Type;)Lqz0/a;

    .line 152
    .line 153
    .line 154
    move-result-object p0

    .line 155
    goto :goto_2

    .line 156
    :cond_6
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 157
    .line 158
    .line 159
    invoke-static {p0, p1, v5}, Ljp/ng;->e(Lwq/f;Ljava/lang/reflect/Type;Z)Lqz0/a;

    .line 160
    .line 161
    .line 162
    move-result-object p0

    .line 163
    if-nez p0, :cond_7

    .line 164
    .line 165
    goto :goto_5

    .line 166
    :cond_7
    :goto_2
    invoke-static {p1}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 167
    .line 168
    .line 169
    move-result-object p1

    .line 170
    invoke-static {p1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    new-instance p2, Luz0/j1;

    .line 174
    .line 175
    invoke-direct {p2, p1, p0}, Luz0/j1;-><init>(Lhy0/d;Lqz0/a;)V

    .line 176
    .line 177
    .line 178
    return-object p2

    .line 179
    :cond_8
    sget-object p2, Lmx0/s;->d:Lmx0/s;

    .line 180
    .line 181
    invoke-static {p0, p1, p2}, Ljp/ng;->d(Lwq/f;Ljava/lang/Class;Ljava/util/List;)Lqz0/a;

    .line 182
    .line 183
    .line 184
    move-result-object p0

    .line 185
    return-object p0

    .line 186
    :cond_9
    instance-of v0, p1, Ljava/lang/reflect/ParameterizedType;

    .line 187
    .line 188
    const/4 v2, 0x1

    .line 189
    if-eqz v0, :cond_15

    .line 190
    .line 191
    check-cast p1, Ljava/lang/reflect/ParameterizedType;

    .line 192
    .line 193
    invoke-interface {p1}, Ljava/lang/reflect/ParameterizedType;->getRawType()Ljava/lang/reflect/Type;

    .line 194
    .line 195
    .line 196
    move-result-object v0

    .line 197
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    check-cast v0, Ljava/lang/Class;

    .line 201
    .line 202
    invoke-interface {p1}, Ljava/lang/reflect/ParameterizedType;->getActualTypeArguments()[Ljava/lang/reflect/Type;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    invoke-static {p1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 207
    .line 208
    .line 209
    if-eqz p2, :cond_a

    .line 210
    .line 211
    new-instance p2, Ljava/util/ArrayList;

    .line 212
    .line 213
    array-length v1, p1

    .line 214
    invoke-direct {p2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 215
    .line 216
    .line 217
    array-length v1, p1

    .line 218
    move v3, v5

    .line 219
    :goto_3
    if-ge v3, v1, :cond_c

    .line 220
    .line 221
    aget-object v4, p1, v3

    .line 222
    .line 223
    invoke-static {v4}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 224
    .line 225
    .line 226
    invoke-static {p0, v4}, Ljp/mg;->e(Lwq/f;Ljava/lang/reflect/Type;)Lqz0/a;

    .line 227
    .line 228
    .line 229
    move-result-object v4

    .line 230
    invoke-virtual {p2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 231
    .line 232
    .line 233
    add-int/lit8 v3, v3, 0x1

    .line 234
    .line 235
    goto :goto_3

    .line 236
    :cond_a
    new-instance p2, Ljava/util/ArrayList;

    .line 237
    .line 238
    array-length v3, p1

    .line 239
    invoke-direct {p2, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 240
    .line 241
    .line 242
    array-length v3, p1

    .line 243
    move v4, v5

    .line 244
    :goto_4
    if-ge v4, v3, :cond_c

    .line 245
    .line 246
    aget-object v6, p1, v4

    .line 247
    .line 248
    invoke-static {v6}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    invoke-static {p0, v6, v5}, Ljp/ng;->e(Lwq/f;Ljava/lang/reflect/Type;Z)Lqz0/a;

    .line 255
    .line 256
    .line 257
    move-result-object v6

    .line 258
    if-nez v6, :cond_b

    .line 259
    .line 260
    :goto_5
    const/4 p0, 0x0

    .line 261
    return-object p0

    .line 262
    :cond_b
    invoke-virtual {p2, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 263
    .line 264
    .line 265
    add-int/lit8 v4, v4, 0x1

    .line 266
    .line 267
    goto :goto_4

    .line 268
    :cond_c
    const-class p1, Ljava/util/Set;

    .line 269
    .line 270
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 271
    .line 272
    .line 273
    move-result p1

    .line 274
    if-eqz p1, :cond_d

    .line 275
    .line 276
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 277
    .line 278
    .line 279
    move-result-object p0

    .line 280
    check-cast p0, Lqz0/a;

    .line 281
    .line 282
    const-string p1, "elementSerializer"

    .line 283
    .line 284
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    new-instance p1, Luz0/d;

    .line 288
    .line 289
    const/4 p2, 0x2

    .line 290
    invoke-direct {p1, p0, p2}, Luz0/d;-><init>(Lqz0/a;I)V

    .line 291
    .line 292
    .line 293
    return-object p1

    .line 294
    :cond_d
    const-class p1, Ljava/util/List;

    .line 295
    .line 296
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 297
    .line 298
    .line 299
    move-result p1

    .line 300
    if-nez p1, :cond_14

    .line 301
    .line 302
    const-class p1, Ljava/util/Collection;

    .line 303
    .line 304
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 305
    .line 306
    .line 307
    move-result p1

    .line 308
    if-eqz p1, :cond_e

    .line 309
    .line 310
    goto/16 :goto_7

    .line 311
    .line 312
    :cond_e
    const-class p1, Ljava/util/Map;

    .line 313
    .line 314
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 315
    .line 316
    .line 317
    move-result p1

    .line 318
    if-eqz p1, :cond_f

    .line 319
    .line 320
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 321
    .line 322
    .line 323
    move-result-object p0

    .line 324
    check-cast p0, Lqz0/a;

    .line 325
    .line 326
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 327
    .line 328
    .line 329
    move-result-object p1

    .line 330
    check-cast p1, Lqz0/a;

    .line 331
    .line 332
    invoke-static {p0, p1}, Lkp/u6;->b(Lqz0/a;Lqz0/a;)Luz0/e0;

    .line 333
    .line 334
    .line 335
    move-result-object p0

    .line 336
    return-object p0

    .line 337
    :cond_f
    const-class p1, Ljava/util/Map$Entry;

    .line 338
    .line 339
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 340
    .line 341
    .line 342
    move-result p1

    .line 343
    const-string v1, "valueSerializer"

    .line 344
    .line 345
    const-string v3, "keySerializer"

    .line 346
    .line 347
    if-eqz p1, :cond_10

    .line 348
    .line 349
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object p0

    .line 353
    check-cast p0, Lqz0/a;

    .line 354
    .line 355
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object p1

    .line 359
    check-cast p1, Lqz0/a;

    .line 360
    .line 361
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 362
    .line 363
    .line 364
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 365
    .line 366
    .line 367
    new-instance p2, Luz0/t0;

    .line 368
    .line 369
    const/4 v0, 0x0

    .line 370
    invoke-direct {p2, p0, p1, v0}, Luz0/t0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 371
    .line 372
    .line 373
    return-object p2

    .line 374
    :cond_10
    const-class p1, Llx0/l;

    .line 375
    .line 376
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 377
    .line 378
    .line 379
    move-result p1

    .line 380
    if-eqz p1, :cond_11

    .line 381
    .line 382
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object p0

    .line 386
    check-cast p0, Lqz0/a;

    .line 387
    .line 388
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 389
    .line 390
    .line 391
    move-result-object p1

    .line 392
    check-cast p1, Lqz0/a;

    .line 393
    .line 394
    invoke-static {p0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 398
    .line 399
    .line 400
    new-instance p2, Luz0/t0;

    .line 401
    .line 402
    const/4 v0, 0x1

    .line 403
    invoke-direct {p2, p0, p1, v0}, Luz0/t0;-><init>(Lqz0/a;Lqz0/a;I)V

    .line 404
    .line 405
    .line 406
    return-object p2

    .line 407
    :cond_11
    const-class p1, Llx0/r;

    .line 408
    .line 409
    invoke-virtual {p1, v0}, Ljava/lang/Class;->isAssignableFrom(Ljava/lang/Class;)Z

    .line 410
    .line 411
    .line 412
    move-result p1

    .line 413
    if-eqz p1, :cond_12

    .line 414
    .line 415
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 416
    .line 417
    .line 418
    move-result-object p0

    .line 419
    check-cast p0, Lqz0/a;

    .line 420
    .line 421
    invoke-interface {p2, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 422
    .line 423
    .line 424
    move-result-object p1

    .line 425
    check-cast p1, Lqz0/a;

    .line 426
    .line 427
    const/4 v0, 0x2

    .line 428
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 429
    .line 430
    .line 431
    move-result-object p2

    .line 432
    check-cast p2, Lqz0/a;

    .line 433
    .line 434
    const-string v0, "aSerializer"

    .line 435
    .line 436
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 437
    .line 438
    .line 439
    const-string v0, "bSerializer"

    .line 440
    .line 441
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    const-string v0, "cSerializer"

    .line 445
    .line 446
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 447
    .line 448
    .line 449
    new-instance v0, Luz0/r1;

    .line 450
    .line 451
    invoke-direct {v0, p0, p1, p2}, Luz0/r1;-><init>(Lqz0/a;Lqz0/a;Lqz0/a;)V

    .line 452
    .line 453
    .line 454
    return-object v0

    .line 455
    :cond_12
    new-instance p1, Ljava/util/ArrayList;

    .line 456
    .line 457
    const/16 v1, 0xa

    .line 458
    .line 459
    invoke-static {p2, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 460
    .line 461
    .line 462
    move-result v1

    .line 463
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 464
    .line 465
    .line 466
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 467
    .line 468
    .line 469
    move-result-object p2

    .line 470
    :goto_6
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 471
    .line 472
    .line 473
    move-result v1

    .line 474
    if-eqz v1, :cond_13

    .line 475
    .line 476
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 477
    .line 478
    .line 479
    move-result-object v1

    .line 480
    check-cast v1, Lqz0/a;

    .line 481
    .line 482
    const-string v2, "null cannot be cast to non-null type kotlinx.serialization.KSerializer<kotlin.Any?>"

    .line 483
    .line 484
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 485
    .line 486
    .line 487
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 488
    .line 489
    .line 490
    goto :goto_6

    .line 491
    :cond_13
    invoke-static {p0, v0, p1}, Ljp/ng;->d(Lwq/f;Ljava/lang/Class;Ljava/util/List;)Lqz0/a;

    .line 492
    .line 493
    .line 494
    move-result-object p0

    .line 495
    return-object p0

    .line 496
    :cond_14
    :goto_7
    invoke-interface {p2, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 497
    .line 498
    .line 499
    move-result-object p0

    .line 500
    check-cast p0, Lqz0/a;

    .line 501
    .line 502
    invoke-static {p0}, Lkp/u6;->a(Lqz0/a;)Luz0/d;

    .line 503
    .line 504
    .line 505
    move-result-object p0

    .line 506
    return-object p0

    .line 507
    :cond_15
    instance-of p2, p1, Ljava/lang/reflect/WildcardType;

    .line 508
    .line 509
    if-eqz p2, :cond_16

    .line 510
    .line 511
    check-cast p1, Ljava/lang/reflect/WildcardType;

    .line 512
    .line 513
    invoke-interface {p1}, Ljava/lang/reflect/WildcardType;->getUpperBounds()[Ljava/lang/reflect/Type;

    .line 514
    .line 515
    .line 516
    move-result-object p1

    .line 517
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 518
    .line 519
    .line 520
    invoke-static {p1}, Lmx0/n;->u([Ljava/lang/Object;)Ljava/lang/Object;

    .line 521
    .line 522
    .line 523
    move-result-object p1

    .line 524
    const-string p2, "first(...)"

    .line 525
    .line 526
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 527
    .line 528
    .line 529
    check-cast p1, Ljava/lang/reflect/Type;

    .line 530
    .line 531
    invoke-static {p0, p1, v2}, Ljp/ng;->e(Lwq/f;Ljava/lang/reflect/Type;Z)Lqz0/a;

    .line 532
    .line 533
    .line 534
    move-result-object p0

    .line 535
    return-object p0

    .line 536
    :cond_16
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 537
    .line 538
    new-instance p2, Ljava/lang/StringBuilder;

    .line 539
    .line 540
    const-string v0, "type should be an instance of Class<?>, GenericArrayType, ParametrizedType or WildcardType, but actual argument "

    .line 541
    .line 542
    invoke-direct {p2, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 543
    .line 544
    .line 545
    invoke-virtual {p2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 546
    .line 547
    .line 548
    const-string v0, " has type "

    .line 549
    .line 550
    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 551
    .line 552
    .line 553
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 554
    .line 555
    .line 556
    move-result-object p1

    .line 557
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 558
    .line 559
    invoke-static {v0, p1, p2}, Lia/b;->i(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 560
    .line 561
    .line 562
    move-result-object p1

    .line 563
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 564
    .line 565
    .line 566
    throw p0
.end method


# virtual methods
.method public abstract a(Lhy0/d;)Ljava/lang/Object;
.end method

.method public abstract b(Lhy0/d;Ljava/lang/Object;)Ljp/ng;
.end method

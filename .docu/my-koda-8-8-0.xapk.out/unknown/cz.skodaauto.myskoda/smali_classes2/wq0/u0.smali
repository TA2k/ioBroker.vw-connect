.class public final Lwq0/u0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# direct methods
.method public static a(Ljava/lang/String;)Ljava/lang/Boolean;
    .locals 7

    .line 1
    const-string v0, "$v$c$cz-skodaauto-myskoda-library-spin-model-Spin$-input$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    const/4 v1, 0x4

    .line 11
    const/4 v2, 0x0

    .line 12
    if-ne v0, v1, :cond_c

    .line 13
    .line 14
    move v0, v2

    .line 15
    :goto_0
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-ge v0, v1, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Ljava/lang/String;->charAt(I)C

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    invoke-static {v1}, Ljava/lang/Character;->isDigit(C)Z

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    if-nez v1, :cond_0

    .line 30
    .line 31
    goto/16 :goto_6

    .line 32
    .line 33
    :cond_0
    add-int/lit8 v0, v0, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    invoke-static {p0}, Lly0/p;->k0(Ljava/lang/String;)Ljava/util/List;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Ljava/lang/Iterable;

    .line 41
    .line 42
    invoke-static {v0}, Lmx0/q;->F0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    check-cast v0, Ljava/lang/Iterable;

    .line 47
    .line 48
    instance-of v1, v0, Ljava/util/Collection;

    .line 49
    .line 50
    if-eqz v1, :cond_2

    .line 51
    .line 52
    move-object v1, v0

    .line 53
    check-cast v1, Ljava/util/Collection;

    .line 54
    .line 55
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_2

    .line 60
    .line 61
    goto/16 :goto_6

    .line 62
    .line 63
    :cond_2
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-eqz v1, :cond_c

    .line 72
    .line 73
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v1

    .line 77
    check-cast v1, Llx0/l;

    .line 78
    .line 79
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast v3, Ljava/lang/Character;

    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/Character;->charValue()C

    .line 84
    .line 85
    .line 86
    move-result v3

    .line 87
    const/4 v4, 0x1

    .line 88
    add-int/2addr v3, v4

    .line 89
    int-to-char v3, v3

    .line 90
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 91
    .line 92
    check-cast v1, Ljava/lang/Character;

    .line 93
    .line 94
    invoke-virtual {v1}, Ljava/lang/Character;->charValue()C

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-ne v3, v1, :cond_3

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_3
    invoke-static {p0}, Lly0/p;->k0(Ljava/lang/String;)Ljava/util/List;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    check-cast v0, Ljava/lang/Iterable;

    .line 106
    .line 107
    invoke-static {v0}, Lmx0/q;->F0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 108
    .line 109
    .line 110
    move-result-object v0

    .line 111
    check-cast v0, Ljava/lang/Iterable;

    .line 112
    .line 113
    instance-of v1, v0, Ljava/util/Collection;

    .line 114
    .line 115
    if-eqz v1, :cond_4

    .line 116
    .line 117
    move-object v1, v0

    .line 118
    check-cast v1, Ljava/util/Collection;

    .line 119
    .line 120
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 121
    .line 122
    .line 123
    move-result v1

    .line 124
    if-eqz v1, :cond_4

    .line 125
    .line 126
    goto/16 :goto_6

    .line 127
    .line 128
    :cond_4
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    if-eqz v1, :cond_c

    .line 137
    .line 138
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object v1

    .line 142
    check-cast v1, Llx0/l;

    .line 143
    .line 144
    iget-object v3, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 145
    .line 146
    check-cast v3, Ljava/lang/Character;

    .line 147
    .line 148
    invoke-virtual {v3}, Ljava/lang/Character;->charValue()C

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    sub-int/2addr v3, v4

    .line 153
    int-to-char v3, v3

    .line 154
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v1, Ljava/lang/Character;

    .line 157
    .line 158
    invoke-virtual {v1}, Ljava/lang/Character;->charValue()C

    .line 159
    .line 160
    .line 161
    move-result v1

    .line 162
    if-ne v3, v1, :cond_5

    .line 163
    .line 164
    goto :goto_2

    .line 165
    :cond_5
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 166
    .line 167
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 168
    .line 169
    .line 170
    move v1, v2

    .line 171
    :goto_3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 172
    .line 173
    .line 174
    move-result v3

    .line 175
    if-ge v1, v3, :cond_7

    .line 176
    .line 177
    add-int/lit8 v3, v1, 0x1

    .line 178
    .line 179
    invoke-virtual {p0, v1}, Ljava/lang/String;->charAt(I)C

    .line 180
    .line 181
    .line 182
    move-result v1

    .line 183
    invoke-static {v1}, Ljava/lang/Character;->valueOf(C)Ljava/lang/Character;

    .line 184
    .line 185
    .line 186
    move-result-object v1

    .line 187
    invoke-virtual {v0, v1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 188
    .line 189
    .line 190
    move-result-object v5

    .line 191
    if-nez v5, :cond_6

    .line 192
    .line 193
    invoke-interface {v0, v1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 194
    .line 195
    .line 196
    move-result v6

    .line 197
    if-nez v6, :cond_6

    .line 198
    .line 199
    new-instance v5, Lkotlin/jvm/internal/d0;

    .line 200
    .line 201
    invoke-direct {v5}, Ljava/lang/Object;-><init>()V

    .line 202
    .line 203
    .line 204
    :cond_6
    check-cast v5, Lkotlin/jvm/internal/d0;

    .line 205
    .line 206
    iget v6, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 207
    .line 208
    add-int/2addr v6, v4

    .line 209
    iput v6, v5, Lkotlin/jvm/internal/d0;->d:I

    .line 210
    .line 211
    invoke-interface {v0, v1, v5}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move v1, v3

    .line 215
    goto :goto_3

    .line 216
    :cond_7
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 217
    .line 218
    .line 219
    move-result-object p0

    .line 220
    check-cast p0, Ljava/lang/Iterable;

    .line 221
    .line 222
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 223
    .line 224
    .line 225
    move-result-object p0

    .line 226
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 227
    .line 228
    .line 229
    move-result v1

    .line 230
    if-eqz v1, :cond_a

    .line 231
    .line 232
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v1

    .line 236
    check-cast v1, Ljava/util/Map$Entry;

    .line 237
    .line 238
    const-string v3, "null cannot be cast to non-null type kotlin.collections.MutableMap.MutableEntry<K of kotlin.collections.GroupingKt__GroupingJVMKt.mapValuesInPlace, R of kotlin.collections.GroupingKt__GroupingJVMKt.mapValuesInPlace>"

    .line 239
    .line 240
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    instance-of v3, v1, Lby0/a;

    .line 244
    .line 245
    if-eqz v3, :cond_9

    .line 246
    .line 247
    instance-of v3, v1, Lby0/d;

    .line 248
    .line 249
    if-eqz v3, :cond_8

    .line 250
    .line 251
    goto :goto_5

    .line 252
    :cond_8
    const-string p0, "kotlin.collections.MutableMap.MutableEntry"

    .line 253
    .line 254
    invoke-static {v1, p0}, Lkotlin/jvm/internal/j0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 255
    .line 256
    .line 257
    const/4 p0, 0x0

    .line 258
    throw p0

    .line 259
    :cond_9
    :goto_5
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v3

    .line 263
    check-cast v3, Lkotlin/jvm/internal/d0;

    .line 264
    .line 265
    iget v3, v3, Lkotlin/jvm/internal/d0;->d:I

    .line 266
    .line 267
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 268
    .line 269
    .line 270
    move-result-object v3

    .line 271
    invoke-interface {v1, v3}, Ljava/util/Map$Entry;->setValue(Ljava/lang/Object;)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    goto :goto_4

    .line 275
    :cond_a
    invoke-static {v0}, Lkotlin/jvm/internal/j0;->c(Ljava/lang/Object;)Ljava/util/Map;

    .line 276
    .line 277
    .line 278
    move-result-object p0

    .line 279
    invoke-interface {p0}, Ljava/util/Map;->size()I

    .line 280
    .line 281
    .line 282
    move-result p0

    .line 283
    if-ne p0, v4, :cond_b

    .line 284
    .line 285
    goto :goto_6

    .line 286
    :cond_b
    move v2, v4

    .line 287
    :cond_c
    :goto_6
    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    return-object p0
.end method


# virtual methods
.method public final synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    check-cast p0, Lyq0/k;

    .line 4
    .line 5
    iget-object p0, p0, Lyq0/k;->a:Ljava/lang/String;

    .line 6
    .line 7
    invoke-static {p0}, Lwq0/u0;->a(Ljava/lang/String;)Ljava/lang/Boolean;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

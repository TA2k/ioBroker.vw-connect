.class public abstract Llp/bb;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Ljava/util/List;Ljava/util/List;)Lv71/c;
    .locals 10

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    move v2, v1

    .line 8
    :goto_0
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 9
    .line 10
    .line 11
    move-result v3

    .line 12
    add-int/lit8 v3, v3, -0x1

    .line 13
    .line 14
    if-lt v1, v3, :cond_3

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 17
    .line 18
    .line 19
    move-result v3

    .line 20
    add-int/lit8 v3, v3, -0x1

    .line 21
    .line 22
    if-ge v2, v3, :cond_0

    .line 23
    .line 24
    goto :goto_2

    .line 25
    :cond_0
    new-instance p0, Ljava/util/ArrayList;

    .line 26
    .line 27
    const/16 p1, 0xa

    .line 28
    .line 29
    invoke-static {v0, p1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 30
    .line 31
    .line 32
    move-result p1

    .line 33
    invoke-direct {p0, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-eqz v0, :cond_2

    .line 45
    .line 46
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    check-cast v0, Llx0/r;

    .line 51
    .line 52
    iget-object v1, v0, Llx0/r;->d:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v1, Lw71/c;

    .line 55
    .line 56
    iget-object v2, v0, Llx0/r;->e:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast v2, Lw71/c;

    .line 59
    .line 60
    iget-object v3, v0, Llx0/r;->f:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v3, Lw71/c;

    .line 63
    .line 64
    invoke-static {v2, v1}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 65
    .line 66
    .line 67
    move-result-object v4

    .line 68
    invoke-static {v3, v1}, Lw71/d;->f(Lw71/c;Lw71/c;)Lw71/c;

    .line 69
    .line 70
    .line 71
    move-result-object v5

    .line 72
    iget-wide v6, v4, Lw71/c;->a:D

    .line 73
    .line 74
    iget-wide v8, v5, Lw71/c;->b:D

    .line 75
    .line 76
    mul-double/2addr v6, v8

    .line 77
    iget-wide v8, v4, Lw71/c;->b:D

    .line 78
    .line 79
    iget-wide v4, v5, Lw71/c;->a:D

    .line 80
    .line 81
    mul-double/2addr v8, v4

    .line 82
    sub-double/2addr v6, v8

    .line 83
    const-wide/16 v4, 0x0

    .line 84
    .line 85
    cmpg-double v4, v6, v4

    .line 86
    .line 87
    if-gez v4, :cond_1

    .line 88
    .line 89
    new-instance v0, Llx0/r;

    .line 90
    .line 91
    invoke-direct {v0, v1, v3, v2}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 92
    .line 93
    .line 94
    :cond_1
    invoke-virtual {p0, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_2
    new-instance p1, Lv71/c;

    .line 99
    .line 100
    invoke-direct {p1, p0}, Lv71/c;-><init>(Ljava/util/List;)V

    .line 101
    .line 102
    .line 103
    return-object p1

    .line 104
    :cond_3
    :goto_2
    invoke-interface {p0}, Ljava/util/List;->size()I

    .line 105
    .line 106
    .line 107
    move-result v3

    .line 108
    add-int/lit8 v3, v3, -0x1

    .line 109
    .line 110
    if-ne v1, v3, :cond_4

    .line 111
    .line 112
    new-instance v3, Llx0/r;

    .line 113
    .line 114
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 115
    .line 116
    .line 117
    move-result-object v4

    .line 118
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    add-int/lit8 v2, v2, 0x1

    .line 123
    .line 124
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 125
    .line 126
    .line 127
    move-result-object v6

    .line 128
    invoke-direct {v3, v4, v5, v6}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    goto :goto_0

    .line 135
    :cond_4
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    add-int/lit8 v3, v3, -0x1

    .line 140
    .line 141
    if-ne v2, v3, :cond_5

    .line 142
    .line 143
    new-instance v3, Llx0/r;

    .line 144
    .line 145
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v4

    .line 149
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v5

    .line 153
    add-int/lit8 v1, v1, 0x1

    .line 154
    .line 155
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object v6

    .line 159
    invoke-direct {v3, v4, v5, v6}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    goto/16 :goto_0

    .line 166
    .line 167
    :cond_5
    add-int/lit8 v3, v1, 0x1

    .line 168
    .line 169
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object v4

    .line 173
    check-cast v4, Lw71/c;

    .line 174
    .line 175
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v5

    .line 179
    check-cast v5, Lw71/c;

    .line 180
    .line 181
    invoke-static {v4, v5}, Lw71/d;->b(Lw71/c;Lw71/c;)D

    .line 182
    .line 183
    .line 184
    move-result-wide v4

    .line 185
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 186
    .line 187
    .line 188
    move-result-object v6

    .line 189
    check-cast v6, Lw71/c;

    .line 190
    .line 191
    add-int/lit8 v7, v2, 0x1

    .line 192
    .line 193
    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 194
    .line 195
    .line 196
    move-result-object v8

    .line 197
    check-cast v8, Lw71/c;

    .line 198
    .line 199
    invoke-static {v6, v8}, Lw71/d;->b(Lw71/c;Lw71/c;)D

    .line 200
    .line 201
    .line 202
    move-result-wide v8

    .line 203
    cmpg-double v4, v4, v8

    .line 204
    .line 205
    if-gez v4, :cond_6

    .line 206
    .line 207
    new-instance v4, Llx0/r;

    .line 208
    .line 209
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object v1

    .line 213
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 214
    .line 215
    .line 216
    move-result-object v5

    .line 217
    invoke-interface {p0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v6

    .line 221
    invoke-direct {v4, v1, v5, v6}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    invoke-virtual {v0, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 225
    .line 226
    .line 227
    move v1, v3

    .line 228
    goto/16 :goto_0

    .line 229
    .line 230
    :cond_6
    new-instance v3, Llx0/r;

    .line 231
    .line 232
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 233
    .line 234
    .line 235
    move-result-object v4

    .line 236
    invoke-interface {p1, v2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 237
    .line 238
    .line 239
    move-result-object v2

    .line 240
    invoke-interface {p1, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object v5

    .line 244
    invoke-direct {v3, v4, v2, v5}, Llx0/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 248
    .line 249
    .line 250
    move v2, v7

    .line 251
    goto/16 :goto_0
.end method

.method public static final b(Ljava/lang/String;)V
    .locals 4

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-static {}, Lcz/myskoda/api/vas/infrastructure/Serializer;->getMoshi()Lcom/squareup/moshi/Moshi;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    const-class v1, Lis0/b;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    sget-object v2, Lax/b;->a:Ljava/util/Set;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-virtual {v0, v1, v2, v3}, Lcom/squareup/moshi/Moshi;->a(Ljava/lang/reflect/Type;Ljava/util/Set;Ljava/lang/String;)Lcom/squareup/moshi/JsonAdapter;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-virtual {v0, p0}, Lcom/squareup/moshi/JsonAdapter;->b(Ljava/lang/String;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-nez v0, :cond_0

    .line 27
    .line 28
    return-void

    .line 29
    :cond_0
    new-instance v0, Ljava/lang/ClassCastException;

    .line 30
    .line 31
    invoke-direct {v0}, Ljava/lang/ClassCastException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 35
    :catch_0
    move-exception v0

    .line 36
    invoke-static {p0, v0}, Llp/nd;->j(Ljava/lang/Object;Ljava/lang/Throwable;)V

    .line 37
    .line 38
    .line 39
    return-void
.end method

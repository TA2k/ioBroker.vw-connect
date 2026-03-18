.class public abstract Lua0/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static a(Llz0/n;Ljava/lang/CharSequence;Llz0/c;)Llz0/c;
    .locals 8

    .line 1
    const-string v0, "input"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "initialContainer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v1, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    new-instance v0, Llz0/j;

    .line 17
    .line 18
    const/4 v2, 0x0

    .line 19
    invoke-direct {v0, p2, p0, v2}, Llz0/j;-><init>(Llz0/c;Llz0/n;I)V

    .line 20
    .line 21
    .line 22
    filled-new-array {v0}, [Llz0/j;

    .line 23
    .line 24
    .line 25
    move-result-object p0

    .line 26
    invoke-static {p0}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    :cond_0
    :goto_0
    invoke-static {p0}, Lmx0/q;->f0(Ljava/util/AbstractList;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p2

    .line 34
    check-cast p2, Llz0/j;

    .line 35
    .line 36
    if-nez p2, :cond_3

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 39
    .line 40
    .line 41
    move-result p0

    .line 42
    const/4 p1, 0x1

    .line 43
    if-le p0, p1, :cond_1

    .line 44
    .line 45
    new-instance p0, Llz0/k;

    .line 46
    .line 47
    const/4 p2, 0x0

    .line 48
    invoke-direct {p0, p2}, Llz0/k;-><init>(I)V

    .line 49
    .line 50
    .line 51
    invoke-static {v1, p0}, Lmx0/q;->n0(Ljava/util/List;Ljava/util/Comparator;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    new-instance p0, Llz0/i;

    .line 55
    .line 56
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 57
    .line 58
    .line 59
    move-result p2

    .line 60
    if-ne p2, p1, :cond_2

    .line 61
    .line 62
    new-instance p1, Ljava/lang/StringBuilder;

    .line 63
    .line 64
    const-string p2, "Position "

    .line 65
    .line 66
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p2

    .line 73
    check-cast p2, Llz0/h;

    .line 74
    .line 75
    iget p2, p2, Llz0/h;->a:I

    .line 76
    .line 77
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string p2, ": "

    .line 81
    .line 82
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    check-cast p2, Llz0/h;

    .line 90
    .line 91
    iget-object p2, p2, Llz0/h;->b:Lay0/a;

    .line 92
    .line 93
    invoke-interface {p2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    check-cast p2, Ljava/lang/String;

    .line 98
    .line 99
    invoke-virtual {p1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    goto :goto_1

    .line 107
    :cond_2
    new-instance v2, Ljava/lang/StringBuilder;

    .line 108
    .line 109
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    mul-int/lit8 p1, p1, 0x21

    .line 114
    .line 115
    invoke-direct {v2, p1}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 116
    .line 117
    .line 118
    new-instance v6, Lkq0/a;

    .line 119
    .line 120
    const/16 p1, 0x18

    .line 121
    .line 122
    invoke-direct {v6, p1}, Lkq0/a;-><init>(I)V

    .line 123
    .line 124
    .line 125
    const/16 v7, 0x38

    .line 126
    .line 127
    const-string v3, ", "

    .line 128
    .line 129
    const-string v4, "Errors: "

    .line 130
    .line 131
    const/4 v5, 0x0

    .line 132
    invoke-static/range {v1 .. v7}, Lmx0/q;->Q(Ljava/lang/Iterable;Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)V

    .line 133
    .line 134
    .line 135
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    const-string p2, "toString(...)"

    .line 140
    .line 141
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 142
    .line 143
    .line 144
    :goto_1
    invoke-direct {p0, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    throw p0

    .line 148
    :cond_3
    iget-object v0, p2, Llz0/j;->a:Ljava/lang/Object;

    .line 149
    .line 150
    check-cast v0, Llz0/c;

    .line 151
    .line 152
    invoke-interface {v0}, Llz0/c;->copy()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    check-cast v0, Llz0/c;

    .line 157
    .line 158
    iget v3, p2, Llz0/j;->c:I

    .line 159
    .line 160
    iget-object p2, p2, Llz0/j;->b:Llz0/n;

    .line 161
    .line 162
    iget-object v4, p2, Llz0/n;->a:Ljava/util/List;

    .line 163
    .line 164
    iget-object v5, p2, Llz0/n;->b:Ljava/util/List;

    .line 165
    .line 166
    check-cast v4, Ljava/util/Collection;

    .line 167
    .line 168
    invoke-interface {v4}, Ljava/util/Collection;->size()I

    .line 169
    .line 170
    .line 171
    move-result v4

    .line 172
    move v6, v2

    .line 173
    :goto_2
    if-ge v6, v4, :cond_6

    .line 174
    .line 175
    iget-object v7, p2, Llz0/n;->a:Ljava/util/List;

    .line 176
    .line 177
    invoke-interface {v7, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v7

    .line 181
    check-cast v7, Llz0/m;

    .line 182
    .line 183
    invoke-interface {v7, v0, p1, v3}, Llz0/m;->a(Llz0/c;Ljava/lang/CharSequence;I)Ljava/lang/Object;

    .line 184
    .line 185
    .line 186
    move-result-object v3

    .line 187
    instance-of v7, v3, Ljava/lang/Integer;

    .line 188
    .line 189
    if-eqz v7, :cond_4

    .line 190
    .line 191
    check-cast v3, Ljava/lang/Number;

    .line 192
    .line 193
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 194
    .line 195
    .line 196
    move-result v3

    .line 197
    add-int/lit8 v6, v6, 0x1

    .line 198
    .line 199
    goto :goto_2

    .line 200
    :cond_4
    instance-of p2, v3, Llz0/h;

    .line 201
    .line 202
    if-eqz p2, :cond_5

    .line 203
    .line 204
    check-cast v3, Llz0/h;

    .line 205
    .line 206
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 207
    .line 208
    .line 209
    goto/16 :goto_0

    .line 210
    .line 211
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 212
    .line 213
    new-instance p1, Ljava/lang/StringBuilder;

    .line 214
    .line 215
    const-string p2, "Unexpected parse result: "

    .line 216
    .line 217
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 218
    .line 219
    .line 220
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 221
    .line 222
    .line 223
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 224
    .line 225
    .line 226
    move-result-object p1

    .line 227
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object p1

    .line 231
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 232
    .line 233
    .line 234
    throw p0

    .line 235
    :cond_6
    invoke-interface {v5}, Ljava/util/List;->isEmpty()Z

    .line 236
    .line 237
    .line 238
    move-result p2

    .line 239
    if-eqz p2, :cond_8

    .line 240
    .line 241
    invoke-interface {p1}, Ljava/lang/CharSequence;->length()I

    .line 242
    .line 243
    .line 244
    move-result p2

    .line 245
    if-ne v3, p2, :cond_7

    .line 246
    .line 247
    return-object v0

    .line 248
    :cond_7
    new-instance p2, Llz0/h;

    .line 249
    .line 250
    sget-object v0, Llz0/l;->d:Llz0/l;

    .line 251
    .line 252
    invoke-direct {p2, v3, v0}, Llz0/h;-><init>(ILay0/a;)V

    .line 253
    .line 254
    .line 255
    invoke-virtual {v1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 256
    .line 257
    .line 258
    goto/16 :goto_0

    .line 259
    .line 260
    :cond_8
    move-object p2, v5

    .line 261
    check-cast p2, Ljava/util/Collection;

    .line 262
    .line 263
    invoke-interface {p2}, Ljava/util/Collection;->size()I

    .line 264
    .line 265
    .line 266
    move-result p2

    .line 267
    add-int/lit8 p2, p2, -0x1

    .line 268
    .line 269
    if-ltz p2, :cond_0

    .line 270
    .line 271
    :goto_3
    add-int/lit8 v4, p2, -0x1

    .line 272
    .line 273
    new-instance v6, Llz0/j;

    .line 274
    .line 275
    invoke-interface {v5, p2}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 276
    .line 277
    .line 278
    move-result-object p2

    .line 279
    check-cast p2, Llz0/n;

    .line 280
    .line 281
    invoke-direct {v6, v0, p2, v3}, Llz0/j;-><init>(Llz0/c;Llz0/n;I)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {p0, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 285
    .line 286
    .line 287
    if-gez v4, :cond_9

    .line 288
    .line 289
    goto/16 :goto_0

    .line 290
    .line 291
    :cond_9
    move p2, v4

    .line 292
    goto :goto_3
.end method

.method public static final b(Ljava/time/LocalTime;)Ljava/lang/String;
    .locals 1

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object v0, Ljava/time/format/FormatStyle;->SHORT:Ljava/time/format/FormatStyle;

    .line 7
    .line 8
    invoke-static {v0}, Ljava/time/format/DateTimeFormatter;->ofLocalizedTime(Ljava/time/format/FormatStyle;)Ljava/time/format/DateTimeFormatter;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-virtual {p0, v0}, Ljava/time/LocalTime;->format(Ljava/time/format/DateTimeFormatter;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    const-string v0, "format(...)"

    .line 17
    .line 18
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    return-object p0
.end method

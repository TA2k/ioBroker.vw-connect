.class public final synthetic Lbc/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/util/List;

.field public final synthetic f:Ljava/util/List;


# direct methods
.method public synthetic constructor <init>(Ljava/util/List;Ljava/util/List;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbc/e;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbc/e;->e:Ljava/util/List;

    .line 4
    .line 5
    iput-object p2, p0, Lbc/e;->f:Ljava/util/List;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lbc/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lt3/d1;

    .line 7
    .line 8
    iget-object v0, p0, Lbc/e;->e:Ljava/util/List;

    .line 9
    .line 10
    const/4 v1, 0x0

    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    move-object v2, v0

    .line 14
    check-cast v2, Ljava/util/Collection;

    .line 15
    .line 16
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    move v3, v1

    .line 21
    :goto_0
    if-ge v3, v2, :cond_0

    .line 22
    .line 23
    invoke-interface {v0, v3}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    check-cast v4, Llx0/l;

    .line 28
    .line 29
    iget-object v5, v4, Llx0/l;->d:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast v5, Lt3/e1;

    .line 32
    .line 33
    iget-object v4, v4, Llx0/l;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v4, Lt4/j;

    .line 36
    .line 37
    iget-wide v6, v4, Lt4/j;->a:J

    .line 38
    .line 39
    invoke-static {p1, v5, v6, v7}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 40
    .line 41
    .line 42
    add-int/lit8 v3, v3, 0x1

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    iget-object p0, p0, Lbc/e;->f:Ljava/util/List;

    .line 46
    .line 47
    if-eqz p0, :cond_2

    .line 48
    .line 49
    move-object v0, p0

    .line 50
    check-cast v0, Ljava/util/Collection;

    .line 51
    .line 52
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    :goto_1
    if-ge v1, v0, :cond_2

    .line 57
    .line 58
    invoke-interface {p0, v1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v2

    .line 62
    check-cast v2, Llx0/l;

    .line 63
    .line 64
    iget-object v3, v2, Llx0/l;->d:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v3, Lt3/e1;

    .line 67
    .line 68
    iget-object v2, v2, Llx0/l;->e:Ljava/lang/Object;

    .line 69
    .line 70
    check-cast v2, Lay0/a;

    .line 71
    .line 72
    if-eqz v2, :cond_1

    .line 73
    .line 74
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v2

    .line 78
    check-cast v2, Lt4/j;

    .line 79
    .line 80
    iget-wide v4, v2, Lt4/j;->a:J

    .line 81
    .line 82
    goto :goto_2

    .line 83
    :cond_1
    const-wide/16 v4, 0x0

    .line 84
    .line 85
    :goto_2
    invoke-static {p1, v3, v4, v5}, Lt3/d1;->i(Lt3/d1;Lt3/e1;J)V

    .line 86
    .line 87
    .line 88
    add-int/lit8 v1, v1, 0x1

    .line 89
    .line 90
    goto :goto_1

    .line 91
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    return-object p0

    .line 94
    :pswitch_0
    check-cast p1, Lmw/h;

    .line 95
    .line 96
    const-string v0, "$this$build"

    .line 97
    .line 98
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 99
    .line 100
    .line 101
    iget-object v0, p0, Lbc/e;->e:Ljava/util/List;

    .line 102
    .line 103
    check-cast v0, Ljava/lang/Iterable;

    .line 104
    .line 105
    new-instance v1, Ljava/util/ArrayList;

    .line 106
    .line 107
    const/16 v2, 0xa

    .line 108
    .line 109
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 114
    .line 115
    .line 116
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 117
    .line 118
    .line 119
    move-result-object v0

    .line 120
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    if-eqz v3, :cond_3

    .line 125
    .line 126
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v3

    .line 130
    check-cast v3, Ljava/lang/Number;

    .line 131
    .line 132
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 133
    .line 134
    .line 135
    move-result v3

    .line 136
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_3
    iget-object p0, p0, Lbc/e;->f:Ljava/util/List;

    .line 145
    .line 146
    check-cast p0, Ljava/lang/Iterable;

    .line 147
    .line 148
    new-instance v0, Ljava/util/ArrayList;

    .line 149
    .line 150
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 151
    .line 152
    .line 153
    move-result v2

    .line 154
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 155
    .line 156
    .line 157
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    :goto_4
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    if-eqz v2, :cond_4

    .line 166
    .line 167
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    check-cast v2, Ljava/lang/Number;

    .line 172
    .line 173
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 174
    .line 175
    .line 176
    move-result v2

    .line 177
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 178
    .line 179
    .line 180
    move-result-object v2

    .line 181
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    goto :goto_4

    .line 185
    :cond_4
    invoke-virtual {p1, v1, v0}, Lmw/h;->a(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 186
    .line 187
    .line 188
    :goto_5
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 189
    .line 190
    return-object p0

    .line 191
    :pswitch_1
    check-cast p1, Lmw/h;

    .line 192
    .line 193
    const-string v0, "$this$build"

    .line 194
    .line 195
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    iget-object v0, p0, Lbc/e;->e:Ljava/util/List;

    .line 199
    .line 200
    check-cast v0, Ljava/lang/Iterable;

    .line 201
    .line 202
    new-instance v1, Ljava/util/ArrayList;

    .line 203
    .line 204
    const/16 v2, 0xa

    .line 205
    .line 206
    invoke-static {v0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 207
    .line 208
    .line 209
    move-result v3

    .line 210
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 211
    .line 212
    .line 213
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 214
    .line 215
    .line 216
    move-result-object v0

    .line 217
    :goto_6
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 218
    .line 219
    .line 220
    move-result v3

    .line 221
    if-eqz v3, :cond_5

    .line 222
    .line 223
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v3

    .line 227
    check-cast v3, Ljava/lang/Number;

    .line 228
    .line 229
    invoke-virtual {v3}, Ljava/lang/Number;->floatValue()F

    .line 230
    .line 231
    .line 232
    move-result v3

    .line 233
    invoke-static {v3}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 234
    .line 235
    .line 236
    move-result-object v3

    .line 237
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    goto :goto_6

    .line 241
    :cond_5
    iget-object p0, p0, Lbc/e;->f:Ljava/util/List;

    .line 242
    .line 243
    check-cast p0, Ljava/lang/Iterable;

    .line 244
    .line 245
    new-instance v0, Ljava/util/ArrayList;

    .line 246
    .line 247
    invoke-static {p0, v2}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 248
    .line 249
    .line 250
    move-result v2

    .line 251
    invoke-direct {v0, v2}, Ljava/util/ArrayList;-><init>(I)V

    .line 252
    .line 253
    .line 254
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 255
    .line 256
    .line 257
    move-result-object p0

    .line 258
    :goto_7
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 259
    .line 260
    .line 261
    move-result v2

    .line 262
    if-eqz v2, :cond_6

    .line 263
    .line 264
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 265
    .line 266
    .line 267
    move-result-object v2

    .line 268
    check-cast v2, Ljava/lang/Number;

    .line 269
    .line 270
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 271
    .line 272
    .line 273
    move-result v2

    .line 274
    invoke-static {v2}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 279
    .line 280
    .line 281
    goto :goto_7

    .line 282
    :cond_6
    invoke-virtual {p1, v1, v0}, Lmw/h;->a(Ljava/util/ArrayList;Ljava/util/ArrayList;)V

    .line 283
    .line 284
    .line 285
    goto :goto_5

    .line 286
    nop

    .line 287
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

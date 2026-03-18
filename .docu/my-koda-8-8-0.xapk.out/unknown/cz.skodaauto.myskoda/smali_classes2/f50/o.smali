.class public final Lf50/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwj0/j0;

.field public final b:Lwj0/d0;


# direct methods
.method public constructor <init>(Lwj0/j0;Lwj0/d0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lf50/o;->a:Lwj0/j0;

    .line 5
    .line 6
    iput-object p2, p0, Lf50/o;->b:Lwj0/d0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lqp0/o;)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    if-eqz v1, :cond_4

    .line 6
    .line 7
    iget-object v2, v1, Lqp0/o;->b:Ljava/lang/String;

    .line 8
    .line 9
    const-string v3, "$v$c$cz-skodaauto-myskoda-library-route-model-EncodedPolyline$-$this$decode$0"

    .line 10
    .line 11
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    new-instance v4, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    const/4 v6, 0x0

    .line 24
    const/4 v7, 0x0

    .line 25
    const/4 v8, 0x0

    .line 26
    :goto_0
    if-ge v6, v3, :cond_5

    .line 27
    .line 28
    const/4 v9, 0x1

    .line 29
    move v10, v9

    .line 30
    const/4 v11, 0x0

    .line 31
    :goto_1
    add-int/lit8 v12, v6, 0x1

    .line 32
    .line 33
    invoke-virtual {v2, v6}, Ljava/lang/String;->charAt(I)C

    .line 34
    .line 35
    .line 36
    move-result v6

    .line 37
    add-int/lit8 v6, v6, -0x40

    .line 38
    .line 39
    shl-int v13, v6, v11

    .line 40
    .line 41
    add-int/2addr v10, v13

    .line 42
    const/4 v13, 0x5

    .line 43
    add-int/2addr v11, v13

    .line 44
    const/16 v14, 0x1f

    .line 45
    .line 46
    if-ge v6, v14, :cond_3

    .line 47
    .line 48
    and-int/lit8 v6, v10, 0x1

    .line 49
    .line 50
    if-eqz v6, :cond_0

    .line 51
    .line 52
    shr-int/lit8 v6, v10, 0x1

    .line 53
    .line 54
    not-int v6, v6

    .line 55
    goto :goto_2

    .line 56
    :cond_0
    shr-int/lit8 v6, v10, 0x1

    .line 57
    .line 58
    :goto_2
    add-int/2addr v6, v7

    .line 59
    const/4 v7, 0x0

    .line 60
    :goto_3
    add-int/lit8 v10, v12, 0x1

    .line 61
    .line 62
    invoke-virtual {v2, v12}, Ljava/lang/String;->charAt(I)C

    .line 63
    .line 64
    .line 65
    move-result v11

    .line 66
    add-int/lit8 v11, v11, -0x40

    .line 67
    .line 68
    shl-int v12, v11, v7

    .line 69
    .line 70
    add-int/2addr v9, v12

    .line 71
    add-int/2addr v7, v13

    .line 72
    if-ge v11, v14, :cond_2

    .line 73
    .line 74
    and-int/lit8 v7, v9, 0x1

    .line 75
    .line 76
    if-eqz v7, :cond_1

    .line 77
    .line 78
    shr-int/lit8 v7, v9, 0x1

    .line 79
    .line 80
    not-int v7, v7

    .line 81
    goto :goto_4

    .line 82
    :cond_1
    shr-int/lit8 v7, v9, 0x1

    .line 83
    .line 84
    :goto_4
    add-int/2addr v8, v7

    .line 85
    new-instance v7, Lxj0/f;

    .line 86
    .line 87
    int-to-double v11, v6

    .line 88
    const-wide v14, 0x3ee4f8b588e368f1L    # 1.0E-5

    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    mul-double/2addr v11, v14

    .line 94
    new-instance v9, Ljava/math/BigDecimal;

    .line 95
    .line 96
    invoke-static {v11, v12}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 97
    .line 98
    .line 99
    move-result-object v11

    .line 100
    invoke-direct {v9, v11}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 101
    .line 102
    .line 103
    sget-object v11, Ljava/math/RoundingMode;->FLOOR:Ljava/math/RoundingMode;

    .line 104
    .line 105
    invoke-virtual {v9, v13, v11}, Ljava/math/BigDecimal;->setScale(ILjava/math/RoundingMode;)Ljava/math/BigDecimal;

    .line 106
    .line 107
    .line 108
    move-result-object v9

    .line 109
    move/from16 v16, v6

    .line 110
    .line 111
    invoke-virtual {v9}, Ljava/math/BigDecimal;->doubleValue()D

    .line 112
    .line 113
    .line 114
    move-result-wide v5

    .line 115
    move-wide/from16 v17, v14

    .line 116
    .line 117
    int-to-double v14, v8

    .line 118
    mul-double v14, v14, v17

    .line 119
    .line 120
    new-instance v9, Ljava/math/BigDecimal;

    .line 121
    .line 122
    invoke-static {v14, v15}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v12

    .line 126
    invoke-direct {v9, v12}, Ljava/math/BigDecimal;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    invoke-virtual {v9, v13, v11}, Ljava/math/BigDecimal;->setScale(ILjava/math/RoundingMode;)Ljava/math/BigDecimal;

    .line 130
    .line 131
    .line 132
    move-result-object v9

    .line 133
    invoke-virtual {v9}, Ljava/math/BigDecimal;->doubleValue()D

    .line 134
    .line 135
    .line 136
    move-result-wide v11

    .line 137
    invoke-direct {v7, v5, v6, v11, v12}, Lxj0/f;-><init>(DD)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {v4, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move v6, v10

    .line 144
    move/from16 v7, v16

    .line 145
    .line 146
    goto :goto_0

    .line 147
    :cond_2
    move v12, v10

    .line 148
    goto :goto_3

    .line 149
    :cond_3
    move v6, v12

    .line 150
    goto :goto_1

    .line 151
    :cond_4
    const/4 v4, 0x0

    .line 152
    :cond_5
    if-eqz v4, :cond_a

    .line 153
    .line 154
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 155
    .line 156
    .line 157
    move-result v2

    .line 158
    const/4 v3, 0x2

    .line 159
    if-ge v2, v3, :cond_6

    .line 160
    .line 161
    goto :goto_6

    .line 162
    :cond_6
    new-instance v2, Lxj0/t;

    .line 163
    .line 164
    invoke-direct {v2, v4}, Lxj0/t;-><init>(Ljava/util/ArrayList;)V

    .line 165
    .line 166
    .line 167
    invoke-static {v2}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 168
    .line 169
    .line 170
    move-result-object v2

    .line 171
    iget-object v1, v1, Lqp0/o;->a:Ljava/util/List;

    .line 172
    .line 173
    check-cast v1, Ljava/lang/Iterable;

    .line 174
    .line 175
    new-instance v3, Ljava/util/ArrayList;

    .line 176
    .line 177
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 178
    .line 179
    .line 180
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    const/16 v5, 0x41

    .line 185
    .line 186
    :cond_7
    :goto_5
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 187
    .line 188
    .line 189
    move-result v6

    .line 190
    if-eqz v6, :cond_9

    .line 191
    .line 192
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object v6

    .line 196
    check-cast v6, Lqp0/b0;

    .line 197
    .line 198
    invoke-static {v6, v5}, Ljp/eg;->l(Lqp0/b0;C)Lxj0/r;

    .line 199
    .line 200
    .line 201
    move-result-object v6

    .line 202
    instance-of v7, v6, Lxj0/o;

    .line 203
    .line 204
    if-eqz v7, :cond_8

    .line 205
    .line 206
    add-int/lit8 v5, v5, 0x1

    .line 207
    .line 208
    int-to-char v5, v5

    .line 209
    :cond_8
    if-eqz v6, :cond_7

    .line 210
    .line 211
    invoke-virtual {v3, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 212
    .line 213
    .line 214
    goto :goto_5

    .line 215
    :cond_9
    iget-object v1, v0, Lf50/o;->a:Lwj0/j0;

    .line 216
    .line 217
    invoke-virtual {v1, v4}, Lwj0/j0;->a(Ljava/util/Collection;)V

    .line 218
    .line 219
    .line 220
    goto :goto_7

    .line 221
    :cond_a
    :goto_6
    sget-object v2, Lmx0/s;->d:Lmx0/s;

    .line 222
    .line 223
    move-object v3, v2

    .line 224
    :goto_7
    new-instance v1, Lxj0/u;

    .line 225
    .line 226
    invoke-direct {v1, v3, v2}, Lxj0/u;-><init>(Ljava/util/List;Ljava/util/List;)V

    .line 227
    .line 228
    .line 229
    iget-object v0, v0, Lf50/o;->b:Lwj0/d0;

    .line 230
    .line 231
    iget-object v0, v0, Lwj0/d0;->a:Lwj0/v;

    .line 232
    .line 233
    check-cast v0, Luj0/j;

    .line 234
    .line 235
    iget-object v0, v0, Luj0/j;->a:Lyy0/c2;

    .line 236
    .line 237
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    return-void
.end method

.method public final bridge synthetic invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    move-object v1, v0

    .line 4
    check-cast v1, Lqp0/o;

    .line 5
    .line 6
    invoke-virtual {p0, v1}, Lf50/o;->a(Lqp0/o;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

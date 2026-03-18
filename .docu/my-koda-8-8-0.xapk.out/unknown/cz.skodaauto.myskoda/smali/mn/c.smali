.class public final Lmn/c;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic f:Le3/g;

.field public final synthetic g:Lv3/u1;

.field public final synthetic h:Le3/n0;

.field public final synthetic i:J

.field public final synthetic j:Lmn/a;

.field public final synthetic k:Lv3/u1;

.field public final synthetic l:Lv3/u1;

.field public final synthetic m:Ll2/t2;

.field public final synthetic n:Ll2/t2;

.field public final synthetic o:Ll2/b1;


# direct methods
.method public constructor <init>(Le3/g;Lv3/u1;Le3/n0;JLmn/a;Lv3/u1;Lv3/u1;Lc1/t1;Lc1/t1;Ll2/b1;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lmn/c;->f:Le3/g;

    .line 2
    .line 3
    iput-object p2, p0, Lmn/c;->g:Lv3/u1;

    .line 4
    .line 5
    iput-object p3, p0, Lmn/c;->h:Le3/n0;

    .line 6
    .line 7
    iput-wide p4, p0, Lmn/c;->i:J

    .line 8
    .line 9
    iput-object p6, p0, Lmn/c;->j:Lmn/a;

    .line 10
    .line 11
    iput-object p7, p0, Lmn/c;->k:Lv3/u1;

    .line 12
    .line 13
    iput-object p8, p0, Lmn/c;->l:Lv3/u1;

    .line 14
    .line 15
    iput-object p9, p0, Lmn/c;->m:Ll2/t2;

    .line 16
    .line 17
    iput-object p10, p0, Lmn/c;->n:Ll2/t2;

    .line 18
    .line 19
    iput-object p11, p0, Lmn/c;->o:Ll2/b1;

    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lv3/j0;

    .line 3
    .line 4
    const-string p1, "$this$drawWithContent"

    .line 5
    .line 6
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    iget-object p1, p0, Lmn/c;->m:Ll2/t2;

    .line 10
    .line 11
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    check-cast v1, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    const v2, 0x3c23d70a    # 0.01f

    .line 22
    .line 23
    .line 24
    cmpg-float v3, v2, v1

    .line 25
    .line 26
    const-wide/16 v4, 0x0

    .line 27
    .line 28
    iget-object v6, p0, Lmn/c;->f:Le3/g;

    .line 29
    .line 30
    const v7, 0x3f7d70a4    # 0.99f

    .line 31
    .line 32
    .line 33
    if-gtz v3, :cond_0

    .line 34
    .line 35
    cmpg-float v1, v1, v7

    .line 36
    .line 37
    if-gtz v1, :cond_0

    .line 38
    .line 39
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p1, Ljava/lang/Number;

    .line 44
    .line 45
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    invoke-virtual {v6, p1}, Le3/g;->c(F)V

    .line 50
    .line 51
    .line 52
    iget-object p1, v0, Lv3/j0;->d:Lg3/b;

    .line 53
    .line 54
    iget-object v1, p1, Lg3/b;->e:Lgw0/c;

    .line 55
    .line 56
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-interface {p1}, Lg3/d;->e()J

    .line 61
    .line 62
    .line 63
    move-result-wide v8

    .line 64
    invoke-static {v4, v5, v8, v9}, Ljp/cf;->c(JJ)Ld3/c;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    invoke-interface {v1, p1, v6}, Le3/r;->t(Ld3/c;Le3/g;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0}, Lv3/j0;->b()V

    .line 72
    .line 73
    .line 74
    invoke-interface {v1}, Le3/r;->i()V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_0
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Ljava/lang/Number;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    cmpl-float p1, p1, v7

    .line 89
    .line 90
    if-ltz p1, :cond_1

    .line 91
    .line 92
    invoke-virtual {v0}, Lv3/j0;->b()V

    .line 93
    .line 94
    .line 95
    :cond_1
    :goto_0
    iget-object p1, p0, Lmn/c;->n:Ll2/t2;

    .line 96
    .line 97
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v1

    .line 101
    check-cast v1, Ljava/lang/Number;

    .line 102
    .line 103
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    cmpg-float v2, v2, v1

    .line 108
    .line 109
    iget-object v3, p0, Lmn/c;->o:Ll2/b1;

    .line 110
    .line 111
    iget-object v9, p0, Lmn/c;->l:Lv3/u1;

    .line 112
    .line 113
    iget-object v10, p0, Lmn/c;->k:Lv3/u1;

    .line 114
    .line 115
    iget-object v11, p0, Lmn/c;->g:Lv3/u1;

    .line 116
    .line 117
    if-gtz v2, :cond_2

    .line 118
    .line 119
    cmpg-float v1, v1, v7

    .line 120
    .line 121
    if-gtz v1, :cond_2

    .line 122
    .line 123
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    move-result-object p1

    .line 127
    check-cast p1, Ljava/lang/Number;

    .line 128
    .line 129
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    invoke-virtual {v6, p1}, Le3/g;->c(F)V

    .line 134
    .line 135
    .line 136
    iget-object p1, v0, Lv3/j0;->d:Lg3/b;

    .line 137
    .line 138
    iget-object v1, p1, Lg3/b;->e:Lgw0/c;

    .line 139
    .line 140
    invoke-virtual {v1}, Lgw0/c;->h()Le3/r;

    .line 141
    .line 142
    .line 143
    move-result-object v12

    .line 144
    invoke-interface {p1}, Lg3/d;->e()J

    .line 145
    .line 146
    .line 147
    move-result-wide v1

    .line 148
    invoke-static {v4, v5, v1, v2}, Ljp/cf;->c(JJ)Ld3/c;

    .line 149
    .line 150
    .line 151
    move-result-object p1

    .line 152
    invoke-interface {v12, p1, v6}, Le3/r;->t(Ld3/c;Le3/g;)V

    .line 153
    .line 154
    .line 155
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    check-cast p1, Ljava/lang/Number;

    .line 160
    .line 161
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 162
    .line 163
    .line 164
    move-result v5

    .line 165
    iget-object p1, v11, Lv3/u1;->a:Ljava/lang/Object;

    .line 166
    .line 167
    move-object v6, p1

    .line 168
    check-cast v6, Le3/g0;

    .line 169
    .line 170
    iget-object p1, v10, Lv3/u1;->a:Ljava/lang/Object;

    .line 171
    .line 172
    move-object v7, p1

    .line 173
    check-cast v7, Lt4/m;

    .line 174
    .line 175
    iget-object p1, v9, Lv3/u1;->a:Ljava/lang/Object;

    .line 176
    .line 177
    move-object v8, p1

    .line 178
    check-cast v8, Ld3/e;

    .line 179
    .line 180
    iget-object v1, p0, Lmn/c;->h:Le3/n0;

    .line 181
    .line 182
    iget-wide v2, p0, Lmn/c;->i:J

    .line 183
    .line 184
    iget-object v4, p0, Lmn/c;->j:Lmn/a;

    .line 185
    .line 186
    invoke-static/range {v0 .. v8}, Ljp/g1;->b(Lv3/j0;Le3/n0;JLmn/a;FLe3/g0;Lt4/m;Ld3/e;)Le3/g0;

    .line 187
    .line 188
    .line 189
    move-result-object p0

    .line 190
    iput-object p0, v11, Lv3/u1;->a:Ljava/lang/Object;

    .line 191
    .line 192
    invoke-interface {v12}, Le3/r;->i()V

    .line 193
    .line 194
    .line 195
    goto :goto_1

    .line 196
    :cond_2
    invoke-interface {p1}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p1

    .line 200
    check-cast p1, Ljava/lang/Number;

    .line 201
    .line 202
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 203
    .line 204
    .line 205
    move-result p1

    .line 206
    cmpl-float p1, p1, v7

    .line 207
    .line 208
    if-ltz p1, :cond_3

    .line 209
    .line 210
    invoke-interface {v3}, Ll2/t2;->getValue()Ljava/lang/Object;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    check-cast p1, Ljava/lang/Number;

    .line 215
    .line 216
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 217
    .line 218
    .line 219
    move-result v5

    .line 220
    iget-object p1, v11, Lv3/u1;->a:Ljava/lang/Object;

    .line 221
    .line 222
    move-object v6, p1

    .line 223
    check-cast v6, Le3/g0;

    .line 224
    .line 225
    iget-object p1, v10, Lv3/u1;->a:Ljava/lang/Object;

    .line 226
    .line 227
    move-object v7, p1

    .line 228
    check-cast v7, Lt4/m;

    .line 229
    .line 230
    iget-object p1, v9, Lv3/u1;->a:Ljava/lang/Object;

    .line 231
    .line 232
    move-object v8, p1

    .line 233
    check-cast v8, Ld3/e;

    .line 234
    .line 235
    iget-object v1, p0, Lmn/c;->h:Le3/n0;

    .line 236
    .line 237
    iget-wide v2, p0, Lmn/c;->i:J

    .line 238
    .line 239
    iget-object v4, p0, Lmn/c;->j:Lmn/a;

    .line 240
    .line 241
    invoke-static/range {v0 .. v8}, Ljp/g1;->b(Lv3/j0;Le3/n0;JLmn/a;FLe3/g0;Lt4/m;Ld3/e;)Le3/g0;

    .line 242
    .line 243
    .line 244
    move-result-object p0

    .line 245
    iput-object p0, v11, Lv3/u1;->a:Ljava/lang/Object;

    .line 246
    .line 247
    :cond_3
    :goto_1
    iget-object p0, v0, Lv3/j0;->d:Lg3/b;

    .line 248
    .line 249
    invoke-interface {p0}, Lg3/d;->e()J

    .line 250
    .line 251
    .line 252
    move-result-wide p0

    .line 253
    new-instance v1, Ld3/e;

    .line 254
    .line 255
    invoke-direct {v1, p0, p1}, Ld3/e;-><init>(J)V

    .line 256
    .line 257
    .line 258
    iput-object v1, v9, Lv3/u1;->a:Ljava/lang/Object;

    .line 259
    .line 260
    invoke-virtual {v0}, Lv3/j0;->getLayoutDirection()Lt4/m;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    iput-object p0, v10, Lv3/u1;->a:Ljava/lang/Object;

    .line 265
    .line 266
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 267
    .line 268
    return-object p0
.end method

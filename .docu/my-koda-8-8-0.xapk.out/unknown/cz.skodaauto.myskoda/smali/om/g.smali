.class public final Lom/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyl/j;


# instance fields
.field public final a:Lil/g;

.field public final b:Lb81/c;

.field public final c:I

.field public final d:I


# direct methods
.method public constructor <init>(Lil/g;Lb81/c;II)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lom/g;->a:Lil/g;

    .line 5
    .line 6
    iput-object p2, p0, Lom/g;->b:Lb81/c;

    .line 7
    .line 8
    iput p3, p0, Lom/g;->c:I

    .line 9
    .line 10
    iput p4, p0, Lom/g;->d:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a()J
    .locals 2

    .line 1
    const-wide/16 v0, 0x800

    .line 2
    .line 3
    return-wide v0
.end method

.method public final b()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final c(Landroid/graphics/Canvas;)V
    .locals 9

    .line 1
    iget-object v0, p0, Lom/g;->a:Lil/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object v1, v0, Lil/g;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v1, Ld01/x;

    .line 9
    .line 10
    iget-object p0, p0, Lom/g;->b:Lb81/c;

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    new-instance p0, Lb81/c;

    .line 15
    .line 16
    const/16 v2, 0xa

    .line 17
    .line 18
    invoke-direct {p0, v2}, Lb81/c;-><init>(I)V

    .line 19
    .line 20
    .line 21
    :cond_0
    iget-object v2, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast v2, Ld3/a;

    .line 24
    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_1
    invoke-virtual {p1}, Landroid/graphics/Canvas;->getWidth()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    int-to-float v2, v2

    .line 33
    invoke-virtual {p1}, Landroid/graphics/Canvas;->getHeight()I

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    int-to-float v3, v3

    .line 38
    new-instance v4, Ld3/a;

    .line 39
    .line 40
    const/4 v5, 0x0

    .line 41
    invoke-direct {v4, v5, v5, v2, v3}, Ld3/a;-><init>(FFFF)V

    .line 42
    .line 43
    .line 44
    iput-object v4, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 45
    .line 46
    :goto_0
    new-instance v2, Lin/z1;

    .line 47
    .line 48
    invoke-direct {v2}, Ljava/lang/Object;-><init>()V

    .line 49
    .line 50
    .line 51
    iput-object p1, v2, Lin/z1;->a:Ljava/lang/Object;

    .line 52
    .line 53
    iput-object v0, v2, Lin/z1;->b:Ljava/lang/Object;

    .line 54
    .line 55
    iget-object p1, v0, Lil/g;->e:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast p1, Lin/t0;

    .line 58
    .line 59
    if-nez p1, :cond_2

    .line 60
    .line 61
    const-string p0, "SVGAndroidRenderer"

    .line 62
    .line 63
    const-string p1, "Nothing to render. Document is empty."

    .line 64
    .line 65
    invoke-static {p0, p1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 66
    .line 67
    .line 68
    return-void

    .line 69
    :cond_2
    iget-object v0, p1, Lin/e1;->o:Ld3/a;

    .line 70
    .line 71
    iget-object v3, p1, Lin/c1;->n:Lin/s;

    .line 72
    .line 73
    iget-object v4, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 74
    .line 75
    check-cast v4, Ld01/x;

    .line 76
    .line 77
    const/4 v5, 0x1

    .line 78
    const/4 v6, 0x0

    .line 79
    if-eqz v4, :cond_4

    .line 80
    .line 81
    iget-object v4, v4, Ld01/x;->b:Ljava/util/ArrayList;

    .line 82
    .line 83
    if-eqz v4, :cond_3

    .line 84
    .line 85
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 86
    .line 87
    .line 88
    move-result v4

    .line 89
    goto :goto_1

    .line 90
    :cond_3
    move v4, v6

    .line 91
    :goto_1
    if-lez v4, :cond_4

    .line 92
    .line 93
    move v4, v5

    .line 94
    goto :goto_2

    .line 95
    :cond_4
    move v4, v6

    .line 96
    :goto_2
    if-eqz v4, :cond_5

    .line 97
    .line 98
    iget-object v4, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast v4, Ld01/x;

    .line 101
    .line 102
    invoke-virtual {v1, v4}, Ld01/x;->d(Ld01/x;)V

    .line 103
    .line 104
    .line 105
    :cond_5
    new-instance v4, Lin/x1;

    .line 106
    .line 107
    invoke-direct {v4}, Lin/x1;-><init>()V

    .line 108
    .line 109
    .line 110
    iput-object v4, v2, Lin/z1;->c:Ljava/lang/Object;

    .line 111
    .line 112
    new-instance v4, Ljava/util/Stack;

    .line 113
    .line 114
    invoke-direct {v4}, Ljava/util/Stack;-><init>()V

    .line 115
    .line 116
    .line 117
    iput-object v4, v2, Lin/z1;->d:Ljava/lang/Object;

    .line 118
    .line 119
    iget-object v4, v2, Lin/z1;->c:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v4, Lin/x1;

    .line 122
    .line 123
    invoke-static {}, Lin/s0;->a()Lin/s0;

    .line 124
    .line 125
    .line 126
    move-result-object v7

    .line 127
    invoke-virtual {v2, v4, v7}, Lin/z1;->j0(Lin/x1;Lin/s0;)V

    .line 128
    .line 129
    .line 130
    iget-object v4, v2, Lin/z1;->c:Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v4, Lin/x1;

    .line 133
    .line 134
    const/4 v7, 0x0

    .line 135
    iput-object v7, v4, Lin/x1;->f:Ld3/a;

    .line 136
    .line 137
    iput-boolean v6, v4, Lin/x1;->h:Z

    .line 138
    .line 139
    iget-object v7, v2, Lin/z1;->d:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v7, Ljava/util/Stack;

    .line 142
    .line 143
    new-instance v8, Lin/x1;

    .line 144
    .line 145
    invoke-direct {v8, v4}, Lin/x1;-><init>(Lin/x1;)V

    .line 146
    .line 147
    .line 148
    invoke-virtual {v7, v8}, Ljava/util/Stack;->push(Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    new-instance v4, Ljava/util/Stack;

    .line 152
    .line 153
    invoke-direct {v4}, Ljava/util/Stack;-><init>()V

    .line 154
    .line 155
    .line 156
    iput-object v4, v2, Lin/z1;->f:Ljava/lang/Object;

    .line 157
    .line 158
    new-instance v4, Ljava/util/Stack;

    .line 159
    .line 160
    invoke-direct {v4}, Ljava/util/Stack;-><init>()V

    .line 161
    .line 162
    .line 163
    iput-object v4, v2, Lin/z1;->e:Ljava/lang/Object;

    .line 164
    .line 165
    iget-object v4, p1, Lin/y0;->d:Ljava/lang/Boolean;

    .line 166
    .line 167
    if-eqz v4, :cond_6

    .line 168
    .line 169
    iget-object v7, v2, Lin/z1;->c:Ljava/lang/Object;

    .line 170
    .line 171
    check-cast v7, Lin/x1;

    .line 172
    .line 173
    invoke-virtual {v4}, Ljava/lang/Boolean;->booleanValue()Z

    .line 174
    .line 175
    .line 176
    move-result v4

    .line 177
    iput-boolean v4, v7, Lin/x1;->h:Z

    .line 178
    .line 179
    :cond_6
    invoke-virtual {v2}, Lin/z1;->f0()V

    .line 180
    .line 181
    .line 182
    new-instance v4, Ld3/a;

    .line 183
    .line 184
    iget-object v7, p0, Lb81/c;->f:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v7, Ld3/a;

    .line 187
    .line 188
    invoke-direct {v4, v7}, Ld3/a;-><init>(Ld3/a;)V

    .line 189
    .line 190
    .line 191
    iget-object v7, p1, Lin/t0;->r:Lin/e0;

    .line 192
    .line 193
    if-eqz v7, :cond_7

    .line 194
    .line 195
    iget v8, v4, Ld3/a;->d:F

    .line 196
    .line 197
    invoke-virtual {v7, v2, v8}, Lin/e0;->b(Lin/z1;F)F

    .line 198
    .line 199
    .line 200
    move-result v7

    .line 201
    iput v7, v4, Ld3/a;->d:F

    .line 202
    .line 203
    :cond_7
    iget-object v7, p1, Lin/t0;->s:Lin/e0;

    .line 204
    .line 205
    if-eqz v7, :cond_8

    .line 206
    .line 207
    iget v8, v4, Ld3/a;->e:F

    .line 208
    .line 209
    invoke-virtual {v7, v2, v8}, Lin/e0;->b(Lin/z1;F)F

    .line 210
    .line 211
    .line 212
    move-result v7

    .line 213
    iput v7, v4, Ld3/a;->e:F

    .line 214
    .line 215
    :cond_8
    invoke-virtual {v2, p1, v4, v0, v3}, Lin/z1;->U(Lin/t0;Ld3/a;Ld3/a;Lin/s;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {v2}, Lin/z1;->e0()V

    .line 219
    .line 220
    .line 221
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 222
    .line 223
    check-cast p0, Ld01/x;

    .line 224
    .line 225
    if-eqz p0, :cond_a

    .line 226
    .line 227
    iget-object p0, p0, Ld01/x;->b:Ljava/util/ArrayList;

    .line 228
    .line 229
    if-eqz p0, :cond_9

    .line 230
    .line 231
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 232
    .line 233
    .line 234
    move-result p0

    .line 235
    goto :goto_3

    .line 236
    :cond_9
    move p0, v6

    .line 237
    :goto_3
    if-lez p0, :cond_a

    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_a
    move v5, v6

    .line 241
    :goto_4
    if-eqz v5, :cond_d

    .line 242
    .line 243
    iget-object p0, v1, Ld01/x;->b:Ljava/util/ArrayList;

    .line 244
    .line 245
    if-nez p0, :cond_b

    .line 246
    .line 247
    goto :goto_6

    .line 248
    :cond_b
    invoke-virtual {p0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    :cond_c
    :goto_5
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 253
    .line 254
    .line 255
    move-result p1

    .line 256
    if-eqz p1, :cond_d

    .line 257
    .line 258
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 259
    .line 260
    .line 261
    move-result-object p1

    .line 262
    check-cast p1, Lin/l;

    .line 263
    .line 264
    iget p1, p1, Lin/l;->c:I

    .line 265
    .line 266
    const/4 v0, 0x2

    .line 267
    if-ne p1, v0, :cond_c

    .line 268
    .line 269
    invoke-interface {p0}, Ljava/util/Iterator;->remove()V

    .line 270
    .line 271
    .line 272
    goto :goto_5

    .line 273
    :cond_d
    :goto_6
    return-void
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lom/g;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lom/g;->c:I

    .line 2
    .line 3
    return p0
.end method

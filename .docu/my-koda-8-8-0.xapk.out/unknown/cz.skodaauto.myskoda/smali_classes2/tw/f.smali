.class public Ltw/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltw/l;


# static fields
.field public static final synthetic h:I


# instance fields
.field public final d:Ltw/c;

.field public final e:Ltw/c;

.field public final f:Ltw/c;

.field public final g:Ltw/c;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ltw/b;

    .line 2
    .line 3
    sget-object v1, Ltw/j;->a:Ltw/j;

    .line 4
    .line 5
    const/16 v2, 0x32

    .line 6
    .line 7
    invoke-direct {v0, v2, v1}, Ltw/b;-><init>(ILtw/e;)V

    .line 8
    .line 9
    .line 10
    new-instance v0, Ltw/b;

    .line 11
    .line 12
    invoke-direct {v0, v2, v1}, Ltw/b;-><init>(ILtw/e;)V

    .line 13
    .line 14
    .line 15
    new-instance v0, Ltw/b;

    .line 16
    .line 17
    invoke-direct {v0, v2, v1}, Ltw/b;-><init>(ILtw/e;)V

    .line 18
    .line 19
    .line 20
    new-instance v0, Ltw/b;

    .line 21
    .line 22
    invoke-direct {v0, v2, v1}, Ltw/b;-><init>(ILtw/e;)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public constructor <init>(Ltw/c;Ltw/c;Ltw/c;Ltw/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ltw/f;->d:Ltw/c;

    .line 5
    .line 6
    iput-object p2, p0, Ltw/f;->e:Ltw/c;

    .line 7
    .line 8
    iput-object p3, p0, Ltw/f;->f:Ltw/c;

    .line 9
    .line 10
    iput-object p4, p0, Ltw/f;->g:Ltw/c;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lpw/f;Landroid/graphics/Path;FFFF)V
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v6, p2

    .line 4
    .line 5
    move/from16 v1, p3

    .line 6
    .line 7
    const-string v2, "context"

    .line 8
    .line 9
    move-object/from16 v3, p1

    .line 10
    .line 11
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v2, "path"

    .line 15
    .line 16
    invoke-static {v6, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    invoke-interface {v3}, Lpw/f;->a()F

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    sub-float v3, p5, v1

    .line 24
    .line 25
    sub-float v4, p6, p4

    .line 26
    .line 27
    const/4 v5, 0x0

    .line 28
    cmpg-float v7, v3, v5

    .line 29
    .line 30
    if-nez v7, :cond_0

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    cmpg-float v7, v4, v5

    .line 34
    .line 35
    if-nez v7, :cond_1

    .line 36
    .line 37
    :goto_0
    return-void

    .line 38
    :cond_1
    invoke-static {v3, v4}, Ljava/lang/Math;->min(FF)F

    .line 39
    .line 40
    .line 41
    move-result v7

    .line 42
    invoke-static {v7}, Ljava/lang/Math;->abs(F)F

    .line 43
    .line 44
    .line 45
    move-result v7

    .line 46
    invoke-static {v3, v4}, Ljava/lang/Math;->min(FF)F

    .line 47
    .line 48
    .line 49
    move-result v8

    .line 50
    iget-object v9, v0, Ltw/f;->d:Ltw/c;

    .line 51
    .line 52
    invoke-virtual {v9, v8, v2}, Ltw/c;->a(FF)F

    .line 53
    .line 54
    .line 55
    move-result v10

    .line 56
    iget-object v11, v0, Ltw/f;->e:Ltw/c;

    .line 57
    .line 58
    invoke-virtual {v11, v8, v2}, Ltw/c;->a(FF)F

    .line 59
    .line 60
    .line 61
    move-result v12

    .line 62
    iget-object v13, v0, Ltw/f;->f:Ltw/c;

    .line 63
    .line 64
    invoke-virtual {v13, v8, v2}, Ltw/c;->a(FF)F

    .line 65
    .line 66
    .line 67
    move-result v14

    .line 68
    iget-object v15, v0, Ltw/f;->g:Ltw/c;

    .line 69
    .line 70
    invoke-virtual {v15, v8, v2}, Ltw/c;->a(FF)F

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    add-float v8, v10, v12

    .line 75
    .line 76
    cmpg-float v16, v8, v5

    .line 77
    .line 78
    const/high16 v17, 0x3f800000    # 1.0f

    .line 79
    .line 80
    if-nez v16, :cond_2

    .line 81
    .line 82
    move/from16 v8, v17

    .line 83
    .line 84
    :cond_2
    div-float v8, v3, v8

    .line 85
    .line 86
    add-float v16, v0, v14

    .line 87
    .line 88
    cmpg-float v18, v16, v5

    .line 89
    .line 90
    if-nez v18, :cond_3

    .line 91
    .line 92
    move/from16 v16, v17

    .line 93
    .line 94
    :cond_3
    div-float v3, v3, v16

    .line 95
    .line 96
    add-float/2addr v10, v0

    .line 97
    cmpg-float v0, v10, v5

    .line 98
    .line 99
    if-nez v0, :cond_4

    .line 100
    .line 101
    move/from16 v10, v17

    .line 102
    .line 103
    :cond_4
    div-float v0, v4, v10

    .line 104
    .line 105
    add-float/2addr v12, v14

    .line 106
    cmpg-float v5, v12, v5

    .line 107
    .line 108
    if-nez v5, :cond_5

    .line 109
    .line 110
    move/from16 v12, v17

    .line 111
    .line 112
    :cond_5
    div-float/2addr v4, v12

    .line 113
    const/4 v5, 0x3

    .line 114
    new-array v10, v5, [F

    .line 115
    .line 116
    const/4 v12, 0x0

    .line 117
    aput v3, v10, v12

    .line 118
    .line 119
    const/4 v3, 0x1

    .line 120
    aput v0, v10, v3

    .line 121
    .line 122
    const/4 v0, 0x2

    .line 123
    aput v4, v10, v0

    .line 124
    .line 125
    :goto_1
    if-ge v12, v5, :cond_6

    .line 126
    .line 127
    aget v0, v10, v12

    .line 128
    .line 129
    invoke-static {v8, v0}, Ljava/lang/Math;->min(FF)F

    .line 130
    .line 131
    .line 132
    move-result v8

    .line 133
    add-int/lit8 v12, v12, 0x1

    .line 134
    .line 135
    goto :goto_1

    .line 136
    :cond_6
    cmpl-float v0, v8, v17

    .line 137
    .line 138
    if-lez v0, :cond_7

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_7
    move/from16 v17, v8

    .line 142
    .line 143
    :goto_2
    invoke-virtual {v9, v7, v2}, Ltw/c;->a(FF)F

    .line 144
    .line 145
    .line 146
    move-result v0

    .line 147
    mul-float v0, v0, v17

    .line 148
    .line 149
    invoke-virtual {v11, v7, v2}, Ltw/c;->a(FF)F

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    mul-float v8, v3, v17

    .line 154
    .line 155
    invoke-virtual {v13, v7, v2}, Ltw/c;->a(FF)F

    .line 156
    .line 157
    .line 158
    move-result v3

    .line 159
    mul-float v10, v3, v17

    .line 160
    .line 161
    invoke-virtual {v15, v7, v2}, Ltw/c;->a(FF)F

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    mul-float v7, v2, v17

    .line 166
    .line 167
    add-float v2, p4, v0

    .line 168
    .line 169
    invoke-virtual {v6, v1, v2}, Landroid/graphics/Path;->moveTo(FF)V

    .line 170
    .line 171
    .line 172
    iget-object v3, v9, Ltw/c;->a:Ltw/e;

    .line 173
    .line 174
    add-float/2addr v0, v1

    .line 175
    sget-object v5, Ltw/d;->d:Ltw/d;

    .line 176
    .line 177
    move-object v4, v3

    .line 178
    move v3, v0

    .line 179
    move-object v0, v4

    .line 180
    move/from16 v4, p4

    .line 181
    .line 182
    invoke-interface/range {v0 .. v6}, Ltw/e;->a(FFFFLtw/d;Landroid/graphics/Path;)V

    .line 183
    .line 184
    .line 185
    move v2, v4

    .line 186
    sub-float v1, p5, v8

    .line 187
    .line 188
    invoke-virtual {v6, v1, v2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 189
    .line 190
    .line 191
    iget-object v0, v11, Ltw/c;->a:Ltw/e;

    .line 192
    .line 193
    add-float v4, v2, v8

    .line 194
    .line 195
    sget-object v5, Ltw/d;->e:Ltw/d;

    .line 196
    .line 197
    move/from16 v3, p5

    .line 198
    .line 199
    invoke-interface/range {v0 .. v6}, Ltw/e;->a(FFFFLtw/d;Landroid/graphics/Path;)V

    .line 200
    .line 201
    .line 202
    move v1, v3

    .line 203
    sub-float v2, p6, v10

    .line 204
    .line 205
    invoke-virtual {v6, v1, v2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 206
    .line 207
    .line 208
    iget-object v0, v13, Ltw/c;->a:Ltw/e;

    .line 209
    .line 210
    sub-float v3, v1, v10

    .line 211
    .line 212
    sget-object v5, Ltw/d;->f:Ltw/d;

    .line 213
    .line 214
    move/from16 v4, p6

    .line 215
    .line 216
    invoke-interface/range {v0 .. v6}, Ltw/e;->a(FFFFLtw/d;Landroid/graphics/Path;)V

    .line 217
    .line 218
    .line 219
    move v2, v4

    .line 220
    add-float v1, p3, v7

    .line 221
    .line 222
    invoke-virtual {v6, v1, v2}, Landroid/graphics/Path;->lineTo(FF)V

    .line 223
    .line 224
    .line 225
    iget-object v0, v15, Ltw/c;->a:Ltw/e;

    .line 226
    .line 227
    sub-float v4, v2, v7

    .line 228
    .line 229
    sget-object v5, Ltw/d;->g:Ltw/d;

    .line 230
    .line 231
    move/from16 v3, p3

    .line 232
    .line 233
    invoke-interface/range {v0 .. v6}, Ltw/e;->a(FFFFLtw/d;Landroid/graphics/Path;)V

    .line 234
    .line 235
    .line 236
    invoke-virtual/range {p2 .. p2}, Landroid/graphics/Path;->close()V

    .line 237
    .line 238
    .line 239
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Ltw/f;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Ltw/f;

    .line 8
    .line 9
    iget-object v0, p1, Ltw/f;->d:Ltw/c;

    .line 10
    .line 11
    iget-object v1, p0, Ltw/f;->d:Ltw/c;

    .line 12
    .line 13
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_0

    .line 18
    .line 19
    iget-object v0, p0, Ltw/f;->e:Ltw/c;

    .line 20
    .line 21
    iget-object v1, p1, Ltw/f;->e:Ltw/c;

    .line 22
    .line 23
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_0

    .line 28
    .line 29
    iget-object v0, p0, Ltw/f;->f:Ltw/c;

    .line 30
    .line 31
    iget-object v1, p1, Ltw/f;->f:Ltw/c;

    .line 32
    .line 33
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v0

    .line 37
    if-eqz v0, :cond_0

    .line 38
    .line 39
    iget-object p0, p0, Ltw/f;->g:Ltw/c;

    .line 40
    .line 41
    iget-object p1, p1, Ltw/f;->g:Ltw/c;

    .line 42
    .line 43
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-eqz p0, :cond_0

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    const/4 p0, 0x0

    .line 51
    return p0

    .line 52
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 53
    return p0
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget-object v0, p0, Ltw/f;->d:Ltw/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object v1, p0, Ltw/f;->e:Ltw/c;

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Object;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    add-int/2addr v1, v0

    .line 16
    mul-int/lit8 v1, v1, 0x1f

    .line 17
    .line 18
    iget-object v0, p0, Ltw/f;->f:Ltw/c;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v1

    .line 25
    mul-int/lit8 v0, v0, 0x1f

    .line 26
    .line 27
    iget-object p0, p0, Ltw/f;->g:Ltw/c;

    .line 28
    .line 29
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    add-int/2addr p0, v0

    .line 34
    return p0
.end method

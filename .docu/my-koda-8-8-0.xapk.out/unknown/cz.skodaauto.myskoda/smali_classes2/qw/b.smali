.class public Lqw/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lpw/d;

.field public final b:Ltw/l;

.field public final c:Lpw/c;

.field public final d:Lpw/d;

.field public final e:F

.field public final f:Landroid/graphics/Paint;

.field public final g:Landroid/graphics/Paint;

.field public final h:Landroid/graphics/Path;


# direct methods
.method public constructor <init>(Lpw/d;Ltw/l;Lpw/c;Lpw/d;F)V
    .locals 1

    .line 1
    const-string v0, "margins"

    .line 2
    .line 3
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "strokeFill"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lqw/b;->a:Lpw/d;

    .line 15
    .line 16
    iput-object p2, p0, Lqw/b;->b:Ltw/l;

    .line 17
    .line 18
    iput-object p3, p0, Lqw/b;->c:Lpw/c;

    .line 19
    .line 20
    iput-object p4, p0, Lqw/b;->d:Lpw/d;

    .line 21
    .line 22
    iput p5, p0, Lqw/b;->e:F

    .line 23
    .line 24
    new-instance p2, Landroid/graphics/Paint;

    .line 25
    .line 26
    const/4 p3, 0x1

    .line 27
    invoke-direct {p2, p3}, Landroid/graphics/Paint;-><init>(I)V

    .line 28
    .line 29
    .line 30
    iget p1, p1, Lpw/d;->a:I

    .line 31
    .line 32
    invoke-virtual {p2, p1}, Landroid/graphics/Paint;->setColor(I)V

    .line 33
    .line 34
    .line 35
    iput-object p2, p0, Lqw/b;->f:Landroid/graphics/Paint;

    .line 36
    .line 37
    new-instance p1, Landroid/graphics/Paint;

    .line 38
    .line 39
    invoke-direct {p1, p3}, Landroid/graphics/Paint;-><init>(I)V

    .line 40
    .line 41
    .line 42
    iget p2, p4, Lpw/d;->a:I

    .line 43
    .line 44
    invoke-virtual {p1, p2}, Landroid/graphics/Paint;->setColor(I)V

    .line 45
    .line 46
    .line 47
    sget-object p2, Landroid/graphics/Paint$Style;->STROKE:Landroid/graphics/Paint$Style;

    .line 48
    .line 49
    invoke-virtual {p1, p2}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 50
    .line 51
    .line 52
    iput-object p1, p0, Lqw/b;->g:Landroid/graphics/Paint;

    .line 53
    .line 54
    new-instance p1, Landroid/graphics/Path;

    .line 55
    .line 56
    invoke-direct {p1}, Landroid/graphics/Path;-><init>()V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Lqw/b;->h:Landroid/graphics/Path;

    .line 60
    .line 61
    const/4 p0, 0x0

    .line 62
    cmpl-float p0, p5, p0

    .line 63
    .line 64
    if-ltz p0, :cond_0

    .line 65
    .line 66
    return-void

    .line 67
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 68
    .line 69
    const-string p1, "`strokeThicknessDp` must be nonnegative."

    .line 70
    .line 71
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    throw p0
.end method


# virtual methods
.method public final a(Lc1/h2;FFFF)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    const-string v1, "context"

    .line 6
    .line 7
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, v2, Lc1/h2;->b:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lkw/g;

    .line 13
    .line 14
    invoke-interface {v1}, Lpw/f;->e()Z

    .line 15
    .line 16
    .line 17
    move-result v3

    .line 18
    iget-object v4, v0, Lqw/b;->c:Lpw/c;

    .line 19
    .line 20
    if-eqz v3, :cond_0

    .line 21
    .line 22
    iget v3, v4, Lpw/c;->a:F

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget v3, v4, Lpw/c;->c:F

    .line 26
    .line 27
    :goto_0
    invoke-interface {v1, v3}, Lpw/f;->c(F)F

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    add-float v3, v3, p2

    .line 32
    .line 33
    iget v5, v4, Lpw/c;->b:F

    .line 34
    .line 35
    invoke-interface {v1, v5}, Lpw/f;->c(F)F

    .line 36
    .line 37
    .line 38
    move-result v5

    .line 39
    add-float v5, v5, p3

    .line 40
    .line 41
    invoke-interface {v1}, Lpw/f;->e()Z

    .line 42
    .line 43
    .line 44
    move-result v6

    .line 45
    if-eqz v6, :cond_1

    .line 46
    .line 47
    iget v6, v4, Lpw/c;->c:F

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    iget v6, v4, Lpw/c;->a:F

    .line 51
    .line 52
    :goto_1
    invoke-interface {v1, v6}, Lpw/f;->c(F)F

    .line 53
    .line 54
    .line 55
    move-result v6

    .line 56
    sub-float v6, p4, v6

    .line 57
    .line 58
    iget v4, v4, Lpw/c;->d:F

    .line 59
    .line 60
    invoke-interface {v1, v4}, Lpw/f;->c(F)F

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    sub-float v4, p5, v4

    .line 65
    .line 66
    cmpl-float v7, v3, v6

    .line 67
    .line 68
    if-gez v7, :cond_9

    .line 69
    .line 70
    cmpl-float v7, v5, v4

    .line 71
    .line 72
    if-ltz v7, :cond_2

    .line 73
    .line 74
    goto/16 :goto_4

    .line 75
    .line 76
    :cond_2
    iget v7, v0, Lqw/b;->e:F

    .line 77
    .line 78
    invoke-interface {v1, v7}, Lpw/f;->c(F)F

    .line 79
    .line 80
    .line 81
    move-result v7

    .line 82
    const/4 v1, 0x0

    .line 83
    cmpg-float v8, v7, v1

    .line 84
    .line 85
    if-nez v8, :cond_4

    .line 86
    .line 87
    :cond_3
    move v9, v3

    .line 88
    move v10, v4

    .line 89
    move v11, v5

    .line 90
    move v12, v6

    .line 91
    goto :goto_2

    .line 92
    :cond_4
    const/4 v1, 0x2

    .line 93
    int-to-float v1, v1

    .line 94
    div-float v1, v7, v1

    .line 95
    .line 96
    add-float/2addr v3, v1

    .line 97
    add-float/2addr v5, v1

    .line 98
    sub-float/2addr v6, v1

    .line 99
    sub-float/2addr v4, v1

    .line 100
    cmpl-float v1, v3, v6

    .line 101
    .line 102
    if-gtz v1, :cond_9

    .line 103
    .line 104
    cmpl-float v1, v5, v4

    .line 105
    .line 106
    if-lez v1, :cond_3

    .line 107
    .line 108
    goto/16 :goto_4

    .line 109
    .line 110
    :goto_2
    iget-object v13, v0, Lqw/b;->h:Landroid/graphics/Path;

    .line 111
    .line 112
    invoke-virtual {v13}, Landroid/graphics/Path;->rewind()V

    .line 113
    .line 114
    .line 115
    iget-object v1, v0, Lqw/b;->a:Lpw/d;

    .line 116
    .line 117
    iget-object v1, v1, Lpw/d;->b:Lsw/a;

    .line 118
    .line 119
    iget-object v14, v0, Lqw/b;->f:Landroid/graphics/Paint;

    .line 120
    .line 121
    if-eqz v1, :cond_5

    .line 122
    .line 123
    move/from16 v3, p2

    .line 124
    .line 125
    move/from16 v4, p3

    .line 126
    .line 127
    move/from16 v5, p4

    .line 128
    .line 129
    move/from16 v6, p5

    .line 130
    .line 131
    invoke-virtual/range {v1 .. v6}, Lsw/a;->a(Lc1/h2;FFFF)Landroid/graphics/Shader;

    .line 132
    .line 133
    .line 134
    move-result-object v1

    .line 135
    invoke-virtual {v14, v1}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 136
    .line 137
    .line 138
    :cond_5
    iget-object v15, v0, Lqw/b;->d:Lpw/d;

    .line 139
    .line 140
    iget-object v1, v15, Lpw/d;->b:Lsw/a;

    .line 141
    .line 142
    iget-object v2, v0, Lqw/b;->g:Landroid/graphics/Paint;

    .line 143
    .line 144
    if-eqz v1, :cond_6

    .line 145
    .line 146
    move/from16 v3, p2

    .line 147
    .line 148
    move/from16 v4, p3

    .line 149
    .line 150
    move/from16 v5, p4

    .line 151
    .line 152
    move/from16 v6, p5

    .line 153
    .line 154
    move/from16 v16, v8

    .line 155
    .line 156
    move-object v8, v2

    .line 157
    move-object/from16 v2, p1

    .line 158
    .line 159
    invoke-virtual/range {v1 .. v6}, Lsw/a;->a(Lc1/h2;FFFF)Landroid/graphics/Shader;

    .line 160
    .line 161
    .line 162
    move-result-object v1

    .line 163
    invoke-virtual {v8, v1}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 164
    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_6
    move/from16 v16, v8

    .line 168
    .line 169
    move-object v8, v2

    .line 170
    :goto_3
    iget-object v0, v0, Lqw/b;->b:Ltw/l;

    .line 171
    .line 172
    move-object/from16 v1, p1

    .line 173
    .line 174
    move v3, v9

    .line 175
    move v6, v10

    .line 176
    move v4, v11

    .line 177
    move v5, v12

    .line 178
    move-object v2, v13

    .line 179
    invoke-interface/range {v0 .. v6}, Ltw/l;->a(Lpw/f;Landroid/graphics/Path;FFFF)V

    .line 180
    .line 181
    .line 182
    move-object v0, v2

    .line 183
    move-object v2, v1

    .line 184
    iget-object v1, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 185
    .line 186
    check-cast v1, Landroid/graphics/Canvas;

    .line 187
    .line 188
    invoke-virtual {v1, v0, v14}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 189
    .line 190
    .line 191
    if-nez v16, :cond_7

    .line 192
    .line 193
    goto :goto_4

    .line 194
    :cond_7
    iget v1, v15, Lpw/d;->a:I

    .line 195
    .line 196
    shr-int/lit8 v1, v1, 0x18

    .line 197
    .line 198
    and-int/lit16 v1, v1, 0xff

    .line 199
    .line 200
    if-nez v1, :cond_8

    .line 201
    .line 202
    goto :goto_4

    .line 203
    :cond_8
    invoke-virtual {v8, v7}, Landroid/graphics/Paint;->setStrokeWidth(F)V

    .line 204
    .line 205
    .line 206
    iget-object v1, v2, Lc1/h2;->d:Ljava/lang/Object;

    .line 207
    .line 208
    check-cast v1, Landroid/graphics/Canvas;

    .line 209
    .line 210
    invoke-virtual {v1, v0, v8}, Landroid/graphics/Canvas;->drawPath(Landroid/graphics/Path;Landroid/graphics/Paint;)V

    .line 211
    .line 212
    .line 213
    :cond_9
    :goto_4
    return-void
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-eq p0, p1, :cond_1

    .line 2
    .line 3
    instance-of v0, p1, Lqw/b;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    check-cast p1, Lqw/b;

    .line 8
    .line 9
    iget-object v0, p1, Lqw/b;->a:Lpw/d;

    .line 10
    .line 11
    iget-object v1, p0, Lqw/b;->a:Lpw/d;

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
    iget-object v0, p0, Lqw/b;->b:Ltw/l;

    .line 20
    .line 21
    iget-object v1, p1, Lqw/b;->b:Ltw/l;

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
    iget-object v0, p0, Lqw/b;->c:Lpw/c;

    .line 30
    .line 31
    iget-object v1, p1, Lqw/b;->c:Lpw/c;

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
    iget-object v0, p0, Lqw/b;->d:Lpw/d;

    .line 40
    .line 41
    iget-object v1, p1, Lqw/b;->d:Lpw/d;

    .line 42
    .line 43
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    if-eqz v0, :cond_0

    .line 48
    .line 49
    iget p0, p0, Lqw/b;->e:F

    .line 50
    .line 51
    iget p1, p1, Lqw/b;->e:F

    .line 52
    .line 53
    cmpg-float p0, p0, p1

    .line 54
    .line 55
    if-nez p0, :cond_0

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_0
    const/4 p0, 0x0

    .line 59
    return p0

    .line 60
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 61
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lqw/b;->a:Lpw/d;

    .line 2
    .line 3
    invoke-virtual {v0}, Lpw/d;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lqw/b;->b:Ltw/l;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Lqw/b;->c:Lpw/c;

    .line 19
    .line 20
    invoke-virtual {v0}, Lpw/c;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Lqw/b;->d:Lpw/d;

    .line 27
    .line 28
    invoke-virtual {v2}, Lpw/d;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    iget p0, p0, Lqw/b;->e:F

    .line 35
    .line 36
    invoke-static {p0, v2, v1}, La7/g0;->c(FII)I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    return p0
.end method

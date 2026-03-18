.class public abstract Le3/j0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Le3/i0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Le3/i0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le3/j0;->a:Le3/i0;

    .line 7
    .line 8
    return-void
.end method

.method public static final A(I)Landroid/graphics/Bitmap$Config;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    if-ne p0, v0, :cond_1

    .line 8
    .line 9
    sget-object p0, Landroid/graphics/Bitmap$Config;->ALPHA_8:Landroid/graphics/Bitmap$Config;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    const/4 v0, 0x2

    .line 13
    if-ne p0, v0, :cond_2

    .line 14
    .line 15
    sget-object p0, Landroid/graphics/Bitmap$Config;->RGB_565:Landroid/graphics/Bitmap$Config;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_2
    const/4 v0, 0x3

    .line 19
    if-ne p0, v0, :cond_3

    .line 20
    .line 21
    sget-object p0, Landroid/graphics/Bitmap$Config;->RGBA_F16:Landroid/graphics/Bitmap$Config;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_3
    const/4 v0, 0x4

    .line 25
    if-ne p0, v0, :cond_4

    .line 26
    .line 27
    sget-object p0, Landroid/graphics/Bitmap$Config;->HARDWARE:Landroid/graphics/Bitmap$Config;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_4
    sget-object p0, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 31
    .line 32
    return-object p0
.end method

.method public static final B(Landroid/graphics/Rect;)Ld3/c;
    .locals 4

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    iget v1, p0, Landroid/graphics/Rect;->left:I

    .line 4
    .line 5
    int-to-float v1, v1

    .line 6
    iget v2, p0, Landroid/graphics/Rect;->top:I

    .line 7
    .line 8
    int-to-float v2, v2

    .line 9
    iget v3, p0, Landroid/graphics/Rect;->right:I

    .line 10
    .line 11
    int-to-float v3, v3

    .line 12
    iget p0, p0, Landroid/graphics/Rect;->bottom:I

    .line 13
    .line 14
    int-to-float p0, p0

    .line 15
    invoke-direct {v0, v1, v2, v3, p0}, Ld3/c;-><init>(FFFF)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static final C(Landroid/graphics/RectF;)Ld3/c;
    .locals 4

    .line 1
    new-instance v0, Ld3/c;

    .line 2
    .line 3
    iget v1, p0, Landroid/graphics/RectF;->left:F

    .line 4
    .line 5
    iget v2, p0, Landroid/graphics/RectF;->top:F

    .line 6
    .line 7
    iget v3, p0, Landroid/graphics/RectF;->right:F

    .line 8
    .line 9
    iget p0, p0, Landroid/graphics/RectF;->bottom:F

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Ld3/c;-><init>(FFFF)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static D(I)Ljava/lang/String;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    const-string p0, "Clear"

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    if-ne p0, v0, :cond_1

    .line 8
    .line 9
    const-string p0, "Src"

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    const/4 v0, 0x2

    .line 13
    if-ne p0, v0, :cond_2

    .line 14
    .line 15
    const-string p0, "Dst"

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_2
    const/4 v0, 0x3

    .line 19
    if-ne p0, v0, :cond_3

    .line 20
    .line 21
    const-string p0, "SrcOver"

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_3
    const/4 v0, 0x4

    .line 25
    if-ne p0, v0, :cond_4

    .line 26
    .line 27
    const-string p0, "DstOver"

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_4
    const/4 v0, 0x5

    .line 31
    if-ne p0, v0, :cond_5

    .line 32
    .line 33
    const-string p0, "SrcIn"

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_5
    const/4 v0, 0x6

    .line 37
    if-ne p0, v0, :cond_6

    .line 38
    .line 39
    const-string p0, "DstIn"

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_6
    const/4 v0, 0x7

    .line 43
    if-ne p0, v0, :cond_7

    .line 44
    .line 45
    const-string p0, "SrcOut"

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_7
    const/16 v0, 0x8

    .line 49
    .line 50
    if-ne p0, v0, :cond_8

    .line 51
    .line 52
    const-string p0, "DstOut"

    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_8
    const/16 v0, 0x9

    .line 56
    .line 57
    if-ne p0, v0, :cond_9

    .line 58
    .line 59
    const-string p0, "SrcAtop"

    .line 60
    .line 61
    return-object p0

    .line 62
    :cond_9
    const/16 v0, 0xa

    .line 63
    .line 64
    if-ne p0, v0, :cond_a

    .line 65
    .line 66
    const-string p0, "DstAtop"

    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_a
    const/16 v0, 0xb

    .line 70
    .line 71
    if-ne p0, v0, :cond_b

    .line 72
    .line 73
    const-string p0, "Xor"

    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_b
    const/16 v0, 0xc

    .line 77
    .line 78
    if-ne p0, v0, :cond_c

    .line 79
    .line 80
    const-string p0, "Plus"

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_c
    const/16 v0, 0xd

    .line 84
    .line 85
    if-ne p0, v0, :cond_d

    .line 86
    .line 87
    const-string p0, "Modulate"

    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_d
    const/16 v0, 0xe

    .line 91
    .line 92
    if-ne p0, v0, :cond_e

    .line 93
    .line 94
    const-string p0, "Screen"

    .line 95
    .line 96
    return-object p0

    .line 97
    :cond_e
    const/16 v0, 0xf

    .line 98
    .line 99
    if-ne p0, v0, :cond_f

    .line 100
    .line 101
    const-string p0, "Overlay"

    .line 102
    .line 103
    return-object p0

    .line 104
    :cond_f
    const/16 v0, 0x10

    .line 105
    .line 106
    if-ne p0, v0, :cond_10

    .line 107
    .line 108
    const-string p0, "Darken"

    .line 109
    .line 110
    return-object p0

    .line 111
    :cond_10
    const/16 v0, 0x11

    .line 112
    .line 113
    if-ne p0, v0, :cond_11

    .line 114
    .line 115
    const-string p0, "Lighten"

    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_11
    const/16 v0, 0x12

    .line 119
    .line 120
    if-ne p0, v0, :cond_12

    .line 121
    .line 122
    const-string p0, "ColorDodge"

    .line 123
    .line 124
    return-object p0

    .line 125
    :cond_12
    const/16 v0, 0x13

    .line 126
    .line 127
    if-ne p0, v0, :cond_13

    .line 128
    .line 129
    const-string p0, "ColorBurn"

    .line 130
    .line 131
    return-object p0

    .line 132
    :cond_13
    const/16 v0, 0x14

    .line 133
    .line 134
    if-ne p0, v0, :cond_14

    .line 135
    .line 136
    const-string p0, "HardLight"

    .line 137
    .line 138
    return-object p0

    .line 139
    :cond_14
    const/16 v0, 0x15

    .line 140
    .line 141
    if-ne p0, v0, :cond_15

    .line 142
    .line 143
    const-string p0, "Softlight"

    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_15
    const/16 v0, 0x16

    .line 147
    .line 148
    if-ne p0, v0, :cond_16

    .line 149
    .line 150
    const-string p0, "Difference"

    .line 151
    .line 152
    return-object p0

    .line 153
    :cond_16
    const/16 v0, 0x17

    .line 154
    .line 155
    if-ne p0, v0, :cond_17

    .line 156
    .line 157
    const-string p0, "Exclusion"

    .line 158
    .line 159
    return-object p0

    .line 160
    :cond_17
    const/16 v0, 0x18

    .line 161
    .line 162
    if-ne p0, v0, :cond_18

    .line 163
    .line 164
    const-string p0, "Multiply"

    .line 165
    .line 166
    return-object p0

    .line 167
    :cond_18
    const/16 v0, 0x19

    .line 168
    .line 169
    if-ne p0, v0, :cond_19

    .line 170
    .line 171
    const-string p0, "Hue"

    .line 172
    .line 173
    return-object p0

    .line 174
    :cond_19
    const/16 v0, 0x1a

    .line 175
    .line 176
    if-ne p0, v0, :cond_1a

    .line 177
    .line 178
    const-string p0, "Saturation"

    .line 179
    .line 180
    return-object p0

    .line 181
    :cond_1a
    const/16 v0, 0x1b

    .line 182
    .line 183
    if-ne p0, v0, :cond_1b

    .line 184
    .line 185
    const-string p0, "Color"

    .line 186
    .line 187
    return-object p0

    .line 188
    :cond_1b
    const/16 v0, 0x1c

    .line 189
    .line 190
    if-ne p0, v0, :cond_1c

    .line 191
    .line 192
    const-string p0, "Luminosity"

    .line 193
    .line 194
    return-object p0

    .line 195
    :cond_1c
    const-string p0, "Unknown"

    .line 196
    .line 197
    return-object p0
.end method

.method public static final E(F[FI)I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    cmpg-float v1, p0, v0

    .line 3
    .line 4
    if-gez v1, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    move v0, p0

    .line 8
    :goto_0
    const/high16 v1, 0x3f800000    # 1.0f

    .line 9
    .line 10
    cmpl-float v2, v0, v1

    .line 11
    .line 12
    if-lez v2, :cond_1

    .line 13
    .line 14
    move v0, v1

    .line 15
    :cond_1
    sub-float p0, v0, p0

    .line 16
    .line 17
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    const v1, 0x358cedba    # 1.05E-6f

    .line 22
    .line 23
    .line 24
    cmpl-float p0, p0, v1

    .line 25
    .line 26
    if-lez p0, :cond_2

    .line 27
    .line 28
    const/high16 v0, 0x7fc00000    # Float.NaN

    .line 29
    .line 30
    :cond_2
    aput v0, p1, p2

    .line 31
    .line 32
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    xor-int/lit8 p0, p0, 0x1

    .line 37
    .line 38
    return p0
.end method

.method public static final a(Le3/f;)Le3/a;
    .locals 2

    .line 1
    sget-object v0, Le3/b;->a:Landroid/graphics/Canvas;

    .line 2
    .line 3
    new-instance v0, Le3/a;

    .line 4
    .line 5
    invoke-direct {v0}, Le3/a;-><init>()V

    .line 6
    .line 7
    .line 8
    new-instance v1, Landroid/graphics/Canvas;

    .line 9
    .line 10
    invoke-static {p0}, Le3/j0;->k(Le3/f;)Landroid/graphics/Bitmap;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-direct {v1, p0}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 15
    .line 16
    .line 17
    iput-object v1, v0, Le3/a;->a:Landroid/graphics/Canvas;

    .line 18
    .line 19
    return-object v0
.end method

.method public static final b(FFFFLf3/c;)J
    .locals 21

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    invoke-virtual {v0}, Lf3/c;->c()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/16 v2, 0x10

    .line 8
    .line 9
    const/16 v3, 0x20

    .line 10
    .line 11
    const/high16 v4, 0x3f000000    # 0.5f

    .line 12
    .line 13
    const/high16 v5, 0x3f800000    # 1.0f

    .line 14
    .line 15
    const/4 v6, 0x0

    .line 16
    if-eqz v1, :cond_8

    .line 17
    .line 18
    cmpg-float v0, p3, v6

    .line 19
    .line 20
    if-gez v0, :cond_0

    .line 21
    .line 22
    move v0, v6

    .line 23
    goto :goto_0

    .line 24
    :cond_0
    move/from16 v0, p3

    .line 25
    .line 26
    :goto_0
    cmpl-float v1, v0, v5

    .line 27
    .line 28
    if-lez v1, :cond_1

    .line 29
    .line 30
    move v0, v5

    .line 31
    :cond_1
    const/high16 v1, 0x437f0000    # 255.0f

    .line 32
    .line 33
    mul-float/2addr v0, v1

    .line 34
    add-float/2addr v0, v4

    .line 35
    float-to-int v0, v0

    .line 36
    shl-int/lit8 v0, v0, 0x18

    .line 37
    .line 38
    cmpg-float v7, p0, v6

    .line 39
    .line 40
    if-gez v7, :cond_2

    .line 41
    .line 42
    move v7, v6

    .line 43
    goto :goto_1

    .line 44
    :cond_2
    move/from16 v7, p0

    .line 45
    .line 46
    :goto_1
    cmpl-float v8, v7, v5

    .line 47
    .line 48
    if-lez v8, :cond_3

    .line 49
    .line 50
    move v7, v5

    .line 51
    :cond_3
    mul-float/2addr v7, v1

    .line 52
    add-float/2addr v7, v4

    .line 53
    float-to-int v7, v7

    .line 54
    shl-int/lit8 v2, v7, 0x10

    .line 55
    .line 56
    or-int/2addr v0, v2

    .line 57
    cmpg-float v2, p1, v6

    .line 58
    .line 59
    if-gez v2, :cond_4

    .line 60
    .line 61
    move v2, v6

    .line 62
    goto :goto_2

    .line 63
    :cond_4
    move/from16 v2, p1

    .line 64
    .line 65
    :goto_2
    cmpl-float v7, v2, v5

    .line 66
    .line 67
    if-lez v7, :cond_5

    .line 68
    .line 69
    move v2, v5

    .line 70
    :cond_5
    mul-float/2addr v2, v1

    .line 71
    add-float/2addr v2, v4

    .line 72
    float-to-int v2, v2

    .line 73
    shl-int/lit8 v2, v2, 0x8

    .line 74
    .line 75
    or-int/2addr v0, v2

    .line 76
    cmpg-float v2, p2, v6

    .line 77
    .line 78
    if-gez v2, :cond_6

    .line 79
    .line 80
    goto :goto_3

    .line 81
    :cond_6
    move/from16 v6, p2

    .line 82
    .line 83
    :goto_3
    cmpl-float v2, v6, v5

    .line 84
    .line 85
    if-lez v2, :cond_7

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_7
    move v5, v6

    .line 89
    :goto_4
    mul-float/2addr v5, v1

    .line 90
    add-float/2addr v5, v4

    .line 91
    float-to-int v1, v5

    .line 92
    or-int/2addr v0, v1

    .line 93
    int-to-long v0, v0

    .line 94
    shl-long/2addr v0, v3

    .line 95
    sget v2, Le3/s;->j:I

    .line 96
    .line 97
    return-wide v0

    .line 98
    :cond_8
    iget-wide v7, v0, Lf3/c;->b:J

    .line 99
    .line 100
    sget v1, Lf3/b;->e:I

    .line 101
    .line 102
    shr-long/2addr v7, v3

    .line 103
    long-to-int v1, v7

    .line 104
    const/4 v7, 0x3

    .line 105
    if-ne v1, v7, :cond_9

    .line 106
    .line 107
    goto :goto_5

    .line 108
    :cond_9
    const-string v1, "Color only works with ColorSpaces with 3 components"

    .line 109
    .line 110
    invoke-static {v1}, Le3/a0;->a(Ljava/lang/String;)V

    .line 111
    .line 112
    .line 113
    :goto_5
    iget v1, v0, Lf3/c;->c:I

    .line 114
    .line 115
    const/4 v7, -0x1

    .line 116
    if-eq v1, v7, :cond_a

    .line 117
    .line 118
    goto :goto_6

    .line 119
    :cond_a
    const-string v7, "Unknown color space, please use a color space in ColorSpaces"

    .line 120
    .line 121
    invoke-static {v7}, Le3/a0;->a(Ljava/lang/String;)V

    .line 122
    .line 123
    .line 124
    :goto_6
    const/4 v7, 0x0

    .line 125
    invoke-virtual {v0, v7}, Lf3/c;->b(I)F

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    invoke-virtual {v0, v7}, Lf3/c;->a(I)F

    .line 130
    .line 131
    .line 132
    move-result v9

    .line 133
    cmpg-float v10, p0, v8

    .line 134
    .line 135
    if-gez v10, :cond_b

    .line 136
    .line 137
    goto :goto_7

    .line 138
    :cond_b
    move/from16 v8, p0

    .line 139
    .line 140
    :goto_7
    cmpl-float v10, v8, v9

    .line 141
    .line 142
    if-lez v10, :cond_c

    .line 143
    .line 144
    goto :goto_8

    .line 145
    :cond_c
    move v9, v8

    .line 146
    :goto_8
    invoke-static {v9}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 147
    .line 148
    .line 149
    move-result v8

    .line 150
    ushr-int/lit8 v9, v8, 0x1f

    .line 151
    .line 152
    ushr-int/lit8 v10, v8, 0x17

    .line 153
    .line 154
    const/16 v11, 0xff

    .line 155
    .line 156
    and-int/2addr v10, v11

    .line 157
    const v12, 0x7fffff

    .line 158
    .line 159
    .line 160
    and-int v13, v8, v12

    .line 161
    .line 162
    const/high16 v14, 0x800000

    .line 163
    .line 164
    const/16 v15, -0xa

    .line 165
    .line 166
    const/16 v16, 0x31

    .line 167
    .line 168
    const/16 v17, 0x200

    .line 169
    .line 170
    move/from16 v18, v2

    .line 171
    .line 172
    const/16 v2, 0x1f

    .line 173
    .line 174
    move/from16 v19, v3

    .line 175
    .line 176
    const/4 v3, 0x1

    .line 177
    if-ne v10, v11, :cond_e

    .line 178
    .line 179
    if-eqz v13, :cond_d

    .line 180
    .line 181
    move/from16 v8, v17

    .line 182
    .line 183
    goto :goto_9

    .line 184
    :cond_d
    move v8, v7

    .line 185
    :goto_9
    move v10, v2

    .line 186
    goto :goto_b

    .line 187
    :cond_e
    add-int/lit8 v10, v10, -0x70

    .line 188
    .line 189
    if-lt v10, v2, :cond_f

    .line 190
    .line 191
    move v8, v7

    .line 192
    move/from16 v10, v16

    .line 193
    .line 194
    goto :goto_b

    .line 195
    :cond_f
    if-gtz v10, :cond_12

    .line 196
    .line 197
    if-lt v10, v15, :cond_11

    .line 198
    .line 199
    or-int v8, v13, v14

    .line 200
    .line 201
    rsub-int/lit8 v10, v10, 0x1

    .line 202
    .line 203
    shr-int/2addr v8, v10

    .line 204
    and-int/lit16 v10, v8, 0x1000

    .line 205
    .line 206
    if-eqz v10, :cond_10

    .line 207
    .line 208
    add-int/lit16 v8, v8, 0x2000

    .line 209
    .line 210
    :cond_10
    shr-int/lit8 v8, v8, 0xd

    .line 211
    .line 212
    move v10, v7

    .line 213
    goto :goto_b

    .line 214
    :cond_11
    move v8, v7

    .line 215
    move v10, v8

    .line 216
    goto :goto_b

    .line 217
    :cond_12
    shr-int/lit8 v13, v13, 0xd

    .line 218
    .line 219
    and-int/lit16 v8, v8, 0x1000

    .line 220
    .line 221
    if-eqz v8, :cond_13

    .line 222
    .line 223
    shl-int/lit8 v8, v10, 0xa

    .line 224
    .line 225
    or-int/2addr v8, v13

    .line 226
    add-int/2addr v8, v3

    .line 227
    shl-int/lit8 v9, v9, 0xf

    .line 228
    .line 229
    or-int/2addr v8, v9

    .line 230
    :goto_a
    int-to-short v8, v8

    .line 231
    goto :goto_c

    .line 232
    :cond_13
    move v8, v13

    .line 233
    :goto_b
    shl-int/lit8 v9, v9, 0xf

    .line 234
    .line 235
    shl-int/lit8 v10, v10, 0xa

    .line 236
    .line 237
    or-int/2addr v9, v10

    .line 238
    or-int/2addr v8, v9

    .line 239
    goto :goto_a

    .line 240
    :goto_c
    invoke-virtual {v0, v3}, Lf3/c;->b(I)F

    .line 241
    .line 242
    .line 243
    move-result v9

    .line 244
    invoke-virtual {v0, v3}, Lf3/c;->a(I)F

    .line 245
    .line 246
    .line 247
    move-result v10

    .line 248
    cmpg-float v13, p1, v9

    .line 249
    .line 250
    if-gez v13, :cond_14

    .line 251
    .line 252
    goto :goto_d

    .line 253
    :cond_14
    move/from16 v9, p1

    .line 254
    .line 255
    :goto_d
    cmpl-float v13, v9, v10

    .line 256
    .line 257
    if-lez v13, :cond_15

    .line 258
    .line 259
    goto :goto_e

    .line 260
    :cond_15
    move v10, v9

    .line 261
    :goto_e
    invoke-static {v10}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 262
    .line 263
    .line 264
    move-result v9

    .line 265
    ushr-int/lit8 v10, v9, 0x1f

    .line 266
    .line 267
    ushr-int/lit8 v13, v9, 0x17

    .line 268
    .line 269
    and-int/2addr v13, v11

    .line 270
    and-int v20, v9, v12

    .line 271
    .line 272
    if-ne v13, v11, :cond_17

    .line 273
    .line 274
    if-eqz v20, :cond_16

    .line 275
    .line 276
    move/from16 v9, v17

    .line 277
    .line 278
    goto :goto_f

    .line 279
    :cond_16
    move v9, v7

    .line 280
    :goto_f
    move v13, v2

    .line 281
    goto :goto_11

    .line 282
    :cond_17
    add-int/lit8 v13, v13, -0x70

    .line 283
    .line 284
    if-lt v13, v2, :cond_18

    .line 285
    .line 286
    move v9, v7

    .line 287
    move/from16 v13, v16

    .line 288
    .line 289
    goto :goto_11

    .line 290
    :cond_18
    if-gtz v13, :cond_1b

    .line 291
    .line 292
    if-lt v13, v15, :cond_1a

    .line 293
    .line 294
    or-int v9, v20, v14

    .line 295
    .line 296
    rsub-int/lit8 v13, v13, 0x1

    .line 297
    .line 298
    shr-int/2addr v9, v13

    .line 299
    and-int/lit16 v13, v9, 0x1000

    .line 300
    .line 301
    if-eqz v13, :cond_19

    .line 302
    .line 303
    add-int/lit16 v9, v9, 0x2000

    .line 304
    .line 305
    :cond_19
    shr-int/lit8 v9, v9, 0xd

    .line 306
    .line 307
    move v13, v7

    .line 308
    goto :goto_11

    .line 309
    :cond_1a
    move v9, v7

    .line 310
    move v13, v9

    .line 311
    goto :goto_11

    .line 312
    :cond_1b
    shr-int/lit8 v20, v20, 0xd

    .line 313
    .line 314
    and-int/lit16 v9, v9, 0x1000

    .line 315
    .line 316
    if-eqz v9, :cond_1c

    .line 317
    .line 318
    shl-int/lit8 v9, v13, 0xa

    .line 319
    .line 320
    or-int v9, v9, v20

    .line 321
    .line 322
    add-int/2addr v9, v3

    .line 323
    shl-int/lit8 v10, v10, 0xf

    .line 324
    .line 325
    or-int/2addr v9, v10

    .line 326
    :goto_10
    int-to-short v9, v9

    .line 327
    goto :goto_12

    .line 328
    :cond_1c
    move/from16 v9, v20

    .line 329
    .line 330
    :goto_11
    shl-int/lit8 v10, v10, 0xf

    .line 331
    .line 332
    shl-int/lit8 v13, v13, 0xa

    .line 333
    .line 334
    or-int/2addr v10, v13

    .line 335
    or-int/2addr v9, v10

    .line 336
    goto :goto_10

    .line 337
    :goto_12
    const/4 v10, 0x2

    .line 338
    invoke-virtual {v0, v10}, Lf3/c;->b(I)F

    .line 339
    .line 340
    .line 341
    move-result v13

    .line 342
    invoke-virtual {v0, v10}, Lf3/c;->a(I)F

    .line 343
    .line 344
    .line 345
    move-result v0

    .line 346
    cmpg-float v10, p2, v13

    .line 347
    .line 348
    if-gez v10, :cond_1d

    .line 349
    .line 350
    goto :goto_13

    .line 351
    :cond_1d
    move/from16 v13, p2

    .line 352
    .line 353
    :goto_13
    cmpl-float v10, v13, v0

    .line 354
    .line 355
    if-lez v10, :cond_1e

    .line 356
    .line 357
    goto :goto_14

    .line 358
    :cond_1e
    move v0, v13

    .line 359
    :goto_14
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 360
    .line 361
    .line 362
    move-result v0

    .line 363
    ushr-int/lit8 v10, v0, 0x1f

    .line 364
    .line 365
    ushr-int/lit8 v13, v0, 0x17

    .line 366
    .line 367
    and-int/2addr v13, v11

    .line 368
    and-int/2addr v12, v0

    .line 369
    if-ne v13, v11, :cond_20

    .line 370
    .line 371
    if-eqz v12, :cond_1f

    .line 372
    .line 373
    move/from16 v7, v17

    .line 374
    .line 375
    :cond_1f
    move v0, v7

    .line 376
    move v7, v2

    .line 377
    goto :goto_16

    .line 378
    :cond_20
    add-int/lit8 v13, v13, -0x70

    .line 379
    .line 380
    if-lt v13, v2, :cond_21

    .line 381
    .line 382
    move v0, v7

    .line 383
    move/from16 v7, v16

    .line 384
    .line 385
    goto :goto_16

    .line 386
    :cond_21
    if-gtz v13, :cond_24

    .line 387
    .line 388
    if-lt v13, v15, :cond_23

    .line 389
    .line 390
    or-int v0, v12, v14

    .line 391
    .line 392
    rsub-int/lit8 v2, v13, 0x1

    .line 393
    .line 394
    shr-int/2addr v0, v2

    .line 395
    and-int/lit16 v2, v0, 0x1000

    .line 396
    .line 397
    if-eqz v2, :cond_22

    .line 398
    .line 399
    add-int/lit16 v0, v0, 0x2000

    .line 400
    .line 401
    :cond_22
    shr-int/lit8 v0, v0, 0xd

    .line 402
    .line 403
    goto :goto_16

    .line 404
    :cond_23
    move v0, v7

    .line 405
    goto :goto_16

    .line 406
    :cond_24
    shr-int/lit8 v7, v12, 0xd

    .line 407
    .line 408
    and-int/lit16 v0, v0, 0x1000

    .line 409
    .line 410
    if-eqz v0, :cond_25

    .line 411
    .line 412
    shl-int/lit8 v0, v13, 0xa

    .line 413
    .line 414
    or-int/2addr v0, v7

    .line 415
    add-int/2addr v0, v3

    .line 416
    shl-int/lit8 v2, v10, 0xf

    .line 417
    .line 418
    or-int/2addr v0, v2

    .line 419
    :goto_15
    int-to-short v0, v0

    .line 420
    goto :goto_17

    .line 421
    :cond_25
    move v0, v7

    .line 422
    move v7, v13

    .line 423
    :goto_16
    shl-int/lit8 v2, v10, 0xf

    .line 424
    .line 425
    shl-int/lit8 v3, v7, 0xa

    .line 426
    .line 427
    or-int/2addr v2, v3

    .line 428
    or-int/2addr v0, v2

    .line 429
    goto :goto_15

    .line 430
    :goto_17
    cmpg-float v2, p3, v6

    .line 431
    .line 432
    if-gez v2, :cond_26

    .line 433
    .line 434
    goto :goto_18

    .line 435
    :cond_26
    move/from16 v6, p3

    .line 436
    .line 437
    :goto_18
    cmpl-float v2, v6, v5

    .line 438
    .line 439
    if-lez v2, :cond_27

    .line 440
    .line 441
    goto :goto_19

    .line 442
    :cond_27
    move v5, v6

    .line 443
    :goto_19
    const v2, 0x447fc000    # 1023.0f

    .line 444
    .line 445
    .line 446
    mul-float/2addr v5, v2

    .line 447
    add-float/2addr v5, v4

    .line 448
    float-to-int v2, v5

    .line 449
    int-to-long v3, v8

    .line 450
    const-wide/32 v5, 0xffff

    .line 451
    .line 452
    .line 453
    and-long/2addr v3, v5

    .line 454
    const/16 v7, 0x30

    .line 455
    .line 456
    shl-long/2addr v3, v7

    .line 457
    int-to-long v7, v9

    .line 458
    and-long/2addr v7, v5

    .line 459
    shl-long v7, v7, v19

    .line 460
    .line 461
    or-long/2addr v3, v7

    .line 462
    int-to-long v7, v0

    .line 463
    and-long/2addr v5, v7

    .line 464
    shl-long v5, v5, v18

    .line 465
    .line 466
    or-long/2addr v3, v5

    .line 467
    int-to-long v5, v2

    .line 468
    const-wide/16 v7, 0x3ff

    .line 469
    .line 470
    and-long/2addr v5, v7

    .line 471
    const/4 v0, 0x6

    .line 472
    shl-long/2addr v5, v0

    .line 473
    or-long v2, v3, v5

    .line 474
    .line 475
    int-to-long v0, v1

    .line 476
    const-wide/16 v4, 0x3f

    .line 477
    .line 478
    and-long/2addr v0, v4

    .line 479
    or-long/2addr v0, v2

    .line 480
    sget v2, Le3/s;->j:I

    .line 481
    .line 482
    return-wide v0
.end method

.method public static final c(I)J
    .locals 2

    .line 1
    int-to-long v0, p0

    .line 2
    const/16 p0, 0x20

    .line 3
    .line 4
    shl-long/2addr v0, p0

    .line 5
    sget p0, Le3/s;->j:I

    .line 6
    .line 7
    return-wide v0
.end method

.method public static final d(IIII)J
    .locals 0

    .line 1
    and-int/lit16 p3, p3, 0xff

    .line 2
    .line 3
    shl-int/lit8 p3, p3, 0x18

    .line 4
    .line 5
    and-int/lit16 p0, p0, 0xff

    .line 6
    .line 7
    shl-int/lit8 p0, p0, 0x10

    .line 8
    .line 9
    or-int/2addr p0, p3

    .line 10
    and-int/lit16 p1, p1, 0xff

    .line 11
    .line 12
    shl-int/lit8 p1, p1, 0x8

    .line 13
    .line 14
    or-int/2addr p0, p1

    .line 15
    and-int/lit16 p1, p2, 0xff

    .line 16
    .line 17
    or-int/2addr p0, p1

    .line 18
    invoke-static {p0}, Le3/j0;->c(I)J

    .line 19
    .line 20
    .line 21
    move-result-wide p0

    .line 22
    return-wide p0
.end method

.method public static final e(J)J
    .locals 1

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shl-long/2addr p0, v0

    .line 4
    sget v0, Le3/s;->j:I

    .line 5
    .line 6
    return-wide p0
.end method

.method public static synthetic f(III)J
    .locals 1

    .line 1
    const/16 v0, 0xff

    .line 2
    .line 3
    invoke-static {p0, p1, p2, v0}, Le3/j0;->d(IIII)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public static g(III)Le3/f;
    .locals 25

    .line 1
    sget-object v0, Lf3/e;->e:Lf3/r;

    .line 2
    .line 3
    invoke-static/range {p2 .. p2}, Le3/j0;->A(I)Landroid/graphics/Bitmap$Config;

    .line 4
    .line 5
    .line 6
    sget v1, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 7
    .line 8
    invoke-static/range {p2 .. p2}, Le3/j0;->A(I)Landroid/graphics/Bitmap$Config;

    .line 9
    .line 10
    .line 11
    move-result-object v5

    .line 12
    invoke-static {v0, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    sget-object v0, Landroid/graphics/ColorSpace$Named;->SRGB:Landroid/graphics/ColorSpace$Named;

    .line 19
    .line 20
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    :goto_0
    move-object v7, v0

    .line 25
    goto/16 :goto_3

    .line 26
    .line 27
    :cond_0
    sget-object v2, Lf3/e;->q:Lf3/r;

    .line 28
    .line 29
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    sget-object v0, Landroid/graphics/ColorSpace$Named;->ACES:Landroid/graphics/ColorSpace$Named;

    .line 36
    .line 37
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    goto :goto_0

    .line 42
    :cond_1
    sget-object v2, Lf3/e;->r:Lf3/r;

    .line 43
    .line 44
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    if-eqz v2, :cond_2

    .line 49
    .line 50
    sget-object v0, Landroid/graphics/ColorSpace$Named;->ACESCG:Landroid/graphics/ColorSpace$Named;

    .line 51
    .line 52
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    goto :goto_0

    .line 57
    :cond_2
    sget-object v2, Lf3/e;->o:Lf3/r;

    .line 58
    .line 59
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 60
    .line 61
    .line 62
    move-result v2

    .line 63
    if-eqz v2, :cond_3

    .line 64
    .line 65
    sget-object v0, Landroid/graphics/ColorSpace$Named;->ADOBE_RGB:Landroid/graphics/ColorSpace$Named;

    .line 66
    .line 67
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 68
    .line 69
    .line 70
    move-result-object v0

    .line 71
    goto :goto_0

    .line 72
    :cond_3
    sget-object v2, Lf3/e;->j:Lf3/r;

    .line 73
    .line 74
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-eqz v2, :cond_4

    .line 79
    .line 80
    sget-object v0, Landroid/graphics/ColorSpace$Named;->BT2020:Landroid/graphics/ColorSpace$Named;

    .line 81
    .line 82
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    goto :goto_0

    .line 87
    :cond_4
    sget-object v2, Lf3/e;->i:Lf3/r;

    .line 88
    .line 89
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    if-eqz v2, :cond_5

    .line 94
    .line 95
    sget-object v0, Landroid/graphics/ColorSpace$Named;->BT709:Landroid/graphics/ColorSpace$Named;

    .line 96
    .line 97
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    goto :goto_0

    .line 102
    :cond_5
    sget-object v2, Lf3/e;->t:Lf3/l;

    .line 103
    .line 104
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v2

    .line 108
    if-eqz v2, :cond_6

    .line 109
    .line 110
    sget-object v0, Landroid/graphics/ColorSpace$Named;->CIE_LAB:Landroid/graphics/ColorSpace$Named;

    .line 111
    .line 112
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    goto :goto_0

    .line 117
    :cond_6
    sget-object v2, Lf3/e;->s:Lf3/l;

    .line 118
    .line 119
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-eqz v2, :cond_7

    .line 124
    .line 125
    sget-object v0, Landroid/graphics/ColorSpace$Named;->CIE_XYZ:Landroid/graphics/ColorSpace$Named;

    .line 126
    .line 127
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    goto :goto_0

    .line 132
    :cond_7
    sget-object v2, Lf3/e;->k:Lf3/r;

    .line 133
    .line 134
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 135
    .line 136
    .line 137
    move-result v2

    .line 138
    if-eqz v2, :cond_8

    .line 139
    .line 140
    sget-object v0, Landroid/graphics/ColorSpace$Named;->DCI_P3:Landroid/graphics/ColorSpace$Named;

    .line 141
    .line 142
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 143
    .line 144
    .line 145
    move-result-object v0

    .line 146
    goto :goto_0

    .line 147
    :cond_8
    sget-object v2, Lf3/e;->l:Lf3/r;

    .line 148
    .line 149
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v2

    .line 153
    if-eqz v2, :cond_9

    .line 154
    .line 155
    sget-object v0, Landroid/graphics/ColorSpace$Named;->DISPLAY_P3:Landroid/graphics/ColorSpace$Named;

    .line 156
    .line 157
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    goto/16 :goto_0

    .line 162
    .line 163
    :cond_9
    sget-object v2, Lf3/e;->g:Lf3/r;

    .line 164
    .line 165
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v2

    .line 169
    if-eqz v2, :cond_a

    .line 170
    .line 171
    sget-object v0, Landroid/graphics/ColorSpace$Named;->EXTENDED_SRGB:Landroid/graphics/ColorSpace$Named;

    .line 172
    .line 173
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    goto/16 :goto_0

    .line 178
    .line 179
    :cond_a
    sget-object v2, Lf3/e;->h:Lf3/r;

    .line 180
    .line 181
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 182
    .line 183
    .line 184
    move-result v2

    .line 185
    if-eqz v2, :cond_b

    .line 186
    .line 187
    sget-object v0, Landroid/graphics/ColorSpace$Named;->LINEAR_EXTENDED_SRGB:Landroid/graphics/ColorSpace$Named;

    .line 188
    .line 189
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 190
    .line 191
    .line 192
    move-result-object v0

    .line 193
    goto/16 :goto_0

    .line 194
    .line 195
    :cond_b
    sget-object v2, Lf3/e;->f:Lf3/r;

    .line 196
    .line 197
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    move-result v2

    .line 201
    if-eqz v2, :cond_c

    .line 202
    .line 203
    sget-object v0, Landroid/graphics/ColorSpace$Named;->LINEAR_SRGB:Landroid/graphics/ColorSpace$Named;

    .line 204
    .line 205
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 206
    .line 207
    .line 208
    move-result-object v0

    .line 209
    goto/16 :goto_0

    .line 210
    .line 211
    :cond_c
    sget-object v2, Lf3/e;->m:Lf3/r;

    .line 212
    .line 213
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 214
    .line 215
    .line 216
    move-result v2

    .line 217
    if-eqz v2, :cond_d

    .line 218
    .line 219
    sget-object v0, Landroid/graphics/ColorSpace$Named;->NTSC_1953:Landroid/graphics/ColorSpace$Named;

    .line 220
    .line 221
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 222
    .line 223
    .line 224
    move-result-object v0

    .line 225
    goto/16 :goto_0

    .line 226
    .line 227
    :cond_d
    sget-object v2, Lf3/e;->p:Lf3/r;

    .line 228
    .line 229
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    move-result v2

    .line 233
    if-eqz v2, :cond_e

    .line 234
    .line 235
    sget-object v0, Landroid/graphics/ColorSpace$Named;->PRO_PHOTO_RGB:Landroid/graphics/ColorSpace$Named;

    .line 236
    .line 237
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 238
    .line 239
    .line 240
    move-result-object v0

    .line 241
    goto/16 :goto_0

    .line 242
    .line 243
    :cond_e
    sget-object v2, Lf3/e;->n:Lf3/r;

    .line 244
    .line 245
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 246
    .line 247
    .line 248
    move-result v2

    .line 249
    if-eqz v2, :cond_f

    .line 250
    .line 251
    sget-object v0, Landroid/graphics/ColorSpace$Named;->SMPTE_C:Landroid/graphics/ColorSpace$Named;

    .line 252
    .line 253
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 254
    .line 255
    .line 256
    move-result-object v0

    .line 257
    goto/16 :goto_0

    .line 258
    .line 259
    :cond_f
    const/16 v2, 0x22

    .line 260
    .line 261
    const/4 v3, 0x0

    .line 262
    if-lt v1, v2, :cond_12

    .line 263
    .line 264
    sget-object v1, Lf3/e;->v:Lf3/r;

    .line 265
    .line 266
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 267
    .line 268
    .line 269
    move-result v1

    .line 270
    if-eqz v1, :cond_10

    .line 271
    .line 272
    invoke-static {}, Lc2/h;->g()Landroid/graphics/ColorSpace$Named;

    .line 273
    .line 274
    .line 275
    move-result-object v1

    .line 276
    invoke-static {v1}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 277
    .line 278
    .line 279
    move-result-object v1

    .line 280
    goto :goto_1

    .line 281
    :cond_10
    sget-object v1, Lf3/e;->w:Lf3/r;

    .line 282
    .line 283
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    move-result v1

    .line 287
    if-eqz v1, :cond_11

    .line 288
    .line 289
    invoke-static {}, Lc2/h;->A()Landroid/graphics/ColorSpace$Named;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    invoke-static {v1}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 294
    .line 295
    .line 296
    move-result-object v1

    .line 297
    goto :goto_1

    .line 298
    :cond_11
    move-object v1, v3

    .line 299
    :goto_1
    if-eqz v1, :cond_12

    .line 300
    .line 301
    :goto_2
    move-object v7, v1

    .line 302
    goto :goto_3

    .line 303
    :cond_12
    if-eqz v0, :cond_15

    .line 304
    .line 305
    iget-object v7, v0, Lf3/c;->a:Ljava/lang/String;

    .line 306
    .line 307
    iget-object v1, v0, Lf3/r;->d:Lf3/t;

    .line 308
    .line 309
    invoke-virtual {v1}, Lf3/t;->a()[F

    .line 310
    .line 311
    .line 312
    move-result-object v9

    .line 313
    iget-object v1, v0, Lf3/r;->g:Lf3/s;

    .line 314
    .line 315
    if-eqz v1, :cond_13

    .line 316
    .line 317
    new-instance v10, Landroid/graphics/ColorSpace$Rgb$TransferParameters;

    .line 318
    .line 319
    iget-wide v11, v1, Lf3/s;->b:D

    .line 320
    .line 321
    iget-wide v13, v1, Lf3/s;->c:D

    .line 322
    .line 323
    iget-wide v2, v1, Lf3/s;->d:D

    .line 324
    .line 325
    move-wide v15, v2

    .line 326
    iget-wide v2, v1, Lf3/s;->e:D

    .line 327
    .line 328
    move-wide/from16 v17, v2

    .line 329
    .line 330
    iget-wide v2, v1, Lf3/s;->f:D

    .line 331
    .line 332
    move-wide/from16 v19, v2

    .line 333
    .line 334
    iget-wide v2, v1, Lf3/s;->g:D

    .line 335
    .line 336
    move-wide/from16 v21, v2

    .line 337
    .line 338
    iget-wide v1, v1, Lf3/s;->a:D

    .line 339
    .line 340
    move-wide/from16 v23, v1

    .line 341
    .line 342
    invoke-direct/range {v10 .. v24}, Landroid/graphics/ColorSpace$Rgb$TransferParameters;-><init>(DDDDDDD)V

    .line 343
    .line 344
    .line 345
    move-object v3, v10

    .line 346
    :cond_13
    if-eqz v3, :cond_14

    .line 347
    .line 348
    new-instance v1, Landroid/graphics/ColorSpace$Rgb;

    .line 349
    .line 350
    iget-object v0, v0, Lf3/r;->h:[F

    .line 351
    .line 352
    invoke-direct {v1, v7, v0, v9, v3}, Landroid/graphics/ColorSpace$Rgb;-><init>(Ljava/lang/String;[F[FLandroid/graphics/ColorSpace$Rgb$TransferParameters;)V

    .line 353
    .line 354
    .line 355
    goto :goto_2

    .line 356
    :cond_14
    new-instance v6, Landroid/graphics/ColorSpace$Rgb;

    .line 357
    .line 358
    iget-object v8, v0, Lf3/r;->h:[F

    .line 359
    .line 360
    iget-object v1, v0, Lf3/r;->l:Lf3/q;

    .line 361
    .line 362
    new-instance v10, Le3/u;

    .line 363
    .line 364
    const/4 v2, 0x0

    .line 365
    invoke-direct {v10, v2, v1}, Le3/u;-><init>(ILay0/k;)V

    .line 366
    .line 367
    .line 368
    iget-object v1, v0, Lf3/r;->o:Lf3/q;

    .line 369
    .line 370
    new-instance v11, Le3/u;

    .line 371
    .line 372
    const/4 v2, 0x1

    .line 373
    invoke-direct {v11, v2, v1}, Le3/u;-><init>(ILay0/k;)V

    .line 374
    .line 375
    .line 376
    iget v12, v0, Lf3/r;->e:F

    .line 377
    .line 378
    iget v13, v0, Lf3/r;->f:F

    .line 379
    .line 380
    invoke-direct/range {v6 .. v13}, Landroid/graphics/ColorSpace$Rgb;-><init>(Ljava/lang/String;[F[FLjava/util/function/DoubleUnaryOperator;Ljava/util/function/DoubleUnaryOperator;FF)V

    .line 381
    .line 382
    .line 383
    move-object v7, v6

    .line 384
    goto :goto_3

    .line 385
    :cond_15
    sget-object v0, Landroid/graphics/ColorSpace$Named;->SRGB:Landroid/graphics/ColorSpace$Named;

    .line 386
    .line 387
    invoke-static {v0}, Landroid/graphics/ColorSpace;->get(Landroid/graphics/ColorSpace$Named;)Landroid/graphics/ColorSpace;

    .line 388
    .line 389
    .line 390
    move-result-object v0

    .line 391
    goto/16 :goto_0

    .line 392
    .line 393
    :goto_3
    const/4 v2, 0x0

    .line 394
    const/4 v6, 0x1

    .line 395
    move/from16 v3, p0

    .line 396
    .line 397
    move/from16 v4, p1

    .line 398
    .line 399
    invoke-static/range {v2 .. v7}, Landroid/graphics/Bitmap;->createBitmap(Landroid/util/DisplayMetrics;IILandroid/graphics/Bitmap$Config;ZLandroid/graphics/ColorSpace;)Landroid/graphics/Bitmap;

    .line 400
    .line 401
    .line 402
    move-result-object v0

    .line 403
    new-instance v1, Le3/f;

    .line 404
    .line 405
    invoke-direct {v1, v0}, Le3/f;-><init>(Landroid/graphics/Bitmap;)V

    .line 406
    .line 407
    .line 408
    return-object v1
.end method

.method public static final h()Le3/g;
    .locals 3

    .line 1
    new-instance v0, Le3/g;

    .line 2
    .line 3
    new-instance v1, Landroid/graphics/Paint;

    .line 4
    .line 5
    const/4 v2, 0x7

    .line 6
    invoke-direct {v1, v2}, Landroid/graphics/Paint;-><init>(I)V

    .line 7
    .line 8
    .line 9
    invoke-direct {v0, v1}, Le3/g;-><init>(Landroid/graphics/Paint;)V

    .line 10
    .line 11
    .line 12
    return-object v0
.end method

.method public static final i(FF)J
    .locals 4

    .line 1
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    int-to-long v0, p0

    .line 6
    invoke-static {p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    int-to-long p0, p0

    .line 11
    const/16 v2, 0x20

    .line 12
    .line 13
    shl-long/2addr v0, v2

    .line 14
    const-wide v2, 0xffffffffL

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    and-long/2addr p0, v2

    .line 20
    or-long/2addr p0, v0

    .line 21
    sget v0, Le3/q0;->c:I

    .line 22
    .line 23
    return-wide p0
.end method

.method public static final j(FFFFLf3/c;)J
    .locals 17

    .line 1
    move/from16 v0, p3

    .line 2
    .line 3
    invoke-virtual/range {p4 .. p4}, Lf3/c;->c()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/16 v2, 0x20

    .line 8
    .line 9
    const/16 v3, 0x10

    .line 10
    .line 11
    const/high16 v4, 0x3f000000    # 0.5f

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    const/high16 v1, 0x437f0000    # 255.0f

    .line 16
    .line 17
    mul-float/2addr v0, v1

    .line 18
    add-float/2addr v0, v4

    .line 19
    float-to-int v0, v0

    .line 20
    shl-int/lit8 v0, v0, 0x18

    .line 21
    .line 22
    mul-float v5, p0, v1

    .line 23
    .line 24
    add-float/2addr v5, v4

    .line 25
    float-to-int v5, v5

    .line 26
    shl-int/lit8 v3, v5, 0x10

    .line 27
    .line 28
    or-int/2addr v0, v3

    .line 29
    mul-float v3, p1, v1

    .line 30
    .line 31
    add-float/2addr v3, v4

    .line 32
    float-to-int v3, v3

    .line 33
    shl-int/lit8 v3, v3, 0x8

    .line 34
    .line 35
    or-int/2addr v0, v3

    .line 36
    mul-float v1, v1, p2

    .line 37
    .line 38
    add-float/2addr v1, v4

    .line 39
    float-to-int v1, v1

    .line 40
    or-int/2addr v0, v1

    .line 41
    int-to-long v0, v0

    .line 42
    shl-long/2addr v0, v2

    .line 43
    sget v2, Le3/s;->j:I

    .line 44
    .line 45
    return-wide v0

    .line 46
    :cond_0
    invoke-static/range {p0 .. p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    ushr-int/lit8 v5, v1, 0x1f

    .line 51
    .line 52
    ushr-int/lit8 v6, v1, 0x17

    .line 53
    .line 54
    const/16 v7, 0xff

    .line 55
    .line 56
    and-int/2addr v6, v7

    .line 57
    const v8, 0x7fffff

    .line 58
    .line 59
    .line 60
    and-int v9, v1, v8

    .line 61
    .line 62
    const/high16 v10, 0x800000

    .line 63
    .line 64
    const/16 v11, -0xa

    .line 65
    .line 66
    const/16 v12, 0x31

    .line 67
    .line 68
    const/16 v13, 0x200

    .line 69
    .line 70
    const/4 v14, 0x0

    .line 71
    const/16 v15, 0x1f

    .line 72
    .line 73
    if-ne v6, v7, :cond_2

    .line 74
    .line 75
    if-eqz v9, :cond_1

    .line 76
    .line 77
    move v1, v13

    .line 78
    goto :goto_0

    .line 79
    :cond_1
    move v1, v14

    .line 80
    :goto_0
    move v6, v15

    .line 81
    goto :goto_2

    .line 82
    :cond_2
    add-int/lit8 v6, v6, -0x70

    .line 83
    .line 84
    if-lt v6, v15, :cond_3

    .line 85
    .line 86
    move v6, v12

    .line 87
    move v1, v14

    .line 88
    goto :goto_2

    .line 89
    :cond_3
    if-gtz v6, :cond_6

    .line 90
    .line 91
    if-lt v6, v11, :cond_5

    .line 92
    .line 93
    or-int v1, v9, v10

    .line 94
    .line 95
    rsub-int/lit8 v6, v6, 0x1

    .line 96
    .line 97
    shr-int/2addr v1, v6

    .line 98
    and-int/lit16 v6, v1, 0x1000

    .line 99
    .line 100
    if-eqz v6, :cond_4

    .line 101
    .line 102
    add-int/lit16 v1, v1, 0x2000

    .line 103
    .line 104
    :cond_4
    shr-int/lit8 v1, v1, 0xd

    .line 105
    .line 106
    move v6, v14

    .line 107
    goto :goto_2

    .line 108
    :cond_5
    move v1, v14

    .line 109
    move v6, v1

    .line 110
    goto :goto_2

    .line 111
    :cond_6
    shr-int/lit8 v9, v9, 0xd

    .line 112
    .line 113
    and-int/lit16 v1, v1, 0x1000

    .line 114
    .line 115
    if-eqz v1, :cond_7

    .line 116
    .line 117
    shl-int/lit8 v1, v6, 0xa

    .line 118
    .line 119
    or-int/2addr v1, v9

    .line 120
    add-int/lit8 v1, v1, 0x1

    .line 121
    .line 122
    shl-int/lit8 v5, v5, 0xf

    .line 123
    .line 124
    or-int/2addr v1, v5

    .line 125
    :goto_1
    int-to-short v1, v1

    .line 126
    goto :goto_3

    .line 127
    :cond_7
    move v1, v9

    .line 128
    :goto_2
    shl-int/lit8 v5, v5, 0xf

    .line 129
    .line 130
    shl-int/lit8 v6, v6, 0xa

    .line 131
    .line 132
    or-int/2addr v5, v6

    .line 133
    or-int/2addr v1, v5

    .line 134
    goto :goto_1

    .line 135
    :goto_3
    invoke-static/range {p1 .. p1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 136
    .line 137
    .line 138
    move-result v5

    .line 139
    ushr-int/lit8 v6, v5, 0x1f

    .line 140
    .line 141
    ushr-int/lit8 v9, v5, 0x17

    .line 142
    .line 143
    and-int/2addr v9, v7

    .line 144
    and-int v16, v5, v8

    .line 145
    .line 146
    if-ne v9, v7, :cond_9

    .line 147
    .line 148
    if-eqz v16, :cond_8

    .line 149
    .line 150
    move v5, v13

    .line 151
    goto :goto_4

    .line 152
    :cond_8
    move v5, v14

    .line 153
    :goto_4
    move v9, v15

    .line 154
    goto :goto_6

    .line 155
    :cond_9
    add-int/lit8 v9, v9, -0x70

    .line 156
    .line 157
    if-lt v9, v15, :cond_a

    .line 158
    .line 159
    move v9, v12

    .line 160
    move v5, v14

    .line 161
    goto :goto_6

    .line 162
    :cond_a
    if-gtz v9, :cond_d

    .line 163
    .line 164
    if-lt v9, v11, :cond_c

    .line 165
    .line 166
    or-int v5, v16, v10

    .line 167
    .line 168
    rsub-int/lit8 v9, v9, 0x1

    .line 169
    .line 170
    shr-int/2addr v5, v9

    .line 171
    and-int/lit16 v9, v5, 0x1000

    .line 172
    .line 173
    if-eqz v9, :cond_b

    .line 174
    .line 175
    add-int/lit16 v5, v5, 0x2000

    .line 176
    .line 177
    :cond_b
    shr-int/lit8 v5, v5, 0xd

    .line 178
    .line 179
    move v9, v14

    .line 180
    goto :goto_6

    .line 181
    :cond_c
    move v5, v14

    .line 182
    move v9, v5

    .line 183
    goto :goto_6

    .line 184
    :cond_d
    shr-int/lit8 v16, v16, 0xd

    .line 185
    .line 186
    and-int/lit16 v5, v5, 0x1000

    .line 187
    .line 188
    if-eqz v5, :cond_e

    .line 189
    .line 190
    shl-int/lit8 v5, v9, 0xa

    .line 191
    .line 192
    or-int v5, v5, v16

    .line 193
    .line 194
    add-int/lit8 v5, v5, 0x1

    .line 195
    .line 196
    shl-int/lit8 v6, v6, 0xf

    .line 197
    .line 198
    or-int/2addr v5, v6

    .line 199
    :goto_5
    int-to-short v5, v5

    .line 200
    goto :goto_7

    .line 201
    :cond_e
    move/from16 v5, v16

    .line 202
    .line 203
    :goto_6
    shl-int/lit8 v6, v6, 0xf

    .line 204
    .line 205
    shl-int/lit8 v9, v9, 0xa

    .line 206
    .line 207
    or-int/2addr v6, v9

    .line 208
    or-int/2addr v5, v6

    .line 209
    goto :goto_5

    .line 210
    :goto_7
    invoke-static/range {p2 .. p2}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 211
    .line 212
    .line 213
    move-result v6

    .line 214
    ushr-int/lit8 v9, v6, 0x1f

    .line 215
    .line 216
    move/from16 v16, v2

    .line 217
    .line 218
    ushr-int/lit8 v2, v6, 0x17

    .line 219
    .line 220
    and-int/2addr v2, v7

    .line 221
    and-int/2addr v8, v6

    .line 222
    if-ne v2, v7, :cond_10

    .line 223
    .line 224
    if-eqz v8, :cond_f

    .line 225
    .line 226
    goto :goto_8

    .line 227
    :cond_f
    move v13, v14

    .line 228
    :goto_8
    move v14, v13

    .line 229
    move v12, v15

    .line 230
    goto :goto_a

    .line 231
    :cond_10
    add-int/lit8 v2, v2, -0x70

    .line 232
    .line 233
    if-lt v2, v15, :cond_11

    .line 234
    .line 235
    goto :goto_a

    .line 236
    :cond_11
    if-gtz v2, :cond_14

    .line 237
    .line 238
    if-lt v2, v11, :cond_13

    .line 239
    .line 240
    or-int v6, v8, v10

    .line 241
    .line 242
    rsub-int/lit8 v2, v2, 0x1

    .line 243
    .line 244
    shr-int v2, v6, v2

    .line 245
    .line 246
    and-int/lit16 v6, v2, 0x1000

    .line 247
    .line 248
    if-eqz v6, :cond_12

    .line 249
    .line 250
    add-int/lit16 v2, v2, 0x2000

    .line 251
    .line 252
    :cond_12
    shr-int/lit8 v2, v2, 0xd

    .line 253
    .line 254
    move v12, v14

    .line 255
    move v14, v2

    .line 256
    goto :goto_a

    .line 257
    :cond_13
    move v12, v14

    .line 258
    goto :goto_a

    .line 259
    :cond_14
    shr-int/lit8 v14, v8, 0xd

    .line 260
    .line 261
    and-int/lit16 v6, v6, 0x1000

    .line 262
    .line 263
    if-eqz v6, :cond_15

    .line 264
    .line 265
    shl-int/lit8 v2, v2, 0xa

    .line 266
    .line 267
    or-int/2addr v2, v14

    .line 268
    add-int/lit8 v2, v2, 0x1

    .line 269
    .line 270
    shl-int/lit8 v6, v9, 0xf

    .line 271
    .line 272
    or-int/2addr v2, v6

    .line 273
    :goto_9
    int-to-short v2, v2

    .line 274
    goto :goto_b

    .line 275
    :cond_15
    move v12, v2

    .line 276
    :goto_a
    shl-int/lit8 v2, v9, 0xf

    .line 277
    .line 278
    shl-int/lit8 v6, v12, 0xa

    .line 279
    .line 280
    or-int/2addr v2, v6

    .line 281
    or-int/2addr v2, v14

    .line 282
    goto :goto_9

    .line 283
    :goto_b
    const/high16 v6, 0x3f800000    # 1.0f

    .line 284
    .line 285
    invoke-static {v0, v6}, Ljava/lang/Math;->min(FF)F

    .line 286
    .line 287
    .line 288
    move-result v0

    .line 289
    const/4 v6, 0x0

    .line 290
    invoke-static {v6, v0}, Ljava/lang/Math;->max(FF)F

    .line 291
    .line 292
    .line 293
    move-result v0

    .line 294
    const v6, 0x447fc000    # 1023.0f

    .line 295
    .line 296
    .line 297
    mul-float/2addr v0, v6

    .line 298
    add-float/2addr v0, v4

    .line 299
    float-to-int v0, v0

    .line 300
    move-object/from16 v4, p4

    .line 301
    .line 302
    iget v4, v4, Lf3/c;->c:I

    .line 303
    .line 304
    int-to-long v6, v1

    .line 305
    const-wide/32 v8, 0xffff

    .line 306
    .line 307
    .line 308
    and-long/2addr v6, v8

    .line 309
    const/16 v1, 0x30

    .line 310
    .line 311
    shl-long/2addr v6, v1

    .line 312
    int-to-long v10, v5

    .line 313
    and-long/2addr v10, v8

    .line 314
    shl-long v10, v10, v16

    .line 315
    .line 316
    or-long v5, v6, v10

    .line 317
    .line 318
    int-to-long v1, v2

    .line 319
    and-long/2addr v1, v8

    .line 320
    shl-long/2addr v1, v3

    .line 321
    or-long/2addr v1, v5

    .line 322
    int-to-long v5, v0

    .line 323
    const-wide/16 v7, 0x3ff

    .line 324
    .line 325
    and-long/2addr v5, v7

    .line 326
    const/4 v0, 0x6

    .line 327
    shl-long/2addr v5, v0

    .line 328
    or-long v0, v1, v5

    .line 329
    .line 330
    int-to-long v2, v4

    .line 331
    const-wide/16 v4, 0x3f

    .line 332
    .line 333
    and-long/2addr v2, v4

    .line 334
    or-long/2addr v0, v2

    .line 335
    sget v2, Le3/s;->j:I

    .line 336
    .line 337
    return-wide v0
.end method

.method public static final k(Le3/f;)Landroid/graphics/Bitmap;
    .locals 1

    .line 1
    instance-of v0, p0, Le3/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Le3/f;->a:Landroid/graphics/Bitmap;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 9
    .line 10
    const-string v0, "Unable to obtain android.graphics.Bitmap"

    .line 11
    .line 12
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    throw p0
.end method

.method public static final l(JJ)J
    .locals 9

    .line 1
    invoke-static {p2, p3}, Le3/s;->f(J)Lf3/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-static {p0, p1, v0}, Le3/s;->a(JLf3/c;)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {p2, p3}, Le3/s;->d(J)F

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    const/high16 v2, 0x3f800000    # 1.0f

    .line 18
    .line 19
    sub-float/2addr v2, v1

    .line 20
    mul-float v3, v0, v2

    .line 21
    .line 22
    add-float/2addr v3, v1

    .line 23
    invoke-static {p0, p1}, Le3/s;->h(J)F

    .line 24
    .line 25
    .line 26
    move-result v4

    .line 27
    invoke-static {p2, p3}, Le3/s;->h(J)F

    .line 28
    .line 29
    .line 30
    move-result v5

    .line 31
    const/4 v6, 0x0

    .line 32
    cmpg-float v7, v3, v6

    .line 33
    .line 34
    if-nez v7, :cond_0

    .line 35
    .line 36
    move v5, v6

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    mul-float/2addr v4, v1

    .line 39
    mul-float/2addr v5, v0

    .line 40
    mul-float/2addr v5, v2

    .line 41
    add-float/2addr v5, v4

    .line 42
    div-float/2addr v5, v3

    .line 43
    :goto_0
    invoke-static {p0, p1}, Le3/s;->g(J)F

    .line 44
    .line 45
    .line 46
    move-result v4

    .line 47
    invoke-static {p2, p3}, Le3/s;->g(J)F

    .line 48
    .line 49
    .line 50
    move-result v8

    .line 51
    if-nez v7, :cond_1

    .line 52
    .line 53
    move v8, v6

    .line 54
    goto :goto_1

    .line 55
    :cond_1
    mul-float/2addr v4, v1

    .line 56
    mul-float/2addr v8, v0

    .line 57
    mul-float/2addr v8, v2

    .line 58
    add-float/2addr v8, v4

    .line 59
    div-float/2addr v8, v3

    .line 60
    :goto_1
    invoke-static {p0, p1}, Le3/s;->e(J)F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    invoke-static {p2, p3}, Le3/s;->e(J)F

    .line 65
    .line 66
    .line 67
    move-result p1

    .line 68
    if-nez v7, :cond_2

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_2
    mul-float/2addr p0, v1

    .line 72
    mul-float/2addr p1, v0

    .line 73
    mul-float/2addr p1, v2

    .line 74
    add-float/2addr p1, p0

    .line 75
    div-float v6, p1, v3

    .line 76
    .line 77
    :goto_2
    invoke-static {p2, p3}, Le3/s;->f(J)Lf3/c;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    invoke-static {v5, v8, v6, v3, p0}, Le3/j0;->j(FFFFLf3/c;)J

    .line 82
    .line 83
    .line 84
    move-result-wide p0

    .line 85
    return-wide p0
.end method

.method public static final m(Le3/r;Le3/g0;Le3/g;)V
    .locals 13

    .line 1
    instance-of v0, p1, Le3/e0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Le3/e0;

    .line 6
    .line 7
    iget-object p1, p1, Le3/e0;->a:Ld3/c;

    .line 8
    .line 9
    iget v1, p1, Ld3/c;->a:F

    .line 10
    .line 11
    iget v2, p1, Ld3/c;->b:F

    .line 12
    .line 13
    iget v3, p1, Ld3/c;->c:F

    .line 14
    .line 15
    iget v4, p1, Ld3/c;->d:F

    .line 16
    .line 17
    move-object v0, p0

    .line 18
    move-object v5, p2

    .line 19
    invoke-interface/range {v0 .. v5}, Le3/r;->r(FFFFLe3/g;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    move-object v0, p0

    .line 24
    move-object v5, p2

    .line 25
    instance-of p0, p1, Le3/f0;

    .line 26
    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    check-cast p1, Le3/f0;

    .line 30
    .line 31
    iget-object p0, p1, Le3/f0;->a:Ld3/d;

    .line 32
    .line 33
    iget-wide v1, p0, Ld3/d;->h:J

    .line 34
    .line 35
    iget-object p1, p1, Le3/f0;->b:Le3/i;

    .line 36
    .line 37
    if-eqz p1, :cond_1

    .line 38
    .line 39
    invoke-interface {v0, p1, v5}, Le3/r;->s(Le3/i;Le3/g;)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_1
    iget v6, p0, Ld3/d;->a:F

    .line 44
    .line 45
    iget v7, p0, Ld3/d;->b:F

    .line 46
    .line 47
    iget v8, p0, Ld3/d;->c:F

    .line 48
    .line 49
    iget v9, p0, Ld3/d;->d:F

    .line 50
    .line 51
    const/16 p0, 0x20

    .line 52
    .line 53
    shr-long p0, v1, p0

    .line 54
    .line 55
    long-to-int p0, p0

    .line 56
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 57
    .line 58
    .line 59
    move-result v10

    .line 60
    const-wide p0, 0xffffffffL

    .line 61
    .line 62
    .line 63
    .line 64
    .line 65
    and-long/2addr p0, v1

    .line 66
    long-to-int p0, p0

    .line 67
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 68
    .line 69
    .line 70
    move-result v11

    .line 71
    move-object v12, v5

    .line 72
    move-object v5, v0

    .line 73
    invoke-interface/range {v5 .. v12}, Le3/r;->b(FFFFFFLe3/g;)V

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :cond_2
    instance-of p0, p1, Le3/d0;

    .line 78
    .line 79
    if-eqz p0, :cond_3

    .line 80
    .line 81
    check-cast p1, Le3/d0;

    .line 82
    .line 83
    iget-object p0, p1, Le3/d0;->a:Le3/i;

    .line 84
    .line 85
    invoke-interface {v0, p0, v5}, Le3/r;->s(Le3/i;Le3/g;)V

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :cond_3
    new-instance p0, La8/r0;

    .line 90
    .line 91
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 92
    .line 93
    .line 94
    throw p0
.end method

.method public static n(Lg3/d;Le3/g0;Le3/p;F)V
    .locals 15

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    instance-of v1, v0, Le3/e0;

    .line 4
    .line 5
    const-wide v2, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    const/16 v4, 0x20

    .line 11
    .line 12
    sget-object v9, Lg3/g;->a:Lg3/g;

    .line 13
    .line 14
    const/4 v10, 0x3

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    check-cast v0, Le3/e0;

    .line 18
    .line 19
    iget-object v0, v0, Le3/e0;->a:Ld3/c;

    .line 20
    .line 21
    iget v1, v0, Ld3/c;->a:F

    .line 22
    .line 23
    iget v5, v0, Ld3/c;->b:F

    .line 24
    .line 25
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 26
    .line 27
    .line 28
    move-result v1

    .line 29
    int-to-long v6, v1

    .line 30
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 31
    .line 32
    .line 33
    move-result v1

    .line 34
    int-to-long v11, v1

    .line 35
    shl-long v4, v6, v4

    .line 36
    .line 37
    and-long v1, v11, v2

    .line 38
    .line 39
    or-long v7, v4, v1

    .line 40
    .line 41
    invoke-static {v0}, Le3/j0;->t(Ld3/c;)J

    .line 42
    .line 43
    .line 44
    move-result-wide v0

    .line 45
    move-object v5, p0

    .line 46
    move-object/from16 v6, p2

    .line 47
    .line 48
    move/from16 v11, p3

    .line 49
    .line 50
    move-object v12, v9

    .line 51
    move v13, v10

    .line 52
    move-wide v9, v0

    .line 53
    invoke-interface/range {v5 .. v13}, Lg3/d;->f0(Le3/p;JJFLg3/e;I)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_0
    instance-of v1, v0, Le3/f0;

    .line 58
    .line 59
    if-eqz v1, :cond_2

    .line 60
    .line 61
    check-cast v0, Le3/f0;

    .line 62
    .line 63
    iget-object v6, v0, Le3/f0;->b:Le3/i;

    .line 64
    .line 65
    if-eqz v6, :cond_1

    .line 66
    .line 67
    move-object v5, p0

    .line 68
    move-object/from16 v7, p2

    .line 69
    .line 70
    move/from16 v8, p3

    .line 71
    .line 72
    invoke-interface/range {v5 .. v10}, Lg3/d;->H(Le3/i;Le3/p;FLg3/e;I)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_1
    iget-object v0, v0, Le3/f0;->a:Ld3/d;

    .line 77
    .line 78
    iget-wide v5, v0, Ld3/d;->h:J

    .line 79
    .line 80
    shr-long/2addr v5, v4

    .line 81
    long-to-int v1, v5

    .line 82
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 83
    .line 84
    .line 85
    move-result v1

    .line 86
    iget v5, v0, Ld3/d;->a:F

    .line 87
    .line 88
    iget v6, v0, Ld3/d;->b:F

    .line 89
    .line 90
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 91
    .line 92
    .line 93
    move-result v5

    .line 94
    int-to-long v7, v5

    .line 95
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 96
    .line 97
    .line 98
    move-result v5

    .line 99
    int-to-long v5, v5

    .line 100
    shl-long/2addr v7, v4

    .line 101
    and-long/2addr v5, v2

    .line 102
    or-long/2addr v7, v5

    .line 103
    invoke-virtual {v0}, Ld3/d;->b()F

    .line 104
    .line 105
    .line 106
    move-result v5

    .line 107
    invoke-virtual {v0}, Ld3/d;->a()F

    .line 108
    .line 109
    .line 110
    move-result v0

    .line 111
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 112
    .line 113
    .line 114
    move-result v5

    .line 115
    int-to-long v5, v5

    .line 116
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 117
    .line 118
    .line 119
    move-result v0

    .line 120
    int-to-long v10, v0

    .line 121
    shl-long/2addr v5, v4

    .line 122
    and-long/2addr v10, v2

    .line 123
    or-long/2addr v5, v10

    .line 124
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    int-to-long v10, v0

    .line 129
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 130
    .line 131
    .line 132
    move-result v0

    .line 133
    int-to-long v0, v0

    .line 134
    shl-long/2addr v10, v4

    .line 135
    and-long/2addr v0, v2

    .line 136
    or-long v11, v10, v0

    .line 137
    .line 138
    move/from16 v13, p3

    .line 139
    .line 140
    move-object v14, v9

    .line 141
    move-wide v9, v5

    .line 142
    move-object v5, p0

    .line 143
    move-object/from16 v6, p2

    .line 144
    .line 145
    invoke-interface/range {v5 .. v14}, Lg3/d;->k0(Le3/p;JJJFLg3/e;)V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_2
    instance-of v1, v0, Le3/d0;

    .line 150
    .line 151
    if-eqz v1, :cond_3

    .line 152
    .line 153
    check-cast v0, Le3/d0;

    .line 154
    .line 155
    iget-object v6, v0, Le3/d0;->a:Le3/i;

    .line 156
    .line 157
    move-object v5, p0

    .line 158
    move-object/from16 v7, p2

    .line 159
    .line 160
    move/from16 v8, p3

    .line 161
    .line 162
    invoke-interface/range {v5 .. v10}, Lg3/d;->H(Le3/i;Le3/p;FLg3/e;I)V

    .line 163
    .line 164
    .line 165
    return-void

    .line 166
    :cond_3
    new-instance p0, La8/r0;

    .line 167
    .line 168
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 169
    .line 170
    .line 171
    throw p0
.end method

.method public static o(Lg3/d;Le3/g0;J)V
    .locals 20

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    instance-of v1, v0, Le3/e0;

    .line 4
    .line 5
    const-wide v2, 0xffffffffL

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    const/16 v4, 0x20

    .line 11
    .line 12
    const/high16 v9, 0x3f800000    # 1.0f

    .line 13
    .line 14
    sget-object v10, Lg3/g;->a:Lg3/g;

    .line 15
    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    check-cast v0, Le3/e0;

    .line 19
    .line 20
    iget-object v0, v0, Le3/e0;->a:Ld3/c;

    .line 21
    .line 22
    iget v1, v0, Ld3/c;->a:F

    .line 23
    .line 24
    iget v5, v0, Ld3/c;->b:F

    .line 25
    .line 26
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    int-to-long v6, v1

    .line 31
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    int-to-long v11, v1

    .line 36
    shl-long v4, v6, v4

    .line 37
    .line 38
    and-long v1, v11, v2

    .line 39
    .line 40
    or-long/2addr v1, v4

    .line 41
    invoke-static {v0}, Le3/j0;->t(Ld3/c;)J

    .line 42
    .line 43
    .line 44
    move-result-wide v3

    .line 45
    const/4 v14, 0x0

    .line 46
    const/4 v15, 0x3

    .line 47
    move-object/from16 v5, p0

    .line 48
    .line 49
    move-wide/from16 v6, p2

    .line 50
    .line 51
    move v12, v9

    .line 52
    move-object v13, v10

    .line 53
    move-wide v8, v1

    .line 54
    move-wide v10, v3

    .line 55
    invoke-interface/range {v5 .. v15}, Lg3/d;->M(JJJFLg3/e;Le3/m;I)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_0
    instance-of v1, v0, Le3/f0;

    .line 60
    .line 61
    if-eqz v1, :cond_2

    .line 62
    .line 63
    check-cast v0, Le3/f0;

    .line 64
    .line 65
    iget-object v6, v0, Le3/f0;->b:Le3/i;

    .line 66
    .line 67
    if-eqz v6, :cond_1

    .line 68
    .line 69
    move-object/from16 v5, p0

    .line 70
    .line 71
    move-wide/from16 v7, p2

    .line 72
    .line 73
    invoke-interface/range {v5 .. v10}, Lg3/d;->s0(Le3/i;JFLg3/e;)V

    .line 74
    .line 75
    .line 76
    return-void

    .line 77
    :cond_1
    iget-object v0, v0, Le3/f0;->a:Ld3/d;

    .line 78
    .line 79
    iget-wide v5, v0, Ld3/d;->h:J

    .line 80
    .line 81
    shr-long/2addr v5, v4

    .line 82
    long-to-int v1, v5

    .line 83
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    iget v5, v0, Ld3/d;->a:F

    .line 88
    .line 89
    iget v6, v0, Ld3/d;->b:F

    .line 90
    .line 91
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 92
    .line 93
    .line 94
    move-result v5

    .line 95
    int-to-long v7, v5

    .line 96
    invoke-static {v6}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 97
    .line 98
    .line 99
    move-result v5

    .line 100
    int-to-long v5, v5

    .line 101
    shl-long/2addr v7, v4

    .line 102
    and-long/2addr v5, v2

    .line 103
    or-long v13, v7, v5

    .line 104
    .line 105
    invoke-virtual {v0}, Ld3/d;->b()F

    .line 106
    .line 107
    .line 108
    move-result v5

    .line 109
    invoke-virtual {v0}, Ld3/d;->a()F

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    invoke-static {v5}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 114
    .line 115
    .line 116
    move-result v5

    .line 117
    int-to-long v5, v5

    .line 118
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    int-to-long v7, v0

    .line 123
    shl-long/2addr v5, v4

    .line 124
    and-long/2addr v7, v2

    .line 125
    or-long v15, v5, v7

    .line 126
    .line 127
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 128
    .line 129
    .line 130
    move-result v0

    .line 131
    int-to-long v5, v0

    .line 132
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    int-to-long v0, v0

    .line 137
    shl-long v4, v5, v4

    .line 138
    .line 139
    and-long/2addr v0, v2

    .line 140
    or-long v17, v4, v0

    .line 141
    .line 142
    move-wide/from16 v11, p2

    .line 143
    .line 144
    move-object/from16 v19, v10

    .line 145
    .line 146
    move-object/from16 v10, p0

    .line 147
    .line 148
    invoke-interface/range {v10 .. v19}, Lg3/d;->U(JJJJLg3/e;)V

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :cond_2
    instance-of v1, v0, Le3/d0;

    .line 153
    .line 154
    if-eqz v1, :cond_3

    .line 155
    .line 156
    check-cast v0, Le3/d0;

    .line 157
    .line 158
    iget-object v6, v0, Le3/d0;->a:Le3/i;

    .line 159
    .line 160
    move-object/from16 v5, p0

    .line 161
    .line 162
    move-wide/from16 v7, p2

    .line 163
    .line 164
    invoke-interface/range {v5 .. v10}, Lg3/d;->s0(Le3/i;JFLg3/e;)V

    .line 165
    .line 166
    .line 167
    return-void

    .line 168
    :cond_3
    new-instance v0, La8/r0;

    .line 169
    .line 170
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 171
    .line 172
    .line 173
    throw v0
.end method

.method public static final p([F)Z
    .locals 5

    .line 1
    array-length v0, p0

    .line 2
    const/16 v1, 0x10

    .line 3
    .line 4
    const/4 v2, 0x0

    .line 5
    if-ge v0, v1, :cond_0

    .line 6
    .line 7
    return v2

    .line 8
    :cond_0
    aget v0, p0, v2

    .line 9
    .line 10
    const/high16 v1, 0x3f800000    # 1.0f

    .line 11
    .line 12
    cmpg-float v0, v0, v1

    .line 13
    .line 14
    if-nez v0, :cond_1

    .line 15
    .line 16
    const/4 v0, 0x1

    .line 17
    aget v3, p0, v0

    .line 18
    .line 19
    const/4 v4, 0x0

    .line 20
    cmpg-float v3, v3, v4

    .line 21
    .line 22
    if-nez v3, :cond_1

    .line 23
    .line 24
    const/4 v3, 0x2

    .line 25
    aget v3, p0, v3

    .line 26
    .line 27
    cmpg-float v3, v3, v4

    .line 28
    .line 29
    if-nez v3, :cond_1

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    aget v3, p0, v3

    .line 33
    .line 34
    cmpg-float v3, v3, v4

    .line 35
    .line 36
    if-nez v3, :cond_1

    .line 37
    .line 38
    const/4 v3, 0x4

    .line 39
    aget v3, p0, v3

    .line 40
    .line 41
    cmpg-float v3, v3, v4

    .line 42
    .line 43
    if-nez v3, :cond_1

    .line 44
    .line 45
    const/4 v3, 0x5

    .line 46
    aget v3, p0, v3

    .line 47
    .line 48
    cmpg-float v3, v3, v1

    .line 49
    .line 50
    if-nez v3, :cond_1

    .line 51
    .line 52
    const/4 v3, 0x6

    .line 53
    aget v3, p0, v3

    .line 54
    .line 55
    cmpg-float v3, v3, v4

    .line 56
    .line 57
    if-nez v3, :cond_1

    .line 58
    .line 59
    const/4 v3, 0x7

    .line 60
    aget v3, p0, v3

    .line 61
    .line 62
    cmpg-float v3, v3, v4

    .line 63
    .line 64
    if-nez v3, :cond_1

    .line 65
    .line 66
    const/16 v3, 0x8

    .line 67
    .line 68
    aget v3, p0, v3

    .line 69
    .line 70
    cmpg-float v3, v3, v4

    .line 71
    .line 72
    if-nez v3, :cond_1

    .line 73
    .line 74
    const/16 v3, 0x9

    .line 75
    .line 76
    aget v3, p0, v3

    .line 77
    .line 78
    cmpg-float v3, v3, v4

    .line 79
    .line 80
    if-nez v3, :cond_1

    .line 81
    .line 82
    const/16 v3, 0xa

    .line 83
    .line 84
    aget v3, p0, v3

    .line 85
    .line 86
    cmpg-float v3, v3, v1

    .line 87
    .line 88
    if-nez v3, :cond_1

    .line 89
    .line 90
    const/16 v3, 0xb

    .line 91
    .line 92
    aget v3, p0, v3

    .line 93
    .line 94
    cmpg-float v3, v3, v4

    .line 95
    .line 96
    if-nez v3, :cond_1

    .line 97
    .line 98
    const/16 v3, 0xc

    .line 99
    .line 100
    aget v3, p0, v3

    .line 101
    .line 102
    cmpg-float v3, v3, v4

    .line 103
    .line 104
    if-nez v3, :cond_1

    .line 105
    .line 106
    const/16 v3, 0xd

    .line 107
    .line 108
    aget v3, p0, v3

    .line 109
    .line 110
    cmpg-float v3, v3, v4

    .line 111
    .line 112
    if-nez v3, :cond_1

    .line 113
    .line 114
    const/16 v3, 0xe

    .line 115
    .line 116
    aget v3, p0, v3

    .line 117
    .line 118
    cmpg-float v3, v3, v4

    .line 119
    .line 120
    if-nez v3, :cond_1

    .line 121
    .line 122
    const/16 v3, 0xf

    .line 123
    .line 124
    aget p0, p0, v3

    .line 125
    .line 126
    cmpg-float p0, p0, v1

    .line 127
    .line 128
    if-nez p0, :cond_1

    .line 129
    .line 130
    return v0

    .line 131
    :cond_1
    return v2
.end method

.method public static final q(JJF)J
    .locals 9

    .line 1
    sget-object v0, Lf3/e;->x:Lf3/m;

    .line 2
    .line 3
    invoke-static {p0, p1, v0}, Le3/s;->a(JLf3/c;)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    invoke-static {p2, p3, v0}, Le3/s;->a(JLf3/c;)J

    .line 8
    .line 9
    .line 10
    move-result-wide v1

    .line 11
    invoke-static {p0, p1}, Le3/s;->d(J)F

    .line 12
    .line 13
    .line 14
    move-result v3

    .line 15
    invoke-static {p0, p1}, Le3/s;->h(J)F

    .line 16
    .line 17
    .line 18
    move-result v4

    .line 19
    invoke-static {p0, p1}, Le3/s;->g(J)F

    .line 20
    .line 21
    .line 22
    move-result v5

    .line 23
    invoke-static {p0, p1}, Le3/s;->e(J)F

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    invoke-static {v1, v2}, Le3/s;->d(J)F

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-static {v1, v2}, Le3/s;->h(J)F

    .line 32
    .line 33
    .line 34
    move-result v6

    .line 35
    invoke-static {v1, v2}, Le3/s;->g(J)F

    .line 36
    .line 37
    .line 38
    move-result v7

    .line 39
    invoke-static {v1, v2}, Le3/s;->e(J)F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    const/4 v2, 0x0

    .line 44
    cmpg-float v8, p4, v2

    .line 45
    .line 46
    if-gez v8, :cond_0

    .line 47
    .line 48
    move p4, v2

    .line 49
    :cond_0
    const/high16 v2, 0x3f800000    # 1.0f

    .line 50
    .line 51
    cmpl-float v8, p4, v2

    .line 52
    .line 53
    if-lez v8, :cond_1

    .line 54
    .line 55
    move p4, v2

    .line 56
    :cond_1
    invoke-static {v4, v6, p4}, Llp/wa;->b(FFF)F

    .line 57
    .line 58
    .line 59
    move-result v2

    .line 60
    invoke-static {v5, v7, p4}, Llp/wa;->b(FFF)F

    .line 61
    .line 62
    .line 63
    move-result v4

    .line 64
    invoke-static {p0, v1, p4}, Llp/wa;->b(FFF)F

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    invoke-static {v3, p1, p4}, Llp/wa;->b(FFF)F

    .line 69
    .line 70
    .line 71
    move-result p1

    .line 72
    invoke-static {v2, v4, p0, p1, v0}, Le3/j0;->j(FFFFLf3/c;)J

    .line 73
    .line 74
    .line 75
    move-result-wide p0

    .line 76
    invoke-static {p2, p3}, Le3/s;->f(J)Lf3/c;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    invoke-static {p0, p1, p2}, Le3/s;->a(JLf3/c;)J

    .line 81
    .line 82
    .line 83
    move-result-wide p0

    .line 84
    return-wide p0
.end method

.method public static final r(J)F
    .locals 7

    .line 1
    invoke-static {p0, p1}, Le3/s;->f(J)Lf3/c;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-wide v1, v0, Lf3/c;->b:J

    .line 6
    .line 7
    sget-wide v3, Lf3/b;->a:J

    .line 8
    .line 9
    invoke-static {v1, v2, v3, v4}, Lf3/b;->a(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    if-nez v1, :cond_0

    .line 14
    .line 15
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v2, "The specified color must be encoded in an RGB color space. The supplied color space is "

    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-wide v2, v0, Lf3/c;->b:J

    .line 23
    .line 24
    invoke-static {v2, v3}, Lf3/b;->b(J)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-static {v1}, Le3/a0;->a(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    :cond_0
    check-cast v0, Lf3/r;

    .line 39
    .line 40
    iget-object v0, v0, Lf3/r;->p:Lf3/n;

    .line 41
    .line 42
    invoke-static {p0, p1}, Le3/s;->h(J)F

    .line 43
    .line 44
    .line 45
    move-result v1

    .line 46
    float-to-double v1, v1

    .line 47
    invoke-virtual {v0, v1, v2}, Lf3/n;->h(D)D

    .line 48
    .line 49
    .line 50
    move-result-wide v1

    .line 51
    invoke-static {p0, p1}, Le3/s;->g(J)F

    .line 52
    .line 53
    .line 54
    move-result v3

    .line 55
    float-to-double v3, v3

    .line 56
    invoke-virtual {v0, v3, v4}, Lf3/n;->h(D)D

    .line 57
    .line 58
    .line 59
    move-result-wide v3

    .line 60
    invoke-static {p0, p1}, Le3/s;->e(J)F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    float-to-double p0, p0

    .line 65
    invoke-virtual {v0, p0, p1}, Lf3/n;->h(D)D

    .line 66
    .line 67
    .line 68
    move-result-wide p0

    .line 69
    const-wide v5, 0x3fcb367a0f9096bcL    # 0.2126

    .line 70
    .line 71
    .line 72
    .line 73
    .line 74
    mul-double/2addr v1, v5

    .line 75
    const-wide v5, 0x3fe6e2eb1c432ca5L    # 0.7152

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    mul-double/2addr v3, v5

    .line 81
    add-double/2addr v3, v1

    .line 82
    const-wide v0, 0x3fb27bb2fec56d5dL    # 0.0722

    .line 83
    .line 84
    .line 85
    .line 86
    .line 87
    mul-double/2addr p0, v0

    .line 88
    add-double/2addr p0, v3

    .line 89
    double-to-float p0, p0

    .line 90
    const/4 p1, 0x0

    .line 91
    cmpg-float v0, p0, p1

    .line 92
    .line 93
    if-gez v0, :cond_1

    .line 94
    .line 95
    move p0, p1

    .line 96
    :cond_1
    const/high16 p1, 0x3f800000    # 1.0f

    .line 97
    .line 98
    cmpl-float v0, p0, p1

    .line 99
    .line 100
    if-lez v0, :cond_2

    .line 101
    .line 102
    return p1

    .line 103
    :cond_2
    return p0
.end method

.method public static final s(Landroid/graphics/Matrix;[F)V
    .locals 21

    .line 1
    const/4 v0, 0x0

    .line 2
    aget v1, p1, v0

    .line 3
    .line 4
    const/4 v2, 0x1

    .line 5
    aget v3, p1, v2

    .line 6
    .line 7
    const/4 v4, 0x2

    .line 8
    aget v5, p1, v4

    .line 9
    .line 10
    const/4 v6, 0x3

    .line 11
    aget v7, p1, v6

    .line 12
    .line 13
    const/4 v8, 0x4

    .line 14
    aget v9, p1, v8

    .line 15
    .line 16
    const/4 v10, 0x5

    .line 17
    aget v11, p1, v10

    .line 18
    .line 19
    const/4 v12, 0x6

    .line 20
    aget v13, p1, v12

    .line 21
    .line 22
    const/4 v14, 0x7

    .line 23
    aget v15, p1, v14

    .line 24
    .line 25
    const/16 v16, 0x8

    .line 26
    .line 27
    aget v17, p1, v16

    .line 28
    .line 29
    const/16 v18, 0xc

    .line 30
    .line 31
    aget v18, p1, v18

    .line 32
    .line 33
    const/16 v19, 0xd

    .line 34
    .line 35
    aget v19, p1, v19

    .line 36
    .line 37
    const/16 v20, 0xf

    .line 38
    .line 39
    aget v20, p1, v20

    .line 40
    .line 41
    aput v1, p1, v0

    .line 42
    .line 43
    aput v9, p1, v2

    .line 44
    .line 45
    aput v18, p1, v4

    .line 46
    .line 47
    aput v3, p1, v6

    .line 48
    .line 49
    aput v11, p1, v8

    .line 50
    .line 51
    aput v19, p1, v10

    .line 52
    .line 53
    aput v7, p1, v12

    .line 54
    .line 55
    aput v15, p1, v14

    .line 56
    .line 57
    aput v20, p1, v16

    .line 58
    .line 59
    invoke-virtual/range {p0 .. p1}, Landroid/graphics/Matrix;->setValues([F)V

    .line 60
    .line 61
    .line 62
    aput v1, p1, v0

    .line 63
    .line 64
    aput v3, p1, v2

    .line 65
    .line 66
    aput v5, p1, v4

    .line 67
    .line 68
    aput v7, p1, v6

    .line 69
    .line 70
    aput v9, p1, v8

    .line 71
    .line 72
    aput v11, p1, v10

    .line 73
    .line 74
    aput v13, p1, v12

    .line 75
    .line 76
    aput v15, p1, v14

    .line 77
    .line 78
    aput v17, p1, v16

    .line 79
    .line 80
    return-void
.end method

.method public static final t(Ld3/c;)J
    .locals 6

    .line 1
    iget v0, p0, Ld3/c;->c:F

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    sub-float/2addr v0, v1

    .line 6
    iget v1, p0, Ld3/c;->d:F

    .line 7
    .line 8
    iget p0, p0, Ld3/c;->b:F

    .line 9
    .line 10
    sub-float/2addr v1, p0

    .line 11
    invoke-static {v0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    int-to-long v2, p0

    .line 16
    invoke-static {v1}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    int-to-long v0, p0

    .line 21
    const/16 p0, 0x20

    .line 22
    .line 23
    shl-long/2addr v2, p0

    .line 24
    const-wide v4, 0xffffffffL

    .line 25
    .line 26
    .line 27
    .line 28
    .line 29
    and-long/2addr v0, v4

    .line 30
    or-long/2addr v0, v2

    .line 31
    return-wide v0
.end method

.method public static final u(I)Landroid/graphics/BlendMode;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Landroid/graphics/BlendMode;->CLEAR:Landroid/graphics/BlendMode;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    if-ne p0, v0, :cond_1

    .line 8
    .line 9
    sget-object p0, Landroid/graphics/BlendMode;->SRC:Landroid/graphics/BlendMode;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    const/4 v0, 0x2

    .line 13
    if-ne p0, v0, :cond_2

    .line 14
    .line 15
    sget-object p0, Landroid/graphics/BlendMode;->DST:Landroid/graphics/BlendMode;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_2
    const/4 v0, 0x3

    .line 19
    if-ne p0, v0, :cond_3

    .line 20
    .line 21
    sget-object p0, Landroid/graphics/BlendMode;->SRC_OVER:Landroid/graphics/BlendMode;

    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_3
    const/4 v0, 0x4

    .line 25
    if-ne p0, v0, :cond_4

    .line 26
    .line 27
    sget-object p0, Landroid/graphics/BlendMode;->DST_OVER:Landroid/graphics/BlendMode;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_4
    const/4 v0, 0x5

    .line 31
    if-ne p0, v0, :cond_5

    .line 32
    .line 33
    sget-object p0, Landroid/graphics/BlendMode;->SRC_IN:Landroid/graphics/BlendMode;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_5
    const/4 v0, 0x6

    .line 37
    if-ne p0, v0, :cond_6

    .line 38
    .line 39
    sget-object p0, Landroid/graphics/BlendMode;->DST_IN:Landroid/graphics/BlendMode;

    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_6
    const/4 v0, 0x7

    .line 43
    if-ne p0, v0, :cond_7

    .line 44
    .line 45
    sget-object p0, Landroid/graphics/BlendMode;->SRC_OUT:Landroid/graphics/BlendMode;

    .line 46
    .line 47
    return-object p0

    .line 48
    :cond_7
    const/16 v0, 0x8

    .line 49
    .line 50
    if-ne p0, v0, :cond_8

    .line 51
    .line 52
    sget-object p0, Landroid/graphics/BlendMode;->DST_OUT:Landroid/graphics/BlendMode;

    .line 53
    .line 54
    return-object p0

    .line 55
    :cond_8
    const/16 v0, 0x9

    .line 56
    .line 57
    if-ne p0, v0, :cond_9

    .line 58
    .line 59
    sget-object p0, Landroid/graphics/BlendMode;->SRC_ATOP:Landroid/graphics/BlendMode;

    .line 60
    .line 61
    return-object p0

    .line 62
    :cond_9
    const/16 v0, 0xa

    .line 63
    .line 64
    if-ne p0, v0, :cond_a

    .line 65
    .line 66
    sget-object p0, Landroid/graphics/BlendMode;->DST_ATOP:Landroid/graphics/BlendMode;

    .line 67
    .line 68
    return-object p0

    .line 69
    :cond_a
    const/16 v0, 0xb

    .line 70
    .line 71
    if-ne p0, v0, :cond_b

    .line 72
    .line 73
    sget-object p0, Landroid/graphics/BlendMode;->XOR:Landroid/graphics/BlendMode;

    .line 74
    .line 75
    return-object p0

    .line 76
    :cond_b
    const/16 v0, 0xc

    .line 77
    .line 78
    if-ne p0, v0, :cond_c

    .line 79
    .line 80
    sget-object p0, Landroid/graphics/BlendMode;->PLUS:Landroid/graphics/BlendMode;

    .line 81
    .line 82
    return-object p0

    .line 83
    :cond_c
    const/16 v0, 0xd

    .line 84
    .line 85
    if-ne p0, v0, :cond_d

    .line 86
    .line 87
    sget-object p0, Landroid/graphics/BlendMode;->MODULATE:Landroid/graphics/BlendMode;

    .line 88
    .line 89
    return-object p0

    .line 90
    :cond_d
    const/16 v0, 0xe

    .line 91
    .line 92
    if-ne p0, v0, :cond_e

    .line 93
    .line 94
    sget-object p0, Landroid/graphics/BlendMode;->SCREEN:Landroid/graphics/BlendMode;

    .line 95
    .line 96
    return-object p0

    .line 97
    :cond_e
    const/16 v0, 0xf

    .line 98
    .line 99
    if-ne p0, v0, :cond_f

    .line 100
    .line 101
    sget-object p0, Landroid/graphics/BlendMode;->OVERLAY:Landroid/graphics/BlendMode;

    .line 102
    .line 103
    return-object p0

    .line 104
    :cond_f
    const/16 v0, 0x10

    .line 105
    .line 106
    if-ne p0, v0, :cond_10

    .line 107
    .line 108
    sget-object p0, Landroid/graphics/BlendMode;->DARKEN:Landroid/graphics/BlendMode;

    .line 109
    .line 110
    return-object p0

    .line 111
    :cond_10
    const/16 v0, 0x11

    .line 112
    .line 113
    if-ne p0, v0, :cond_11

    .line 114
    .line 115
    sget-object p0, Landroid/graphics/BlendMode;->LIGHTEN:Landroid/graphics/BlendMode;

    .line 116
    .line 117
    return-object p0

    .line 118
    :cond_11
    const/16 v0, 0x12

    .line 119
    .line 120
    if-ne p0, v0, :cond_12

    .line 121
    .line 122
    sget-object p0, Landroid/graphics/BlendMode;->COLOR_DODGE:Landroid/graphics/BlendMode;

    .line 123
    .line 124
    return-object p0

    .line 125
    :cond_12
    const/16 v0, 0x13

    .line 126
    .line 127
    if-ne p0, v0, :cond_13

    .line 128
    .line 129
    sget-object p0, Landroid/graphics/BlendMode;->COLOR_BURN:Landroid/graphics/BlendMode;

    .line 130
    .line 131
    return-object p0

    .line 132
    :cond_13
    const/16 v0, 0x14

    .line 133
    .line 134
    if-ne p0, v0, :cond_14

    .line 135
    .line 136
    sget-object p0, Landroid/graphics/BlendMode;->HARD_LIGHT:Landroid/graphics/BlendMode;

    .line 137
    .line 138
    return-object p0

    .line 139
    :cond_14
    const/16 v0, 0x15

    .line 140
    .line 141
    if-ne p0, v0, :cond_15

    .line 142
    .line 143
    sget-object p0, Landroid/graphics/BlendMode;->SOFT_LIGHT:Landroid/graphics/BlendMode;

    .line 144
    .line 145
    return-object p0

    .line 146
    :cond_15
    const/16 v0, 0x16

    .line 147
    .line 148
    if-ne p0, v0, :cond_16

    .line 149
    .line 150
    sget-object p0, Landroid/graphics/BlendMode;->DIFFERENCE:Landroid/graphics/BlendMode;

    .line 151
    .line 152
    return-object p0

    .line 153
    :cond_16
    const/16 v0, 0x17

    .line 154
    .line 155
    if-ne p0, v0, :cond_17

    .line 156
    .line 157
    sget-object p0, Landroid/graphics/BlendMode;->EXCLUSION:Landroid/graphics/BlendMode;

    .line 158
    .line 159
    return-object p0

    .line 160
    :cond_17
    const/16 v0, 0x18

    .line 161
    .line 162
    if-ne p0, v0, :cond_18

    .line 163
    .line 164
    sget-object p0, Landroid/graphics/BlendMode;->MULTIPLY:Landroid/graphics/BlendMode;

    .line 165
    .line 166
    return-object p0

    .line 167
    :cond_18
    const/16 v0, 0x19

    .line 168
    .line 169
    if-ne p0, v0, :cond_19

    .line 170
    .line 171
    sget-object p0, Landroid/graphics/BlendMode;->HUE:Landroid/graphics/BlendMode;

    .line 172
    .line 173
    return-object p0

    .line 174
    :cond_19
    const/16 v0, 0x1a

    .line 175
    .line 176
    if-ne p0, v0, :cond_1a

    .line 177
    .line 178
    sget-object p0, Landroid/graphics/BlendMode;->SATURATION:Landroid/graphics/BlendMode;

    .line 179
    .line 180
    return-object p0

    .line 181
    :cond_1a
    const/16 v0, 0x1b

    .line 182
    .line 183
    if-ne p0, v0, :cond_1b

    .line 184
    .line 185
    sget-object p0, Landroid/graphics/BlendMode;->COLOR:Landroid/graphics/BlendMode;

    .line 186
    .line 187
    return-object p0

    .line 188
    :cond_1b
    const/16 v0, 0x1c

    .line 189
    .line 190
    if-ne p0, v0, :cond_1c

    .line 191
    .line 192
    sget-object p0, Landroid/graphics/BlendMode;->LUMINOSITY:Landroid/graphics/BlendMode;

    .line 193
    .line 194
    return-object p0

    .line 195
    :cond_1c
    sget-object p0, Landroid/graphics/BlendMode;->SRC_OVER:Landroid/graphics/BlendMode;

    .line 196
    .line 197
    return-object p0
.end method

.method public static final v(Ld3/c;)Landroid/graphics/Rect;
    .locals 4

    .line 1
    new-instance v0, Landroid/graphics/Rect;

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    float-to-int v1, v1

    .line 6
    iget v2, p0, Ld3/c;->b:F

    .line 7
    .line 8
    float-to-int v2, v2

    .line 9
    iget v3, p0, Ld3/c;->c:F

    .line 10
    .line 11
    float-to-int v3, v3

    .line 12
    iget p0, p0, Ld3/c;->d:F

    .line 13
    .line 14
    float-to-int p0, p0

    .line 15
    invoke-direct {v0, v1, v2, v3, p0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 16
    .line 17
    .line 18
    return-object v0
.end method

.method public static final w(Lt4/k;)Landroid/graphics/Rect;
    .locals 4

    .line 1
    new-instance v0, Landroid/graphics/Rect;

    .line 2
    .line 3
    iget v1, p0, Lt4/k;->a:I

    .line 4
    .line 5
    iget v2, p0, Lt4/k;->b:I

    .line 6
    .line 7
    iget v3, p0, Lt4/k;->c:I

    .line 8
    .line 9
    iget p0, p0, Lt4/k;->d:I

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static final x(Ld3/c;)Landroid/graphics/RectF;
    .locals 4

    .line 1
    new-instance v0, Landroid/graphics/RectF;

    .line 2
    .line 3
    iget v1, p0, Ld3/c;->a:F

    .line 4
    .line 5
    iget v2, p0, Ld3/c;->b:F

    .line 6
    .line 7
    iget v3, p0, Ld3/c;->c:F

    .line 8
    .line 9
    iget p0, p0, Ld3/c;->d:F

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, p0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public static final y(I)Landroid/graphics/Shader$TileMode;
    .locals 1

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    sget-object p0, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const/4 v0, 0x1

    .line 7
    if-ne p0, v0, :cond_1

    .line 8
    .line 9
    sget-object p0, Landroid/graphics/Shader$TileMode;->REPEAT:Landroid/graphics/Shader$TileMode;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    const/4 v0, 0x2

    .line 13
    if-ne p0, v0, :cond_2

    .line 14
    .line 15
    sget-object p0, Landroid/graphics/Shader$TileMode;->MIRROR:Landroid/graphics/Shader$TileMode;

    .line 16
    .line 17
    return-object p0

    .line 18
    :cond_2
    const/4 v0, 0x3

    .line 19
    if-ne p0, v0, :cond_4

    .line 20
    .line 21
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 22
    .line 23
    const/16 v0, 0x1f

    .line 24
    .line 25
    if-lt p0, v0, :cond_3

    .line 26
    .line 27
    invoke-static {}, Lc4/a;->j()Landroid/graphics/Shader$TileMode;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    return-object p0

    .line 32
    :cond_3
    sget-object p0, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_4
    sget-object p0, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 36
    .line 37
    return-object p0
.end method

.method public static final z(J)I
    .locals 1

    .line 1
    sget-object v0, Lf3/e;->a:[F

    .line 2
    .line 3
    sget-object v0, Lf3/e;->e:Lf3/r;

    .line 4
    .line 5
    invoke-static {p0, p1, v0}, Le3/s;->a(JLf3/c;)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    const/16 v0, 0x20

    .line 10
    .line 11
    ushr-long/2addr p0, v0

    .line 12
    long-to-int p0, p0

    .line 13
    return p0
.end method

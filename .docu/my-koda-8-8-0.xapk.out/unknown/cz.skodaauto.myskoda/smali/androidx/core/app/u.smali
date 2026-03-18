.class public final Landroidx/core/app/u;
.super Landroidx/core/app/a0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public e:Landroidx/core/graphics/drawable/IconCompat;

.field public f:Landroidx/core/graphics/drawable/IconCompat;

.field public g:Z


# virtual methods
.method public final a(Lcom/google/firebase/messaging/w;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lcom/google/firebase/messaging/w;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Landroid/app/Notification$Builder;

    .line 8
    .line 9
    iget-object v1, v1, Lcom/google/firebase/messaging/w;->e:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Landroid/content/Context;

    .line 12
    .line 13
    new-instance v3, Landroid/app/Notification$BigPictureStyle;

    .line 14
    .line 15
    invoke-direct {v3, v2}, Landroid/app/Notification$BigPictureStyle;-><init>(Landroid/app/Notification$Builder;)V

    .line 16
    .line 17
    .line 18
    iget-object v2, v0, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast v2, Ljava/lang/CharSequence;

    .line 21
    .line 22
    invoke-virtual {v3, v2}, Landroid/app/Notification$BigPictureStyle;->setBigContentTitle(Ljava/lang/CharSequence;)Landroid/app/Notification$BigPictureStyle;

    .line 23
    .line 24
    .line 25
    move-result-object v2

    .line 26
    iget-object v3, v0, Landroidx/core/app/u;->e:Landroidx/core/graphics/drawable/IconCompat;

    .line 27
    .line 28
    const/4 v4, 0x0

    .line 29
    const/4 v5, 0x0

    .line 30
    const/16 v6, 0x1f

    .line 31
    .line 32
    if-eqz v3, :cond_5

    .line 33
    .line 34
    sget v7, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 35
    .line 36
    if-lt v7, v6, :cond_0

    .line 37
    .line 38
    invoke-virtual {v3, v1}, Landroidx/core/graphics/drawable/IconCompat;->f(Landroid/content/Context;)Landroid/graphics/drawable/Icon;

    .line 39
    .line 40
    .line 41
    move-result-object v3

    .line 42
    invoke-static {v2, v3}, Landroidx/core/app/t;->a(Landroid/app/Notification$BigPictureStyle;Landroid/graphics/drawable/Icon;)V

    .line 43
    .line 44
    .line 45
    goto/16 :goto_1

    .line 46
    .line 47
    :cond_0
    invoke-virtual {v3}, Landroidx/core/graphics/drawable/IconCompat;->c()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    const/4 v7, 0x1

    .line 52
    if-ne v3, v7, :cond_5

    .line 53
    .line 54
    iget-object v3, v0, Landroidx/core/app/u;->e:Landroidx/core/graphics/drawable/IconCompat;

    .line 55
    .line 56
    iget v8, v3, Landroidx/core/graphics/drawable/IconCompat;->a:I

    .line 57
    .line 58
    const/4 v9, -0x1

    .line 59
    if-ne v8, v9, :cond_2

    .line 60
    .line 61
    iget-object v3, v3, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 62
    .line 63
    instance-of v7, v3, Landroid/graphics/Bitmap;

    .line 64
    .line 65
    if-eqz v7, :cond_1

    .line 66
    .line 67
    check-cast v3, Landroid/graphics/Bitmap;

    .line 68
    .line 69
    goto/16 :goto_0

    .line 70
    .line 71
    :cond_1
    move-object v3, v5

    .line 72
    goto/16 :goto_0

    .line 73
    .line 74
    :cond_2
    if-ne v8, v7, :cond_3

    .line 75
    .line 76
    iget-object v3, v3, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v3, Landroid/graphics/Bitmap;

    .line 79
    .line 80
    goto/16 :goto_0

    .line 81
    .line 82
    :cond_3
    const/4 v7, 0x5

    .line 83
    if-ne v8, v7, :cond_4

    .line 84
    .line 85
    iget-object v3, v3, Landroidx/core/graphics/drawable/IconCompat;->b:Ljava/lang/Object;

    .line 86
    .line 87
    check-cast v3, Landroid/graphics/Bitmap;

    .line 88
    .line 89
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 90
    .line 91
    .line 92
    move-result v7

    .line 93
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    invoke-static {v7, v8}, Ljava/lang/Math;->min(II)I

    .line 98
    .line 99
    .line 100
    move-result v7

    .line 101
    int-to-float v7, v7

    .line 102
    const v8, 0x3f2aaaab

    .line 103
    .line 104
    .line 105
    mul-float/2addr v7, v8

    .line 106
    float-to-int v7, v7

    .line 107
    sget-object v8, Landroid/graphics/Bitmap$Config;->ARGB_8888:Landroid/graphics/Bitmap$Config;

    .line 108
    .line 109
    invoke-static {v7, v7, v8}, Landroid/graphics/Bitmap;->createBitmap(IILandroid/graphics/Bitmap$Config;)Landroid/graphics/Bitmap;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    new-instance v9, Landroid/graphics/Canvas;

    .line 114
    .line 115
    invoke-direct {v9, v8}, Landroid/graphics/Canvas;-><init>(Landroid/graphics/Bitmap;)V

    .line 116
    .line 117
    .line 118
    new-instance v10, Landroid/graphics/Paint;

    .line 119
    .line 120
    const/4 v11, 0x3

    .line 121
    invoke-direct {v10, v11}, Landroid/graphics/Paint;-><init>(I)V

    .line 122
    .line 123
    .line 124
    int-to-float v11, v7

    .line 125
    const/high16 v12, 0x3f000000    # 0.5f

    .line 126
    .line 127
    mul-float/2addr v12, v11

    .line 128
    const v13, 0x3f6aaaab

    .line 129
    .line 130
    .line 131
    mul-float/2addr v13, v12

    .line 132
    const v14, 0x3c2aaaab

    .line 133
    .line 134
    .line 135
    mul-float/2addr v14, v11

    .line 136
    invoke-virtual {v10, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 137
    .line 138
    .line 139
    const v15, 0x3caaaaab

    .line 140
    .line 141
    .line 142
    mul-float/2addr v11, v15

    .line 143
    const/high16 v15, 0x3d000000    # 0.03125f

    .line 144
    .line 145
    const/4 v4, 0x0

    .line 146
    invoke-virtual {v10, v14, v4, v11, v15}, Landroid/graphics/Paint;->setShadowLayer(FFFI)V

    .line 147
    .line 148
    .line 149
    invoke-virtual {v9, v12, v12, v13, v10}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 150
    .line 151
    .line 152
    const/high16 v11, 0x1e000000

    .line 153
    .line 154
    invoke-virtual {v10, v14, v4, v4, v11}, Landroid/graphics/Paint;->setShadowLayer(FFFI)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v9, v12, v12, v13, v10}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 158
    .line 159
    .line 160
    invoke-virtual {v10}, Landroid/graphics/Paint;->clearShadowLayer()V

    .line 161
    .line 162
    .line 163
    const/high16 v4, -0x1000000

    .line 164
    .line 165
    invoke-virtual {v10, v4}, Landroid/graphics/Paint;->setColor(I)V

    .line 166
    .line 167
    .line 168
    new-instance v4, Landroid/graphics/BitmapShader;

    .line 169
    .line 170
    sget-object v11, Landroid/graphics/Shader$TileMode;->CLAMP:Landroid/graphics/Shader$TileMode;

    .line 171
    .line 172
    invoke-direct {v4, v3, v11, v11}, Landroid/graphics/BitmapShader;-><init>(Landroid/graphics/Bitmap;Landroid/graphics/Shader$TileMode;Landroid/graphics/Shader$TileMode;)V

    .line 173
    .line 174
    .line 175
    new-instance v11, Landroid/graphics/Matrix;

    .line 176
    .line 177
    invoke-direct {v11}, Landroid/graphics/Matrix;-><init>()V

    .line 178
    .line 179
    .line 180
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getWidth()I

    .line 181
    .line 182
    .line 183
    move-result v14

    .line 184
    sub-int/2addr v14, v7

    .line 185
    neg-int v14, v14

    .line 186
    int-to-float v14, v14

    .line 187
    const/high16 v15, 0x40000000    # 2.0f

    .line 188
    .line 189
    div-float/2addr v14, v15

    .line 190
    invoke-virtual {v3}, Landroid/graphics/Bitmap;->getHeight()I

    .line 191
    .line 192
    .line 193
    move-result v3

    .line 194
    sub-int/2addr v3, v7

    .line 195
    neg-int v3, v3

    .line 196
    int-to-float v3, v3

    .line 197
    div-float/2addr v3, v15

    .line 198
    invoke-virtual {v11, v14, v3}, Landroid/graphics/Matrix;->setTranslate(FF)V

    .line 199
    .line 200
    .line 201
    invoke-virtual {v4, v11}, Landroid/graphics/Shader;->setLocalMatrix(Landroid/graphics/Matrix;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {v10, v4}, Landroid/graphics/Paint;->setShader(Landroid/graphics/Shader;)Landroid/graphics/Shader;

    .line 205
    .line 206
    .line 207
    invoke-virtual {v9, v12, v12, v13, v10}, Landroid/graphics/Canvas;->drawCircle(FFFLandroid/graphics/Paint;)V

    .line 208
    .line 209
    .line 210
    invoke-virtual {v9, v5}, Landroid/graphics/Canvas;->setBitmap(Landroid/graphics/Bitmap;)V

    .line 211
    .line 212
    .line 213
    move-object v3, v8

    .line 214
    :goto_0
    invoke-virtual {v2, v3}, Landroid/app/Notification$BigPictureStyle;->bigPicture(Landroid/graphics/Bitmap;)Landroid/app/Notification$BigPictureStyle;

    .line 215
    .line 216
    .line 217
    move-result-object v2

    .line 218
    goto :goto_1

    .line 219
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 220
    .line 221
    new-instance v1, Ljava/lang/StringBuilder;

    .line 222
    .line 223
    const-string v2, "called getBitmap() on "

    .line 224
    .line 225
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 236
    .line 237
    .line 238
    throw v0

    .line 239
    :cond_5
    :goto_1
    iget-boolean v3, v0, Landroidx/core/app/u;->g:Z

    .line 240
    .line 241
    if-eqz v3, :cond_7

    .line 242
    .line 243
    iget-object v3, v0, Landroidx/core/app/u;->f:Landroidx/core/graphics/drawable/IconCompat;

    .line 244
    .line 245
    if-nez v3, :cond_6

    .line 246
    .line 247
    invoke-virtual {v2, v5}, Landroid/app/Notification$BigPictureStyle;->bigLargeIcon(Landroid/graphics/Bitmap;)Landroid/app/Notification$BigPictureStyle;

    .line 248
    .line 249
    .line 250
    goto :goto_2

    .line 251
    :cond_6
    invoke-virtual {v3, v1}, Landroidx/core/graphics/drawable/IconCompat;->f(Landroid/content/Context;)Landroid/graphics/drawable/Icon;

    .line 252
    .line 253
    .line 254
    move-result-object v1

    .line 255
    invoke-static {v2, v1}, Landroidx/core/app/s;->a(Landroid/app/Notification$BigPictureStyle;Landroid/graphics/drawable/Icon;)V

    .line 256
    .line 257
    .line 258
    :cond_7
    :goto_2
    iget-boolean v1, v0, Landroidx/core/app/a0;->a:Z

    .line 259
    .line 260
    if-eqz v1, :cond_8

    .line 261
    .line 262
    iget-object v0, v0, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v0, Ljava/lang/CharSequence;

    .line 265
    .line 266
    invoke-virtual {v2, v0}, Landroid/app/Notification$BigPictureStyle;->setSummaryText(Ljava/lang/CharSequence;)Landroid/app/Notification$BigPictureStyle;

    .line 267
    .line 268
    .line 269
    :cond_8
    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 270
    .line 271
    if-lt v0, v6, :cond_9

    .line 272
    .line 273
    const/4 v0, 0x0

    .line 274
    invoke-static {v2, v0}, Landroidx/core/app/t;->c(Landroid/app/Notification$BigPictureStyle;Z)V

    .line 275
    .line 276
    .line 277
    invoke-static {v2, v5}, Landroidx/core/app/t;->b(Landroid/app/Notification$BigPictureStyle;Ljava/lang/CharSequence;)V

    .line 278
    .line 279
    .line 280
    :cond_9
    return-void
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "androidx.core.app.NotificationCompat$BigPictureStyle"

    .line 2
    .line 3
    return-object p0
.end method

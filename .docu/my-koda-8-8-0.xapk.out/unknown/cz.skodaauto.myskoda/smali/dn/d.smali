.class public final Ldn/d;
.super Ldn/b;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final A:Ldn/i;

.field public final B:Landroid/graphics/Rect;

.field public final C:Landroid/graphics/Rect;

.field public final D:Landroid/graphics/RectF;

.field public final E:Lum/l;

.field public final F:Lxm/g;

.field public G:Lgn/g;

.field public H:Lb11/a;


# direct methods
.method public constructor <init>(Lum/j;Ldn/e;)V
    .locals 3

    .line 1
    invoke-direct {p0, p1, p2}, Ldn/b;-><init>(Lum/j;Ldn/e;)V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ldn/i;

    .line 5
    .line 6
    const/4 v1, 0x3

    .line 7
    const/4 v2, 0x2

    .line 8
    invoke-direct {v0, v1, v2}, Ldn/i;-><init>(II)V

    .line 9
    .line 10
    .line 11
    iput-object v0, p0, Ldn/d;->A:Ldn/i;

    .line 12
    .line 13
    new-instance v0, Landroid/graphics/Rect;

    .line 14
    .line 15
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Ldn/d;->B:Landroid/graphics/Rect;

    .line 19
    .line 20
    new-instance v0, Landroid/graphics/Rect;

    .line 21
    .line 22
    invoke-direct {v0}, Landroid/graphics/Rect;-><init>()V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Ldn/d;->C:Landroid/graphics/Rect;

    .line 26
    .line 27
    new-instance v0, Landroid/graphics/RectF;

    .line 28
    .line 29
    invoke-direct {v0}, Landroid/graphics/RectF;-><init>()V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Ldn/d;->D:Landroid/graphics/RectF;

    .line 33
    .line 34
    iget-object p2, p2, Ldn/e;->g:Ljava/lang/String;

    .line 35
    .line 36
    iget-object p1, p1, Lum/j;->d:Lum/a;

    .line 37
    .line 38
    if-nez p1, :cond_0

    .line 39
    .line 40
    const/4 p1, 0x0

    .line 41
    goto :goto_0

    .line 42
    :cond_0
    invoke-virtual {p1}, Lum/a;->c()Ljava/util/Map;

    .line 43
    .line 44
    .line 45
    move-result-object p1

    .line 46
    check-cast p1, Ljava/util/HashMap;

    .line 47
    .line 48
    invoke-virtual {p1, p2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 49
    .line 50
    .line 51
    move-result-object p1

    .line 52
    check-cast p1, Lum/l;

    .line 53
    .line 54
    :goto_0
    iput-object p1, p0, Ldn/d;->E:Lum/l;

    .line 55
    .line 56
    iget-object p1, p0, Ldn/b;->p:Ldn/e;

    .line 57
    .line 58
    iget-object p1, p1, Ldn/e;->x:Landroidx/lifecycle/c1;

    .line 59
    .line 60
    if-eqz p1, :cond_1

    .line 61
    .line 62
    new-instance p2, Lxm/g;

    .line 63
    .line 64
    invoke-direct {p2, p0, p0, p1}, Lxm/g;-><init>(Ldn/b;Ldn/b;Landroidx/lifecycle/c1;)V

    .line 65
    .line 66
    .line 67
    iput-object p2, p0, Ldn/d;->F:Lxm/g;

    .line 68
    .line 69
    :cond_1
    return-void
.end method


# virtual methods
.method public final e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V
    .locals 2

    .line 1
    invoke-super {p0, p1, p2, p3}, Ldn/b;->e(Landroid/graphics/RectF;Landroid/graphics/Matrix;Z)V

    .line 2
    .line 3
    .line 4
    iget-object p2, p0, Ldn/d;->E:Lum/l;

    .line 5
    .line 6
    if-eqz p2, :cond_1

    .line 7
    .line 8
    invoke-static {}, Lgn/h;->c()F

    .line 9
    .line 10
    .line 11
    move-result p3

    .line 12
    iget-object v0, p0, Ldn/b;->o:Lum/j;

    .line 13
    .line 14
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 15
    .line 16
    .line 17
    invoke-virtual {p0}, Ldn/d;->m()Landroid/graphics/Bitmap;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    const/4 v1, 0x0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 25
    .line 26
    .line 27
    move-result p2

    .line 28
    int-to-float p2, p2

    .line 29
    mul-float/2addr p2, p3

    .line 30
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    int-to-float v0, v0

    .line 35
    mul-float/2addr v0, p3

    .line 36
    invoke-virtual {p1, v1, v1, p2, v0}, Landroid/graphics/RectF;->set(FFFF)V

    .line 37
    .line 38
    .line 39
    goto :goto_0

    .line 40
    :cond_0
    iget v0, p2, Lum/l;->a:I

    .line 41
    .line 42
    int-to-float v0, v0

    .line 43
    mul-float/2addr v0, p3

    .line 44
    iget p2, p2, Lum/l;->b:I

    .line 45
    .line 46
    int-to-float p2, p2

    .line 47
    mul-float/2addr p2, p3

    .line 48
    invoke-virtual {p1, v1, v1, v0, p2}, Landroid/graphics/RectF;->set(FFFF)V

    .line 49
    .line 50
    .line 51
    :goto_0
    iget-object p0, p0, Ldn/b;->n:Landroid/graphics/Matrix;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 54
    .line 55
    .line 56
    :cond_1
    return-void
.end method

.method public final h(Landroid/graphics/Canvas;Landroid/graphics/Matrix;ILgn/a;)V
    .locals 8

    .line 1
    invoke-virtual {p0}, Ldn/d;->m()Landroid/graphics/Bitmap;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_7

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->isRecycled()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-nez v1, :cond_7

    .line 12
    .line 13
    iget-object v1, p0, Ldn/d;->E:Lum/l;

    .line 14
    .line 15
    if-nez v1, :cond_0

    .line 16
    .line 17
    goto/16 :goto_0

    .line 18
    .line 19
    :cond_0
    invoke-static {}, Lgn/h;->c()F

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    iget-object v2, p0, Ldn/d;->A:Ldn/i;

    .line 24
    .line 25
    invoke-virtual {v2, p3}, Ldn/i;->setAlpha(I)V

    .line 26
    .line 27
    .line 28
    iget-object v3, p0, Ldn/d;->F:Lxm/g;

    .line 29
    .line 30
    if-eqz v3, :cond_1

    .line 31
    .line 32
    invoke-virtual {v3, p2, p3}, Lxm/g;->b(Landroid/graphics/Matrix;I)Lgn/a;

    .line 33
    .line 34
    .line 35
    move-result-object p4

    .line 36
    :cond_1
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 37
    .line 38
    .line 39
    move-result v3

    .line 40
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 41
    .line 42
    .line 43
    move-result v4

    .line 44
    iget-object v5, p0, Ldn/d;->B:Landroid/graphics/Rect;

    .line 45
    .line 46
    const/4 v6, 0x0

    .line 47
    invoke-virtual {v5, v6, v6, v3, v4}, Landroid/graphics/Rect;->set(IIII)V

    .line 48
    .line 49
    .line 50
    iget-object v3, p0, Ldn/b;->o:Lum/j;

    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getWidth()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    int-to-float v3, v3

    .line 60
    mul-float/2addr v3, v1

    .line 61
    float-to-int v3, v3

    .line 62
    invoke-virtual {v0}, Landroid/graphics/Bitmap;->getHeight()I

    .line 63
    .line 64
    .line 65
    move-result v4

    .line 66
    int-to-float v4, v4

    .line 67
    mul-float/2addr v4, v1

    .line 68
    float-to-int v1, v4

    .line 69
    iget-object v4, p0, Ldn/d;->C:Landroid/graphics/Rect;

    .line 70
    .line 71
    invoke-virtual {v4, v6, v6, v3, v1}, Landroid/graphics/Rect;->set(IIII)V

    .line 72
    .line 73
    .line 74
    if-eqz p4, :cond_2

    .line 75
    .line 76
    const/4 v6, 0x1

    .line 77
    :cond_2
    if-eqz v6, :cond_5

    .line 78
    .line 79
    iget-object v1, p0, Ldn/d;->G:Lgn/g;

    .line 80
    .line 81
    if-nez v1, :cond_3

    .line 82
    .line 83
    new-instance v1, Lgn/g;

    .line 84
    .line 85
    invoke-direct {v1}, Lgn/g;-><init>()V

    .line 86
    .line 87
    .line 88
    iput-object v1, p0, Ldn/d;->G:Lgn/g;

    .line 89
    .line 90
    :cond_3
    iget-object v1, p0, Ldn/d;->H:Lb11/a;

    .line 91
    .line 92
    if-nez v1, :cond_4

    .line 93
    .line 94
    new-instance v1, Lb11/a;

    .line 95
    .line 96
    const/4 v3, 0x4

    .line 97
    const/4 v7, 0x0

    .line 98
    invoke-direct {v1, v7, v3}, Lb11/a;-><init>(BI)V

    .line 99
    .line 100
    .line 101
    iput-object v1, p0, Ldn/d;->H:Lb11/a;

    .line 102
    .line 103
    :cond_4
    iget-object v1, p0, Ldn/d;->H:Lb11/a;

    .line 104
    .line 105
    const/16 v3, 0xff

    .line 106
    .line 107
    iput v3, v1, Lb11/a;->e:I

    .line 108
    .line 109
    const/4 v3, 0x0

    .line 110
    iput-object v3, v1, Lb11/a;->f:Ljava/lang/Object;

    .line 111
    .line 112
    invoke-virtual {p4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 113
    .line 114
    .line 115
    new-instance v3, Lgn/a;

    .line 116
    .line 117
    invoke-direct {v3, p4}, Lgn/a;-><init>(Lgn/a;)V

    .line 118
    .line 119
    .line 120
    iput-object v3, v1, Lb11/a;->f:Ljava/lang/Object;

    .line 121
    .line 122
    invoke-virtual {v3, p3}, Lgn/a;->b(I)V

    .line 123
    .line 124
    .line 125
    iget p3, v4, Landroid/graphics/Rect;->left:I

    .line 126
    .line 127
    int-to-float p3, p3

    .line 128
    iget p4, v4, Landroid/graphics/Rect;->top:I

    .line 129
    .line 130
    int-to-float p4, p4

    .line 131
    iget v1, v4, Landroid/graphics/Rect;->right:I

    .line 132
    .line 133
    int-to-float v1, v1

    .line 134
    iget v3, v4, Landroid/graphics/Rect;->bottom:I

    .line 135
    .line 136
    int-to-float v3, v3

    .line 137
    iget-object v7, p0, Ldn/d;->D:Landroid/graphics/RectF;

    .line 138
    .line 139
    invoke-virtual {v7, p3, p4, v1, v3}, Landroid/graphics/RectF;->set(FFFF)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p2, v7}, Landroid/graphics/Matrix;->mapRect(Landroid/graphics/RectF;)Z

    .line 143
    .line 144
    .line 145
    iget-object p3, p0, Ldn/d;->G:Lgn/g;

    .line 146
    .line 147
    iget-object p4, p0, Ldn/d;->H:Lb11/a;

    .line 148
    .line 149
    invoke-virtual {p3, p1, v7, p4}, Lgn/g;->e(Landroid/graphics/Canvas;Landroid/graphics/RectF;Lb11/a;)Landroid/graphics/Canvas;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    :cond_5
    invoke-virtual {p1}, Landroid/graphics/Canvas;->save()I

    .line 154
    .line 155
    .line 156
    invoke-virtual {p1, p2}, Landroid/graphics/Canvas;->concat(Landroid/graphics/Matrix;)V

    .line 157
    .line 158
    .line 159
    invoke-virtual {p1, v0, v5, v4, v2}, Landroid/graphics/Canvas;->drawBitmap(Landroid/graphics/Bitmap;Landroid/graphics/Rect;Landroid/graphics/Rect;Landroid/graphics/Paint;)V

    .line 160
    .line 161
    .line 162
    if-eqz v6, :cond_6

    .line 163
    .line 164
    iget-object p2, p0, Ldn/d;->G:Lgn/g;

    .line 165
    .line 166
    invoke-virtual {p2}, Lgn/g;->c()V

    .line 167
    .line 168
    .line 169
    iget-object p0, p0, Ldn/d;->G:Lgn/g;

    .line 170
    .line 171
    iget p0, p0, Lgn/g;->c:I

    .line 172
    .line 173
    const/4 p2, 0x4

    .line 174
    if-ne p0, p2, :cond_6

    .line 175
    .line 176
    goto :goto_0

    .line 177
    :cond_6
    invoke-virtual {p1}, Landroid/graphics/Canvas;->restore()V

    .line 178
    .line 179
    .line 180
    :cond_7
    :goto_0
    return-void
.end method

.method public final m()Landroid/graphics/Bitmap;
    .locals 15

    .line 1
    iget-object v0, p0, Ldn/b;->p:Ldn/e;

    .line 2
    .line 3
    iget-object v0, v0, Ldn/e;->g:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v1, p0, Ldn/b;->o:Lum/j;

    .line 6
    .line 7
    iget-object v2, v1, Lum/j;->h:Lzm/a;

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    if-eqz v2, :cond_3

    .line 11
    .line 12
    invoke-virtual {v1}, Lum/j;->f()Landroid/content/Context;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    iget-object v2, v2, Lzm/a;->a:Landroid/content/Context;

    .line 17
    .line 18
    if-nez v4, :cond_0

    .line 19
    .line 20
    if-nez v2, :cond_2

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    instance-of v5, v2, Landroid/app/Application;

    .line 24
    .line 25
    if-eqz v5, :cond_1

    .line 26
    .line 27
    invoke-virtual {v4}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 28
    .line 29
    .line 30
    move-result-object v4

    .line 31
    :cond_1
    if-ne v4, v2, :cond_2

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_2
    iput-object v3, v1, Lum/j;->h:Lzm/a;

    .line 35
    .line 36
    :cond_3
    :goto_0
    iget-object v2, v1, Lum/j;->h:Lzm/a;

    .line 37
    .line 38
    if-nez v2, :cond_4

    .line 39
    .line 40
    new-instance v2, Lzm/a;

    .line 41
    .line 42
    invoke-virtual {v1}, Landroid/graphics/drawable/Drawable;->getCallback()Landroid/graphics/drawable/Drawable$Callback;

    .line 43
    .line 44
    .line 45
    move-result-object v4

    .line 46
    iget-object v5, v1, Lum/j;->d:Lum/a;

    .line 47
    .line 48
    invoke-virtual {v5}, Lum/a;->c()Ljava/util/Map;

    .line 49
    .line 50
    .line 51
    move-result-object v5

    .line 52
    invoke-direct {v2, v4, v5}, Lzm/a;-><init>(Landroid/graphics/drawable/Drawable$Callback;Ljava/util/Map;)V

    .line 53
    .line 54
    .line 55
    iput-object v2, v1, Lum/j;->h:Lzm/a;

    .line 56
    .line 57
    :cond_4
    iget-object v1, v1, Lum/j;->h:Lzm/a;

    .line 58
    .line 59
    if-eqz v1, :cond_8

    .line 60
    .line 61
    iget-object v2, v1, Lzm/a;->b:Ljava/lang/String;

    .line 62
    .line 63
    const-string v4, "`."

    .line 64
    .line 65
    const-string v5, "Unable to decode image `"

    .line 66
    .line 67
    const-string v6, "` is null."

    .line 68
    .line 69
    const-string v7, "Decoded image `"

    .line 70
    .line 71
    iget-object v8, v1, Lzm/a;->c:Ljava/util/Map;

    .line 72
    .line 73
    invoke-interface {v8, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v8

    .line 77
    check-cast v8, Lum/l;

    .line 78
    .line 79
    if-nez v8, :cond_5

    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_5
    iget v9, v8, Lum/l;->b:I

    .line 83
    .line 84
    iget v10, v8, Lum/l;->a:I

    .line 85
    .line 86
    iget-object v11, v8, Lum/l;->f:Landroid/graphics/Bitmap;

    .line 87
    .line 88
    if-eqz v11, :cond_6

    .line 89
    .line 90
    goto/16 :goto_3

    .line 91
    .line 92
    :cond_6
    iget-object v11, v1, Lzm/a;->a:Landroid/content/Context;

    .line 93
    .line 94
    if-nez v11, :cond_7

    .line 95
    .line 96
    goto :goto_1

    .line 97
    :cond_7
    iget-object v8, v8, Lum/l;->d:Ljava/lang/String;

    .line 98
    .line 99
    new-instance v12, Landroid/graphics/BitmapFactory$Options;

    .line 100
    .line 101
    invoke-direct {v12}, Landroid/graphics/BitmapFactory$Options;-><init>()V

    .line 102
    .line 103
    .line 104
    const/4 v13, 0x1

    .line 105
    iput-boolean v13, v12, Landroid/graphics/BitmapFactory$Options;->inScaled:Z

    .line 106
    .line 107
    const/16 v14, 0xa0

    .line 108
    .line 109
    iput v14, v12, Landroid/graphics/BitmapFactory$Options;->inDensity:I

    .line 110
    .line 111
    const-string v14, "data:"

    .line 112
    .line 113
    invoke-virtual {v8, v14}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 114
    .line 115
    .line 116
    move-result v14

    .line 117
    if-eqz v14, :cond_a

    .line 118
    .line 119
    const-string v14, "base64,"

    .line 120
    .line 121
    invoke-virtual {v8, v14}, Ljava/lang/String;->indexOf(Ljava/lang/String;)I

    .line 122
    .line 123
    .line 124
    move-result v14

    .line 125
    if-lez v14, :cond_a

    .line 126
    .line 127
    const/16 v2, 0x2c

    .line 128
    .line 129
    :try_start_0
    invoke-virtual {v8, v2}, Ljava/lang/String;->indexOf(I)I

    .line 130
    .line 131
    .line 132
    move-result v2

    .line 133
    add-int/2addr v2, v13

    .line 134
    invoke-virtual {v8, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    const/4 v8, 0x0

    .line 139
    invoke-static {v2, v8}, Landroid/util/Base64;->decode(Ljava/lang/String;I)[B

    .line 140
    .line 141
    .line 142
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_1

    .line 143
    :try_start_1
    array-length v11, v2

    .line 144
    invoke-static {v2, v8, v11, v12}, Landroid/graphics/BitmapFactory;->decodeByteArray([BIILandroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 145
    .line 146
    .line 147
    move-result-object v2
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_0

    .line 148
    if-nez v2, :cond_9

    .line 149
    .line 150
    new-instance v1, Ljava/lang/StringBuilder;

    .line 151
    .line 152
    invoke-direct {v1, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object v0

    .line 165
    invoke-static {v0}, Lgn/c;->a(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    :cond_8
    :goto_1
    move-object v11, v3

    .line 169
    goto/16 :goto_3

    .line 170
    .line 171
    :cond_9
    invoke-static {v2, v10, v9}, Lgn/h;->d(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;

    .line 172
    .line 173
    .line 174
    move-result-object v11

    .line 175
    sget-object v2, Lzm/a;->d:Ljava/lang/Object;

    .line 176
    .line 177
    monitor-enter v2

    .line 178
    :try_start_2
    iget-object v1, v1, Lzm/a;->c:Ljava/util/Map;

    .line 179
    .line 180
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v0

    .line 184
    check-cast v0, Lum/l;

    .line 185
    .line 186
    iput-object v11, v0, Lum/l;->f:Landroid/graphics/Bitmap;

    .line 187
    .line 188
    monitor-exit v2

    .line 189
    goto/16 :goto_3

    .line 190
    .line 191
    :catchall_0
    move-exception p0

    .line 192
    monitor-exit v2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 193
    throw p0

    .line 194
    :catch_0
    move-exception v1

    .line 195
    new-instance v2, Ljava/lang/StringBuilder;

    .line 196
    .line 197
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 201
    .line 202
    .line 203
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 204
    .line 205
    .line 206
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 207
    .line 208
    .line 209
    move-result-object v0

    .line 210
    invoke-static {v0, v1}, Lgn/c;->b(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 211
    .line 212
    .line 213
    goto :goto_1

    .line 214
    :catch_1
    move-exception v0

    .line 215
    const-string v1, "data URL did not have correct base64 format."

    .line 216
    .line 217
    invoke-static {v1, v0}, Lgn/c;->b(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 218
    .line 219
    .line 220
    goto :goto_1

    .line 221
    :cond_a
    :try_start_3
    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 222
    .line 223
    .line 224
    move-result v13

    .line 225
    if-nez v13, :cond_c

    .line 226
    .line 227
    invoke-virtual {v11}, Landroid/content/Context;->getAssets()Landroid/content/res/AssetManager;

    .line 228
    .line 229
    .line 230
    move-result-object v11

    .line 231
    new-instance v13, Ljava/lang/StringBuilder;

    .line 232
    .line 233
    invoke-direct {v13}, Ljava/lang/StringBuilder;-><init>()V

    .line 234
    .line 235
    .line 236
    invoke-virtual {v13, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    invoke-virtual {v13, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 240
    .line 241
    .line 242
    invoke-virtual {v13}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    invoke-virtual {v11, v2}, Landroid/content/res/AssetManager;->open(Ljava/lang/String;)Ljava/io/InputStream;

    .line 247
    .line 248
    .line 249
    move-result-object v2
    :try_end_3
    .catch Ljava/io/IOException; {:try_start_3 .. :try_end_3} :catch_3

    .line 250
    :try_start_4
    invoke-static {v2, v3, v12}, Landroid/graphics/BitmapFactory;->decodeStream(Ljava/io/InputStream;Landroid/graphics/Rect;Landroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 251
    .line 252
    .line 253
    move-result-object v2
    :try_end_4
    .catch Ljava/lang/IllegalArgumentException; {:try_start_4 .. :try_end_4} :catch_2

    .line 254
    if-nez v2, :cond_b

    .line 255
    .line 256
    new-instance v1, Ljava/lang/StringBuilder;

    .line 257
    .line 258
    invoke-direct {v1, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 262
    .line 263
    .line 264
    invoke-virtual {v1, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 268
    .line 269
    .line 270
    move-result-object v0

    .line 271
    invoke-static {v0}, Lgn/c;->a(Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    goto :goto_1

    .line 275
    :cond_b
    invoke-static {v2, v10, v9}, Lgn/h;->d(Landroid/graphics/Bitmap;II)Landroid/graphics/Bitmap;

    .line 276
    .line 277
    .line 278
    move-result-object v11

    .line 279
    sget-object v2, Lzm/a;->d:Ljava/lang/Object;

    .line 280
    .line 281
    monitor-enter v2

    .line 282
    :try_start_5
    iget-object v1, v1, Lzm/a;->c:Ljava/util/Map;

    .line 283
    .line 284
    invoke-interface {v1, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object v0

    .line 288
    check-cast v0, Lum/l;

    .line 289
    .line 290
    iput-object v11, v0, Lum/l;->f:Landroid/graphics/Bitmap;

    .line 291
    .line 292
    monitor-exit v2

    .line 293
    goto :goto_3

    .line 294
    :catchall_1
    move-exception p0

    .line 295
    monitor-exit v2
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 296
    throw p0

    .line 297
    :catch_2
    move-exception v1

    .line 298
    new-instance v2, Ljava/lang/StringBuilder;

    .line 299
    .line 300
    invoke-direct {v2, v5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 301
    .line 302
    .line 303
    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 307
    .line 308
    .line 309
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object v0

    .line 313
    invoke-static {v0, v1}, Lgn/c;->b(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 314
    .line 315
    .line 316
    goto/16 :goto_1

    .line 317
    .line 318
    :catch_3
    move-exception v0

    .line 319
    goto :goto_2

    .line 320
    :cond_c
    :try_start_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 321
    .line 322
    const-string v1, "You must set an images folder before loading an image. Set it with LottieComposition#setImagesFolder or LottieDrawable#setImagesFolder"

    .line 323
    .line 324
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw v0
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_3

    .line 328
    :goto_2
    const-string v1, "Unable to open asset."

    .line 329
    .line 330
    invoke-static {v1, v0}, Lgn/c;->b(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 331
    .line 332
    .line 333
    goto/16 :goto_1

    .line 334
    .line 335
    :goto_3
    if-eqz v11, :cond_d

    .line 336
    .line 337
    return-object v11

    .line 338
    :cond_d
    iget-object p0, p0, Ldn/d;->E:Lum/l;

    .line 339
    .line 340
    if-eqz p0, :cond_e

    .line 341
    .line 342
    iget-object p0, p0, Lum/l;->f:Landroid/graphics/Bitmap;

    .line 343
    .line 344
    return-object p0

    .line 345
    :cond_e
    return-object v3
.end method

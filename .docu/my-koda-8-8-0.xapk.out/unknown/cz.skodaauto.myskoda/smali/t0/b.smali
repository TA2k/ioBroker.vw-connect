.class public final Lt0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final h:D


# instance fields
.field public final a:Landroid/util/Size;

.field public final b:Landroid/util/Rational;

.field public final c:Landroid/util/Rational;

.field public final d:Ljava/util/HashSet;

.field public final e:Lil/g;

.field public final f:Lh0/z;

.field public final g:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const-wide v0, 0x4002f684bda12f68L    # 2.3703703703703702

    .line 2
    .line 3
    .line 4
    .line 5
    .line 6
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    sput-wide v0, Lt0/b;->h:D

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Lh0/b0;Ljava/util/HashSet;)V
    .locals 6

    .line 1
    invoke-interface {p1}, Lh0/b0;->l()Lh0/z;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0}, Lh0/z;->g()Landroid/graphics/Rect;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-static {v0}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-interface {p1}, Lh0/b0;->l()Lh0/z;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    new-instance v1, Lil/g;

    .line 18
    .line 19
    invoke-direct {v1, p1, v0}, Lil/g;-><init>(Lh0/z;Landroid/util/Size;)V

    .line 20
    .line 21
    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    .line 24
    .line 25
    new-instance v2, Ljava/util/HashMap;

    .line 26
    .line 27
    invoke-direct {v2}, Ljava/util/HashMap;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v2, p0, Lt0/b;->g:Ljava/util/HashMap;

    .line 31
    .line 32
    iput-object v0, p0, Lt0/b;->a:Landroid/util/Size;

    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/util/Size;->getWidth()I

    .line 35
    .line 36
    .line 37
    move-result v2

    .line 38
    int-to-double v2, v2

    .line 39
    invoke-virtual {v0}, Landroid/util/Size;->getHeight()I

    .line 40
    .line 41
    .line 42
    move-result v4

    .line 43
    int-to-double v4, v4

    .line 44
    div-double/2addr v2, v4

    .line 45
    sget-wide v4, Lt0/b;->h:D

    .line 46
    .line 47
    cmpl-double v2, v2, v4

    .line 48
    .line 49
    if-lez v2, :cond_0

    .line 50
    .line 51
    sget-object v2, Li0/b;->c:Landroid/util/Rational;

    .line 52
    .line 53
    goto :goto_0

    .line 54
    :cond_0
    sget-object v2, Li0/b;->a:Landroid/util/Rational;

    .line 55
    .line 56
    :goto_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 57
    .line 58
    const-string v4, "The closer aspect ratio to the sensor size ("

    .line 59
    .line 60
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v0, ") is "

    .line 67
    .line 68
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    const-string v0, "."

    .line 75
    .line 76
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    const-string v3, "ResolutionsMerger"

    .line 84
    .line 85
    invoke-static {v3, v0}, Ljp/v1;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iput-object v2, p0, Lt0/b;->b:Landroid/util/Rational;

    .line 89
    .line 90
    sget-object v0, Li0/b;->a:Landroid/util/Rational;

    .line 91
    .line 92
    invoke-virtual {v2, v0}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    if-eqz v3, :cond_1

    .line 97
    .line 98
    sget-object v0, Li0/b;->c:Landroid/util/Rational;

    .line 99
    .line 100
    goto :goto_1

    .line 101
    :cond_1
    sget-object v3, Li0/b;->c:Landroid/util/Rational;

    .line 102
    .line 103
    invoke-virtual {v2, v3}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 104
    .line 105
    .line 106
    move-result v3

    .line 107
    if-eqz v3, :cond_2

    .line 108
    .line 109
    :goto_1
    iput-object v0, p0, Lt0/b;->c:Landroid/util/Rational;

    .line 110
    .line 111
    iput-object p1, p0, Lt0/b;->f:Lh0/z;

    .line 112
    .line 113
    iput-object p2, p0, Lt0/b;->d:Ljava/util/HashSet;

    .line 114
    .line 115
    iput-object v1, p0, Lt0/b;->e:Lil/g;

    .line 116
    .line 117
    return-void

    .line 118
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 119
    .line 120
    new-instance p1, Ljava/lang/StringBuilder;

    .line 121
    .line 122
    const-string p2, "Invalid sensor aspect-ratio: "

    .line 123
    .line 124
    invoke-direct {p1, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    throw p0
.end method

.method public static a(Landroid/util/Size;Landroid/util/Size;)Landroid/graphics/Rect;
    .locals 4

    .line 1
    invoke-static {p1}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-static {p0}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    cmpl-float v2, v2, v3

    .line 26
    .line 27
    const/4 v3, 0x0

    .line 28
    if-nez v2, :cond_0

    .line 29
    .line 30
    new-instance p0, Landroid/graphics/RectF;

    .line 31
    .line 32
    int-to-float p1, v0

    .line 33
    int-to-float v0, v1

    .line 34
    invoke-direct {p0, v3, v3, p1, v0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 35
    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_0
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 43
    .line 44
    .line 45
    move-result p0

    .line 46
    cmpl-float p0, v2, p0

    .line 47
    .line 48
    const/high16 v2, 0x40000000    # 2.0f

    .line 49
    .line 50
    if-lez p0, :cond_1

    .line 51
    .line 52
    int-to-float p0, v0

    .line 53
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    div-float p1, p0, p1

    .line 58
    .line 59
    int-to-float v0, v1

    .line 60
    sub-float/2addr v0, p1

    .line 61
    div-float/2addr v0, v2

    .line 62
    new-instance v1, Landroid/graphics/RectF;

    .line 63
    .line 64
    add-float/2addr p1, v0

    .line 65
    invoke-direct {v1, v3, v0, p0, p1}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 66
    .line 67
    .line 68
    :goto_0
    move-object p0, v1

    .line 69
    goto :goto_1

    .line 70
    :cond_1
    int-to-float p0, v1

    .line 71
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 72
    .line 73
    .line 74
    move-result p1

    .line 75
    mul-float/2addr p1, p0

    .line 76
    int-to-float v0, v0

    .line 77
    sub-float/2addr v0, p1

    .line 78
    div-float/2addr v0, v2

    .line 79
    new-instance v1, Landroid/graphics/RectF;

    .line 80
    .line 81
    add-float/2addr p1, v0

    .line 82
    invoke-direct {v1, v0, v3, p1, p0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 83
    .line 84
    .line 85
    goto :goto_0

    .line 86
    :goto_1
    new-instance p1, Landroid/graphics/Rect;

    .line 87
    .line 88
    invoke-direct {p1}, Landroid/graphics/Rect;-><init>()V

    .line 89
    .line 90
    .line 91
    invoke-virtual {p0, p1}, Landroid/graphics/RectF;->round(Landroid/graphics/Rect;)V

    .line 92
    .line 93
    .line 94
    return-object p1
.end method

.method public static d(Landroid/util/Size;Landroid/util/Size;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/util/Size;->getHeight()I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    if-gt v0, v1, :cond_1

    .line 10
    .line 11
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    invoke-virtual {p1}, Landroid/util/Size;->getWidth()I

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-le p0, p1, :cond_0

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 25
    return p0
.end method

.method public static h(Landroid/util/Size;)Landroid/util/Rational;
    .locals 2

    .line 1
    new-instance v0, Landroid/util/Rational;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-direct {v0, v1, p0}, Landroid/util/Rational;-><init>(II)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method


# virtual methods
.method public final b(Lh0/o2;Landroid/graphics/Rect;IZ)Lt0/a;
    .locals 4

    .line 1
    invoke-static {p3}, Li0/f;->c(I)Z

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    if-eqz p3, :cond_0

    .line 6
    .line 7
    new-instance p3, Landroid/graphics/Rect;

    .line 8
    .line 9
    iget v0, p2, Landroid/graphics/Rect;->top:I

    .line 10
    .line 11
    iget v1, p2, Landroid/graphics/Rect;->left:I

    .line 12
    .line 13
    iget v2, p2, Landroid/graphics/Rect;->bottom:I

    .line 14
    .line 15
    iget p2, p2, Landroid/graphics/Rect;->right:I

    .line 16
    .line 17
    invoke-direct {p3, v0, v1, v2, p2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 18
    .line 19
    .line 20
    const/4 p2, 0x1

    .line 21
    move-object v3, p3

    .line 22
    move p3, p2

    .line 23
    move-object p2, v3

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p3, 0x0

    .line 26
    :goto_0
    if-eqz p4, :cond_3

    .line 27
    .line 28
    invoke-static {p2}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 29
    .line 30
    .line 31
    move-result-object p4

    .line 32
    invoke-virtual {p0, p1}, Lt0/b;->c(Lh0/o2;)Ljava/util/List;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 41
    .line 42
    .line 43
    move-result p1

    .line 44
    if-eqz p1, :cond_2

    .line 45
    .line 46
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object p1

    .line 50
    check-cast p1, Landroid/util/Size;

    .line 51
    .line 52
    invoke-static {p1, p4}, Lt0/b;->a(Landroid/util/Size;Landroid/util/Size;)Landroid/graphics/Rect;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    invoke-static {v0}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-static {v0, p4}, Lt0/b;->d(Landroid/util/Size;Landroid/util/Size;)Z

    .line 61
    .line 62
    .line 63
    move-result v1

    .line 64
    if-nez v1, :cond_1

    .line 65
    .line 66
    invoke-static {p1, v0}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    goto :goto_1

    .line 71
    :cond_2
    invoke-static {p4, p4}, Landroid/util/Pair;->create(Ljava/lang/Object;Ljava/lang/Object;)Landroid/util/Pair;

    .line 72
    .line 73
    .line 74
    move-result-object p0

    .line 75
    :goto_1
    iget-object p1, p0, Landroid/util/Pair;->first:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast p1, Landroid/util/Size;

    .line 78
    .line 79
    iget-object p0, p0, Landroid/util/Pair;->second:Ljava/lang/Object;

    .line 80
    .line 81
    check-cast p0, Landroid/util/Size;

    .line 82
    .line 83
    goto :goto_5

    .line 84
    :cond_3
    invoke-static {p2}, Li0/f;->f(Landroid/graphics/Rect;)Landroid/util/Size;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    invoke-virtual {p0, p1}, Lt0/b;->c(Lh0/o2;)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object p4

    .line 96
    :cond_4
    :goto_2
    invoke-interface {p4}, Ljava/util/Iterator;->hasNext()Z

    .line 97
    .line 98
    .line 99
    move-result v0

    .line 100
    if-eqz v0, :cond_8

    .line 101
    .line 102
    invoke-interface {p4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    check-cast v0, Landroid/util/Size;

    .line 107
    .line 108
    sget-object v1, Li0/b;->a:Landroid/util/Rational;

    .line 109
    .line 110
    invoke-static {v1, p2}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 111
    .line 112
    .line 113
    move-result v2

    .line 114
    if-eqz v2, :cond_5

    .line 115
    .line 116
    goto :goto_3

    .line 117
    :cond_5
    sget-object v1, Li0/b;->c:Landroid/util/Rational;

    .line 118
    .line 119
    invoke-static {v1, p2}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-eqz v2, :cond_6

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_6
    invoke-static {p2}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 127
    .line 128
    .line 129
    move-result-object v1

    .line 130
    :goto_3
    invoke-virtual {p0, v1, v0}, Lt0/b;->e(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    if-eqz v1, :cond_7

    .line 135
    .line 136
    goto :goto_2

    .line 137
    :cond_7
    invoke-static {v0, p2}, Lt0/b;->d(Landroid/util/Size;Landroid/util/Size;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-nez v1, :cond_4

    .line 142
    .line 143
    move-object p1, v0

    .line 144
    goto :goto_4

    .line 145
    :cond_8
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 146
    .line 147
    .line 148
    move-result-object p0

    .line 149
    :cond_9
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 150
    .line 151
    .line 152
    move-result p1

    .line 153
    if-eqz p1, :cond_a

    .line 154
    .line 155
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 156
    .line 157
    .line 158
    move-result-object p1

    .line 159
    check-cast p1, Landroid/util/Size;

    .line 160
    .line 161
    invoke-static {p1, p2}, Lt0/b;->d(Landroid/util/Size;Landroid/util/Size;)Z

    .line 162
    .line 163
    .line 164
    move-result p4

    .line 165
    if-nez p4, :cond_9

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_a
    move-object p1, p2

    .line 169
    :goto_4
    invoke-static {p2, p1}, Lt0/b;->a(Landroid/util/Size;Landroid/util/Size;)Landroid/graphics/Rect;

    .line 170
    .line 171
    .line 172
    move-result-object p2

    .line 173
    move-object p0, p1

    .line 174
    :goto_5
    new-instance p4, Lt0/a;

    .line 175
    .line 176
    invoke-direct {p4, p2, p0, p1}, Lt0/a;-><init>(Landroid/graphics/Rect;Landroid/util/Size;Landroid/util/Size;)V

    .line 177
    .line 178
    .line 179
    if-eqz p3, :cond_b

    .line 180
    .line 181
    new-instance p3, Lt0/a;

    .line 182
    .line 183
    new-instance p4, Landroid/graphics/Rect;

    .line 184
    .line 185
    iget v0, p2, Landroid/graphics/Rect;->top:I

    .line 186
    .line 187
    iget v1, p2, Landroid/graphics/Rect;->left:I

    .line 188
    .line 189
    iget v2, p2, Landroid/graphics/Rect;->bottom:I

    .line 190
    .line 191
    iget p2, p2, Landroid/graphics/Rect;->right:I

    .line 192
    .line 193
    invoke-direct {p4, v0, v1, v2, p2}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 194
    .line 195
    .line 196
    new-instance p2, Landroid/util/Size;

    .line 197
    .line 198
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    invoke-virtual {p0}, Landroid/util/Size;->getWidth()I

    .line 203
    .line 204
    .line 205
    move-result p0

    .line 206
    invoke-direct {p2, v0, p0}, Landroid/util/Size;-><init>(II)V

    .line 207
    .line 208
    .line 209
    invoke-direct {p3, p4, p2, p1}, Lt0/a;-><init>(Landroid/graphics/Rect;Landroid/util/Size;Landroid/util/Size;)V

    .line 210
    .line 211
    .line 212
    return-object p3

    .line 213
    :cond_b
    return-object p4
.end method

.method public final c(Lh0/o2;)Ljava/util/List;
    .locals 8

    .line 1
    iget-object v0, p0, Lt0/b;->d:Ljava/util/HashSet;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-eqz v0, :cond_7

    .line 8
    .line 9
    iget-object v0, p0, Lt0/b;->g:Ljava/util/HashMap;

    .line 10
    .line 11
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->containsKey(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    invoke-virtual {v0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/util/List;

    .line 22
    .line 23
    invoke-static {p0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    check-cast p0, Ljava/util/List;

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    iget-object p0, p0, Lt0/b;->e:Lil/g;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lil/g;->J(Lh0/o2;)Ljava/util/ArrayList;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    new-instance v1, Ljava/util/HashMap;

    .line 36
    .line 37
    invoke-direct {v1}, Ljava/util/HashMap;-><init>()V

    .line 38
    .line 39
    .line 40
    new-instance v2, Ljava/util/ArrayList;

    .line 41
    .line 42
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 43
    .line 44
    .line 45
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    :cond_1
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_6

    .line 54
    .line 55
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, Landroid/util/Size;

    .line 60
    .line 61
    invoke-virtual {v1}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 62
    .line 63
    .line 64
    move-result-object v4

    .line 65
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 66
    .line 67
    .line 68
    move-result-object v4

    .line 69
    :cond_2
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result v5

    .line 73
    if-eqz v5, :cond_3

    .line 74
    .line 75
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v5

    .line 79
    check-cast v5, Landroid/util/Rational;

    .line 80
    .line 81
    invoke-static {v5, v3}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 82
    .line 83
    .line 84
    move-result v6

    .line 85
    if-eqz v6, :cond_2

    .line 86
    .line 87
    goto :goto_1

    .line 88
    :cond_3
    const/4 v5, 0x0

    .line 89
    :goto_1
    if-eqz v5, :cond_4

    .line 90
    .line 91
    invoke-virtual {v1, v5}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v4

    .line 95
    check-cast v4, Landroid/util/Size;

    .line 96
    .line 97
    invoke-static {v4}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 101
    .line 102
    .line 103
    move-result v6

    .line 104
    invoke-virtual {v4}, Landroid/util/Size;->getHeight()I

    .line 105
    .line 106
    .line 107
    move-result v7

    .line 108
    if-gt v6, v7, :cond_1

    .line 109
    .line 110
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 111
    .line 112
    .line 113
    move-result v6

    .line 114
    invoke-virtual {v4}, Landroid/util/Size;->getWidth()I

    .line 115
    .line 116
    .line 117
    move-result v7

    .line 118
    if-gt v6, v7, :cond_1

    .line 119
    .line 120
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 121
    .line 122
    .line 123
    move-result v6

    .line 124
    invoke-virtual {v4}, Landroid/util/Size;->getWidth()I

    .line 125
    .line 126
    .line 127
    move-result v7

    .line 128
    if-ne v6, v7, :cond_5

    .line 129
    .line 130
    invoke-virtual {v3}, Landroid/util/Size;->getHeight()I

    .line 131
    .line 132
    .line 133
    move-result v6

    .line 134
    invoke-virtual {v4}, Landroid/util/Size;->getHeight()I

    .line 135
    .line 136
    .line 137
    move-result v4

    .line 138
    if-ne v6, v4, :cond_5

    .line 139
    .line 140
    goto :goto_0

    .line 141
    :cond_4
    invoke-static {v3}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 142
    .line 143
    .line 144
    move-result-object v5

    .line 145
    :cond_5
    invoke-virtual {v2, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 146
    .line 147
    .line 148
    invoke-virtual {v1, v5, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 149
    .line 150
    .line 151
    goto :goto_0

    .line 152
    :cond_6
    invoke-virtual {v0, p1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    return-object v2

    .line 156
    :cond_7
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 157
    .line 158
    new-instance v0, Ljava/lang/StringBuilder;

    .line 159
    .line 160
    const-string v1, "Invalid child config: "

    .line 161
    .line 162
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object p1

    .line 172
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 173
    .line 174
    .line 175
    throw p0
.end method

.method public final e(Landroid/util/Rational;Landroid/util/Size;)Z
    .locals 2

    .line 1
    iget-object p0, p0, Lt0/b;->b:Landroid/util/Rational;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_5

    .line 8
    .line 9
    invoke-static {p1, p2}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    goto :goto_2

    .line 16
    :cond_0
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 21
    .line 22
    .line 23
    move-result p1

    .line 24
    sget-object v0, Li0/b;->a:Landroid/util/Rational;

    .line 25
    .line 26
    invoke-static {v0, p2}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 27
    .line 28
    .line 29
    move-result v1

    .line 30
    if-eqz v1, :cond_1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_1
    sget-object v0, Li0/b;->c:Landroid/util/Rational;

    .line 34
    .line 35
    invoke-static {v0, p2}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_2

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static {p2}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    :goto_0
    invoke-virtual {v0}, Landroid/util/Rational;->floatValue()F

    .line 47
    .line 48
    .line 49
    move-result p2

    .line 50
    cmpl-float p0, p0, p1

    .line 51
    .line 52
    if-eqz p0, :cond_5

    .line 53
    .line 54
    cmpl-float v0, p1, p2

    .line 55
    .line 56
    if-nez v0, :cond_3

    .line 57
    .line 58
    goto :goto_2

    .line 59
    :cond_3
    if-lez p0, :cond_4

    .line 60
    .line 61
    cmpg-float p0, p1, p2

    .line 62
    .line 63
    if-gez p0, :cond_5

    .line 64
    .line 65
    goto :goto_1

    .line 66
    :cond_4
    if-lez v0, :cond_5

    .line 67
    .line 68
    :goto_1
    const/4 p0, 0x1

    .line 69
    return p0

    .line 70
    :cond_5
    :goto_2
    const/4 p0, 0x0

    .line 71
    return p0
.end method

.method public final f(Ljava/util/List;Z)Ljava/util/ArrayList;
    .locals 6

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sget-object v1, Li0/b;->a:Landroid/util/Rational;

    .line 7
    .line 8
    new-instance v2, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0, v1, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    sget-object v2, Li0/b;->c:Landroid/util/Rational;

    .line 17
    .line 18
    new-instance v3, Ljava/util/ArrayList;

    .line 19
    .line 20
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 21
    .line 22
    .line 23
    invoke-virtual {v0, v2, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    new-instance v3, Ljava/util/ArrayList;

    .line 27
    .line 28
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v3, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 32
    .line 33
    .line 34
    invoke-virtual {v3, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 42
    .line 43
    .line 44
    move-result v1

    .line 45
    if-eqz v1, :cond_4

    .line 46
    .line 47
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    check-cast v1, Landroid/util/Size;

    .line 52
    .line 53
    invoke-virtual {v1}, Landroid/util/Size;->getHeight()I

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-gtz v2, :cond_0

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_0
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    :cond_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 65
    .line 66
    .line 67
    move-result v4

    .line 68
    if-eqz v4, :cond_2

    .line 69
    .line 70
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v4

    .line 74
    check-cast v4, Landroid/util/Rational;

    .line 75
    .line 76
    invoke-static {v4, v1}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 77
    .line 78
    .line 79
    move-result v5

    .line 80
    if-eqz v5, :cond_1

    .line 81
    .line 82
    invoke-virtual {v0, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    check-cast v2, Ljava/util/List;

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_2
    const/4 v2, 0x0

    .line 90
    :goto_1
    if-nez v2, :cond_3

    .line 91
    .line 92
    new-instance v2, Ljava/util/ArrayList;

    .line 93
    .line 94
    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 95
    .line 96
    .line 97
    invoke-static {v1}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    invoke-virtual {v3, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 102
    .line 103
    .line 104
    invoke-virtual {v0, v4, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    :cond_3
    check-cast v2, Ljava/util/List;

    .line 108
    .line 109
    invoke-interface {v2, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 110
    .line 111
    .line 112
    goto :goto_0

    .line 113
    :cond_4
    new-instance p1, Ljava/util/ArrayList;

    .line 114
    .line 115
    invoke-virtual {v0}, Ljava/util/HashMap;->keySet()Ljava/util/Set;

    .line 116
    .line 117
    .line 118
    move-result-object v1

    .line 119
    invoke-direct {p1, v1}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 120
    .line 121
    .line 122
    iget-object v1, p0, Lt0/b;->a:Landroid/util/Size;

    .line 123
    .line 124
    invoke-static {v1}, Lt0/b;->h(Landroid/util/Size;)Landroid/util/Rational;

    .line 125
    .line 126
    .line 127
    move-result-object v1

    .line 128
    new-instance v2, Ld4/b0;

    .line 129
    .line 130
    const/4 v3, 0x4

    .line 131
    invoke-direct {v2, v1, v3}, Ld4/b0;-><init>(Ljava/lang/Object;I)V

    .line 132
    .line 133
    .line 134
    invoke-static {p1, v2}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 135
    .line 136
    .line 137
    new-instance v1, Ljava/util/ArrayList;

    .line 138
    .line 139
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 140
    .line 141
    .line 142
    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    :cond_5
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 147
    .line 148
    .line 149
    move-result v2

    .line 150
    if-eqz v2, :cond_7

    .line 151
    .line 152
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 153
    .line 154
    .line 155
    move-result-object v2

    .line 156
    check-cast v2, Landroid/util/Rational;

    .line 157
    .line 158
    sget-object v3, Li0/b;->c:Landroid/util/Rational;

    .line 159
    .line 160
    invoke-virtual {v2, v3}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v3

    .line 164
    if-nez v3, :cond_5

    .line 165
    .line 166
    sget-object v3, Li0/b;->a:Landroid/util/Rational;

    .line 167
    .line 168
    invoke-virtual {v2, v3}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 169
    .line 170
    .line 171
    move-result v3

    .line 172
    if-eqz v3, :cond_6

    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_6
    invoke-virtual {v0, v2}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 176
    .line 177
    .line 178
    move-result-object v3

    .line 179
    check-cast v3, Ljava/util/List;

    .line 180
    .line 181
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 182
    .line 183
    .line 184
    check-cast v3, Ljava/util/List;

    .line 185
    .line 186
    invoke-virtual {p0, v2, v3, p2}, Lt0/b;->g(Landroid/util/Rational;Ljava/util/List;Z)Ljava/util/ArrayList;

    .line 187
    .line 188
    .line 189
    move-result-object v2

    .line 190
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 191
    .line 192
    .line 193
    goto :goto_2

    .line 194
    :cond_7
    return-object v1
.end method

.method public final g(Landroid/util/Rational;Ljava/util/List;Z)Ljava/util/ArrayList;
    .locals 9

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    :cond_0
    :goto_0
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    check-cast v1, Landroid/util/Size;

    .line 21
    .line 22
    invoke-static {p1, v1}, Li0/b;->a(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    if-eqz v2, :cond_0

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    new-instance p2, Li0/c;

    .line 33
    .line 34
    const/4 v1, 0x1

    .line 35
    invoke-direct {p2, v1}, Li0/c;-><init>(Z)V

    .line 36
    .line 37
    .line 38
    invoke-static {v0, p2}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 39
    .line 40
    .line 41
    new-instance p2, Ljava/util/HashSet;

    .line 42
    .line 43
    invoke-direct {p2, v0}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 44
    .line 45
    .line 46
    iget-object v2, p0, Lt0/b;->d:Ljava/util/HashSet;

    .line 47
    .line 48
    invoke-virtual {v2}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 53
    .line 54
    .line 55
    move-result v3

    .line 56
    if-eqz v3, :cond_12

    .line 57
    .line 58
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 59
    .line 60
    .line 61
    move-result-object v3

    .line 62
    check-cast v3, Lh0/o2;

    .line 63
    .line 64
    invoke-virtual {p0, v3}, Lt0/b;->c(Lh0/o2;)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object v3

    .line 68
    if-nez p3, :cond_4

    .line 69
    .line 70
    new-instance v4, Ljava/util/ArrayList;

    .line 71
    .line 72
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 73
    .line 74
    .line 75
    invoke-interface {v3}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 76
    .line 77
    .line 78
    move-result-object v3

    .line 79
    :cond_2
    :goto_2
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 80
    .line 81
    .line 82
    move-result v5

    .line 83
    if-eqz v5, :cond_3

    .line 84
    .line 85
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object v5

    .line 89
    check-cast v5, Landroid/util/Size;

    .line 90
    .line 91
    invoke-virtual {p0, p1, v5}, Lt0/b;->e(Landroid/util/Rational;Landroid/util/Size;)Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    if-nez v6, :cond_2

    .line 96
    .line 97
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_3
    move-object v3, v4

    .line 102
    :cond_4
    invoke-interface {v3}, Ljava/util/List;->isEmpty()Z

    .line 103
    .line 104
    .line 105
    move-result v4

    .line 106
    if-eqz v4, :cond_5

    .line 107
    .line 108
    new-instance p0, Ljava/util/ArrayList;

    .line 109
    .line 110
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 111
    .line 112
    .line 113
    return-object p0

    .line 114
    :cond_5
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 115
    .line 116
    .line 117
    move-result v4

    .line 118
    if-nez v4, :cond_a

    .line 119
    .line 120
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 121
    .line 122
    .line 123
    move-result v4

    .line 124
    if-eqz v4, :cond_6

    .line 125
    .line 126
    goto :goto_4

    .line 127
    :cond_6
    new-instance v4, Ljava/util/ArrayList;

    .line 128
    .line 129
    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 130
    .line 131
    .line 132
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 133
    .line 134
    .line 135
    move-result-object v0

    .line 136
    :cond_7
    :goto_3
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    if-eqz v5, :cond_9

    .line 141
    .line 142
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object v5

    .line 146
    check-cast v5, Landroid/util/Size;

    .line 147
    .line 148
    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 149
    .line 150
    .line 151
    move-result-object v6

    .line 152
    :cond_8
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 153
    .line 154
    .line 155
    move-result v7

    .line 156
    if-eqz v7, :cond_7

    .line 157
    .line 158
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v7

    .line 162
    check-cast v7, Landroid/util/Size;

    .line 163
    .line 164
    invoke-static {v7, v5}, Lt0/b;->d(Landroid/util/Size;Landroid/util/Size;)Z

    .line 165
    .line 166
    .line 167
    move-result v7

    .line 168
    if-nez v7, :cond_8

    .line 169
    .line 170
    invoke-virtual {v4, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_9
    move-object v0, v4

    .line 175
    goto :goto_5

    .line 176
    :cond_a
    :goto_4
    new-instance v0, Ljava/util/ArrayList;

    .line 177
    .line 178
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 179
    .line 180
    .line 181
    :goto_5
    invoke-interface {v3}, Ljava/util/Collection;->isEmpty()Z

    .line 182
    .line 183
    .line 184
    move-result v4

    .line 185
    if-nez v4, :cond_10

    .line 186
    .line 187
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 188
    .line 189
    .line 190
    move-result v4

    .line 191
    if-eqz v4, :cond_b

    .line 192
    .line 193
    goto :goto_8

    .line 194
    :cond_b
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 195
    .line 196
    .line 197
    move-result v4

    .line 198
    if-eqz v4, :cond_c

    .line 199
    .line 200
    move-object v4, v0

    .line 201
    goto :goto_6

    .line 202
    :cond_c
    new-instance v4, Ljava/util/ArrayList;

    .line 203
    .line 204
    new-instance v5, Ljava/util/LinkedHashSet;

    .line 205
    .line 206
    invoke-direct {v5, v0}, Ljava/util/LinkedHashSet;-><init>(Ljava/util/Collection;)V

    .line 207
    .line 208
    .line 209
    invoke-direct {v4, v5}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 210
    .line 211
    .line 212
    :goto_6
    new-instance v5, Ljava/util/ArrayList;

    .line 213
    .line 214
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 215
    .line 216
    .line 217
    invoke-interface {v4}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 218
    .line 219
    .line 220
    move-result-object v4

    .line 221
    :goto_7
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    if-eqz v6, :cond_f

    .line 226
    .line 227
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 228
    .line 229
    .line 230
    move-result-object v6

    .line 231
    check-cast v6, Landroid/util/Size;

    .line 232
    .line 233
    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 234
    .line 235
    .line 236
    move-result-object v7

    .line 237
    :cond_d
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 238
    .line 239
    .line 240
    move-result v8

    .line 241
    if-eqz v8, :cond_e

    .line 242
    .line 243
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 244
    .line 245
    .line 246
    move-result-object v8

    .line 247
    check-cast v8, Landroid/util/Size;

    .line 248
    .line 249
    invoke-static {v8, v6}, Lt0/b;->d(Landroid/util/Size;Landroid/util/Size;)Z

    .line 250
    .line 251
    .line 252
    move-result v8

    .line 253
    if-eqz v8, :cond_d

    .line 254
    .line 255
    goto :goto_7

    .line 256
    :cond_e
    invoke-virtual {v5, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 257
    .line 258
    .line 259
    goto :goto_7

    .line 260
    :cond_f
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 261
    .line 262
    .line 263
    move-result v3

    .line 264
    if-nez v3, :cond_11

    .line 265
    .line 266
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 267
    .line 268
    .line 269
    move-result v3

    .line 270
    sub-int/2addr v3, v1

    .line 271
    invoke-virtual {v5, v3}, Ljava/util/ArrayList;->remove(I)Ljava/lang/Object;

    .line 272
    .line 273
    .line 274
    goto :goto_9

    .line 275
    :cond_10
    :goto_8
    new-instance v5, Ljava/util/ArrayList;

    .line 276
    .line 277
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 278
    .line 279
    .line 280
    :cond_11
    :goto_9
    invoke-interface {p2, v5}, Ljava/util/Set;->retainAll(Ljava/util/Collection;)Z

    .line 281
    .line 282
    .line 283
    goto/16 :goto_1

    .line 284
    .line 285
    :cond_12
    new-instance p0, Ljava/util/ArrayList;

    .line 286
    .line 287
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 288
    .line 289
    .line 290
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 291
    .line 292
    .line 293
    move-result-object p1

    .line 294
    :cond_13
    :goto_a
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 295
    .line 296
    .line 297
    move-result p3

    .line 298
    if-eqz p3, :cond_14

    .line 299
    .line 300
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 301
    .line 302
    .line 303
    move-result-object p3

    .line 304
    check-cast p3, Landroid/util/Size;

    .line 305
    .line 306
    invoke-virtual {p2, p3}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 307
    .line 308
    .line 309
    move-result v0

    .line 310
    if-nez v0, :cond_13

    .line 311
    .line 312
    invoke-virtual {p0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 313
    .line 314
    .line 315
    goto :goto_a

    .line 316
    :cond_14
    return-object p0
.end method

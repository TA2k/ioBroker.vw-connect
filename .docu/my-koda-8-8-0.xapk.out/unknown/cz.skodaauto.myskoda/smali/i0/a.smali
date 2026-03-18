.class public final Li0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Comparator;


# instance fields
.field public final synthetic d:I

.field public final e:Ljava/lang/Object;

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/util/Rational;Landroid/util/Rational;)V
    .locals 2

    const/4 v0, 0x0

    iput v0, p0, Li0/a;->d:I

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p2, :cond_0

    goto :goto_0

    .line 3
    :cond_0
    new-instance p2, Landroid/util/Rational;

    const/4 v0, 0x4

    const/4 v1, 0x3

    invoke-direct {p2, v0, v1}, Landroid/util/Rational;-><init>(II)V

    :goto_0
    iput-object p2, p0, Li0/a;->f:Ljava/lang/Object;

    .line 4
    invoke-virtual {p0, p1}, Li0/a;->b(Landroid/util/Rational;)Landroid/graphics/RectF;

    move-result-object p1

    iput-object p1, p0, Li0/a;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/LinkedHashMap;Lx31/n;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Li0/a;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Li0/a;->e:Ljava/lang/Object;

    iput-object p2, p0, Li0/a;->f:Ljava/lang/Object;

    return-void
.end method

.method public static a(Landroid/graphics/RectF;Landroid/graphics/RectF;)F
    .locals 3

    .line 1
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    cmpg-float v0, v0, v1

    .line 10
    .line 11
    if-gez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    :goto_0
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 23
    .line 24
    .line 25
    move-result v1

    .line 26
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 27
    .line 28
    .line 29
    move-result v2

    .line 30
    cmpg-float v1, v1, v2

    .line 31
    .line 32
    if-gez v1, :cond_1

    .line 33
    .line 34
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    goto :goto_1

    .line 39
    :cond_1
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 40
    .line 41
    .line 42
    move-result p0

    .line 43
    :goto_1
    mul-float/2addr v0, p0

    .line 44
    return v0
.end method


# virtual methods
.method public b(Landroid/util/Rational;)Landroid/graphics/RectF;
    .locals 4

    .line 1
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget-object p0, p0, Li0/a;->f:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Landroid/util/Rational;

    .line 8
    .line 9
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    cmpl-float v0, v0, v1

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    if-nez v0, :cond_0

    .line 17
    .line 18
    new-instance p1, Landroid/graphics/RectF;

    .line 19
    .line 20
    invoke-virtual {p0}, Landroid/util/Rational;->getNumerator()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    int-to-float v0, v0

    .line 25
    invoke-virtual {p0}, Landroid/util/Rational;->getDenominator()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    int-to-float p0, p0

    .line 30
    invoke-direct {p1, v1, v1, v0, p0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 31
    .line 32
    .line 33
    return-object p1

    .line 34
    :cond_0
    invoke-virtual {p1}, Landroid/util/Rational;->floatValue()F

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-virtual {p0}, Landroid/util/Rational;->floatValue()F

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    cmpl-float v0, v0, v2

    .line 43
    .line 44
    if-lez v0, :cond_1

    .line 45
    .line 46
    new-instance v0, Landroid/graphics/RectF;

    .line 47
    .line 48
    invoke-virtual {p0}, Landroid/util/Rational;->getNumerator()I

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    int-to-float v2, v2

    .line 53
    invoke-virtual {p1}, Landroid/util/Rational;->getDenominator()I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    int-to-float v3, v3

    .line 58
    invoke-virtual {p0}, Landroid/util/Rational;->getNumerator()I

    .line 59
    .line 60
    .line 61
    move-result p0

    .line 62
    int-to-float p0, p0

    .line 63
    mul-float/2addr v3, p0

    .line 64
    invoke-virtual {p1}, Landroid/util/Rational;->getNumerator()I

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    int-to-float p0, p0

    .line 69
    div-float/2addr v3, p0

    .line 70
    invoke-direct {v0, v1, v1, v2, v3}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 71
    .line 72
    .line 73
    return-object v0

    .line 74
    :cond_1
    new-instance v0, Landroid/graphics/RectF;

    .line 75
    .line 76
    invoke-virtual {p1}, Landroid/util/Rational;->getNumerator()I

    .line 77
    .line 78
    .line 79
    move-result v2

    .line 80
    int-to-float v2, v2

    .line 81
    invoke-virtual {p0}, Landroid/util/Rational;->getDenominator()I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    int-to-float v3, v3

    .line 86
    mul-float/2addr v2, v3

    .line 87
    invoke-virtual {p1}, Landroid/util/Rational;->getDenominator()I

    .line 88
    .line 89
    .line 90
    move-result p1

    .line 91
    int-to-float p1, p1

    .line 92
    div-float/2addr v2, p1

    .line 93
    invoke-virtual {p0}, Landroid/util/Rational;->getDenominator()I

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    int-to-float p0, p0

    .line 98
    invoke-direct {v0, v1, v1, v2, p0}, Landroid/graphics/RectF;-><init>(FFFF)V

    .line 99
    .line 100
    .line 101
    return-object v0
.end method

.method public final compare(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 5

    .line 1
    iget v0, p0, Li0/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li0/a;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Lx31/n;

    .line 9
    .line 10
    check-cast p1, Lp31/f;

    .line 11
    .line 12
    iget-object p0, p0, Li0/a;->e:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast p0, Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    iget-object p1, p1, Lp31/f;->a:Li31/e;

    .line 17
    .line 18
    iget-object p1, p1, Li31/e;->g:Ljava/lang/String;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, Lp31/f;

    .line 25
    .line 26
    const v1, 0x7fffffff

    .line 27
    .line 28
    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    iget-object v2, v0, Lx31/n;->m:Lv2/o;

    .line 32
    .line 33
    invoke-virtual {v2, p1}, Lv2/o;->indexOf(Ljava/lang/Object;)I

    .line 34
    .line 35
    .line 36
    move-result p1

    .line 37
    goto :goto_0

    .line 38
    :cond_0
    move p1, v1

    .line 39
    :goto_0
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 40
    .line 41
    .line 42
    move-result-object p1

    .line 43
    check-cast p2, Lp31/f;

    .line 44
    .line 45
    iget-object p2, p2, Lp31/f;->a:Li31/e;

    .line 46
    .line 47
    iget-object p2, p2, Li31/e;->g:Ljava/lang/String;

    .line 48
    .line 49
    invoke-virtual {p0, p2}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lp31/f;

    .line 54
    .line 55
    if-eqz p0, :cond_1

    .line 56
    .line 57
    iget-object p2, v0, Lx31/n;->m:Lv2/o;

    .line 58
    .line 59
    invoke-virtual {p2, p0}, Lv2/o;->indexOf(Ljava/lang/Object;)I

    .line 60
    .line 61
    .line 62
    move-result v1

    .line 63
    :cond_1
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    invoke-static {p1, p0}, Ljp/vc;->c(Ljava/lang/Comparable;Ljava/lang/Comparable;)I

    .line 68
    .line 69
    .line 70
    move-result p0

    .line 71
    return p0

    .line 72
    :pswitch_0
    check-cast p1, Landroid/util/Rational;

    .line 73
    .line 74
    check-cast p2, Landroid/util/Rational;

    .line 75
    .line 76
    iget-object v0, p0, Li0/a;->e:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v0, Landroid/graphics/RectF;

    .line 79
    .line 80
    invoke-virtual {p1, p2}, Landroid/util/Rational;->equals(Ljava/lang/Object;)Z

    .line 81
    .line 82
    .line 83
    move-result v1

    .line 84
    const/4 v2, 0x0

    .line 85
    if-eqz v1, :cond_2

    .line 86
    .line 87
    goto/16 :goto_2

    .line 88
    .line 89
    :cond_2
    invoke-virtual {p0, p1}, Li0/a;->b(Landroid/util/Rational;)Landroid/graphics/RectF;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    invoke-virtual {p0, p2}, Li0/a;->b(Landroid/util/Rational;)Landroid/graphics/RectF;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 98
    .line 99
    .line 100
    move-result p2

    .line 101
    invoke-virtual {v0}, Landroid/graphics/RectF;->width()F

    .line 102
    .line 103
    .line 104
    move-result v1

    .line 105
    cmpl-float p2, p2, v1

    .line 106
    .line 107
    const/4 v1, 0x1

    .line 108
    if-ltz p2, :cond_3

    .line 109
    .line 110
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 111
    .line 112
    .line 113
    move-result p2

    .line 114
    invoke-virtual {v0}, Landroid/graphics/RectF;->height()F

    .line 115
    .line 116
    .line 117
    move-result v3

    .line 118
    cmpl-float p2, p2, v3

    .line 119
    .line 120
    if-ltz p2, :cond_3

    .line 121
    .line 122
    move p2, v1

    .line 123
    goto :goto_1

    .line 124
    :cond_3
    move p2, v2

    .line 125
    :goto_1
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    invoke-virtual {v0}, Landroid/graphics/RectF;->width()F

    .line 130
    .line 131
    .line 132
    move-result v4

    .line 133
    cmpl-float v3, v3, v4

    .line 134
    .line 135
    if-ltz v3, :cond_4

    .line 136
    .line 137
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 138
    .line 139
    .line 140
    move-result v3

    .line 141
    invoke-virtual {v0}, Landroid/graphics/RectF;->height()F

    .line 142
    .line 143
    .line 144
    move-result v4

    .line 145
    cmpl-float v3, v3, v4

    .line 146
    .line 147
    if-ltz v3, :cond_4

    .line 148
    .line 149
    move v2, v1

    .line 150
    :cond_4
    if-eqz p2, :cond_5

    .line 151
    .line 152
    if-eqz v2, :cond_5

    .line 153
    .line 154
    invoke-virtual {p1}, Landroid/graphics/RectF;->width()F

    .line 155
    .line 156
    .line 157
    move-result p2

    .line 158
    invoke-virtual {p1}, Landroid/graphics/RectF;->height()F

    .line 159
    .line 160
    .line 161
    move-result p1

    .line 162
    mul-float/2addr p1, p2

    .line 163
    invoke-virtual {p0}, Landroid/graphics/RectF;->width()F

    .line 164
    .line 165
    .line 166
    move-result p2

    .line 167
    invoke-virtual {p0}, Landroid/graphics/RectF;->height()F

    .line 168
    .line 169
    .line 170
    move-result p0

    .line 171
    mul-float/2addr p0, p2

    .line 172
    sub-float/2addr p1, p0

    .line 173
    invoke-static {p1}, Ljava/lang/Math;->signum(F)F

    .line 174
    .line 175
    .line 176
    move-result p0

    .line 177
    float-to-int v2, p0

    .line 178
    goto :goto_2

    .line 179
    :cond_5
    if-eqz p2, :cond_6

    .line 180
    .line 181
    const/4 v2, -0x1

    .line 182
    goto :goto_2

    .line 183
    :cond_6
    if-eqz v2, :cond_7

    .line 184
    .line 185
    move v2, v1

    .line 186
    goto :goto_2

    .line 187
    :cond_7
    invoke-static {p1, v0}, Li0/a;->a(Landroid/graphics/RectF;Landroid/graphics/RectF;)F

    .line 188
    .line 189
    .line 190
    move-result p1

    .line 191
    invoke-static {p0, v0}, Li0/a;->a(Landroid/graphics/RectF;Landroid/graphics/RectF;)F

    .line 192
    .line 193
    .line 194
    move-result p0

    .line 195
    sub-float/2addr p1, p0

    .line 196
    invoke-static {p1}, Ljava/lang/Math;->signum(F)F

    .line 197
    .line 198
    .line 199
    move-result p0

    .line 200
    float-to-int p0, p0

    .line 201
    neg-int v2, p0

    .line 202
    :goto_2
    return v2

    .line 203
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

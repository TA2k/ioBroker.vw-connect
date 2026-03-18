.class public final Lbb/b;
.super Landroid/util/Property;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I


# direct methods
.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/Class;)V
    .locals 0

    .line 1
    iput p1, p0, Lbb/b;->a:I

    .line 2
    .line 3
    invoke-direct {p0, p3, p2}, Landroid/util/Property;-><init>(Ljava/lang/Class;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final get(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    iget p0, p0, Lbb/b;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Landroid/view/View;

    .line 7
    .line 8
    invoke-virtual {p1}, Landroid/view/View;->getClipBounds()Landroid/graphics/Rect;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0

    .line 13
    :pswitch_0
    check-cast p1, Landroid/view/View;

    .line 14
    .line 15
    invoke-virtual {p1}, Landroid/view/View;->getTransitionAlpha()F

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_1
    check-cast p1, Landroid/view/View;

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    return-object p0

    .line 28
    :pswitch_2
    check-cast p1, Landroid/view/View;

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    return-object p0

    .line 32
    :pswitch_3
    check-cast p1, Landroid/view/View;

    .line 33
    .line 34
    const/4 p0, 0x0

    .line 35
    return-object p0

    .line 36
    :pswitch_4
    check-cast p1, Lbb/e;

    .line 37
    .line 38
    const/4 p0, 0x0

    .line 39
    return-object p0

    .line 40
    :pswitch_5
    check-cast p1, Lbb/e;

    .line 41
    .line 42
    const/4 p0, 0x0

    .line 43
    return-object p0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final set(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 5

    .line 1
    iget p0, p0, Lbb/b;->a:I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    packed-switch p0, :pswitch_data_0

    .line 5
    .line 6
    .line 7
    check-cast p1, Landroid/view/View;

    .line 8
    .line 9
    check-cast p2, Landroid/graphics/Rect;

    .line 10
    .line 11
    invoke-virtual {p1, p2}, Landroid/view/View;->setClipBounds(Landroid/graphics/Rect;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    check-cast p1, Landroid/view/View;

    .line 16
    .line 17
    check-cast p2, Ljava/lang/Float;

    .line 18
    .line 19
    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-virtual {p1, p0}, Landroid/view/View;->setTransitionAlpha(F)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_1
    check-cast p1, Landroid/view/View;

    .line 28
    .line 29
    check-cast p2, Landroid/graphics/PointF;

    .line 30
    .line 31
    iget p0, p2, Landroid/graphics/PointF;->x:F

    .line 32
    .line 33
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    iget p2, p2, Landroid/graphics/PointF;->y:F

    .line 38
    .line 39
    invoke-static {p2}, Ljava/lang/Math;->round(F)I

    .line 40
    .line 41
    .line 42
    move-result p2

    .line 43
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 44
    .line 45
    .line 46
    move-result v0

    .line 47
    add-int/2addr v0, p0

    .line 48
    invoke-virtual {p1}, Landroid/view/View;->getHeight()I

    .line 49
    .line 50
    .line 51
    move-result v1

    .line 52
    add-int/2addr v1, p2

    .line 53
    sget-object v2, Lbb/i0;->a:Lbb/b;

    .line 54
    .line 55
    invoke-virtual {p1, p0, p2, v0, v1}, Landroid/view/View;->setLeftTopRightBottom(IIII)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :pswitch_2
    check-cast p1, Landroid/view/View;

    .line 60
    .line 61
    check-cast p2, Landroid/graphics/PointF;

    .line 62
    .line 63
    iget p0, p2, Landroid/graphics/PointF;->x:F

    .line 64
    .line 65
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 66
    .line 67
    .line 68
    move-result p0

    .line 69
    iget p2, p2, Landroid/graphics/PointF;->y:F

    .line 70
    .line 71
    invoke-static {p2}, Ljava/lang/Math;->round(F)I

    .line 72
    .line 73
    .line 74
    move-result p2

    .line 75
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 76
    .line 77
    .line 78
    move-result v0

    .line 79
    invoke-virtual {p1}, Landroid/view/View;->getBottom()I

    .line 80
    .line 81
    .line 82
    move-result v1

    .line 83
    sget-object v2, Lbb/i0;->a:Lbb/b;

    .line 84
    .line 85
    invoke-virtual {p1, p0, p2, v0, v1}, Landroid/view/View;->setLeftTopRightBottom(IIII)V

    .line 86
    .line 87
    .line 88
    return-void

    .line 89
    :pswitch_3
    check-cast p1, Landroid/view/View;

    .line 90
    .line 91
    check-cast p2, Landroid/graphics/PointF;

    .line 92
    .line 93
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 94
    .line 95
    .line 96
    move-result p0

    .line 97
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    iget v1, p2, Landroid/graphics/PointF;->x:F

    .line 102
    .line 103
    invoke-static {v1}, Ljava/lang/Math;->round(F)I

    .line 104
    .line 105
    .line 106
    move-result v1

    .line 107
    iget p2, p2, Landroid/graphics/PointF;->y:F

    .line 108
    .line 109
    invoke-static {p2}, Ljava/lang/Math;->round(F)I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    sget-object v2, Lbb/i0;->a:Lbb/b;

    .line 114
    .line 115
    invoke-virtual {p1, p0, v0, v1, p2}, Landroid/view/View;->setLeftTopRightBottom(IIII)V

    .line 116
    .line 117
    .line 118
    return-void

    .line 119
    :pswitch_4
    check-cast p1, Lbb/e;

    .line 120
    .line 121
    check-cast p2, Landroid/graphics/PointF;

    .line 122
    .line 123
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 124
    .line 125
    .line 126
    iget p0, p2, Landroid/graphics/PointF;->x:F

    .line 127
    .line 128
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 129
    .line 130
    .line 131
    move-result p0

    .line 132
    iput p0, p1, Lbb/e;->c:I

    .line 133
    .line 134
    iget p0, p2, Landroid/graphics/PointF;->y:F

    .line 135
    .line 136
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    iput p0, p1, Lbb/e;->d:I

    .line 141
    .line 142
    iget p2, p1, Lbb/e;->g:I

    .line 143
    .line 144
    add-int/lit8 p2, p2, 0x1

    .line 145
    .line 146
    iput p2, p1, Lbb/e;->g:I

    .line 147
    .line 148
    iget v1, p1, Lbb/e;->f:I

    .line 149
    .line 150
    if-ne v1, p2, :cond_0

    .line 151
    .line 152
    iget-object p2, p1, Lbb/e;->e:Landroid/view/View;

    .line 153
    .line 154
    iget v1, p1, Lbb/e;->a:I

    .line 155
    .line 156
    iget v2, p1, Lbb/e;->b:I

    .line 157
    .line 158
    iget v3, p1, Lbb/e;->c:I

    .line 159
    .line 160
    sget-object v4, Lbb/i0;->a:Lbb/b;

    .line 161
    .line 162
    invoke-virtual {p2, v1, v2, v3, p0}, Landroid/view/View;->setLeftTopRightBottom(IIII)V

    .line 163
    .line 164
    .line 165
    iput v0, p1, Lbb/e;->f:I

    .line 166
    .line 167
    iput v0, p1, Lbb/e;->g:I

    .line 168
    .line 169
    :cond_0
    return-void

    .line 170
    :pswitch_5
    check-cast p1, Lbb/e;

    .line 171
    .line 172
    check-cast p2, Landroid/graphics/PointF;

    .line 173
    .line 174
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 175
    .line 176
    .line 177
    iget p0, p2, Landroid/graphics/PointF;->x:F

    .line 178
    .line 179
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 180
    .line 181
    .line 182
    move-result p0

    .line 183
    iput p0, p1, Lbb/e;->a:I

    .line 184
    .line 185
    iget p0, p2, Landroid/graphics/PointF;->y:F

    .line 186
    .line 187
    invoke-static {p0}, Ljava/lang/Math;->round(F)I

    .line 188
    .line 189
    .line 190
    move-result p0

    .line 191
    iput p0, p1, Lbb/e;->b:I

    .line 192
    .line 193
    iget p2, p1, Lbb/e;->f:I

    .line 194
    .line 195
    add-int/lit8 p2, p2, 0x1

    .line 196
    .line 197
    iput p2, p1, Lbb/e;->f:I

    .line 198
    .line 199
    iget v1, p1, Lbb/e;->g:I

    .line 200
    .line 201
    if-ne p2, v1, :cond_1

    .line 202
    .line 203
    iget-object p2, p1, Lbb/e;->e:Landroid/view/View;

    .line 204
    .line 205
    iget v1, p1, Lbb/e;->a:I

    .line 206
    .line 207
    iget v2, p1, Lbb/e;->c:I

    .line 208
    .line 209
    iget v3, p1, Lbb/e;->d:I

    .line 210
    .line 211
    sget-object v4, Lbb/i0;->a:Lbb/b;

    .line 212
    .line 213
    invoke-virtual {p2, v1, p0, v2, v3}, Landroid/view/View;->setLeftTopRightBottom(IIII)V

    .line 214
    .line 215
    .line 216
    iput v0, p1, Lbb/e;->f:I

    .line 217
    .line 218
    iput v0, p1, Lbb/e;->g:I

    .line 219
    .line 220
    :cond_1
    return-void

    .line 221
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

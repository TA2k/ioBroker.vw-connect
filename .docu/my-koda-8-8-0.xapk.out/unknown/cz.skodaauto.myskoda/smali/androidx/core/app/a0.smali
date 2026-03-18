.class public abstract Landroidx/core/app/a0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Z

.field public b:Ljava/lang/Object;

.field public c:Ljava/lang/Object;

.field public d:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Landroidx/core/app/a0;->a:Z

    return-void
.end method

.method public constructor <init>(Landroid/widget/FrameLayout;Lw0/d;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Landroidx/core/app/a0;->a:Z

    .line 3
    iput-object p1, p0, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 4
    iput-object p2, p0, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public abstract a(Lcom/google/firebase/messaging/w;)V
.end method

.method public abstract b()Ljava/lang/String;
.end method

.method public abstract c()Landroid/view/View;
.end method

.method public abstract d()Landroid/graphics/Bitmap;
.end method

.method public abstract e()V
.end method

.method public abstract f()V
.end method

.method public abstract g(Lb0/x1;Lbb/i;)V
.end method

.method public h()V
    .locals 8

    .line 1
    iget-object v0, p0, Landroidx/core/app/a0;->c:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Landroid/widget/FrameLayout;

    .line 4
    .line 5
    invoke-virtual {p0}, Landroidx/core/app/a0;->c()Landroid/view/View;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    if-eqz v1, :cond_a

    .line 10
    .line 11
    iget-boolean v2, p0, Landroidx/core/app/a0;->a:Z

    .line 12
    .line 13
    if-nez v2, :cond_0

    .line 14
    .line 15
    goto/16 :goto_4

    .line 16
    .line 17
    :cond_0
    iget-object p0, p0, Landroidx/core/app/a0;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lw0/d;

    .line 20
    .line 21
    new-instance v2, Landroid/util/Size;

    .line 22
    .line 23
    invoke-virtual {v0}, Landroid/view/View;->getWidth()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    invoke-virtual {v0}, Landroid/view/View;->getHeight()I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    invoke-direct {v2, v3, v4}, Landroid/util/Size;-><init>(II)V

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Landroid/view/View;->getLayoutDirection()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 39
    .line 40
    .line 41
    invoke-virtual {v2}, Landroid/util/Size;->getHeight()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    const-string v4, "PreviewTransform"

    .line 46
    .line 47
    if-eqz v3, :cond_9

    .line 48
    .line 49
    invoke-virtual {v2}, Landroid/util/Size;->getWidth()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-nez v3, :cond_1

    .line 54
    .line 55
    goto/16 :goto_3

    .line 56
    .line 57
    :cond_1
    invoke-virtual {p0}, Lw0/d;->f()Z

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    if-nez v3, :cond_2

    .line 62
    .line 63
    goto/16 :goto_4

    .line 64
    .line 65
    :cond_2
    instance-of v3, v1, Landroid/view/TextureView;

    .line 66
    .line 67
    if-eqz v3, :cond_3

    .line 68
    .line 69
    move-object v3, v1

    .line 70
    check-cast v3, Landroid/view/TextureView;

    .line 71
    .line 72
    invoke-virtual {p0}, Lw0/d;->d()Landroid/graphics/Matrix;

    .line 73
    .line 74
    .line 75
    move-result-object v4

    .line 76
    invoke-virtual {v3, v4}, Landroid/view/TextureView;->setTransform(Landroid/graphics/Matrix;)V

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_3
    invoke-virtual {v1}, Landroid/view/View;->getDisplay()Landroid/view/Display;

    .line 81
    .line 82
    .line 83
    move-result-object v3

    .line 84
    iget-boolean v5, p0, Lw0/d;->g:Z

    .line 85
    .line 86
    const/4 v6, 0x0

    .line 87
    const/4 v7, 0x1

    .line 88
    if-eqz v5, :cond_4

    .line 89
    .line 90
    if-eqz v3, :cond_4

    .line 91
    .line 92
    invoke-virtual {v3}, Landroid/view/Display;->getRotation()I

    .line 93
    .line 94
    .line 95
    move-result v3

    .line 96
    iget v5, p0, Lw0/d;->e:I

    .line 97
    .line 98
    if-eq v3, v5, :cond_4

    .line 99
    .line 100
    move v3, v7

    .line 101
    goto :goto_0

    .line 102
    :cond_4
    move v3, v6

    .line 103
    :goto_0
    iget-boolean v5, p0, Lw0/d;->g:Z

    .line 104
    .line 105
    if-nez v5, :cond_6

    .line 106
    .line 107
    if-nez v5, :cond_5

    .line 108
    .line 109
    iget v5, p0, Lw0/d;->c:I

    .line 110
    .line 111
    goto :goto_1

    .line 112
    :cond_5
    iget v5, p0, Lw0/d;->e:I

    .line 113
    .line 114
    invoke-static {v5}, Llp/h1;->c(I)I

    .line 115
    .line 116
    .line 117
    move-result v5

    .line 118
    neg-int v5, v5

    .line 119
    :goto_1
    if-eqz v5, :cond_6

    .line 120
    .line 121
    move v6, v7

    .line 122
    :cond_6
    if-nez v3, :cond_7

    .line 123
    .line 124
    if-eqz v6, :cond_8

    .line 125
    .line 126
    :cond_7
    const-string v3, "Custom rotation not supported with SurfaceView/PERFORMANCE mode."

    .line 127
    .line 128
    invoke-static {v4, v3}, Ljp/v1;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 129
    .line 130
    .line 131
    :cond_8
    :goto_2
    invoke-virtual {p0, v2, v0}, Lw0/d;->e(Landroid/util/Size;I)Landroid/graphics/RectF;

    .line 132
    .line 133
    .line 134
    move-result-object v0

    .line 135
    const/4 v2, 0x0

    .line 136
    invoke-virtual {v1, v2}, Landroid/view/View;->setPivotX(F)V

    .line 137
    .line 138
    .line 139
    invoke-virtual {v1, v2}, Landroid/view/View;->setPivotY(F)V

    .line 140
    .line 141
    .line 142
    invoke-virtual {v0}, Landroid/graphics/RectF;->width()F

    .line 143
    .line 144
    .line 145
    move-result v2

    .line 146
    iget-object v3, p0, Lw0/d;->a:Landroid/util/Size;

    .line 147
    .line 148
    invoke-virtual {v3}, Landroid/util/Size;->getWidth()I

    .line 149
    .line 150
    .line 151
    move-result v3

    .line 152
    int-to-float v3, v3

    .line 153
    div-float/2addr v2, v3

    .line 154
    invoke-virtual {v1, v2}, Landroid/view/View;->setScaleX(F)V

    .line 155
    .line 156
    .line 157
    invoke-virtual {v0}, Landroid/graphics/RectF;->height()F

    .line 158
    .line 159
    .line 160
    move-result v2

    .line 161
    iget-object p0, p0, Lw0/d;->a:Landroid/util/Size;

    .line 162
    .line 163
    invoke-virtual {p0}, Landroid/util/Size;->getHeight()I

    .line 164
    .line 165
    .line 166
    move-result p0

    .line 167
    int-to-float p0, p0

    .line 168
    div-float/2addr v2, p0

    .line 169
    invoke-virtual {v1, v2}, Landroid/view/View;->setScaleY(F)V

    .line 170
    .line 171
    .line 172
    iget p0, v0, Landroid/graphics/RectF;->left:F

    .line 173
    .line 174
    invoke-virtual {v1}, Landroid/view/View;->getLeft()I

    .line 175
    .line 176
    .line 177
    move-result v2

    .line 178
    int-to-float v2, v2

    .line 179
    sub-float/2addr p0, v2

    .line 180
    invoke-virtual {v1, p0}, Landroid/view/View;->setTranslationX(F)V

    .line 181
    .line 182
    .line 183
    iget p0, v0, Landroid/graphics/RectF;->top:F

    .line 184
    .line 185
    invoke-virtual {v1}, Landroid/view/View;->getTop()I

    .line 186
    .line 187
    .line 188
    move-result v0

    .line 189
    int-to-float v0, v0

    .line 190
    sub-float/2addr p0, v0

    .line 191
    invoke-virtual {v1, p0}, Landroid/view/View;->setTranslationY(F)V

    .line 192
    .line 193
    .line 194
    return-void

    .line 195
    :cond_9
    :goto_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 196
    .line 197
    const-string v0, "Transform not applied due to PreviewView size: "

    .line 198
    .line 199
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 200
    .line 201
    .line 202
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 203
    .line 204
    .line 205
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 206
    .line 207
    .line 208
    move-result-object p0

    .line 209
    invoke-static {v4, p0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 210
    .line 211
    .line 212
    :cond_a
    :goto_4
    return-void
.end method

.method public abstract i()Lcom/google/common/util/concurrent/ListenableFuture;
.end method

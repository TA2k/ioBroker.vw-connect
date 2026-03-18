.class public Lcom/google/android/material/carousel/CarouselLayoutManager;
.super Lka/f0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lka/q0;


# instance fields
.field public final p:Lb1/x0;

.field public q:Lkq/d;

.field public final r:Landroid/view/View$OnLayoutChangeListener;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    new-instance v0, Lb1/x0;

    invoke-direct {v0}, Lb1/x0;-><init>()V

    .line 2
    invoke-direct {p0}, Lka/f0;-><init>()V

    .line 3
    new-instance v1, Lkq/b;

    invoke-direct {v1}, Lkq/b;-><init>()V

    .line 4
    new-instance v1, Lkq/a;

    const/4 v2, 0x0

    invoke-direct {v1, p0, v2}, Lkq/a;-><init>(Ljava/lang/Object;I)V

    iput-object v1, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->r:Landroid/view/View$OnLayoutChangeListener;

    .line 5
    iput-object v0, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->p:Lb1/x0;

    .line 6
    invoke-virtual {p0}, Lka/f0;->n0()V

    const/4 v0, 0x0

    .line 7
    invoke-virtual {p0, v0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->F0(I)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Landroid/util/AttributeSet;II)V
    .locals 0
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "UnknownNullness"
        }
    .end annotation

    .line 8
    invoke-direct {p0}, Lka/f0;-><init>()V

    .line 9
    new-instance p3, Lkq/b;

    invoke-direct {p3}, Lkq/b;-><init>()V

    .line 10
    new-instance p3, Lkq/a;

    const/4 p4, 0x0

    invoke-direct {p3, p0, p4}, Lkq/a;-><init>(Ljava/lang/Object;I)V

    iput-object p3, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->r:Landroid/view/View$OnLayoutChangeListener;

    .line 11
    new-instance p3, Lb1/x0;

    invoke-direct {p3}, Lb1/x0;-><init>()V

    .line 12
    iput-object p3, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->p:Lb1/x0;

    .line 13
    invoke-virtual {p0}, Lka/f0;->n0()V

    if-eqz p2, :cond_0

    .line 14
    sget-object p3, Ldq/a;->b:[I

    invoke-virtual {p1, p2, p3}, Landroid/content/Context;->obtainStyledAttributes(Landroid/util/AttributeSet;[I)Landroid/content/res/TypedArray;

    move-result-object p1

    const/4 p2, 0x0

    .line 15
    invoke-virtual {p1, p2, p2}, Landroid/content/res/TypedArray;->getInt(II)I

    .line 16
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 17
    invoke-virtual {p1, p2, p2}, Landroid/content/res/TypedArray;->getInt(II)I

    move-result p2

    .line 18
    invoke-virtual {p0, p2}, Lcom/google/android/material/carousel/CarouselLayoutManager;->F0(I)V

    .line 19
    invoke-virtual {p1}, Landroid/content/res/TypedArray;->recycle()V

    :cond_0
    return-void
.end method


# virtual methods
.method public final C0(FF)F
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->E0()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    sub-float/2addr p1, p2

    .line 8
    return p1

    .line 9
    :cond_0
    add-float/2addr p1, p2

    .line 10
    return p1
.end method

.method public final D0()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->q:Lkq/d;

    .line 2
    .line 3
    iget p0, p0, Lkq/d;->e:I

    .line 4
    .line 5
    if-nez p0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final E0()Z
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->D0()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lka/f0;->C()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    const/4 v0, 0x1

    .line 12
    if-ne p0, v0, :cond_0

    .line 13
    .line 14
    return v0

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return p0
.end method

.method public final F0(I)V
    .locals 2

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eqz p1, :cond_1

    .line 3
    .line 4
    if-ne p1, v0, :cond_0

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 8
    .line 9
    const-string v0, "invalid orientation:"

    .line 10
    .line 11
    invoke-static {p1, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    throw p0

    .line 19
    :cond_1
    :goto_0
    const/4 v1, 0x0

    .line 20
    invoke-virtual {p0, v1}, Lka/f0;->c(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    iget-object v1, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->q:Lkq/d;

    .line 24
    .line 25
    if-eqz v1, :cond_3

    .line 26
    .line 27
    iget v1, v1, Lkq/d;->e:I

    .line 28
    .line 29
    if-eq p1, v1, :cond_2

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_2
    return-void

    .line 33
    :cond_3
    :goto_1
    if-eqz p1, :cond_5

    .line 34
    .line 35
    if-ne p1, v0, :cond_4

    .line 36
    .line 37
    new-instance p1, Lkq/c;

    .line 38
    .line 39
    const/4 v0, 0x0

    .line 40
    invoke-direct {p1, p0, v0}, Lkq/c;-><init>(Lcom/google/android/material/carousel/CarouselLayoutManager;I)V

    .line 41
    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 45
    .line 46
    const-string p1, "invalid orientation"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_5
    new-instance p1, Lkq/c;

    .line 53
    .line 54
    const/4 v0, 0x1

    .line 55
    invoke-direct {p1, p0, v0}, Lkq/c;-><init>(Lcom/google/android/material/carousel/CarouselLayoutManager;I)V

    .line 56
    .line 57
    .line 58
    :goto_2
    iput-object p1, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->q:Lkq/d;

    .line 59
    .line 60
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 61
    .line 62
    .line 63
    return-void
.end method

.method public final L()Z
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final R(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 5

    .line 1
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-object v1, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->p:Lb1/x0;

    .line 6
    .line 7
    iget v2, v1, Lb1/x0;->d:F

    .line 8
    .line 9
    const/4 v3, 0x0

    .line 10
    cmpl-float v4, v2, v3

    .line 11
    .line 12
    if-lez v4, :cond_0

    .line 13
    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 16
    .line 17
    .line 18
    move-result-object v2

    .line 19
    const v4, 0x7f070120

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2, v4}, Landroid/content/res/Resources;->getDimension(I)F

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    :goto_0
    iput v2, v1, Lb1/x0;->d:F

    .line 27
    .line 28
    iget v2, v1, Lb1/x0;->e:F

    .line 29
    .line 30
    cmpl-float v3, v2, v3

    .line 31
    .line 32
    if-lez v3, :cond_1

    .line 33
    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    const v2, 0x7f07011f

    .line 40
    .line 41
    .line 42
    invoke-virtual {v0, v2}, Landroid/content/res/Resources;->getDimension(I)F

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    :goto_1
    iput v2, v1, Lb1/x0;->e:F

    .line 47
    .line 48
    invoke-virtual {p0}, Lka/f0;->n0()V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->r:Landroid/view/View$OnLayoutChangeListener;

    .line 52
    .line 53
    invoke-virtual {p1, p0}, Landroid/view/View;->addOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public final S(Landroidx/recyclerview/widget/RecyclerView;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->r:Landroid/view/View$OnLayoutChangeListener;

    .line 2
    .line 3
    invoke-virtual {p1, p0}, Landroid/view/View;->removeOnLayoutChangeListener(Landroid/view/View$OnLayoutChangeListener;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final T(Landroid/view/View;ILka/l0;Lka/r0;)Landroid/view/View;
    .locals 3

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    if-nez p3, :cond_0

    .line 6
    .line 7
    goto/16 :goto_4

    .line 8
    .line 9
    :cond_0
    iget-object p3, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->q:Lkq/d;

    .line 10
    .line 11
    iget p3, p3, Lkq/d;->e:I

    .line 12
    .line 13
    const/high16 p4, -0x80000000

    .line 14
    .line 15
    const/4 v0, -0x1

    .line 16
    const/4 v1, 0x1

    .line 17
    if-eq p2, v1, :cond_5

    .line 18
    .line 19
    const/4 v2, 0x2

    .line 20
    if-eq p2, v2, :cond_3

    .line 21
    .line 22
    const/16 v2, 0x11

    .line 23
    .line 24
    if-eq p2, v2, :cond_7

    .line 25
    .line 26
    const/16 v2, 0x21

    .line 27
    .line 28
    if-eq p2, v2, :cond_6

    .line 29
    .line 30
    const/16 v2, 0x42

    .line 31
    .line 32
    if-eq p2, v2, :cond_4

    .line 33
    .line 34
    const/16 v2, 0x82

    .line 35
    .line 36
    if-eq p2, v2, :cond_2

    .line 37
    .line 38
    new-instance p3, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    const-string v2, "Unknown focus request:"

    .line 41
    .line 42
    invoke-direct {p3, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p3, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p2

    .line 52
    const-string p3, "CarouselLayoutManager"

    .line 53
    .line 54
    invoke-static {p3, p2}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 55
    .line 56
    .line 57
    :cond_1
    move p2, p4

    .line 58
    goto :goto_2

    .line 59
    :cond_2
    if-ne p3, v1, :cond_1

    .line 60
    .line 61
    :cond_3
    :goto_0
    move p2, v1

    .line 62
    goto :goto_2

    .line 63
    :cond_4
    if-nez p3, :cond_1

    .line 64
    .line 65
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->E0()Z

    .line 66
    .line 67
    .line 68
    move-result p2

    .line 69
    if-eqz p2, :cond_3

    .line 70
    .line 71
    :cond_5
    :goto_1
    move p2, v0

    .line 72
    goto :goto_2

    .line 73
    :cond_6
    if-ne p3, v1, :cond_1

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_7
    if-nez p3, :cond_1

    .line 77
    .line 78
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->E0()Z

    .line 79
    .line 80
    .line 81
    move-result p2

    .line 82
    if-eqz p2, :cond_5

    .line 83
    .line 84
    goto :goto_0

    .line 85
    :goto_2
    if-ne p2, p4, :cond_8

    .line 86
    .line 87
    goto :goto_4

    .line 88
    :cond_8
    const/4 p3, 0x0

    .line 89
    if-ne p2, v0, :cond_d

    .line 90
    .line 91
    invoke-static {p1}, Lka/f0;->H(Landroid/view/View;)I

    .line 92
    .line 93
    .line 94
    move-result p1

    .line 95
    if-nez p1, :cond_9

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_9
    invoke-virtual {p0, p3}, Lka/f0;->u(I)Landroid/view/View;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    invoke-static {p1}, Lka/f0;->H(Landroid/view/View;)I

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    sub-int/2addr p1, v1

    .line 107
    if-ltz p1, :cond_b

    .line 108
    .line 109
    invoke-virtual {p0}, Lka/f0;->B()I

    .line 110
    .line 111
    .line 112
    move-result p2

    .line 113
    if-lt p1, p2, :cond_a

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_a
    iget-object p0, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->q:Lkq/d;

    .line 117
    .line 118
    invoke-virtual {p0}, Lkq/d;->j()I

    .line 119
    .line 120
    .line 121
    const/4 p0, 0x0

    .line 122
    throw p0

    .line 123
    :cond_b
    :goto_3
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->E0()Z

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    if-eqz p1, :cond_c

    .line 128
    .line 129
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    add-int/lit8 p3, p1, -0x1

    .line 134
    .line 135
    :cond_c
    invoke-virtual {p0, p3}, Lka/f0;->u(I)Landroid/view/View;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    return-object p0

    .line 140
    :cond_d
    invoke-static {p1}, Lka/f0;->H(Landroid/view/View;)I

    .line 141
    .line 142
    .line 143
    move-result p1

    .line 144
    invoke-virtual {p0}, Lka/f0;->B()I

    .line 145
    .line 146
    .line 147
    move-result p2

    .line 148
    sub-int/2addr p2, v1

    .line 149
    if-ne p1, p2, :cond_e

    .line 150
    .line 151
    :goto_4
    const/4 p0, 0x0

    .line 152
    return-object p0

    .line 153
    :cond_e
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 154
    .line 155
    .line 156
    move-result p1

    .line 157
    sub-int/2addr p1, v1

    .line 158
    invoke-virtual {p0, p1}, Lka/f0;->u(I)Landroid/view/View;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    invoke-static {p1}, Lka/f0;->H(Landroid/view/View;)I

    .line 163
    .line 164
    .line 165
    move-result p1

    .line 166
    add-int/2addr p1, v1

    .line 167
    if-ltz p1, :cond_10

    .line 168
    .line 169
    invoke-virtual {p0}, Lka/f0;->B()I

    .line 170
    .line 171
    .line 172
    move-result p2

    .line 173
    if-lt p1, p2, :cond_f

    .line 174
    .line 175
    goto :goto_5

    .line 176
    :cond_f
    iget-object p0, p0, Lcom/google/android/material/carousel/CarouselLayoutManager;->q:Lkq/d;

    .line 177
    .line 178
    invoke-virtual {p0}, Lkq/d;->j()I

    .line 179
    .line 180
    .line 181
    const/4 p0, 0x0

    .line 182
    throw p0

    .line 183
    :cond_10
    :goto_5
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->E0()Z

    .line 184
    .line 185
    .line 186
    move-result p1

    .line 187
    if-eqz p1, :cond_11

    .line 188
    .line 189
    goto :goto_6

    .line 190
    :cond_11
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 191
    .line 192
    .line 193
    move-result p1

    .line 194
    add-int/lit8 p3, p1, -0x1

    .line 195
    .line 196
    :goto_6
    invoke-virtual {p0, p3}, Lka/f0;->u(I)Landroid/view/View;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    return-object p0
.end method

.method public final U(Landroid/view/accessibility/AccessibilityEvent;)V
    .locals 1

    .line 1
    invoke-super {p0, p1}, Lka/f0;->U(Landroid/view/accessibility/AccessibilityEvent;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    if-lez v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    invoke-virtual {p0, v0}, Lka/f0;->u(I)Landroid/view/View;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    invoke-static {v0}, Lka/f0;->H(Landroid/view/View;)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    invoke-virtual {p1, v0}, Landroid/view/accessibility/AccessibilityRecord;->setFromIndex(I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    add-int/lit8 v0, v0, -0x1

    .line 27
    .line 28
    invoke-virtual {p0, v0}, Lka/f0;->u(I)Landroid/view/View;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-static {p0}, Lka/f0;->H(Landroid/view/View;)I

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    invoke-virtual {p1, p0}, Landroid/view/accessibility/AccessibilityRecord;->setToIndex(I)V

    .line 37
    .line 38
    .line 39
    :cond_0
    return-void
.end method

.method public final Y(II)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lka/f0;->B()I

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final Z()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lka/f0;->B()I

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final a(I)Landroid/graphics/PointF;
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return-object p0
.end method

.method public final b0(II)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lka/f0;->B()I

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final d()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->D0()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final d0(Lka/l0;Lka/r0;)V
    .locals 1

    .line 1
    invoke-virtual {p2}, Lka/r0;->b()I

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    if-lez p2, :cond_2

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->D0()Z

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    if-eqz p2, :cond_0

    .line 12
    .line 13
    iget p2, p0, Lka/f0;->n:I

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    iget p2, p0, Lka/f0;->o:I

    .line 17
    .line 18
    :goto_0
    int-to-float p2, p2

    .line 19
    const/4 v0, 0x0

    .line 20
    cmpg-float p2, p2, v0

    .line 21
    .line 22
    if-gtz p2, :cond_1

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->E0()Z

    .line 26
    .line 27
    .line 28
    const/4 p0, 0x0

    .line 29
    invoke-virtual {p1, p0}, Lka/l0;->d(I)Landroid/view/View;

    .line 30
    .line 31
    .line 32
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 33
    .line 34
    const-string p1, "All children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup."

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_2
    :goto_1
    invoke-virtual {p0, p1}, Lka/f0;->i0(Lka/l0;)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final e()Z
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->D0()Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    xor-int/lit8 p0, p0, 0x1

    .line 6
    .line 7
    return p0
.end method

.method public final e0(Lka/r0;)V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-nez p1, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    const/4 p1, 0x0

    .line 9
    invoke-virtual {p0, p1}, Lka/f0;->u(I)Landroid/view/View;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Lka/f0;->H(Landroid/view/View;)I

    .line 14
    .line 15
    .line 16
    return-void
.end method

.method public final j(Lka/r0;)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return p0
.end method

.method public final k(Lka/r0;)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final l(Lka/r0;)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final m(Lka/r0;)I
    .locals 0

    .line 1
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 2
    .line 3
    .line 4
    const/4 p0, 0x0

    .line 5
    return p0
.end method

.method public final m0(Landroidx/recyclerview/widget/RecyclerView;Landroid/view/View;Landroid/graphics/Rect;ZZ)Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final n(Lka/r0;)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final o(Lka/r0;)I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final o0(ILka/l0;Lka/r0;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->D0()Z

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p3, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p2, v0}, Lka/l0;->d(I)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "All children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup."

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    :goto_0
    return v0
.end method

.method public final p0(I)V
    .locals 0

    .line 1
    return-void
.end method

.method public final q0(ILka/l0;Lka/r0;)I
    .locals 1

    .line 1
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->e()Z

    .line 2
    .line 3
    .line 4
    move-result p3

    .line 5
    const/4 v0, 0x0

    .line 6
    if-eqz p3, :cond_1

    .line 7
    .line 8
    invoke-virtual {p0}, Lka/f0;->v()I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    if-eqz p0, :cond_1

    .line 13
    .line 14
    if-nez p1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p2, v0}, Lka/l0;->d(I)Landroid/view/View;

    .line 18
    .line 19
    .line 20
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 21
    .line 22
    const-string p1, "All children of a RecyclerView using CarouselLayoutManager must use MaskableFrameLayout as their root ViewGroup."

    .line 23
    .line 24
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    throw p0

    .line 28
    :cond_1
    :goto_0
    return v0
.end method

.method public final r()Lka/g0;
    .locals 1

    .line 1
    new-instance p0, Lka/g0;

    .line 2
    .line 3
    const/4 v0, -0x2

    .line 4
    invoke-direct {p0, v0, v0}, Lka/g0;-><init>(II)V

    .line 5
    .line 6
    .line 7
    return-object p0
.end method

.method public final y(Landroid/view/View;Landroid/graphics/Rect;)V
    .locals 0

    .line 1
    invoke-super {p0, p1, p2}, Lka/f0;->y(Landroid/view/View;Landroid/graphics/Rect;)V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p2}, Landroid/graphics/Rect;->centerY()I

    .line 5
    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/google/android/material/carousel/CarouselLayoutManager;->D0()Z

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p2}, Landroid/graphics/Rect;->centerX()I

    .line 14
    .line 15
    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    throw p0
.end method

.method public final z0(Landroidx/recyclerview/widget/RecyclerView;I)V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/material/datepicker/l0;

    .line 2
    .line 3
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-direct {v0, p0, p1}, Lcom/google/android/material/datepicker/l0;-><init>(Lcom/google/android/material/carousel/CarouselLayoutManager;Landroid/content/Context;)V

    .line 8
    .line 9
    .line 10
    iput p2, v0, Lka/s;->a:I

    .line 11
    .line 12
    invoke-virtual {p0, v0}, Lka/f0;->A0(Lka/s;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

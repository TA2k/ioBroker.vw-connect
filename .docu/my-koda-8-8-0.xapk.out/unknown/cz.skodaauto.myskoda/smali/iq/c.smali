.class public final Liq/c;
.super Lk6/e;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic c:I

.field public final synthetic d:Ll5/a;


# direct methods
.method public synthetic constructor <init>(Ll5/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Liq/c;->c:I

    .line 2
    .line 3
    iput-object p1, p0, Liq/c;->d:Ll5/a;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final clampViewPositionHorizontal(Landroid/view/View;II)I
    .locals 0

    .line 1
    iget p3, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 9
    .line 10
    iget-object p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 11
    .line 12
    invoke-virtual {p1}, Llp/df;->h()I

    .line 13
    .line 14
    .line 15
    move-result p1

    .line 16
    iget-object p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 17
    .line 18
    invoke-virtual {p0}, Llp/df;->g()I

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    invoke-static {p2, p1, p0}, Llp/he;->e(III)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_0
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    return p0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final clampViewPositionVertical(Landroid/view/View;II)I
    .locals 0

    .line 1
    iget p3, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p3, p0, Liq/c;->d:Ll5/a;

    .line 12
    .line 13
    check-cast p3, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 14
    .line 15
    invoke-virtual {p3}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->x()I

    .line 16
    .line 17
    .line 18
    move-result p3

    .line 19
    invoke-virtual {p0, p1}, Liq/c;->getViewVerticalDragRange(Landroid/view/View;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    invoke-static {p2, p3, p0}, Llp/he;->e(III)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    return p0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public getViewHorizontalDragRange(Landroid/view/View;)I
    .locals 1

    .line 1
    iget v0, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lk6/e;->getViewHorizontalDragRange(Landroid/view/View;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 14
    .line 15
    iget p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->l:I

    .line 16
    .line 17
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 18
    .line 19
    add-int/2addr p1, p0

    .line 20
    return p1

    .line 21
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public getViewVerticalDragRange(Landroid/view/View;)I
    .locals 1

    .line 1
    iget v0, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lk6/e;->getViewVerticalDragRange(Landroid/view/View;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 12
    .line 13
    check-cast p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 14
    .line 15
    iget-boolean p1, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->I:Z

    .line 16
    .line 17
    if-eqz p1, :cond_0

    .line 18
    .line 19
    iget p0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->V:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget p0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->G:I

    .line 23
    .line 24
    :goto_0
    return p0

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onViewDragStateChanged(I)V
    .locals 1

    .line 1
    iget v0, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 10
    .line 11
    check-cast p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 12
    .line 13
    iget-boolean p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->g:Z

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    invoke-virtual {p0, v0}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->r(I)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return-void

    .line 21
    :pswitch_0
    const/4 v0, 0x1

    .line 22
    if-ne p1, v0, :cond_1

    .line 23
    .line 24
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 25
    .line 26
    check-cast p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 27
    .line 28
    iget-boolean p1, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->K:Z

    .line 29
    .line 30
    if-eqz p1, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0, v0}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->C(I)V

    .line 33
    .line 34
    .line 35
    :cond_1
    return-void

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onViewPositionChanged(Landroid/view/View;IIII)V
    .locals 1

    .line 1
    iget p4, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch p4, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 9
    .line 10
    iget-object p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->q:Ljava/lang/ref/WeakReference;

    .line 11
    .line 12
    if-eqz p3, :cond_0

    .line 13
    .line 14
    invoke-virtual {p3}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p3

    .line 18
    check-cast p3, Landroid/view/View;

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p3, 0x0

    .line 22
    :goto_0
    if-eqz p3, :cond_1

    .line 23
    .line 24
    invoke-virtual {p3}, Landroid/view/View;->getLayoutParams()Landroid/view/ViewGroup$LayoutParams;

    .line 25
    .line 26
    .line 27
    move-result-object p4

    .line 28
    check-cast p4, Landroid/view/ViewGroup$MarginLayoutParams;

    .line 29
    .line 30
    if-eqz p4, :cond_1

    .line 31
    .line 32
    iget-object p5, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 33
    .line 34
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 35
    .line 36
    .line 37
    move-result v0

    .line 38
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    invoke-virtual {p5, p4, v0, p1}, Llp/df;->p(Landroid/view/ViewGroup$MarginLayoutParams;II)V

    .line 43
    .line 44
    .line 45
    invoke-virtual {p3, p4}, Landroid/view/View;->setLayoutParams(Landroid/view/ViewGroup$LayoutParams;)V

    .line 46
    .line 47
    .line 48
    :cond_1
    iget-object p1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->u:Ljava/util/LinkedHashSet;

    .line 49
    .line 50
    invoke-interface {p1}, Ljava/util/Set;->isEmpty()Z

    .line 51
    .line 52
    .line 53
    move-result p3

    .line 54
    if-nez p3, :cond_3

    .line 55
    .line 56
    iget-object p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 57
    .line 58
    invoke-virtual {p0, p2}, Llp/df;->c(I)F

    .line 59
    .line 60
    .line 61
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 66
    .line 67
    .line 68
    move-result p1

    .line 69
    if-nez p1, :cond_2

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    invoke-static {p0}, Lf2/m0;->e(Ljava/util/Iterator;)Ljava/lang/ClassCastException;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    throw p0

    .line 77
    :cond_3
    :goto_1
    return-void

    .line 78
    :pswitch_0
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 79
    .line 80
    check-cast p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 81
    .line 82
    invoke-virtual {p0, p3}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->u(I)V

    .line 83
    .line 84
    .line 85
    return-void

    .line 86
    nop

    .line 87
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final onViewReleased(Landroid/view/View;FF)V
    .locals 4

    .line 1
    iget v0, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 9
    .line 10
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 11
    .line 12
    invoke-virtual {v0, p2}, Llp/df;->l(F)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 20
    .line 21
    invoke-virtual {v0, p1, p2}, Llp/df;->o(Landroid/view/View;F)Z

    .line 22
    .line 23
    .line 24
    move-result v0

    .line 25
    if-eqz v0, :cond_1

    .line 26
    .line 27
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 28
    .line 29
    invoke-virtual {v0, p2, p3}, Llp/df;->n(FF)Z

    .line 30
    .line 31
    .line 32
    move-result p2

    .line 33
    if-nez p2, :cond_4

    .line 34
    .line 35
    iget-object p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 36
    .line 37
    invoke-virtual {p2, p1}, Llp/df;->m(Landroid/view/View;)Z

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    if-eqz p2, :cond_3

    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    const/4 v0, 0x0

    .line 45
    cmpl-float v0, p2, v0

    .line 46
    .line 47
    if-eqz v0, :cond_2

    .line 48
    .line 49
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 50
    .line 51
    .line 52
    move-result p2

    .line 53
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 54
    .line 55
    .line 56
    move-result p3

    .line 57
    cmpl-float p2, p2, p3

    .line 58
    .line 59
    if-lez p2, :cond_2

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 63
    .line 64
    .line 65
    move-result p2

    .line 66
    iget-object p3, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 67
    .line 68
    invoke-virtual {p3}, Llp/df;->e()I

    .line 69
    .line 70
    .line 71
    move-result p3

    .line 72
    sub-int p3, p2, p3

    .line 73
    .line 74
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 75
    .line 76
    .line 77
    move-result p3

    .line 78
    iget-object v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->a:Llp/df;

    .line 79
    .line 80
    invoke-virtual {v0}, Llp/df;->f()I

    .line 81
    .line 82
    .line 83
    move-result v0

    .line 84
    sub-int/2addr p2, v0

    .line 85
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 86
    .line 87
    .line 88
    move-result p2

    .line 89
    if-ge p3, p2, :cond_4

    .line 90
    .line 91
    :cond_3
    :goto_0
    const/4 p2, 0x3

    .line 92
    goto :goto_2

    .line 93
    :cond_4
    :goto_1
    const/4 p2, 0x5

    .line 94
    :goto_2
    const/4 p3, 0x1

    .line 95
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/material/sidesheet/SideSheetBehavior;->t(Landroid/view/View;IZ)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :pswitch_0
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 100
    .line 101
    check-cast p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 102
    .line 103
    const/4 v0, 0x0

    .line 104
    cmpg-float v1, p3, v0

    .line 105
    .line 106
    const/4 v2, 0x6

    .line 107
    const/4 v3, 0x3

    .line 108
    if-gez v1, :cond_7

    .line 109
    .line 110
    iget-boolean p2, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->b:Z

    .line 111
    .line 112
    if-eqz p2, :cond_6

    .line 113
    .line 114
    :cond_5
    :goto_3
    move v2, v3

    .line 115
    goto/16 :goto_5

    .line 116
    .line 117
    :cond_6
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 118
    .line 119
    .line 120
    move-result p2

    .line 121
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 125
    .line 126
    .line 127
    iget p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->E:I

    .line 128
    .line 129
    if-le p2, p3, :cond_5

    .line 130
    .line 131
    goto/16 :goto_5

    .line 132
    .line 133
    :cond_7
    iget-boolean v1, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->I:Z

    .line 134
    .line 135
    if-eqz v1, :cond_c

    .line 136
    .line 137
    invoke-virtual {p0, p1, p3}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->D(Landroid/view/View;F)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-eqz v1, :cond_c

    .line 142
    .line 143
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 144
    .line 145
    .line 146
    move-result p2

    .line 147
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 148
    .line 149
    .line 150
    move-result v0

    .line 151
    cmpg-float p2, p2, v0

    .line 152
    .line 153
    if-gez p2, :cond_8

    .line 154
    .line 155
    iget p2, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->d:I

    .line 156
    .line 157
    int-to-float p2, p2

    .line 158
    cmpl-float p2, p3, p2

    .line 159
    .line 160
    if-gtz p2, :cond_9

    .line 161
    .line 162
    :cond_8
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 163
    .line 164
    .line 165
    move-result p2

    .line 166
    iget p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->V:I

    .line 167
    .line 168
    invoke-virtual {p0}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->x()I

    .line 169
    .line 170
    .line 171
    move-result v0

    .line 172
    add-int/2addr v0, p3

    .line 173
    div-int/lit8 v0, v0, 0x2

    .line 174
    .line 175
    if-le p2, v0, :cond_a

    .line 176
    .line 177
    :cond_9
    const/4 v2, 0x5

    .line 178
    goto/16 :goto_5

    .line 179
    .line 180
    :cond_a
    iget-boolean p2, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->b:Z

    .line 181
    .line 182
    if-eqz p2, :cond_b

    .line 183
    .line 184
    goto :goto_3

    .line 185
    :cond_b
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 186
    .line 187
    .line 188
    move-result p2

    .line 189
    invoke-virtual {p0}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->x()I

    .line 190
    .line 191
    .line 192
    move-result p3

    .line 193
    sub-int/2addr p2, p3

    .line 194
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 195
    .line 196
    .line 197
    move-result p2

    .line 198
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 199
    .line 200
    .line 201
    move-result p3

    .line 202
    iget v0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->E:I

    .line 203
    .line 204
    sub-int/2addr p3, v0

    .line 205
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 206
    .line 207
    .line 208
    move-result p3

    .line 209
    if-ge p2, p3, :cond_14

    .line 210
    .line 211
    goto :goto_3

    .line 212
    :cond_c
    cmpl-float v0, p3, v0

    .line 213
    .line 214
    const/4 v1, 0x4

    .line 215
    if-eqz v0, :cond_10

    .line 216
    .line 217
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 218
    .line 219
    .line 220
    move-result p2

    .line 221
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 222
    .line 223
    .line 224
    move-result p3

    .line 225
    cmpl-float p2, p2, p3

    .line 226
    .line 227
    if-lez p2, :cond_d

    .line 228
    .line 229
    goto :goto_4

    .line 230
    :cond_d
    iget-boolean p2, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->b:Z

    .line 231
    .line 232
    if-eqz p2, :cond_f

    .line 233
    .line 234
    :cond_e
    move v2, v1

    .line 235
    goto :goto_5

    .line 236
    :cond_f
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 237
    .line 238
    .line 239
    move-result p2

    .line 240
    iget p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->E:I

    .line 241
    .line 242
    sub-int p3, p2, p3

    .line 243
    .line 244
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 245
    .line 246
    .line 247
    move-result p3

    .line 248
    iget v0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->G:I

    .line 249
    .line 250
    sub-int/2addr p2, v0

    .line 251
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 252
    .line 253
    .line 254
    move-result p2

    .line 255
    if-ge p3, p2, :cond_e

    .line 256
    .line 257
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 258
    .line 259
    .line 260
    goto :goto_5

    .line 261
    :cond_10
    :goto_4
    invoke-virtual {p1}, Landroid/view/View;->getTop()I

    .line 262
    .line 263
    .line 264
    move-result p2

    .line 265
    iget-boolean p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->b:Z

    .line 266
    .line 267
    if-eqz p3, :cond_11

    .line 268
    .line 269
    iget p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->D:I

    .line 270
    .line 271
    sub-int p3, p2, p3

    .line 272
    .line 273
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 274
    .line 275
    .line 276
    move-result p3

    .line 277
    iget v0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->G:I

    .line 278
    .line 279
    sub-int/2addr p2, v0

    .line 280
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 281
    .line 282
    .line 283
    move-result p2

    .line 284
    if-ge p3, p2, :cond_e

    .line 285
    .line 286
    goto/16 :goto_3

    .line 287
    .line 288
    :cond_11
    iget p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->E:I

    .line 289
    .line 290
    if-ge p2, p3, :cond_13

    .line 291
    .line 292
    iget p3, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->G:I

    .line 293
    .line 294
    sub-int p3, p2, p3

    .line 295
    .line 296
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 297
    .line 298
    .line 299
    move-result p3

    .line 300
    if-ge p2, p3, :cond_12

    .line 301
    .line 302
    goto/16 :goto_3

    .line 303
    .line 304
    :cond_12
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 305
    .line 306
    .line 307
    goto :goto_5

    .line 308
    :cond_13
    sub-int p3, p2, p3

    .line 309
    .line 310
    invoke-static {p3}, Ljava/lang/Math;->abs(I)I

    .line 311
    .line 312
    .line 313
    move-result p3

    .line 314
    iget v0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->G:I

    .line 315
    .line 316
    sub-int/2addr p2, v0

    .line 317
    invoke-static {p2}, Ljava/lang/Math;->abs(I)I

    .line 318
    .line 319
    .line 320
    move-result p2

    .line 321
    if-ge p3, p2, :cond_e

    .line 322
    .line 323
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 324
    .line 325
    .line 326
    :cond_14
    :goto_5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 327
    .line 328
    .line 329
    const/4 p2, 0x1

    .line 330
    invoke-virtual {p0, p1, v2, p2}, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->E(Landroid/view/View;IZ)V

    .line 331
    .line 332
    .line 333
    return-void

    .line 334
    nop

    .line 335
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final tryCaptureView(Landroid/view/View;I)Z
    .locals 3

    .line 1
    iget v0, p0, Liq/c;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 7
    .line 8
    check-cast p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 9
    .line 10
    iget p2, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->h:I

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    const/4 v1, 0x1

    .line 14
    if-ne p2, v1, :cond_0

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    iget-object p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->p:Ljava/lang/ref/WeakReference;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    if-ne p0, p1, :cond_1

    .line 26
    .line 27
    move v0, v1

    .line 28
    :cond_1
    :goto_0
    return v0

    .line 29
    :pswitch_0
    iget-object p0, p0, Liq/c;->d:Ll5/a;

    .line 30
    .line 31
    check-cast p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;

    .line 32
    .line 33
    iget v0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->N:I

    .line 34
    .line 35
    const/4 v1, 0x1

    .line 36
    if-ne v0, v1, :cond_2

    .line 37
    .line 38
    goto :goto_2

    .line 39
    :cond_2
    iget-boolean v2, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->c0:Z

    .line 40
    .line 41
    if-eqz v2, :cond_3

    .line 42
    .line 43
    goto :goto_2

    .line 44
    :cond_3
    const/4 v2, 0x3

    .line 45
    if-ne v0, v2, :cond_5

    .line 46
    .line 47
    iget v0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->a0:I

    .line 48
    .line 49
    if-ne v0, p2, :cond_5

    .line 50
    .line 51
    iget-object p2, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->X:Ljava/lang/ref/WeakReference;

    .line 52
    .line 53
    if-eqz p2, :cond_4

    .line 54
    .line 55
    invoke-virtual {p2}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p2

    .line 59
    check-cast p2, Landroid/view/View;

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_4
    const/4 p2, 0x0

    .line 63
    :goto_1
    if-eqz p2, :cond_5

    .line 64
    .line 65
    const/4 v0, -0x1

    .line 66
    invoke-virtual {p2, v0}, Landroid/view/View;->canScrollVertically(I)Z

    .line 67
    .line 68
    .line 69
    move-result p2

    .line 70
    if-eqz p2, :cond_5

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_5
    invoke-static {}, Landroid/os/SystemClock;->uptimeMillis()J

    .line 74
    .line 75
    .line 76
    iget-object p0, p0, Lcom/google/android/material/bottomsheet/BottomSheetBehavior;->W:Ljava/lang/ref/WeakReference;

    .line 77
    .line 78
    if-eqz p0, :cond_6

    .line 79
    .line 80
    invoke-virtual {p0}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object p0

    .line 84
    if-ne p0, p1, :cond_6

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :cond_6
    :goto_2
    const/4 v1, 0x0

    .line 88
    :goto_3
    return v1

    .line 89
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public final Lxq/a;
.super Llp/df;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Lcom/google/android/material/sidesheet/SideSheetBehavior;


# direct methods
.method public synthetic constructor <init>(Lcom/google/android/material/sidesheet/SideSheetBehavior;I)V
    .locals 0

    .line 1
    iput p2, p0, Lxq/a;->a:I

    .line 2
    .line 3
    iput-object p1, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b(Landroid/view/ViewGroup$MarginLayoutParams;)I
    .locals 0

    .line 1
    iget p0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 7
    .line 8
    return p0

    .line 9
    :pswitch_0
    iget p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 10
    .line 11
    return p0

    .line 12
    nop

    .line 13
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final c(I)F
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 7
    .line 8
    iget v0, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 9
    .line 10
    int-to-float v0, v0

    .line 11
    invoke-virtual {p0}, Lxq/a;->e()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    int-to-float p0, p0

    .line 16
    sub-float p0, v0, p0

    .line 17
    .line 18
    int-to-float p1, p1

    .line 19
    sub-float/2addr v0, p1

    .line 20
    div-float/2addr v0, p0

    .line 21
    return v0

    .line 22
    :pswitch_0
    invoke-virtual {p0}, Lxq/a;->f()I

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    int-to-float v0, v0

    .line 27
    invoke-virtual {p0}, Lxq/a;->e()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    int-to-float p0, p0

    .line 32
    sub-float/2addr p0, v0

    .line 33
    int-to-float p1, p1

    .line 34
    sub-float/2addr p1, v0

    .line 35
    div-float/2addr p1, p0

    .line 36
    return p1

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final e()I
    .locals 2

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 7
    .line 8
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 9
    .line 10
    iget v1, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->l:I

    .line 11
    .line 12
    sub-int/2addr v0, v1

    .line 13
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 14
    .line 15
    sub-int/2addr v0, p0

    .line 16
    const/4 p0, 0x0

    .line 17
    invoke-static {p0, v0}, Ljava/lang/Math;->max(II)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0

    .line 22
    :pswitch_0
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 23
    .line 24
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->n:I

    .line 25
    .line 26
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 27
    .line 28
    add-int/2addr v0, p0

    .line 29
    const/4 p0, 0x0

    .line 30
    invoke-static {p0, v0}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    return p0

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final f()I
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 7
    .line 8
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 9
    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 12
    .line 13
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->l:I

    .line 14
    .line 15
    neg-int v0, v0

    .line 16
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 17
    .line 18
    sub-int/2addr v0, p0

    .line 19
    return v0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final g()I
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 7
    .line 8
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 9
    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 12
    .line 13
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 14
    .line 15
    return p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final h()I
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0}, Lxq/a;->e()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 12
    .line 13
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->l:I

    .line 14
    .line 15
    neg-int p0, p0

    .line 16
    return p0

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final i(Landroid/view/View;)I
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 11
    .line 12
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 13
    .line 14
    sub-int/2addr p1, p0

    .line 15
    return p1

    .line 16
    :pswitch_0
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 17
    .line 18
    .line 19
    move-result p1

    .line 20
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 21
    .line 22
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->o:I

    .line 23
    .line 24
    add-int/2addr p1, p0

    .line 25
    return p1

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final j(Landroidx/coordinatorlayout/widget/CoordinatorLayout;)I
    .locals 0

    .line 1
    iget p0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final k()I
    .locals 0

    .line 1
    iget p0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/4 p0, 0x1

    .line 9
    return p0

    .line 10
    nop

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final l(F)Z
    .locals 0

    .line 1
    iget p0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    cmpg-float p0, p1, p0

    .line 8
    .line 9
    if-gez p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    goto :goto_0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    :goto_0
    return p0

    .line 15
    :pswitch_0
    const/4 p0, 0x0

    .line 16
    cmpl-float p0, p1, p0

    .line 17
    .line 18
    if-lez p0, :cond_1

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    goto :goto_1

    .line 22
    :cond_1
    const/4 p0, 0x0

    .line 23
    :goto_1
    return p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final m(Landroid/view/View;)Z
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object v0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 11
    .line 12
    iget v0, v0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 13
    .line 14
    invoke-virtual {p0}, Lxq/a;->e()I

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    add-int/2addr p0, v0

    .line 19
    div-int/lit8 p0, p0, 0x2

    .line 20
    .line 21
    if-le p1, p0, :cond_0

    .line 22
    .line 23
    const/4 p0, 0x1

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/4 p0, 0x0

    .line 26
    :goto_0
    return p0

    .line 27
    :pswitch_0
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 28
    .line 29
    .line 30
    move-result p1

    .line 31
    invoke-virtual {p0}, Lxq/a;->e()I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    invoke-virtual {p0}, Lxq/a;->f()I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    sub-int/2addr v0, p0

    .line 40
    div-int/lit8 v0, v0, 0x2

    .line 41
    .line 42
    if-ge p1, v0, :cond_1

    .line 43
    .line 44
    const/4 p0, 0x1

    .line 45
    goto :goto_1

    .line 46
    :cond_1
    const/4 p0, 0x0

    .line 47
    :goto_1
    return p0

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final n(FF)Z
    .locals 0

    .line 1
    iget p0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    cmpl-float p0, p0, p2

    .line 15
    .line 16
    if-lez p0, :cond_0

    .line 17
    .line 18
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    const/16 p1, 0x1f4

    .line 23
    .line 24
    int-to-float p1, p1

    .line 25
    cmpl-float p0, p0, p1

    .line 26
    .line 27
    if-lez p0, :cond_0

    .line 28
    .line 29
    const/4 p0, 0x1

    .line 30
    goto :goto_0

    .line 31
    :cond_0
    const/4 p0, 0x0

    .line 32
    :goto_0
    return p0

    .line 33
    :pswitch_0
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 38
    .line 39
    .line 40
    move-result p2

    .line 41
    cmpl-float p0, p0, p2

    .line 42
    .line 43
    if-lez p0, :cond_1

    .line 44
    .line 45
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 46
    .line 47
    .line 48
    move-result p0

    .line 49
    const/16 p1, 0x1f4

    .line 50
    .line 51
    int-to-float p1, p1

    .line 52
    cmpl-float p0, p0, p1

    .line 53
    .line 54
    if-lez p0, :cond_1

    .line 55
    .line 56
    const/4 p0, 0x1

    .line 57
    goto :goto_1

    .line 58
    :cond_1
    const/4 p0, 0x0

    .line 59
    :goto_1
    return p0

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final o(Landroid/view/View;F)Z
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p1}, Landroid/view/View;->getRight()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    int-to-float p1, p1

    .line 11
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 12
    .line 13
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->k:F

    .line 14
    .line 15
    mul-float/2addr p2, v0

    .line 16
    add-float/2addr p2, p1

    .line 17
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 18
    .line 19
    .line 20
    move-result p1

    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/high16 p0, 0x3f000000    # 0.5f

    .line 25
    .line 26
    cmpl-float p0, p1, p0

    .line 27
    .line 28
    if-lez p0, :cond_0

    .line 29
    .line 30
    const/4 p0, 0x1

    .line 31
    goto :goto_0

    .line 32
    :cond_0
    const/4 p0, 0x0

    .line 33
    :goto_0
    return p0

    .line 34
    :pswitch_0
    invoke-virtual {p1}, Landroid/view/View;->getLeft()I

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    int-to-float p1, p1

    .line 39
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 40
    .line 41
    iget v0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->k:F

    .line 42
    .line 43
    mul-float/2addr p2, v0

    .line 44
    add-float/2addr p2, p1

    .line 45
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 46
    .line 47
    .line 48
    move-result p1

    .line 49
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 50
    .line 51
    .line 52
    const/high16 p0, 0x3f000000    # 0.5f

    .line 53
    .line 54
    cmpl-float p0, p1, p0

    .line 55
    .line 56
    if-lez p0, :cond_1

    .line 57
    .line 58
    const/4 p0, 0x1

    .line 59
    goto :goto_1

    .line 60
    :cond_1
    const/4 p0, 0x0

    .line 61
    :goto_1
    return p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final p(Landroid/view/ViewGroup$MarginLayoutParams;II)V
    .locals 1

    .line 1
    iget v0, p0, Lxq/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 7
    .line 8
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 9
    .line 10
    if-gt p2, p0, :cond_0

    .line 11
    .line 12
    sub-int/2addr p0, p2

    .line 13
    iput p0, p1, Landroid/view/ViewGroup$MarginLayoutParams;->rightMargin:I

    .line 14
    .line 15
    :cond_0
    return-void

    .line 16
    :pswitch_0
    iget-object p0, p0, Lxq/a;->b:Lcom/google/android/material/sidesheet/SideSheetBehavior;

    .line 17
    .line 18
    iget p0, p0, Lcom/google/android/material/sidesheet/SideSheetBehavior;->m:I

    .line 19
    .line 20
    if-gt p2, p0, :cond_1

    .line 21
    .line 22
    iput p3, p1, Landroid/view/ViewGroup$MarginLayoutParams;->leftMargin:I

    .line 23
    .line 24
    :cond_1
    return-void

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

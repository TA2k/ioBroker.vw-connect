.class public final Lzq/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:Landroid/content/res/ColorStateList;

.field public B:Landroid/graphics/Typeface;

.field public final a:I

.field public final b:I

.field public final c:I

.field public final d:Landroid/animation/TimeInterpolator;

.field public final e:Landroid/animation/TimeInterpolator;

.field public final f:Landroid/animation/TimeInterpolator;

.field public final g:Landroid/content/Context;

.field public final h:Lcom/google/android/material/textfield/TextInputLayout;

.field public i:Landroid/widget/LinearLayout;

.field public j:I

.field public k:Landroid/widget/FrameLayout;

.field public l:Landroid/animation/AnimatorSet;

.field public final m:F

.field public n:I

.field public o:I

.field public p:Ljava/lang/CharSequence;

.field public q:Z

.field public r:Lm/x0;

.field public s:Ljava/lang/CharSequence;

.field public t:I

.field public u:I

.field public v:Landroid/content/res/ColorStateList;

.field public w:Ljava/lang/CharSequence;

.field public x:Z

.field public y:Lm/x0;

.field public z:I


# direct methods
.method public constructor <init>(Lcom/google/android/material/textfield/TextInputLayout;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    iput-object v0, p0, Lzq/p;->g:Landroid/content/Context;

    .line 9
    .line 10
    iput-object p1, p0, Lzq/p;->h:Lcom/google/android/material/textfield/TextInputLayout;

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 13
    .line 14
    .line 15
    move-result-object p1

    .line 16
    const v1, 0x7f070091

    .line 17
    .line 18
    .line 19
    invoke-virtual {p1, v1}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    int-to-float p1, p1

    .line 24
    iput p1, p0, Lzq/p;->m:F

    .line 25
    .line 26
    const/16 p1, 0xd9

    .line 27
    .line 28
    const v1, 0x7f0403eb

    .line 29
    .line 30
    .line 31
    invoke-static {v0, v1, p1}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 32
    .line 33
    .line 34
    move-result p1

    .line 35
    iput p1, p0, Lzq/p;->a:I

    .line 36
    .line 37
    const p1, 0x7f0403e7

    .line 38
    .line 39
    .line 40
    const/16 v2, 0xa7

    .line 41
    .line 42
    invoke-static {v0, p1, v2}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    iput p1, p0, Lzq/p;->b:I

    .line 47
    .line 48
    invoke-static {v0, v1, v2}, Lkp/o8;->d(Landroid/content/Context;II)I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    iput p1, p0, Lzq/p;->c:I

    .line 53
    .line 54
    sget-object p1, Leq/a;->d:Ll7/a;

    .line 55
    .line 56
    const v1, 0x7f0403f0

    .line 57
    .line 58
    .line 59
    invoke-static {v0, v1, p1}, Lkp/o8;->e(Landroid/content/Context;ILandroid/animation/TimeInterpolator;)Landroid/animation/TimeInterpolator;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    iput-object p1, p0, Lzq/p;->d:Landroid/animation/TimeInterpolator;

    .line 64
    .line 65
    sget-object p1, Leq/a;->a:Landroid/view/animation/LinearInterpolator;

    .line 66
    .line 67
    invoke-static {v0, v1, p1}, Lkp/o8;->e(Landroid/content/Context;ILandroid/animation/TimeInterpolator;)Landroid/animation/TimeInterpolator;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    iput-object v1, p0, Lzq/p;->e:Landroid/animation/TimeInterpolator;

    .line 72
    .line 73
    const v1, 0x7f0403f3

    .line 74
    .line 75
    .line 76
    invoke-static {v0, v1, p1}, Lkp/o8;->e(Landroid/content/Context;ILandroid/animation/TimeInterpolator;)Landroid/animation/TimeInterpolator;

    .line 77
    .line 78
    .line 79
    move-result-object p1

    .line 80
    iput-object p1, p0, Lzq/p;->f:Landroid/animation/TimeInterpolator;

    .line 81
    .line 82
    return-void
.end method


# virtual methods
.method public final a(Lm/x0;I)V
    .locals 6

    .line 1
    iget-object v0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 2
    .line 3
    const/4 v1, -0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lzq/p;->k:Landroid/widget/FrameLayout;

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    new-instance v0, Landroid/widget/LinearLayout;

    .line 12
    .line 13
    iget-object v3, p0, Lzq/p;->g:Landroid/content/Context;

    .line 14
    .line 15
    invoke-direct {v0, v3}, Landroid/widget/LinearLayout;-><init>(Landroid/content/Context;)V

    .line 16
    .line 17
    .line 18
    iput-object v0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 19
    .line 20
    invoke-virtual {v0, v2}, Landroid/widget/LinearLayout;->setOrientation(I)V

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 24
    .line 25
    const/4 v4, -0x1

    .line 26
    iget-object v5, p0, Lzq/p;->h:Lcom/google/android/material/textfield/TextInputLayout;

    .line 27
    .line 28
    invoke-virtual {v5, v0, v4, v1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;II)V

    .line 29
    .line 30
    .line 31
    new-instance v0, Landroid/widget/FrameLayout;

    .line 32
    .line 33
    invoke-direct {v0, v3}, Landroid/widget/FrameLayout;-><init>(Landroid/content/Context;)V

    .line 34
    .line 35
    .line 36
    iput-object v0, p0, Lzq/p;->k:Landroid/widget/FrameLayout;

    .line 37
    .line 38
    new-instance v0, Landroid/widget/LinearLayout$LayoutParams;

    .line 39
    .line 40
    const/high16 v3, 0x3f800000    # 1.0f

    .line 41
    .line 42
    invoke-direct {v0, v2, v1, v3}, Landroid/widget/LinearLayout$LayoutParams;-><init>(IIF)V

    .line 43
    .line 44
    .line 45
    iget-object v3, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 46
    .line 47
    iget-object v4, p0, Lzq/p;->k:Landroid/widget/FrameLayout;

    .line 48
    .line 49
    invoke-virtual {v3, v4, v0}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v5}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 53
    .line 54
    .line 55
    move-result-object v0

    .line 56
    if-eqz v0, :cond_0

    .line 57
    .line 58
    invoke-virtual {p0}, Lzq/p;->b()V

    .line 59
    .line 60
    .line 61
    :cond_0
    const/4 v0, 0x1

    .line 62
    if-eqz p2, :cond_2

    .line 63
    .line 64
    if-ne p2, v0, :cond_1

    .line 65
    .line 66
    goto :goto_0

    .line 67
    :cond_1
    new-instance p2, Landroid/widget/LinearLayout$LayoutParams;

    .line 68
    .line 69
    invoke-direct {p2, v1, v1}, Landroid/widget/LinearLayout$LayoutParams;-><init>(II)V

    .line 70
    .line 71
    .line 72
    iget-object v1, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 73
    .line 74
    invoke-virtual {v1, p1, p2}, Landroid/view/ViewGroup;->addView(Landroid/view/View;Landroid/view/ViewGroup$LayoutParams;)V

    .line 75
    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_2
    :goto_0
    iget-object p2, p0, Lzq/p;->k:Landroid/widget/FrameLayout;

    .line 79
    .line 80
    invoke-virtual {p2, v2}, Landroid/view/View;->setVisibility(I)V

    .line 81
    .line 82
    .line 83
    iget-object p2, p0, Lzq/p;->k:Landroid/widget/FrameLayout;

    .line 84
    .line 85
    invoke-virtual {p2, p1}, Landroid/view/ViewGroup;->addView(Landroid/view/View;)V

    .line 86
    .line 87
    .line 88
    :goto_1
    iget-object p1, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 89
    .line 90
    invoke-virtual {p1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 91
    .line 92
    .line 93
    iget p1, p0, Lzq/p;->j:I

    .line 94
    .line 95
    add-int/2addr p1, v0

    .line 96
    iput p1, p0, Lzq/p;->j:I

    .line 97
    .line 98
    return-void
.end method

.method public final b()V
    .locals 7

    .line 1
    iget-object v0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 2
    .line 3
    if-eqz v0, :cond_3

    .line 4
    .line 5
    iget-object v0, p0, Lzq/p;->h:Lcom/google/android/material/textfield/TextInputLayout;

    .line 6
    .line 7
    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    if-eqz v1, :cond_3

    .line 12
    .line 13
    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputLayout;->getEditText()Landroid/widget/EditText;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    iget-object v1, p0, Lzq/p;->g:Landroid/content/Context;

    .line 18
    .line 19
    invoke-static {v1}, Llp/x9;->e(Landroid/content/Context;)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    iget-object p0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 24
    .line 25
    invoke-virtual {v0}, Landroid/view/View;->getPaddingStart()I

    .line 26
    .line 27
    .line 28
    move-result v3

    .line 29
    const v4, 0x7f07034b

    .line 30
    .line 31
    .line 32
    if-eqz v2, :cond_0

    .line 33
    .line 34
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 35
    .line 36
    .line 37
    move-result-object v3

    .line 38
    invoke-virtual {v3, v4}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 39
    .line 40
    .line 41
    move-result v3

    .line 42
    :cond_0
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 43
    .line 44
    .line 45
    move-result-object v5

    .line 46
    const v6, 0x7f07034a

    .line 47
    .line 48
    .line 49
    invoke-virtual {v5, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 50
    .line 51
    .line 52
    move-result v5

    .line 53
    if-eqz v2, :cond_1

    .line 54
    .line 55
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 56
    .line 57
    .line 58
    move-result-object v5

    .line 59
    const v6, 0x7f07034c

    .line 60
    .line 61
    .line 62
    invoke-virtual {v5, v6}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 63
    .line 64
    .line 65
    move-result v5

    .line 66
    :cond_1
    invoke-virtual {v0}, Landroid/view/View;->getPaddingEnd()I

    .line 67
    .line 68
    .line 69
    move-result v0

    .line 70
    if-eqz v2, :cond_2

    .line 71
    .line 72
    invoke-virtual {v1}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    invoke-virtual {v0, v4}, Landroid/content/res/Resources;->getDimensionPixelSize(I)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    :cond_2
    const/4 v1, 0x0

    .line 81
    invoke-virtual {p0, v3, v5, v0, v1}, Landroid/view/View;->setPaddingRelative(IIII)V

    .line 82
    .line 83
    .line 84
    :cond_3
    return-void
.end method

.method public final c()V
    .locals 0

    .line 1
    iget-object p0, p0, Lzq/p;->l:Landroid/animation/AnimatorSet;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Landroid/animation/Animator;->cancel()V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final d(Ljava/util/ArrayList;ZLm/x0;III)V
    .locals 7

    .line 1
    if-eqz p3, :cond_7

    .line 2
    .line 3
    if-nez p2, :cond_0

    .line 4
    .line 5
    goto :goto_4

    .line 6
    :cond_0
    if-eq p4, p6, :cond_1

    .line 7
    .line 8
    if-ne p4, p5, :cond_7

    .line 9
    .line 10
    :cond_1
    const/4 p2, 0x0

    .line 11
    const/4 v0, 0x1

    .line 12
    if-ne p6, p4, :cond_2

    .line 13
    .line 14
    move v1, v0

    .line 15
    goto :goto_0

    .line 16
    :cond_2
    move v1, p2

    .line 17
    :goto_0
    const/4 v2, 0x0

    .line 18
    if-eqz v1, :cond_3

    .line 19
    .line 20
    const/high16 v3, 0x3f800000    # 1.0f

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_3
    move v3, v2

    .line 24
    :goto_1
    sget-object v4, Landroid/view/View;->ALPHA:Landroid/util/Property;

    .line 25
    .line 26
    new-array v5, v0, [F

    .line 27
    .line 28
    aput v3, v5, p2

    .line 29
    .line 30
    invoke-static {p3, v4, v5}, Landroid/animation/ObjectAnimator;->ofFloat(Ljava/lang/Object;Landroid/util/Property;[F)Landroid/animation/ObjectAnimator;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    iget v4, p0, Lzq/p;->c:I

    .line 35
    .line 36
    if-eqz v1, :cond_4

    .line 37
    .line 38
    iget v5, p0, Lzq/p;->b:I

    .line 39
    .line 40
    int-to-long v5, v5

    .line 41
    goto :goto_2

    .line 42
    :cond_4
    int-to-long v5, v4

    .line 43
    :goto_2
    invoke-virtual {v3, v5, v6}, Landroid/animation/ObjectAnimator;->setDuration(J)Landroid/animation/ObjectAnimator;

    .line 44
    .line 45
    .line 46
    if-eqz v1, :cond_5

    .line 47
    .line 48
    iget-object v1, p0, Lzq/p;->e:Landroid/animation/TimeInterpolator;

    .line 49
    .line 50
    goto :goto_3

    .line 51
    :cond_5
    iget-object v1, p0, Lzq/p;->f:Landroid/animation/TimeInterpolator;

    .line 52
    .line 53
    :goto_3
    invoke-virtual {v3, v1}, Landroid/animation/Animator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 54
    .line 55
    .line 56
    if-ne p4, p6, :cond_6

    .line 57
    .line 58
    if-eqz p5, :cond_6

    .line 59
    .line 60
    int-to-long v5, v4

    .line 61
    invoke-virtual {v3, v5, v6}, Landroid/animation/Animator;->setStartDelay(J)V

    .line 62
    .line 63
    .line 64
    :cond_6
    invoke-virtual {p1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    if-ne p6, p4, :cond_7

    .line 68
    .line 69
    if-eqz p5, :cond_7

    .line 70
    .line 71
    sget-object p4, Landroid/view/View;->TRANSLATION_Y:Landroid/util/Property;

    .line 72
    .line 73
    iget p5, p0, Lzq/p;->m:F

    .line 74
    .line 75
    neg-float p5, p5

    .line 76
    const/4 p6, 0x2

    .line 77
    new-array p6, p6, [F

    .line 78
    .line 79
    aput p5, p6, p2

    .line 80
    .line 81
    aput v2, p6, v0

    .line 82
    .line 83
    invoke-static {p3, p4, p6}, Landroid/animation/ObjectAnimator;->ofFloat(Ljava/lang/Object;Landroid/util/Property;[F)Landroid/animation/ObjectAnimator;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    iget p3, p0, Lzq/p;->a:I

    .line 88
    .line 89
    int-to-long p3, p3

    .line 90
    invoke-virtual {p2, p3, p4}, Landroid/animation/ObjectAnimator;->setDuration(J)Landroid/animation/ObjectAnimator;

    .line 91
    .line 92
    .line 93
    iget-object p0, p0, Lzq/p;->d:Landroid/animation/TimeInterpolator;

    .line 94
    .line 95
    invoke-virtual {p2, p0}, Landroid/animation/Animator;->setInterpolator(Landroid/animation/TimeInterpolator;)V

    .line 96
    .line 97
    .line 98
    int-to-long p3, v4

    .line 99
    invoke-virtual {p2, p3, p4}, Landroid/animation/Animator;->setStartDelay(J)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {p1, p2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    :cond_7
    :goto_4
    return-void
.end method

.method public final e(I)Landroid/widget/TextView;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p1, v0, :cond_1

    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p1, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return-object p0

    .line 9
    :cond_0
    iget-object p0, p0, Lzq/p;->y:Lm/x0;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_1
    iget-object p0, p0, Lzq/p;->r:Lm/x0;

    .line 13
    .line 14
    return-object p0
.end method

.method public final f()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lzq/p;->p:Ljava/lang/CharSequence;

    .line 3
    .line 4
    invoke-virtual {p0}, Lzq/p;->c()V

    .line 5
    .line 6
    .line 7
    iget v0, p0, Lzq/p;->n:I

    .line 8
    .line 9
    const/4 v1, 0x1

    .line 10
    if-ne v0, v1, :cond_1

    .line 11
    .line 12
    iget-boolean v0, p0, Lzq/p;->x:Z

    .line 13
    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lzq/p;->w:Ljava/lang/CharSequence;

    .line 17
    .line 18
    invoke-static {v0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x2

    .line 25
    iput v0, p0, Lzq/p;->o:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 v0, 0x0

    .line 29
    iput v0, p0, Lzq/p;->o:I

    .line 30
    .line 31
    :cond_1
    :goto_0
    iget v0, p0, Lzq/p;->n:I

    .line 32
    .line 33
    iget v1, p0, Lzq/p;->o:I

    .line 34
    .line 35
    iget-object v2, p0, Lzq/p;->r:Lm/x0;

    .line 36
    .line 37
    const-string v3, ""

    .line 38
    .line 39
    invoke-virtual {p0, v2, v3}, Lzq/p;->h(Lm/x0;Ljava/lang/CharSequence;)Z

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    invoke-virtual {p0, v0, v1, v2}, Lzq/p;->i(IIZ)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public final g(Lm/x0;I)V
    .locals 2

    .line 1
    iget-object v0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    const/4 v1, 0x1

    .line 7
    if-eqz p2, :cond_1

    .line 8
    .line 9
    if-ne p2, v1, :cond_2

    .line 10
    .line 11
    :cond_1
    iget-object p2, p0, Lzq/p;->k:Landroid/widget/FrameLayout;

    .line 12
    .line 13
    if-eqz p2, :cond_2

    .line 14
    .line 15
    invoke-virtual {p2, p1}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_2
    invoke-virtual {v0, p1}, Landroid/view/ViewGroup;->removeView(Landroid/view/View;)V

    .line 20
    .line 21
    .line 22
    :goto_0
    iget p1, p0, Lzq/p;->j:I

    .line 23
    .line 24
    sub-int/2addr p1, v1

    .line 25
    iput p1, p0, Lzq/p;->j:I

    .line 26
    .line 27
    iget-object p0, p0, Lzq/p;->i:Landroid/widget/LinearLayout;

    .line 28
    .line 29
    if-nez p1, :cond_3

    .line 30
    .line 31
    const/16 p1, 0x8

    .line 32
    .line 33
    invoke-virtual {p0, p1}, Landroid/view/View;->setVisibility(I)V

    .line 34
    .line 35
    .line 36
    :cond_3
    :goto_1
    return-void
.end method

.method public final h(Lm/x0;Ljava/lang/CharSequence;)Z
    .locals 2

    .line 1
    iget-object v0, p0, Lzq/p;->h:Lcom/google/android/material/textfield/TextInputLayout;

    .line 2
    .line 3
    invoke-virtual {v0}, Landroid/view/View;->isLaidOut()Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    invoke-virtual {v0}, Landroid/view/View;->isEnabled()Z

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    iget v0, p0, Lzq/p;->o:I

    .line 16
    .line 17
    iget p0, p0, Lzq/p;->n:I

    .line 18
    .line 19
    if-ne v0, p0, :cond_0

    .line 20
    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    invoke-virtual {p1}, Lm/x0;->getText()Ljava/lang/CharSequence;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-static {p0, p2}, Landroid/text/TextUtils;->equals(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-nez p0, :cond_1

    .line 32
    .line 33
    :cond_0
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_1
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public final i(IIZ)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v5, p1

    .line 4
    .line 5
    move/from16 v6, p2

    .line 6
    .line 7
    move/from16 v7, p3

    .line 8
    .line 9
    if-ne v5, v6, :cond_0

    .line 10
    .line 11
    return-void

    .line 12
    :cond_0
    const/4 v8, 0x0

    .line 13
    if-eqz v7, :cond_2

    .line 14
    .line 15
    new-instance v9, Landroid/animation/AnimatorSet;

    .line 16
    .line 17
    invoke-direct {v9}, Landroid/animation/AnimatorSet;-><init>()V

    .line 18
    .line 19
    .line 20
    iput-object v9, v0, Lzq/p;->l:Landroid/animation/AnimatorSet;

    .line 21
    .line 22
    new-instance v1, Ljava/util/ArrayList;

    .line 23
    .line 24
    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 25
    .line 26
    .line 27
    iget-boolean v2, v0, Lzq/p;->x:Z

    .line 28
    .line 29
    iget-object v3, v0, Lzq/p;->y:Lm/x0;

    .line 30
    .line 31
    const/4 v4, 0x2

    .line 32
    invoke-virtual/range {v0 .. v6}, Lzq/p;->d(Ljava/util/ArrayList;ZLm/x0;III)V

    .line 33
    .line 34
    .line 35
    iget-boolean v2, v0, Lzq/p;->q:Z

    .line 36
    .line 37
    iget-object v3, v0, Lzq/p;->r:Lm/x0;

    .line 38
    .line 39
    const/4 v4, 0x1

    .line 40
    move/from16 v5, p1

    .line 41
    .line 42
    move/from16 v6, p2

    .line 43
    .line 44
    invoke-virtual/range {v0 .. v6}, Lzq/p;->d(Ljava/util/ArrayList;ZLm/x0;III)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 48
    .line 49
    .line 50
    move-result v2

    .line 51
    const-wide/16 v3, 0x0

    .line 52
    .line 53
    move v5, v8

    .line 54
    :goto_0
    if-ge v5, v2, :cond_1

    .line 55
    .line 56
    invoke-virtual {v1, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v10

    .line 60
    check-cast v10, Landroid/animation/Animator;

    .line 61
    .line 62
    invoke-virtual {v10}, Landroid/animation/Animator;->getStartDelay()J

    .line 63
    .line 64
    .line 65
    move-result-wide v11

    .line 66
    invoke-virtual {v10}, Landroid/animation/Animator;->getDuration()J

    .line 67
    .line 68
    .line 69
    move-result-wide v13

    .line 70
    add-long/2addr v13, v11

    .line 71
    invoke-static {v3, v4, v13, v14}, Ljava/lang/Math;->max(JJ)J

    .line 72
    .line 73
    .line 74
    move-result-wide v3

    .line 75
    add-int/lit8 v5, v5, 0x1

    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_1
    filled-new-array {v8, v8}, [I

    .line 79
    .line 80
    .line 81
    move-result-object v2

    .line 82
    invoke-static {v2}, Landroid/animation/ValueAnimator;->ofInt([I)Landroid/animation/ValueAnimator;

    .line 83
    .line 84
    .line 85
    move-result-object v2

    .line 86
    invoke-virtual {v2, v3, v4}, Landroid/animation/Animator;->setDuration(J)Landroid/animation/Animator;

    .line 87
    .line 88
    .line 89
    invoke-virtual {v1, v8, v2}, Ljava/util/ArrayList;->add(ILjava/lang/Object;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {v9, v1}, Landroid/animation/AnimatorSet;->playTogether(Ljava/util/Collection;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual/range {p0 .. p1}, Lzq/p;->e(I)Landroid/widget/TextView;

    .line 96
    .line 97
    .line 98
    move-result-object v3

    .line 99
    invoke-virtual {v0, v6}, Lzq/p;->e(I)Landroid/widget/TextView;

    .line 100
    .line 101
    .line 102
    move-result-object v5

    .line 103
    new-instance v0, Lzq/n;

    .line 104
    .line 105
    move-object/from16 v1, p0

    .line 106
    .line 107
    move/from16 v4, p1

    .line 108
    .line 109
    move v2, v6

    .line 110
    invoke-direct/range {v0 .. v5}, Lzq/n;-><init>(Lzq/p;ILandroid/widget/TextView;ILandroid/widget/TextView;)V

    .line 111
    .line 112
    .line 113
    move-object v15, v1

    .line 114
    move-object v1, v0

    .line 115
    move-object v0, v15

    .line 116
    invoke-virtual {v9, v1}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 117
    .line 118
    .line 119
    invoke-virtual {v9}, Landroid/animation/AnimatorSet;->start()V

    .line 120
    .line 121
    .line 122
    goto :goto_1

    .line 123
    :cond_2
    if-ne v5, v6, :cond_3

    .line 124
    .line 125
    goto :goto_1

    .line 126
    :cond_3
    if-eqz v6, :cond_4

    .line 127
    .line 128
    invoke-virtual {v0, v6}, Lzq/p;->e(I)Landroid/widget/TextView;

    .line 129
    .line 130
    .line 131
    move-result-object v1

    .line 132
    if-eqz v1, :cond_4

    .line 133
    .line 134
    invoke-virtual {v1, v8}, Landroid/view/View;->setVisibility(I)V

    .line 135
    .line 136
    .line 137
    const/high16 v2, 0x3f800000    # 1.0f

    .line 138
    .line 139
    invoke-virtual {v1, v2}, Landroid/view/View;->setAlpha(F)V

    .line 140
    .line 141
    .line 142
    :cond_4
    if-eqz v5, :cond_5

    .line 143
    .line 144
    invoke-virtual/range {p0 .. p1}, Lzq/p;->e(I)Landroid/widget/TextView;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    if-eqz v1, :cond_5

    .line 149
    .line 150
    const/4 v2, 0x4

    .line 151
    invoke-virtual {v1, v2}, Landroid/view/View;->setVisibility(I)V

    .line 152
    .line 153
    .line 154
    const/4 v2, 0x1

    .line 155
    if-ne v5, v2, :cond_5

    .line 156
    .line 157
    const/4 v2, 0x0

    .line 158
    invoke-virtual {v1, v2}, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V

    .line 159
    .line 160
    .line 161
    :cond_5
    iput v6, v0, Lzq/p;->n:I

    .line 162
    .line 163
    :goto_1
    iget-object v0, v0, Lzq/p;->h:Lcom/google/android/material/textfield/TextInputLayout;

    .line 164
    .line 165
    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputLayout;->t()V

    .line 166
    .line 167
    .line 168
    invoke-virtual {v0, v7, v8}, Lcom/google/android/material/textfield/TextInputLayout;->w(ZZ)V

    .line 169
    .line 170
    .line 171
    invoke-virtual {v0}, Lcom/google/android/material/textfield/TextInputLayout;->z()V

    .line 172
    .line 173
    .line 174
    return-void
.end method

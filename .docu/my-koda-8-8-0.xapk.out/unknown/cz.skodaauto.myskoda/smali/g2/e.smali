.class public final Lg2/e;
.super Landroid/view/View;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final i:[I

.field public static final j:[I


# instance fields
.field public d:Lg2/g;

.field public e:Ljava/lang/Boolean;

.field public f:Ljava/lang/Long;

.field public g:La0/d;

.field public h:Ld2/g;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const v0, 0x10100a7

    .line 2
    .line 3
    .line 4
    const v1, 0x101009e

    .line 5
    .line 6
    .line 7
    filled-new-array {v0, v1}, [I

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lg2/e;->i:[I

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    new-array v0, v0, [I

    .line 15
    .line 16
    sput-object v0, Lg2/e;->j:[I

    .line 17
    .line 18
    return-void
.end method

.method public static synthetic a(Lg2/e;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lg2/e;->setRippleState$lambda$2(Lg2/e;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private final setRippleState(Z)V
    .locals 6

    .line 1
    invoke-static {}, Landroid/view/animation/AnimationUtils;->currentAnimationTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iget-object v2, p0, Lg2/e;->g:La0/d;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, v2}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 10
    .line 11
    .line 12
    invoke-virtual {v2}, La0/d;->run()V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v2, p0, Lg2/e;->f:Ljava/lang/Long;

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    invoke-virtual {v2}, Ljava/lang/Long;->longValue()J

    .line 20
    .line 21
    .line 22
    move-result-wide v2

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    const-wide/16 v2, 0x0

    .line 25
    .line 26
    :goto_0
    sub-long v2, v0, v2

    .line 27
    .line 28
    if-nez p1, :cond_2

    .line 29
    .line 30
    const-wide/16 v4, 0x5

    .line 31
    .line 32
    cmp-long v2, v2, v4

    .line 33
    .line 34
    if-gez v2, :cond_2

    .line 35
    .line 36
    new-instance p1, La0/d;

    .line 37
    .line 38
    const/16 v2, 0x13

    .line 39
    .line 40
    invoke-direct {p1, p0, v2}, La0/d;-><init>(Ljava/lang/Object;I)V

    .line 41
    .line 42
    .line 43
    iput-object p1, p0, Lg2/e;->g:La0/d;

    .line 44
    .line 45
    const-wide/16 v2, 0x32

    .line 46
    .line 47
    invoke-virtual {p0, p1, v2, v3}, Landroid/view/View;->postDelayed(Ljava/lang/Runnable;J)Z

    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :cond_2
    if-eqz p1, :cond_3

    .line 52
    .line 53
    sget-object p1, Lg2/e;->i:[I

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    sget-object p1, Lg2/e;->j:[I

    .line 57
    .line 58
    :goto_1
    iget-object v2, p0, Lg2/e;->d:Lg2/g;

    .line 59
    .line 60
    if-eqz v2, :cond_4

    .line 61
    .line 62
    invoke-virtual {v2, p1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 63
    .line 64
    .line 65
    :cond_4
    :goto_2
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    iput-object p1, p0, Lg2/e;->f:Ljava/lang/Long;

    .line 70
    .line 71
    return-void
.end method

.method private static final setRippleState$lambda$2(Lg2/e;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v1, Lg2/e;->j:[I

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 8
    .line 9
    .line 10
    :cond_0
    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lg2/e;->g:La0/d;

    .line 12
    .line 13
    return-void
.end method


# virtual methods
.method public final b(Li1/n;ZJIJFLd2/g;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    iget-object v1, p0, Lg2/e;->e:Ljava/lang/Boolean;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    if-nez v0, :cond_1

    .line 16
    .line 17
    :cond_0
    new-instance v0, Lg2/g;

    .line 18
    .line 19
    invoke-direct {v0, p2}, Lg2/g;-><init>(Z)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {p0, v0}, Landroid/view/View;->setBackground(Landroid/graphics/drawable/Drawable;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 26
    .line 27
    invoke-static {p2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iput-object v0, p0, Lg2/e;->e:Ljava/lang/Boolean;

    .line 32
    .line 33
    :cond_1
    iget-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 34
    .line 35
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 36
    .line 37
    .line 38
    iput-object p9, p0, Lg2/e;->h:Ld2/g;

    .line 39
    .line 40
    move p9, p8

    .line 41
    move-wide p7, p6

    .line 42
    move p6, p5

    .line 43
    move-wide p4, p3

    .line 44
    move-object p3, p0

    .line 45
    invoke-virtual/range {p3 .. p9}, Lg2/e;->e(JIJF)V

    .line 46
    .line 47
    .line 48
    if-eqz p2, :cond_2

    .line 49
    .line 50
    iget-wide p4, p1, Li1/n;->a:J

    .line 51
    .line 52
    invoke-static {p4, p5}, Ld3/b;->e(J)F

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    iget-wide p1, p1, Li1/n;->a:J

    .line 57
    .line 58
    invoke-static {p1, p2}, Ld3/b;->f(J)F

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    invoke-virtual {v0, p0, p1}, Landroid/graphics/drawable/Drawable;->setHotspot(FF)V

    .line 63
    .line 64
    .line 65
    goto :goto_0

    .line 66
    :cond_2
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    invoke-virtual {p0}, Landroid/graphics/Rect;->centerX()I

    .line 71
    .line 72
    .line 73
    move-result p0

    .line 74
    int-to-float p0, p0

    .line 75
    invoke-virtual {v0}, Landroid/graphics/drawable/Drawable;->getBounds()Landroid/graphics/Rect;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    invoke-virtual {p1}, Landroid/graphics/Rect;->centerY()I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    int-to-float p1, p1

    .line 84
    invoke-virtual {v0, p0, p1}, Landroid/graphics/drawable/Drawable;->setHotspot(FF)V

    .line 85
    .line 86
    .line 87
    :goto_0
    const/4 p0, 0x1

    .line 88
    invoke-direct {p3, p0}, Lg2/e;->setRippleState(Z)V

    .line 89
    .line 90
    .line 91
    return-void
.end method

.method public final c()V
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lg2/e;->h:Ld2/g;

    .line 3
    .line 4
    iget-object v0, p0, Lg2/e;->g:La0/d;

    .line 5
    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Landroid/view/View;->removeCallbacks(Ljava/lang/Runnable;)Z

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lg2/e;->g:La0/d;

    .line 12
    .line 13
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v0}, La0/d;->run()V

    .line 17
    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    iget-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    sget-object v1, Lg2/e;->j:[I

    .line 25
    .line 26
    invoke-virtual {v0, v1}, Landroid/graphics/drawable/Drawable;->setState([I)Z

    .line 27
    .line 28
    .line 29
    :cond_1
    :goto_0
    iget-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 30
    .line 31
    if-nez v0, :cond_2

    .line 32
    .line 33
    return-void

    .line 34
    :cond_2
    const/4 v1, 0x0

    .line 35
    invoke-virtual {v0, v1, v1}, Landroid/graphics/drawable/Drawable;->setVisible(ZZ)Z

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v0}, Landroid/view/View;->unscheduleDrawable(Landroid/graphics/drawable/Drawable;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public final d()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lg2/e;->setRippleState(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final draw(Landroid/graphics/Canvas;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/view/View;->isAttachedToWindow()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lg2/e;->c()V

    .line 8
    .line 9
    .line 10
    return-void

    .line 11
    :cond_0
    invoke-super {p0, p1}, Landroid/view/View;->draw(Landroid/graphics/Canvas;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public final e(JIJF)V
    .locals 3

    .line 1
    iget-object v0, p0, Lg2/e;->d:Lg2/g;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v1, v0, Lg2/g;->f:Ljava/lang/Integer;

    .line 7
    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_1
    invoke-virtual {v1}, Ljava/lang/Integer;->intValue()I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-eq v1, p3, :cond_2

    .line 16
    .line 17
    :goto_0
    invoke-static {p3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    iput-object v1, v0, Lg2/g;->f:Ljava/lang/Integer;

    .line 22
    .line 23
    invoke-virtual {v0, p3}, Landroid/graphics/drawable/RippleDrawable;->setRadius(I)V

    .line 24
    .line 25
    .line 26
    :cond_2
    const/high16 p3, 0x3f800000    # 1.0f

    .line 27
    .line 28
    cmpl-float v1, p6, p3

    .line 29
    .line 30
    if-lez v1, :cond_3

    .line 31
    .line 32
    move p6, p3

    .line 33
    :cond_3
    invoke-static {p4, p5, p6}, Le3/s;->b(JF)J

    .line 34
    .line 35
    .line 36
    move-result-wide p3

    .line 37
    iget-object p5, v0, Lg2/g;->e:Le3/s;

    .line 38
    .line 39
    const/4 p6, 0x0

    .line 40
    if-nez p5, :cond_4

    .line 41
    .line 42
    move p5, p6

    .line 43
    goto :goto_1

    .line 44
    :cond_4
    iget-wide v1, p5, Le3/s;->a:J

    .line 45
    .line 46
    invoke-static {v1, v2, p3, p4}, Le3/s;->c(JJ)Z

    .line 47
    .line 48
    .line 49
    move-result p5

    .line 50
    :goto_1
    if-nez p5, :cond_5

    .line 51
    .line 52
    new-instance p5, Le3/s;

    .line 53
    .line 54
    invoke-direct {p5, p3, p4}, Le3/s;-><init>(J)V

    .line 55
    .line 56
    .line 57
    iput-object p5, v0, Lg2/g;->e:Le3/s;

    .line 58
    .line 59
    invoke-static {p3, p4}, Le3/j0;->z(J)I

    .line 60
    .line 61
    .line 62
    move-result p3

    .line 63
    invoke-static {p3}, Landroid/content/res/ColorStateList;->valueOf(I)Landroid/content/res/ColorStateList;

    .line 64
    .line 65
    .line 66
    move-result-object p3

    .line 67
    invoke-virtual {v0, p3}, Landroid/graphics/drawable/RippleDrawable;->setColor(Landroid/content/res/ColorStateList;)V

    .line 68
    .line 69
    .line 70
    :cond_5
    new-instance p3, Landroid/graphics/Rect;

    .line 71
    .line 72
    invoke-static {p1, p2}, Ld3/e;->d(J)F

    .line 73
    .line 74
    .line 75
    move-result p4

    .line 76
    invoke-static {p4}, Lcy0/a;->i(F)I

    .line 77
    .line 78
    .line 79
    move-result p4

    .line 80
    invoke-static {p1, p2}, Ld3/e;->b(J)F

    .line 81
    .line 82
    .line 83
    move-result p1

    .line 84
    invoke-static {p1}, Lcy0/a;->i(F)I

    .line 85
    .line 86
    .line 87
    move-result p1

    .line 88
    invoke-direct {p3, p6, p6, p4, p1}, Landroid/graphics/Rect;-><init>(IIII)V

    .line 89
    .line 90
    .line 91
    iget p1, p3, Landroid/graphics/Rect;->left:I

    .line 92
    .line 93
    invoke-virtual {p0, p1}, Landroid/view/View;->setLeft(I)V

    .line 94
    .line 95
    .line 96
    iget p1, p3, Landroid/graphics/Rect;->top:I

    .line 97
    .line 98
    invoke-virtual {p0, p1}, Landroid/view/View;->setTop(I)V

    .line 99
    .line 100
    .line 101
    iget p1, p3, Landroid/graphics/Rect;->right:I

    .line 102
    .line 103
    invoke-virtual {p0, p1}, Landroid/view/View;->setRight(I)V

    .line 104
    .line 105
    .line 106
    iget p1, p3, Landroid/graphics/Rect;->bottom:I

    .line 107
    .line 108
    invoke-virtual {p0, p1}, Landroid/view/View;->setBottom(I)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v0, p3}, Landroid/graphics/drawable/Drawable;->setBounds(Landroid/graphics/Rect;)V

    .line 112
    .line 113
    .line 114
    return-void
.end method

.method public final invalidateDrawable(Landroid/graphics/drawable/Drawable;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lg2/e;->h:Ld2/g;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Ld2/g;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final onLayout(ZIIII)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onMeasure(II)V
    .locals 0

    .line 1
    const/4 p1, 0x0

    .line 2
    invoke-virtual {p0, p1, p1}, Landroid/view/View;->setMeasuredDimension(II)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public final refreshDrawableState()V
    .locals 0

    .line 1
    return-void
.end method

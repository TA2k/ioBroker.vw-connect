.class public final Landroidx/fragment/app/h;
.super Landroidx/fragment/app/f2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Landroidx/fragment/app/f;

.field public d:Landroid/animation/AnimatorSet;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/h;->c:Landroidx/fragment/app/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Landroid/view/ViewGroup;)V
    .locals 1

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Landroidx/fragment/app/h;->d:Landroid/animation/AnimatorSet;

    .line 7
    .line 8
    iget-object v0, p0, Landroidx/fragment/app/h;->c:Landroidx/fragment/app/f;

    .line 9
    .line 10
    if-nez p1, :cond_0

    .line 11
    .line 12
    iget-object p1, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    iget-object p0, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 19
    .line 20
    iget-boolean v0, p0, Landroidx/fragment/app/g2;->g:Z

    .line 21
    .line 22
    if-eqz v0, :cond_1

    .line 23
    .line 24
    sget-object v0, Landroidx/fragment/app/j;->a:Landroidx/fragment/app/j;

    .line 25
    .line 26
    invoke-virtual {v0, p1}, Landroidx/fragment/app/j;->a(Landroid/animation/AnimatorSet;)V

    .line 27
    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_1
    invoke-virtual {p1}, Landroid/animation/AnimatorSet;->end()V

    .line 31
    .line 32
    .line 33
    :goto_0
    const/4 p1, 0x2

    .line 34
    invoke-static {p1}, Landroidx/fragment/app/j1;->L(I)Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-eqz p1, :cond_3

    .line 39
    .line 40
    new-instance p1, Ljava/lang/StringBuilder;

    .line 41
    .line 42
    const-string v0, "Animator from operation "

    .line 43
    .line 44
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v0, " has been canceled"

    .line 51
    .line 52
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-boolean p0, p0, Landroidx/fragment/app/g2;->g:Z

    .line 56
    .line 57
    if-eqz p0, :cond_2

    .line 58
    .line 59
    const-string p0, " with seeking."

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_2
    const-string p0, "."

    .line 63
    .line 64
    :goto_1
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    const/16 p0, 0x20

    .line 68
    .line 69
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    const-string p1, "FragmentManager"

    .line 77
    .line 78
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 79
    .line 80
    .line 81
    :cond_3
    return-void
.end method

.method public final c(Landroid/view/ViewGroup;)V
    .locals 1

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Landroidx/fragment/app/h;->c:Landroidx/fragment/app/f;

    .line 7
    .line 8
    iget-object p1, p1, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 9
    .line 10
    iget-object v0, p0, Landroidx/fragment/app/h;->d:Landroid/animation/AnimatorSet;

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    invoke-virtual {v0}, Landroid/animation/AnimatorSet;->start()V

    .line 19
    .line 20
    .line 21
    const/4 p0, 0x2

    .line 22
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    if-eqz p0, :cond_1

    .line 27
    .line 28
    new-instance p0, Ljava/lang/StringBuilder;

    .line 29
    .line 30
    const-string v0, "Animator from operation "

    .line 31
    .line 32
    invoke-direct {p0, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string p1, " has started."

    .line 39
    .line 40
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const-string p1, "FragmentManager"

    .line 48
    .line 49
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    :cond_1
    return-void
.end method

.method public final d(Lb/c;Landroid/view/ViewGroup;)V
    .locals 9

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Landroidx/fragment/app/h;->c:Landroidx/fragment/app/f;

    .line 7
    .line 8
    iget-object p2, p2, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 9
    .line 10
    iget-object v0, p0, Landroidx/fragment/app/h;->d:Landroid/animation/AnimatorSet;

    .line 11
    .line 12
    if-nez v0, :cond_0

    .line 13
    .line 14
    invoke-virtual {p2, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :cond_0
    sget p0, Landroid/os/Build$VERSION;->SDK_INT:I

    .line 19
    .line 20
    const/16 v1, 0x22

    .line 21
    .line 22
    if-lt p0, v1, :cond_5

    .line 23
    .line 24
    iget-object p0, p2, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 25
    .line 26
    iget-boolean p0, p0, Landroidx/fragment/app/j0;->mTransitioning:Z

    .line 27
    .line 28
    if-eqz p0, :cond_5

    .line 29
    .line 30
    const/4 p0, 0x2

    .line 31
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    const-string v2, "FragmentManager"

    .line 36
    .line 37
    if-eqz v1, :cond_1

    .line 38
    .line 39
    new-instance v1, Ljava/lang/StringBuilder;

    .line 40
    .line 41
    const-string v3, "Adding BackProgressCallbacks for Animators to operation "

    .line 42
    .line 43
    invoke-direct {v1, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v1

    .line 53
    invoke-static {v2, v1}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 54
    .line 55
    .line 56
    :cond_1
    sget-object v1, Landroidx/fragment/app/i;->a:Landroidx/fragment/app/i;

    .line 57
    .line 58
    invoke-virtual {v1, v0}, Landroidx/fragment/app/i;->a(Landroid/animation/AnimatorSet;)J

    .line 59
    .line 60
    .line 61
    move-result-wide v3

    .line 62
    iget p1, p1, Lb/c;->c:F

    .line 63
    .line 64
    long-to-float v1, v3

    .line 65
    mul-float/2addr p1, v1

    .line 66
    float-to-long v5, p1

    .line 67
    const-wide/16 v7, 0x0

    .line 68
    .line 69
    cmp-long p1, v5, v7

    .line 70
    .line 71
    const-wide/16 v7, 0x1

    .line 72
    .line 73
    if-nez p1, :cond_2

    .line 74
    .line 75
    move-wide v5, v7

    .line 76
    :cond_2
    cmp-long p1, v5, v3

    .line 77
    .line 78
    if-nez p1, :cond_3

    .line 79
    .line 80
    sub-long v5, v3, v7

    .line 81
    .line 82
    :cond_3
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    if-eqz p0, :cond_4

    .line 87
    .line 88
    new-instance p0, Ljava/lang/StringBuilder;

    .line 89
    .line 90
    const-string p1, "Setting currentPlayTime to "

    .line 91
    .line 92
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    invoke-virtual {p0, v5, v6}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    const-string p1, " for Animator "

    .line 99
    .line 100
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    const-string p1, " on operation "

    .line 107
    .line 108
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-static {v2, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 119
    .line 120
    .line 121
    :cond_4
    sget-object p0, Landroidx/fragment/app/j;->a:Landroidx/fragment/app/j;

    .line 122
    .line 123
    invoke-virtual {p0, v0, v5, v6}, Landroidx/fragment/app/j;->b(Landroid/animation/AnimatorSet;J)V

    .line 124
    .line 125
    .line 126
    :cond_5
    return-void
.end method

.method public final e(Landroid/view/ViewGroup;)V
    .locals 8

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/h;->c:Landroidx/fragment/app/f;

    .line 7
    .line 8
    invoke-virtual {v0}, Landroidx/fragment/app/k;->a()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    goto :goto_4

    .line 15
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "context"

    .line 20
    .line 21
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {v0, v1}, Landroidx/fragment/app/f;->b(Landroid/content/Context;)Landroidx/fragment/app/p0;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    if-eqz v1, :cond_1

    .line 29
    .line 30
    iget-object v1, v1, Landroidx/fragment/app/p0;->b:Ljava/lang/Cloneable;

    .line 31
    .line 32
    check-cast v1, Landroid/animation/AnimatorSet;

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_1
    const/4 v1, 0x0

    .line 36
    :goto_0
    iput-object v1, p0, Landroidx/fragment/app/h;->d:Landroid/animation/AnimatorSet;

    .line 37
    .line 38
    iget-object v6, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 39
    .line 40
    iget-object v0, v6, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 41
    .line 42
    iget v1, v6, Landroidx/fragment/app/g2;->a:I

    .line 43
    .line 44
    const/4 v2, 0x3

    .line 45
    if-ne v1, v2, :cond_2

    .line 46
    .line 47
    const/4 v1, 0x1

    .line 48
    :goto_1
    move v5, v1

    .line 49
    goto :goto_2

    .line 50
    :cond_2
    const/4 v1, 0x0

    .line 51
    goto :goto_1

    .line 52
    :goto_2
    iget-object v4, v0, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 53
    .line 54
    invoke-virtual {p1, v4}, Landroid/view/ViewGroup;->startViewTransition(Landroid/view/View;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, p0, Landroidx/fragment/app/h;->d:Landroid/animation/AnimatorSet;

    .line 58
    .line 59
    if-eqz v0, :cond_3

    .line 60
    .line 61
    new-instance v2, Landroidx/fragment/app/g;

    .line 62
    .line 63
    move-object v7, p0

    .line 64
    move-object v3, p1

    .line 65
    invoke-direct/range {v2 .. v7}, Landroidx/fragment/app/g;-><init>(Landroid/view/ViewGroup;Landroid/view/View;ZLandroidx/fragment/app/g2;Landroidx/fragment/app/h;)V

    .line 66
    .line 67
    .line 68
    invoke-virtual {v0, v2}, Landroid/animation/Animator;->addListener(Landroid/animation/Animator$AnimatorListener;)V

    .line 69
    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_3
    move-object v7, p0

    .line 73
    :goto_3
    iget-object p0, v7, Landroidx/fragment/app/h;->d:Landroid/animation/AnimatorSet;

    .line 74
    .line 75
    if-eqz p0, :cond_4

    .line 76
    .line 77
    invoke-virtual {p0, v4}, Landroid/animation/AnimatorSet;->setTarget(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :cond_4
    :goto_4
    return-void
.end method

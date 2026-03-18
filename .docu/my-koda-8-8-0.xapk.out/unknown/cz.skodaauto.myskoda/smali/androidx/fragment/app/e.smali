.class public final Landroidx/fragment/app/e;
.super Landroidx/fragment/app/f2;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final c:Landroidx/fragment/app/f;


# direct methods
.method public constructor <init>(Landroidx/fragment/app/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/fragment/app/e;->c:Landroidx/fragment/app/f;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final b(Landroid/view/ViewGroup;)V
    .locals 3

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/e;->c:Landroidx/fragment/app/f;

    .line 7
    .line 8
    iget-object v1, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 9
    .line 10
    iget-object v2, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 11
    .line 12
    iget-object v2, v2, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 13
    .line 14
    invoke-virtual {v2}, Landroid/view/View;->clearAnimation()V

    .line 15
    .line 16
    .line 17
    invoke-virtual {p1, v2}, Landroid/view/ViewGroup;->endViewTransition(Landroid/view/View;)V

    .line 18
    .line 19
    .line 20
    iget-object p1, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 21
    .line 22
    invoke-virtual {p1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 23
    .line 24
    .line 25
    const/4 p0, 0x2

    .line 26
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    if-eqz p0, :cond_0

    .line 31
    .line 32
    new-instance p0, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string p1, "Animation from operation "

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string p1, " has been cancelled."

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    const-string p1, "FragmentManager"

    .line 52
    .line 53
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 54
    .line 55
    .line 56
    :cond_0
    return-void
.end method

.method public final c(Landroid/view/ViewGroup;)V
    .locals 5

    .line 1
    const-string v0, "container"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Landroidx/fragment/app/e;->c:Landroidx/fragment/app/f;

    .line 7
    .line 8
    iget-object v1, v0, Landroidx/fragment/app/k;->a:Landroidx/fragment/app/g2;

    .line 9
    .line 10
    invoke-virtual {v0}, Landroidx/fragment/app/k;->a()Z

    .line 11
    .line 12
    .line 13
    move-result v2

    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-virtual {v1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    invoke-virtual {p1}, Landroid/view/View;->getContext()Landroid/content/Context;

    .line 21
    .line 22
    .line 23
    move-result-object v2

    .line 24
    iget-object v3, v1, Landroidx/fragment/app/g2;->c:Landroidx/fragment/app/j0;

    .line 25
    .line 26
    iget-object v3, v3, Landroidx/fragment/app/j0;->mView:Landroid/view/View;

    .line 27
    .line 28
    const-string v4, "context"

    .line 29
    .line 30
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, v2}, Landroidx/fragment/app/f;->b(Landroid/content/Context;)Landroidx/fragment/app/p0;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    const-string v2, "Required value was null."

    .line 38
    .line 39
    if-eqz v0, :cond_4

    .line 40
    .line 41
    iget-object v0, v0, Landroidx/fragment/app/p0;->a:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v0, Landroid/view/animation/Animation;

    .line 44
    .line 45
    if-eqz v0, :cond_3

    .line 46
    .line 47
    iget v2, v1, Landroidx/fragment/app/g2;->a:I

    .line 48
    .line 49
    const/4 v4, 0x1

    .line 50
    if-eq v2, v4, :cond_1

    .line 51
    .line 52
    invoke-virtual {v3, v0}, Landroid/view/View;->startAnimation(Landroid/view/animation/Animation;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v1, p0}, Landroidx/fragment/app/g2;->c(Landroidx/fragment/app/f2;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_1
    invoke-virtual {p1, v3}, Landroid/view/ViewGroup;->startViewTransition(Landroid/view/View;)V

    .line 60
    .line 61
    .line 62
    new-instance v2, Landroidx/fragment/app/q0;

    .line 63
    .line 64
    invoke-direct {v2, v0, p1, v3}, Landroidx/fragment/app/q0;-><init>(Landroid/view/animation/Animation;Landroid/view/ViewGroup;Landroid/view/View;)V

    .line 65
    .line 66
    .line 67
    new-instance v0, Landroidx/fragment/app/d;

    .line 68
    .line 69
    invoke-direct {v0, v1, p1, v3, p0}, Landroidx/fragment/app/d;-><init>(Landroidx/fragment/app/g2;Landroid/view/ViewGroup;Landroid/view/View;Landroidx/fragment/app/e;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2, v0}, Landroid/view/animation/Animation;->setAnimationListener(Landroid/view/animation/Animation$AnimationListener;)V

    .line 73
    .line 74
    .line 75
    invoke-virtual {v3, v2}, Landroid/view/View;->startAnimation(Landroid/view/animation/Animation;)V

    .line 76
    .line 77
    .line 78
    const/4 p0, 0x2

    .line 79
    invoke-static {p0}, Landroidx/fragment/app/j1;->L(I)Z

    .line 80
    .line 81
    .line 82
    move-result p0

    .line 83
    if-eqz p0, :cond_2

    .line 84
    .line 85
    new-instance p0, Ljava/lang/StringBuilder;

    .line 86
    .line 87
    const-string p1, "Animation from operation "

    .line 88
    .line 89
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 90
    .line 91
    .line 92
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string p1, " has started."

    .line 96
    .line 97
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    const-string p1, "FragmentManager"

    .line 105
    .line 106
    invoke-static {p1, p0}, Landroid/util/Log;->v(Ljava/lang/String;Ljava/lang/String;)I

    .line 107
    .line 108
    .line 109
    :cond_2
    return-void

    .line 110
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 111
    .line 112
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 113
    .line 114
    .line 115
    throw p0

    .line 116
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 117
    .line 118
    invoke-direct {p0, v2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 119
    .line 120
    .line 121
    throw p0
.end method

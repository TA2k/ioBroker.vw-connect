.class public final Lbb/l0;
.super Landroid/animation/AnimatorListenerAdapter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbb/v;


# instance fields
.field public final a:Landroid/view/View;

.field public final b:I

.field public final c:Landroid/view/ViewGroup;

.field public final d:Z

.field public e:Z

.field public f:Z


# direct methods
.method public constructor <init>(Landroid/view/View;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Landroid/animation/AnimatorListenerAdapter;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-boolean v0, p0, Lbb/l0;->f:Z

    .line 6
    .line 7
    iput-object p1, p0, Lbb/l0;->a:Landroid/view/View;

    .line 8
    .line 9
    iput p2, p0, Lbb/l0;->b:I

    .line 10
    .line 11
    invoke-virtual {p1}, Landroid/view/View;->getParent()Landroid/view/ViewParent;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    check-cast p1, Landroid/view/ViewGroup;

    .line 16
    .line 17
    iput-object p1, p0, Lbb/l0;->c:Landroid/view/ViewGroup;

    .line 18
    .line 19
    const/4 p1, 0x1

    .line 20
    iput-boolean p1, p0, Lbb/l0;->d:Z

    .line 21
    .line 22
    invoke-virtual {p0, p1}, Lbb/l0;->g(Z)V

    .line 23
    .line 24
    .line 25
    return-void
.end method


# virtual methods
.method public final a()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lbb/l0;->g(Z)V

    .line 3
    .line 4
    .line 5
    iget-boolean v0, p0, Lbb/l0;->f:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lbb/i0;->a:Lbb/b;

    .line 10
    .line 11
    iget-object v0, p0, Lbb/l0;->a:Landroid/view/View;

    .line 12
    .line 13
    iget p0, p0, Lbb/l0;->b:I

    .line 14
    .line 15
    invoke-virtual {v0, p0}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lbb/l0;->g(Z)V

    .line 3
    .line 4
    .line 5
    iget-boolean v0, p0, Lbb/l0;->f:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lbb/i0;->a:Lbb/b;

    .line 10
    .line 11
    iget-object p0, p0, Lbb/l0;->a:Landroid/view/View;

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    invoke-virtual {p0, v0}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 15
    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final c(Lbb/x;)V
    .locals 0

    .line 1
    invoke-virtual {p1, p0}, Lbb/x;->B(Lbb/v;)Lbb/x;

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final e(Lbb/x;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final f(Lbb/x;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final g(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lbb/l0;->d:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean v0, p0, Lbb/l0;->e:Z

    .line 6
    .line 7
    if-eq v0, p1, :cond_0

    .line 8
    .line 9
    iget-object v0, p0, Lbb/l0;->c:Landroid/view/ViewGroup;

    .line 10
    .line 11
    if-eqz v0, :cond_0

    .line 12
    .line 13
    iput-boolean p1, p0, Lbb/l0;->e:Z

    .line 14
    .line 15
    invoke-static {v0, p1}, Lbb/h0;->b(Landroid/view/ViewGroup;Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final onAnimationCancel(Landroid/animation/Animator;)V
    .locals 0

    .line 1
    const/4 p1, 0x1

    .line 2
    iput-boolean p1, p0, Lbb/l0;->f:Z

    .line 3
    .line 4
    return-void
.end method

.method public final onAnimationEnd(Landroid/animation/Animator;)V
    .locals 1

    .line 1
    iget-boolean p1, p0, Lbb/l0;->f:Z

    if-nez p1, :cond_0

    .line 2
    sget-object p1, Lbb/i0;->a:Lbb/b;

    .line 3
    iget-object p1, p0, Lbb/l0;->a:Landroid/view/View;

    iget v0, p0, Lbb/l0;->b:I

    invoke-virtual {p1, v0}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 4
    iget-object p1, p0, Lbb/l0;->c:Landroid/view/ViewGroup;

    if-eqz p1, :cond_0

    .line 5
    invoke-virtual {p1}, Landroid/view/View;->invalidate()V

    :cond_0
    const/4 p1, 0x0

    .line 6
    invoke-virtual {p0, p1}, Lbb/l0;->g(Z)V

    return-void
.end method

.method public final onAnimationEnd(Landroid/animation/Animator;Z)V
    .locals 0

    if-nez p2, :cond_1

    .line 7
    iget-boolean p1, p0, Lbb/l0;->f:Z

    if-nez p1, :cond_0

    .line 8
    sget-object p1, Lbb/i0;->a:Lbb/b;

    .line 9
    iget-object p1, p0, Lbb/l0;->a:Landroid/view/View;

    iget p2, p0, Lbb/l0;->b:I

    invoke-virtual {p1, p2}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 10
    iget-object p1, p0, Lbb/l0;->c:Landroid/view/ViewGroup;

    if-eqz p1, :cond_0

    .line 11
    invoke-virtual {p1}, Landroid/view/View;->invalidate()V

    :cond_0
    const/4 p1, 0x0

    .line 12
    invoke-virtual {p0, p1}, Lbb/l0;->g(Z)V

    :cond_1
    return-void
.end method

.method public final onAnimationRepeat(Landroid/animation/Animator;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onAnimationStart(Landroid/animation/Animator;)V
    .locals 0

    .line 1
    return-void
.end method

.method public final onAnimationStart(Landroid/animation/Animator;Z)V
    .locals 0

    if-eqz p2, :cond_0

    .line 2
    sget-object p1, Lbb/i0;->a:Lbb/b;

    .line 3
    iget-object p1, p0, Lbb/l0;->a:Landroid/view/View;

    const/4 p2, 0x0

    invoke-virtual {p1, p2}, Landroid/view/View;->setTransitionVisibility(I)V

    .line 4
    iget-object p0, p0, Lbb/l0;->c:Landroid/view/ViewGroup;

    if-eqz p0, :cond_0

    .line 5
    invoke-virtual {p0}, Landroid/view/View;->invalidate()V

    :cond_0
    return-void
.end method

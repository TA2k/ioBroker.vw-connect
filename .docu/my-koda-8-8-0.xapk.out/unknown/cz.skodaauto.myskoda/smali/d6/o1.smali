.class public Ld6/o1;
.super Ld6/n1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public o:Ls5/b;

.field public p:Ls5/b;

.field public q:Ls5/b;


# direct methods
.method public constructor <init>(Ld6/w1;Landroid/view/WindowInsets;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ld6/n1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Ld6/o1;->o:Ls5/b;

    .line 3
    iput-object p1, p0, Ld6/o1;->p:Ls5/b;

    .line 4
    iput-object p1, p0, Ld6/o1;->q:Ls5/b;

    return-void
.end method

.method public constructor <init>(Ld6/w1;Ld6/o1;)V
    .locals 0

    .line 5
    invoke-direct {p0, p1, p2}, Ld6/n1;-><init>(Ld6/w1;Ld6/n1;)V

    const/4 p1, 0x0

    .line 6
    iput-object p1, p0, Ld6/o1;->o:Ls5/b;

    .line 7
    iput-object p1, p0, Ld6/o1;->p:Ls5/b;

    .line 8
    iput-object p1, p0, Ld6/o1;->q:Ls5/b;

    return-void
.end method


# virtual methods
.method public i()Ls5/b;
    .locals 1

    .line 1
    iget-object v0, p0, Ld6/o1;->p:Ls5/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getMandatorySystemGestureInsets()Landroid/graphics/Insets;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Ld6/o1;->p:Ls5/b;

    .line 16
    .line 17
    :cond_0
    iget-object p0, p0, Ld6/o1;->p:Ls5/b;

    .line 18
    .line 19
    return-object p0
.end method

.method public k()Ls5/b;
    .locals 1

    .line 1
    iget-object v0, p0, Ld6/o1;->o:Ls5/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getSystemGestureInsets()Landroid/graphics/Insets;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Ld6/o1;->o:Ls5/b;

    .line 16
    .line 17
    :cond_0
    iget-object p0, p0, Ld6/o1;->o:Ls5/b;

    .line 18
    .line 19
    return-object p0
.end method

.method public m()Ls5/b;
    .locals 1

    .line 1
    iget-object v0, p0, Ld6/o1;->q:Ls5/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getTappableElementInsets()Landroid/graphics/Insets;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-static {v0}, Ls5/b;->c(Landroid/graphics/Insets;)Ls5/b;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Ld6/o1;->q:Ls5/b;

    .line 16
    .line 17
    :cond_0
    iget-object p0, p0, Ld6/o1;->q:Ls5/b;

    .line 18
    .line 19
    return-object p0
.end method

.method public n(IIII)Ld6/w1;
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3, p4}, Landroid/view/WindowInsets;->inset(IIII)Landroid/view/WindowInsets;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 p1, 0x0

    .line 8
    invoke-static {p1, p0}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

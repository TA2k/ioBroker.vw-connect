.class public Ld6/m1;
.super Ld6/l1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public n:Ls5/b;


# direct methods
.method public constructor <init>(Ld6/w1;Landroid/view/WindowInsets;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ld6/l1;-><init>(Ld6/w1;Landroid/view/WindowInsets;)V

    const/4 p1, 0x0

    .line 2
    iput-object p1, p0, Ld6/m1;->n:Ls5/b;

    return-void
.end method

.method public constructor <init>(Ld6/w1;Ld6/m1;)V
    .locals 0

    .line 3
    invoke-direct {p0, p1, p2}, Ld6/l1;-><init>(Ld6/w1;Ld6/l1;)V

    const/4 p1, 0x0

    .line 4
    iput-object p1, p0, Ld6/m1;->n:Ls5/b;

    .line 5
    iget-object p1, p2, Ld6/m1;->n:Ls5/b;

    iput-object p1, p0, Ld6/m1;->n:Ls5/b;

    return-void
.end method


# virtual methods
.method public b()Ld6/w1;
    .locals 1

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/WindowInsets;->consumeStableInsets()Landroid/view/WindowInsets;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-static {v0, p0}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public c()Ld6/w1;
    .locals 1

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/WindowInsets;->consumeSystemWindowInsets()Landroid/view/WindowInsets;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const/4 v0, 0x0

    .line 8
    invoke-static {v0, p0}, Ld6/w1;->h(Landroid/view/View;Landroid/view/WindowInsets;)Ld6/w1;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    return-object p0
.end method

.method public final j()Ls5/b;
    .locals 4

    .line 1
    iget-object v0, p0, Ld6/m1;->n:Ls5/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 6
    .line 7
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getStableInsetLeft()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getStableInsetTop()I

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getStableInsetRight()I

    .line 16
    .line 17
    .line 18
    move-result v3

    .line 19
    invoke-virtual {v0}, Landroid/view/WindowInsets;->getStableInsetBottom()I

    .line 20
    .line 21
    .line 22
    move-result v0

    .line 23
    invoke-static {v1, v2, v3, v0}, Ls5/b;->b(IIII)Ls5/b;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    iput-object v0, p0, Ld6/m1;->n:Ls5/b;

    .line 28
    .line 29
    :cond_0
    iget-object p0, p0, Ld6/m1;->n:Ls5/b;

    .line 30
    .line 31
    return-object p0
.end method

.method public o()Z
    .locals 0

    .line 1
    iget-object p0, p0, Ld6/l1;->c:Landroid/view/WindowInsets;

    .line 2
    .line 3
    invoke-virtual {p0}, Landroid/view/WindowInsets;->isConsumed()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

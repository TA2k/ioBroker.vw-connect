.class public final Lw4/n;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc3/p;


# virtual methods
.method public final t(Lc3/m;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 2
    .line 3
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-static {p0}, Lw4/i;->c(Lx2/r;)Landroid/view/View;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-virtual {p0}, Landroid/view/View;->hasFocusable()Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    :goto_0
    invoke-interface {p1, p0}, Lc3/m;->b(Z)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

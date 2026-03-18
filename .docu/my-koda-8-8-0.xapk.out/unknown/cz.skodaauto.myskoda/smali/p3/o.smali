.class public final Lp3/o;
.super Lp3/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final Y0(Lp3/q;)V
    .locals 1

    .line 1
    sget-object v0, Lw3/h1;->u:Ll2/u2;

    .line 2
    .line 3
    invoke-static {p0, v0}, Lv3/f;->i(Lv3/l;Ll2/s1;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lp3/r;

    .line 8
    .line 9
    if-eqz p0, :cond_1

    .line 10
    .line 11
    check-cast p0, Lw3/r;

    .line 12
    .line 13
    if-nez p1, :cond_0

    .line 14
    .line 15
    sget-object p1, Lp3/q;->a:Lp3/p;

    .line 16
    .line 17
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    sget-object p1, Lp3/s;->a:Lp3/a;

    .line 21
    .line 22
    :cond_0
    sget-object v0, Lw3/f0;->a:Lw3/f0;

    .line 23
    .line 24
    iget-object p0, p0, Lw3/r;->b:Lw3/t;

    .line 25
    .line 26
    invoke-virtual {v0, p0, p1}, Lw3/f0;->a(Landroid/view/View;Lp3/q;)V

    .line 27
    .line 28
    .line 29
    :cond_1
    return-void
.end method

.method public final a1(I)Z
    .locals 0

    .line 1
    const/4 p0, 0x3

    .line 2
    if-ne p1, p0, :cond_0

    .line 3
    .line 4
    goto :goto_0

    .line 5
    :cond_0
    const/4 p0, 0x4

    .line 6
    if-ne p1, p0, :cond_1

    .line 7
    .line 8
    :goto_0
    const/4 p0, 0x0

    .line 9
    return p0

    .line 10
    :cond_1
    const/4 p0, 0x1

    .line 11
    return p0
.end method

.method public final bridge synthetic g()Ljava/lang/Object;
    .locals 0

    .line 1
    const-string p0, "androidx.compose.ui.input.pointer.PointerHoverIcon"

    .line 2
    .line 3
    return-object p0
.end method

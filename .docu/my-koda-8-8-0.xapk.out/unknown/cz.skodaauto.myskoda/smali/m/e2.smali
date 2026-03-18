.class public final Lm/e2;
.super Lm/z1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm/a2;


# instance fields
.field public D:Lhu/q;


# virtual methods
.method public final m(Ll/l;Landroid/view/MenuItem;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm/e2;->D:Lhu/q;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lhu/q;->m(Ll/l;Landroid/view/MenuItem;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public final p(Landroid/content/Context;Z)Lm/m1;
    .locals 1

    .line 1
    new-instance v0, Lm/d2;

    .line 2
    .line 3
    invoke-direct {v0, p1, p2}, Lm/d2;-><init>(Landroid/content/Context;Z)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {v0, p0}, Lm/d2;->setHoverListener(Lm/a2;)V

    .line 7
    .line 8
    .line 9
    return-object v0
.end method

.method public final q(Ll/l;Ll/n;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lm/e2;->D:Lhu/q;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lhu/q;->q(Ll/l;Ll/n;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

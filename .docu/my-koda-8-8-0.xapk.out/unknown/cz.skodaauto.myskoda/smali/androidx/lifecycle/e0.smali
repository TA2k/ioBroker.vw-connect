.class public final Landroidx/lifecycle/e0;
.super Landroidx/lifecycle/f0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/lifecycle/v;


# instance fields
.field public final h:Landroidx/fragment/app/j0;

.field public final synthetic i:Landroidx/lifecycle/g0;


# direct methods
.method public constructor <init>(Landroidx/lifecycle/g0;Landroidx/fragment/app/j0;Landroidx/lifecycle/j0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Landroidx/lifecycle/e0;->i:Landroidx/lifecycle/g0;

    .line 2
    .line 3
    invoke-direct {p0, p1, p3}, Landroidx/lifecycle/f0;-><init>(Landroidx/lifecycle/g0;Landroidx/lifecycle/j0;)V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Landroidx/lifecycle/e0;->h:Landroidx/fragment/app/j0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final b()V
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/lifecycle/e0;->h:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    invoke-interface {v0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {v0, p0}, Landroidx/lifecycle/r;->d(Landroidx/lifecycle/w;)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final c(Landroidx/fragment/app/j0;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/e0;->h:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    if-ne p0, p1, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final d()Z
    .locals 1

    .line 1
    iget-object p0, p0, Landroidx/lifecycle/e0;->h:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    invoke-interface {p0}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    invoke-virtual {p0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    sget-object v0, Landroidx/lifecycle/q;->g:Landroidx/lifecycle/q;

    .line 12
    .line 13
    invoke-virtual {p0, v0}, Ljava/lang/Enum;->compareTo(Ljava/lang/Enum;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-ltz p0, :cond_0

    .line 18
    .line 19
    const/4 p0, 0x1

    .line 20
    return p0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return p0
.end method

.method public final f(Landroidx/lifecycle/x;Landroidx/lifecycle/p;)V
    .locals 2

    .line 1
    iget-object p1, p0, Landroidx/lifecycle/e0;->h:Landroidx/fragment/app/j0;

    .line 2
    .line 3
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 4
    .line 5
    .line 6
    move-result-object p2

    .line 7
    invoke-virtual {p2}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 8
    .line 9
    .line 10
    move-result-object p2

    .line 11
    sget-object v0, Landroidx/lifecycle/q;->d:Landroidx/lifecycle/q;

    .line 12
    .line 13
    if-ne p2, v0, :cond_0

    .line 14
    .line 15
    iget-object p1, p0, Landroidx/lifecycle/e0;->i:Landroidx/lifecycle/g0;

    .line 16
    .line 17
    iget-object p0, p0, Landroidx/lifecycle/f0;->d:Landroidx/lifecycle/j0;

    .line 18
    .line 19
    invoke-virtual {p1, p0}, Landroidx/lifecycle/g0;->i(Landroidx/lifecycle/j0;)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    const/4 v0, 0x0

    .line 24
    :goto_0
    if-eq v0, p2, :cond_1

    .line 25
    .line 26
    invoke-virtual {p0}, Landroidx/lifecycle/e0;->d()Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    invoke-virtual {p0, v0}, Landroidx/lifecycle/f0;->a(Z)V

    .line 31
    .line 32
    .line 33
    invoke-interface {p1}, Landroidx/lifecycle/x;->getLifecycle()Landroidx/lifecycle/r;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-virtual {v0}, Landroidx/lifecycle/r;->b()Landroidx/lifecycle/q;

    .line 38
    .line 39
    .line 40
    move-result-object v0

    .line 41
    move-object v1, v0

    .line 42
    move-object v0, p2

    .line 43
    move-object p2, v1

    .line 44
    goto :goto_0

    .line 45
    :cond_1
    return-void
.end method

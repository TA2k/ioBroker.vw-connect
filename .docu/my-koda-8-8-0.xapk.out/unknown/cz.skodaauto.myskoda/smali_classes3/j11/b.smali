.class public final Lj11/b;
.super Lj11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(Lb11/a;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lj11/s;->b:Lj11/s;

    .line 2
    .line 3
    :goto_0
    if-eqz p0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lj11/s;->e:Lj11/s;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Lj11/s;->a(Lb11/a;)V

    .line 8
    .line 9
    .line 10
    move-object p0, v0

    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-void
.end method

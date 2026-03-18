.class public final Lq11/o;
.super Lq11/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# virtual methods
.method public final a(IJ)J
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Ln11/a;->a(IJ)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final b(J)I
    .locals 1

    .line 1
    iget-object v0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/a;->b(J)I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-nez p1, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0}, Lq11/o;->l()I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    return p1
.end method

.method public final j()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->j()Ln11/g;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Ln11/a;->l()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    add-int/lit8 p0, p0, 0x1

    .line 8
    .line 9
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final r(J)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->r(J)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final t(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->t(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final u(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->u(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final v(IJ)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lq11/o;->l()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-static {p0, p1, v1, v0}, Ljp/je;->g(Ln11/a;III)V

    .line 7
    .line 8
    .line 9
    if-ne p1, v0, :cond_0

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    :cond_0
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 13
    .line 14
    invoke-virtual {p0, p1, p2, p3}, Ln11/a;->v(IJ)J

    .line 15
    .line 16
    .line 17
    move-result-wide p0

    .line 18
    return-wide p0
.end method

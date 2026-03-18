.class public final Lq11/d;
.super Lq11/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:I

.field public final g:Lq11/l;

.field public final h:Ln11/g;

.field public final i:I

.field public final j:I


# direct methods
.method public constructor <init>(Ln11/a;)V
    .locals 4

    .line 1
    sget-object v0, Ln11/b;->j:Ln11/b;

    .line 2
    .line 3
    invoke-virtual {p1}, Ln11/a;->p()Ln11/g;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    invoke-direct {p0, p1, v0}, Lq11/c;-><init>(Ln11/a;Ln11/b;)V

    .line 8
    .line 9
    .line 10
    invoke-virtual {p1}, Ln11/a;->i()Ln11/g;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    const/4 v0, 0x0

    .line 17
    iput-object v0, p0, Lq11/d;->g:Lq11/l;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v2, Lq11/l;

    .line 21
    .line 22
    sget-object v3, Ln11/h;->g:Ln11/h;

    .line 23
    .line 24
    invoke-direct {v2, v0, v3}, Lq11/l;-><init>(Ln11/g;Ln11/h;)V

    .line 25
    .line 26
    .line 27
    iput-object v2, p0, Lq11/d;->g:Lq11/l;

    .line 28
    .line 29
    :goto_0
    iput-object v1, p0, Lq11/d;->h:Ln11/g;

    .line 30
    .line 31
    const/16 v0, 0x64

    .line 32
    .line 33
    iput v0, p0, Lq11/d;->f:I

    .line 34
    .line 35
    invoke-virtual {p1}, Ln11/a;->o()I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-ltz v1, :cond_1

    .line 40
    .line 41
    div-int/2addr v1, v0

    .line 42
    goto :goto_1

    .line 43
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 44
    .line 45
    div-int/2addr v1, v0

    .line 46
    add-int/lit8 v1, v1, -0x1

    .line 47
    .line 48
    :goto_1
    invoke-virtual {p1}, Ln11/a;->l()I

    .line 49
    .line 50
    .line 51
    move-result p1

    .line 52
    if-ltz p1, :cond_2

    .line 53
    .line 54
    div-int/2addr p1, v0

    .line 55
    goto :goto_2

    .line 56
    :cond_2
    add-int/lit8 p1, p1, 0x1

    .line 57
    .line 58
    div-int/2addr p1, v0

    .line 59
    add-int/lit8 p1, p1, -0x1

    .line 60
    .line 61
    :goto_2
    iput v1, p0, Lq11/d;->i:I

    .line 62
    .line 63
    iput p1, p0, Lq11/d;->j:I

    .line 64
    .line 65
    return-void
.end method


# virtual methods
.method public final a(IJ)J
    .locals 1

    .line 1
    iget v0, p0, Lq11/d;->f:I

    .line 2
    .line 3
    mul-int/2addr p1, v0

    .line 4
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 5
    .line 6
    invoke-virtual {p0, p1, p2, p3}, Ln11/a;->a(IJ)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
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
    iget p0, p0, Lq11/d;->f:I

    .line 8
    .line 9
    if-ltz p1, :cond_0

    .line 10
    .line 11
    div-int/2addr p1, p0

    .line 12
    return p1

    .line 13
    :cond_0
    add-int/lit8 p1, p1, 0x1

    .line 14
    .line 15
    div-int/2addr p1, p0

    .line 16
    add-int/lit8 p1, p1, -0x1

    .line 17
    .line 18
    return p1
.end method

.method public final i()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/d;->g:Lq11/l;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget p0, p0, Lq11/d;->j:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lq11/d;->i:I

    .line 2
    .line 3
    return p0
.end method

.method public final p()Ln11/g;
    .locals 1

    .line 1
    iget-object v0, p0, Lq11/d;->h:Ln11/g;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-object v0

    .line 6
    :cond_0
    invoke-super {p0}, Lq11/c;->p()Ln11/g;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method

.method public final t(J)J
    .locals 2

    .line 1
    iget-object v0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {v0, p1, p2}, Ln11/a;->t(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    invoke-virtual {p0, v0, v1}, Lq11/d;->b(J)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-virtual {p0, v0, p1, p2}, Lq11/d;->v(IJ)J

    .line 12
    .line 13
    .line 14
    move-result-wide p0

    .line 15
    return-wide p0
.end method

.method public final u(J)J
    .locals 2

    .line 1
    invoke-virtual {p0, p1, p2}, Lq11/d;->b(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    iget v1, p0, Lq11/d;->f:I

    .line 6
    .line 7
    mul-int/2addr v0, v1

    .line 8
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 9
    .line 10
    invoke-virtual {p0, v0, p1, p2}, Ln11/a;->v(IJ)J

    .line 11
    .line 12
    .line 13
    move-result-wide p1

    .line 14
    invoke-virtual {p0, p1, p2}, Ln11/a;->u(J)J

    .line 15
    .line 16
    .line 17
    move-result-wide p0

    .line 18
    return-wide p0
.end method

.method public final v(IJ)J
    .locals 3

    .line 1
    iget v0, p0, Lq11/d;->i:I

    .line 2
    .line 3
    iget v1, p0, Lq11/d;->j:I

    .line 4
    .line 5
    invoke-static {p0, p1, v0, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lq11/c;->e:Ln11/a;

    .line 9
    .line 10
    invoke-virtual {v0, p2, p3}, Ln11/a;->b(J)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    iget p0, p0, Lq11/d;->f:I

    .line 15
    .line 16
    if-ltz v1, :cond_0

    .line 17
    .line 18
    rem-int/2addr v1, p0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    add-int/lit8 v2, p0, -0x1

    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    rem-int/2addr v1, p0

    .line 25
    add-int/2addr v1, v2

    .line 26
    :goto_0
    mul-int/2addr p1, p0

    .line 27
    add-int/2addr p1, v1

    .line 28
    invoke-virtual {v0, p1, p2, p3}, Ln11/a;->v(IJ)J

    .line 29
    .line 30
    .line 31
    move-result-wide p0

    .line 32
    return-wide p0
.end method

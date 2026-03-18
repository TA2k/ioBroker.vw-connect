.class public final Lp11/l;
.super Lq11/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:Lp11/m;


# direct methods
.method public constructor <init>(Lp11/h;Lp11/m;)V
    .locals 1

    .line 1
    sget-object v0, Ln11/b;->i:Ln11/b;

    .line 2
    .line 3
    invoke-direct {p0, p1, v0}, Lq11/c;-><init>(Ln11/a;Ln11/b;)V

    .line 4
    .line 5
    .line 6
    iput-object p2, p0, Lp11/l;->f:Lp11/m;

    .line 7
    .line 8
    return-void
.end method


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
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Ln11/a;->b(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    if-gtz p0, :cond_0

    .line 8
    .line 9
    rsub-int/lit8 p0, p0, 0x1

    .line 10
    .line 11
    :cond_0
    return p0
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
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lp11/l;->f:Lp11/m;

    .line 2
    .line 3
    iget-object p0, p0, Lp11/b;->q:Ln11/g;

    .line 4
    .line 5
    return-object p0
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
    .locals 3

    .line 1
    iget-object v0, p0, Lq11/c;->e:Ln11/a;

    .line 2
    .line 3
    invoke-virtual {v0}, Ln11/a;->l()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    const/4 v2, 0x1

    .line 8
    invoke-static {p0, p1, v2, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 9
    .line 10
    .line 11
    iget-object p0, p0, Lp11/l;->f:Lp11/m;

    .line 12
    .line 13
    invoke-virtual {p0, p2, p3}, Lp11/e;->X(J)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    if-gtz p0, :cond_0

    .line 18
    .line 19
    rsub-int/lit8 p1, p1, 0x1

    .line 20
    .line 21
    :cond_0
    invoke-virtual {v0, p1, p2, p3}, Ln11/a;->v(IJ)J

    .line 22
    .line 23
    .line 24
    move-result-wide p0

    .line 25
    return-wide p0
.end method

.class public final Lq11/k;
.super Lq11/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final f:I

.field public final g:Ln11/g;

.field public final h:Ln11/g;


# direct methods
.method public constructor <init>(Ln11/a;Ln11/g;)V
    .locals 1

    sget-object v0, Ln11/b;->p:Ln11/b;

    .line 6
    invoke-direct {p0, p1, v0}, Lq11/c;-><init>(Ln11/a;Ln11/b;)V

    .line 7
    iput-object p2, p0, Lq11/k;->h:Ln11/g;

    .line 8
    invoke-virtual {p1}, Ln11/a;->i()Ln11/g;

    move-result-object p1

    iput-object p1, p0, Lq11/k;->g:Ln11/g;

    const/16 p1, 0x64

    .line 9
    iput p1, p0, Lq11/k;->f:I

    return-void
.end method

.method public constructor <init>(Lq11/d;Ln11/g;Ln11/b;)V
    .locals 1

    .line 1
    iget-object v0, p1, Lq11/c;->e:Ln11/a;

    .line 2
    invoke-direct {p0, v0, p3}, Lq11/c;-><init>(Ln11/a;Ln11/b;)V

    .line 3
    iget p3, p1, Lq11/d;->f:I

    iput p3, p0, Lq11/k;->f:I

    .line 4
    iput-object p2, p0, Lq11/k;->g:Ln11/g;

    .line 5
    iget-object p1, p1, Lq11/d;->g:Lq11/l;

    iput-object p1, p0, Lq11/k;->h:Ln11/g;

    return-void
.end method


# virtual methods
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
    iget p0, p0, Lq11/k;->f:I

    .line 8
    .line 9
    if-ltz p1, :cond_0

    .line 10
    .line 11
    rem-int/2addr p1, p0

    .line 12
    return p1

    .line 13
    :cond_0
    add-int/lit8 p2, p0, -0x1

    .line 14
    .line 15
    add-int/lit8 p1, p1, 0x1

    .line 16
    .line 17
    rem-int/2addr p1, p0

    .line 18
    add-int/2addr p1, p2

    .line 19
    return p1
.end method

.method public final i()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/k;->g:Ln11/g;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()I
    .locals 0

    .line 1
    iget p0, p0, Lq11/k;->f:I

    .line 2
    .line 3
    add-int/lit8 p0, p0, -0x1

    .line 4
    .line 5
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    iget-object p0, p0, Lq11/k;->h:Ln11/g;

    .line 2
    .line 3
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
    iget v0, p0, Lq11/k;->f:I

    .line 2
    .line 3
    add-int/lit8 v1, v0, -0x1

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-static {p0, p1, v2, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 7
    .line 8
    .line 9
    iget-object p0, p0, Lq11/c;->e:Ln11/a;

    .line 10
    .line 11
    invoke-virtual {p0, p2, p3}, Ln11/a;->b(J)I

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    if-ltz v1, :cond_0

    .line 16
    .line 17
    div-int/2addr v1, v0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    div-int/2addr v1, v0

    .line 22
    add-int/lit8 v1, v1, -0x1

    .line 23
    .line 24
    :goto_0
    mul-int/2addr v1, v0

    .line 25
    add-int/2addr v1, p1

    .line 26
    invoke-virtual {p0, v1, p2, p3}, Ln11/a;->v(IJ)J

    .line 27
    .line 28
    .line 29
    move-result-wide p0

    .line 30
    return-wide p0
.end method

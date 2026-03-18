.class public final Le3/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt4/c;


# instance fields
.field public d:I

.field public e:F

.field public f:F

.field public g:F

.field public h:F

.field public i:F

.field public j:F

.field public k:J

.field public l:J

.field public m:F

.field public n:F

.field public o:F

.field public p:F

.field public q:J

.field public r:Le3/n0;

.field public s:Z

.field public t:J

.field public u:Lt4/c;

.field public v:Lt4/m;

.field public w:Le3/o;

.field public x:I

.field public y:Le3/g0;


# virtual methods
.method public final A(J)V
    .locals 2

    .line 1
    iget-wide v0, p0, Le3/k0;->q:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Le3/q0;->a(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget v0, p0, Le3/k0;->d:I

    .line 10
    .line 11
    or-int/lit16 v0, v0, 0x1000

    .line 12
    .line 13
    iput v0, p0, Le3/k0;->d:I

    .line 14
    .line 15
    iput-wide p1, p0, Le3/k0;->q:J

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final B(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->h:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x8

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->h:F

    .line 15
    .line 16
    return-void
.end method

.method public final D(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->i:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x10

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->i:F

    .line 15
    .line 16
    return-void
.end method

.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Le3/k0;->u:Lt4/c;

    .line 2
    .line 3
    invoke-interface {p0}, Lt4/c;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final b(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->g:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x4

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->g:F

    .line 15
    .line 16
    return-void
.end method

.method public final c(J)V
    .locals 2

    .line 1
    iget-wide v0, p0, Le3/k0;->k:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Le3/s;->c(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget v0, p0, Le3/k0;->d:I

    .line 10
    .line 11
    or-int/lit8 v0, v0, 0x40

    .line 12
    .line 13
    iput v0, p0, Le3/k0;->d:I

    .line 14
    .line 15
    iput-wide p1, p0, Le3/k0;->k:J

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final d(Z)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Le3/k0;->s:Z

    .line 2
    .line 3
    if-eq v0, p1, :cond_0

    .line 4
    .line 5
    iget v0, p0, Le3/k0;->d:I

    .line 6
    .line 7
    or-int/lit16 v0, v0, 0x4000

    .line 8
    .line 9
    iput v0, p0, Le3/k0;->d:I

    .line 10
    .line 11
    iput-boolean p1, p0, Le3/k0;->s:Z

    .line 12
    .line 13
    :cond_0
    return-void
.end method

.method public final f(Le3/o;)V
    .locals 2

    .line 1
    iget-object v0, p0, Le3/k0;->w:Le3/o;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget v0, p0, Le3/k0;->d:I

    .line 10
    .line 11
    const/high16 v1, 0x20000

    .line 12
    .line 13
    or-int/2addr v0, v1

    .line 14
    iput v0, p0, Le3/k0;->d:I

    .line 15
    .line 16
    iput-object p1, p0, Le3/k0;->w:Le3/o;

    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public final g(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->m:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit16 v0, v0, 0x100

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->m:F

    .line 15
    .line 16
    return-void
.end method

.method public final h(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->n:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit16 v0, v0, 0x200

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->n:F

    .line 15
    .line 16
    return-void
.end method

.method public final i(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->o:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit16 v0, v0, 0x400

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->o:F

    .line 15
    .line 16
    return-void
.end method

.method public final l(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->e:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x1

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->e:F

    .line 15
    .line 16
    return-void
.end method

.method public final p(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->f:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x2

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->f:F

    .line 15
    .line 16
    return-void
.end method

.method public final t(F)V
    .locals 1

    .line 1
    iget v0, p0, Le3/k0;->j:F

    .line 2
    .line 3
    cmpg-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    return-void

    .line 8
    :cond_0
    iget v0, p0, Le3/k0;->d:I

    .line 9
    .line 10
    or-int/lit8 v0, v0, 0x20

    .line 11
    .line 12
    iput v0, p0, Le3/k0;->d:I

    .line 13
    .line 14
    iput p1, p0, Le3/k0;->j:F

    .line 15
    .line 16
    return-void
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Le3/k0;->u:Lt4/c;

    .line 2
    .line 3
    invoke-interface {p0}, Lt4/c;->t0()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final w(Le3/n0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Le3/k0;->r:Le3/n0;

    .line 2
    .line 3
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget v0, p0, Le3/k0;->d:I

    .line 10
    .line 11
    or-int/lit16 v0, v0, 0x2000

    .line 12
    .line 13
    iput v0, p0, Le3/k0;->d:I

    .line 14
    .line 15
    iput-object p1, p0, Le3/k0;->r:Le3/n0;

    .line 16
    .line 17
    :cond_0
    return-void
.end method

.method public final z(J)V
    .locals 2

    .line 1
    iget-wide v0, p0, Le3/k0;->l:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1, p2}, Le3/s;->c(JJ)Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    iget v0, p0, Le3/k0;->d:I

    .line 10
    .line 11
    or-int/lit16 v0, v0, 0x80

    .line 12
    .line 13
    iput v0, p0, Le3/k0;->d:I

    .line 14
    .line 15
    iput-wide p1, p0, Le3/k0;->l:J

    .line 16
    .line 17
    :cond_0
    return-void
.end method

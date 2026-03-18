.class public final Lo1/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/s0;


# instance fields
.field public final d:Lo1/a0;

.field public final e:Lt3/p1;

.field public final f:Lo1/b0;

.field public final g:Landroidx/collection/b0;


# direct methods
.method public constructor <init>(Lo1/a0;Lt3/p1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lo1/d0;->d:Lo1/a0;

    .line 5
    .line 6
    iput-object p2, p0, Lo1/d0;->e:Lt3/p1;

    .line 7
    .line 8
    iget-object p1, p1, Lo1/a0;->b:Lio0/f;

    .line 9
    .line 10
    invoke-virtual {p1}, Lio0/f;->invoke()Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    check-cast p1, Lo1/b0;

    .line 15
    .line 16
    iput-object p1, p0, Lo1/d0;->f:Lo1/b0;

    .line 17
    .line 18
    invoke-static {}, Landroidx/collection/q;->a()Landroidx/collection/b0;

    .line 19
    .line 20
    .line 21
    new-instance p1, Landroidx/collection/b0;

    .line 22
    .line 23
    invoke-direct {p1}, Landroidx/collection/b0;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lo1/d0;->g:Landroidx/collection/b0;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final G0(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->G0(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final I()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/t;->I()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface/range {p0 .. p5}, Lt3/s0;->N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final Q(F)I
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final V(J)F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->V(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

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

.method public final b(I)Ljava/util/List;
    .locals 4

    .line 1
    iget-object v0, p0, Lo1/d0;->g:Landroidx/collection/b0;

    .line 2
    .line 3
    invoke-virtual {v0, p1}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    check-cast v1, Ljava/util/List;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    return-object v1

    .line 12
    :cond_0
    iget-object v1, p0, Lo1/d0;->f:Lo1/b0;

    .line 13
    .line 14
    invoke-interface {v1, p1}, Lo1/b0;->d(I)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-interface {v1, p1}, Lo1/b0;->b(I)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v3, p0, Lo1/d0;->d:Lo1/a0;

    .line 23
    .line 24
    invoke-virtual {v3, p1, v2, v1}, Lo1/a0;->a(ILjava/lang/Object;Ljava/lang/Object;)Lay0/n;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 29
    .line 30
    invoke-interface {p0, v2, v1}, Lt3/p1;->C(Ljava/lang/Object;Lay0/n;)Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    invoke-virtual {v0, p1, p0}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-object p0
.end method

.method public final c0(IILjava/util/Map;Lay0/k;)Lt3/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2, p3, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0}, Lt3/t;->getLayoutDirection()Lt4/m;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final m(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->m(F)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final n(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->n(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final n0(I)F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->n0(I)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final o0(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->o0(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final s(J)F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->s(J)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final t0()F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

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

.method public final w0(F)F
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->w0(F)F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final x(I)J
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->x(I)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final y(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1}, Lt4/c;->y(F)J

    .line 4
    .line 5
    .line 6
    move-result-wide p0

    .line 7
    return-wide p0
.end method

.method public final z0(J)I
    .locals 0

    .line 1
    iget-object p0, p0, Lo1/d0;->e:Lt3/p1;

    .line 2
    .line 3
    invoke-interface {p0, p1, p2}, Lt4/c;->z0(J)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

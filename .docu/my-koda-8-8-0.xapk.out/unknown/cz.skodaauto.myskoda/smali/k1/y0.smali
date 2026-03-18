.class public final Lk1/y0;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;


# instance fields
.field public r:F

.field public s:F

.field public t:F

.field public u:F

.field public v:Z


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 5

    .line 1
    iget v0, p0, Lk1/y0;->r:F

    .line 2
    .line 3
    invoke-interface {p1, v0}, Lt4/c;->Q(F)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    iget v1, p0, Lk1/y0;->t:F

    .line 8
    .line 9
    invoke-interface {p1, v1}, Lt4/c;->Q(F)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    add-int/2addr v1, v0

    .line 14
    iget v0, p0, Lk1/y0;->s:F

    .line 15
    .line 16
    invoke-interface {p1, v0}, Lt4/c;->Q(F)I

    .line 17
    .line 18
    .line 19
    move-result v0

    .line 20
    iget v2, p0, Lk1/y0;->u:F

    .line 21
    .line 22
    invoke-interface {p1, v2}, Lt4/c;->Q(F)I

    .line 23
    .line 24
    .line 25
    move-result v2

    .line 26
    add-int/2addr v2, v0

    .line 27
    neg-int v0, v1

    .line 28
    neg-int v3, v2

    .line 29
    invoke-static {p3, p4, v0, v3}, Lt4/b;->i(JII)J

    .line 30
    .line 31
    .line 32
    move-result-wide v3

    .line 33
    invoke-interface {p2, v3, v4}, Lt3/p0;->L(J)Lt3/e1;

    .line 34
    .line 35
    .line 36
    move-result-object p2

    .line 37
    iget v0, p2, Lt3/e1;->d:I

    .line 38
    .line 39
    add-int/2addr v0, v1

    .line 40
    invoke-static {v0, p3, p4}, Lt4/b;->g(IJ)I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    iget v1, p2, Lt3/e1;->e:I

    .line 45
    .line 46
    add-int/2addr v1, v2

    .line 47
    invoke-static {v1, p3, p4}, Lt4/b;->f(IJ)I

    .line 48
    .line 49
    .line 50
    move-result p3

    .line 51
    new-instance p4, Li40/j0;

    .line 52
    .line 53
    const/16 v1, 0x18

    .line 54
    .line 55
    invoke-direct {p4, v1, p0, p2}, Li40/j0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 59
    .line 60
    invoke-interface {p1, v0, p3, p0, p4}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0
.end method

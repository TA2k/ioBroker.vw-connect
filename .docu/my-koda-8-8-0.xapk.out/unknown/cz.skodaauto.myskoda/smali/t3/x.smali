.class public final Lt3/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/s0;
.implements Lt3/t;


# instance fields
.field public final synthetic d:Lt3/t;

.field public final e:Lt4/m;


# direct methods
.method public constructor <init>(Lt3/t;Lt4/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/x;->d:Lt3/t;

    .line 5
    .line 6
    iput-object p2, p0, Lt3/x;->e:Lt4/m;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final G0(J)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    const/4 p0, 0x0

    .line 2
    if-gez p1, :cond_0

    .line 3
    .line 4
    move p1, p0

    .line 5
    :cond_0
    if-gez p2, :cond_1

    .line 6
    .line 7
    move p2, p0

    .line 8
    :cond_1
    const/high16 p0, -0x1000000

    .line 9
    .line 10
    and-int p5, p1, p0

    .line 11
    .line 12
    if-nez p5, :cond_2

    .line 13
    .line 14
    and-int/2addr p0, p2

    .line 15
    if-nez p0, :cond_2

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_2
    new-instance p0, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string p5, "Size("

    .line 21
    .line 22
    invoke-direct {p0, p5}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string p5, " x "

    .line 29
    .line 30
    invoke-virtual {p0, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    const-string p5, ") is out of range. Each dimension must be between 0 and 16777215."

    .line 37
    .line 38
    invoke-virtual {p0, p5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    invoke-static {p0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    :goto_0
    new-instance p0, Lt3/w;

    .line 49
    .line 50
    invoke-direct {p0, p1, p2, p3, p4}, Lt3/w;-><init>(IILjava/util/Map;Lay0/k;)V

    .line 51
    .line 52
    .line 53
    return-object p0
.end method

.method public final Q(F)I
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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

.method public final getLayoutDirection()Lt4/m;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/x;->e:Lt4/m;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(F)J
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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
    iget-object p0, p0, Lt3/x;->d:Lt3/t;

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

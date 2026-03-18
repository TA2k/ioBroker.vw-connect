.class public abstract Lp3/f;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/c2;
.implements Lv3/t1;
.implements Lv3/l;


# instance fields
.field public r:Lv3/o;

.field public s:Lp3/a;

.field public t:Z


# direct methods
.method public constructor <init>(Lp3/a;Lv3/o;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Lp3/f;->r:Lv3/o;

    .line 5
    .line 6
    iput-object p1, p0, Lp3/f;->s:Lp3/a;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final Q0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lp3/f;->b1()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final X0()V
    .locals 3

    .line 1
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lp3/e;

    .line 7
    .line 8
    const/4 v2, 0x1

    .line 9
    invoke-direct {v1, v2}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 10
    .line 11
    .line 12
    invoke-static {p0, v1}, Lv3/f;->B(Lv3/c2;Lay0/k;)V

    .line 13
    .line 14
    .line 15
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast v0, Lp3/f;

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    iget-object v0, v0, Lp3/f;->s:Lp3/a;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    :cond_0
    iget-object v0, p0, Lp3/f;->s:Lp3/a;

    .line 26
    .line 27
    :cond_1
    invoke-virtual {p0, v0}, Lp3/f;->Y0(Lp3/q;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public abstract Y0(Lp3/q;)V
.end method

.method public final Z0()V
    .locals 2

    .line 1
    new-instance v0, Lkotlin/jvm/internal/b0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x1

    .line 7
    iput-boolean v1, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 8
    .line 9
    new-instance v1, La3/e;

    .line 10
    .line 11
    invoke-direct {v1, v0}, La3/e;-><init>(Lkotlin/jvm/internal/b0;)V

    .line 12
    .line 13
    .line 14
    invoke-static {p0, v1}, Lv3/f;->C(Lv3/c2;Lay0/k;)V

    .line 15
    .line 16
    .line 17
    iget-boolean v0, v0, Lkotlin/jvm/internal/b0;->d:Z

    .line 18
    .line 19
    if-eqz v0, :cond_0

    .line 20
    .line 21
    invoke-virtual {p0}, Lp3/f;->X0()V

    .line 22
    .line 23
    .line 24
    :cond_0
    return-void
.end method

.method public abstract a1(I)Z
.end method

.method public final b0()J
    .locals 4

    .line 1
    iget-object v0, p0, Lp3/f;->r:Lv3/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    iget-object p0, p0, Lv3/h0;->A:Lt4/c;

    .line 10
    .line 11
    sget v1, Lv3/a2;->b:I

    .line 12
    .line 13
    iget v1, v0, Lv3/o;->a:F

    .line 14
    .line 15
    invoke-interface {p0, v1}, Lt4/c;->Q(F)I

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    iget v2, v0, Lv3/o;->b:F

    .line 20
    .line 21
    invoke-interface {p0, v2}, Lt4/c;->Q(F)I

    .line 22
    .line 23
    .line 24
    move-result v2

    .line 25
    iget v3, v0, Lv3/o;->c:F

    .line 26
    .line 27
    invoke-interface {p0, v3}, Lt4/c;->Q(F)I

    .line 28
    .line 29
    .line 30
    move-result v3

    .line 31
    iget v0, v0, Lv3/o;->d:F

    .line 32
    .line 33
    invoke-interface {p0, v0}, Lt4/c;->Q(F)I

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    invoke-static {v1, v2, v3, p0}, Lv3/d;->d(IIII)J

    .line 38
    .line 39
    .line 40
    move-result-wide v0

    .line 41
    return-wide v0

    .line 42
    :cond_0
    sget-wide v0, Lv3/a2;->a:J

    .line 43
    .line 44
    return-wide v0
.end method

.method public final b1()V
    .locals 3

    .line 1
    iget-boolean v0, p0, Lp3/f;->t:Z

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    const/4 v0, 0x0

    .line 6
    iput-boolean v0, p0, Lp3/f;->t:Z

    .line 7
    .line 8
    iget-boolean v0, p0, Lx2/r;->q:Z

    .line 9
    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 13
    .line 14
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    new-instance v1, Lo3/h;

    .line 18
    .line 19
    const/4 v2, 0x1

    .line 20
    invoke-direct {v1, v0, v2}, Lo3/h;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p0, v1}, Lv3/f;->B(Lv3/c2;Lay0/k;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v0, Lp3/f;

    .line 29
    .line 30
    if-eqz v0, :cond_0

    .line 31
    .line 32
    invoke-virtual {v0}, Lp3/f;->X0()V

    .line 33
    .line 34
    .line 35
    return-void

    .line 36
    :cond_0
    const/4 v0, 0x0

    .line 37
    invoke-virtual {p0, v0}, Lp3/f;->Y0(Lp3/q;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    return-void
.end method

.method public final l0()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lp3/f;->b1()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public final v0(Lp3/k;Lp3/l;J)V
    .locals 1

    .line 1
    sget-object p3, Lp3/l;->e:Lp3/l;

    .line 2
    .line 3
    if-ne p2, p3, :cond_2

    .line 4
    .line 5
    iget-object p2, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 6
    .line 7
    move-object p3, p2

    .line 8
    check-cast p3, Ljava/util/Collection;

    .line 9
    .line 10
    invoke-interface {p3}, Ljava/util/Collection;->size()I

    .line 11
    .line 12
    .line 13
    move-result p3

    .line 14
    const/4 p4, 0x0

    .line 15
    :goto_0
    if-ge p4, p3, :cond_2

    .line 16
    .line 17
    invoke-interface {p2, p4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    check-cast v0, Lp3/t;

    .line 22
    .line 23
    iget v0, v0, Lp3/t;->i:I

    .line 24
    .line 25
    invoke-virtual {p0, v0}, Lp3/f;->a1(I)Z

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    iget p1, p1, Lp3/k;->e:I

    .line 32
    .line 33
    const/4 p2, 0x4

    .line 34
    if-ne p1, p2, :cond_0

    .line 35
    .line 36
    const/4 p1, 0x1

    .line 37
    iput-boolean p1, p0, Lp3/f;->t:Z

    .line 38
    .line 39
    invoke-virtual {p0}, Lp3/f;->Z0()V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_0
    const/4 p2, 0x5

    .line 44
    if-ne p1, p2, :cond_2

    .line 45
    .line 46
    invoke-virtual {p0}, Lp3/f;->b1()V

    .line 47
    .line 48
    .line 49
    return-void

    .line 50
    :cond_1
    add-int/lit8 p4, p4, 0x1

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return-void
.end method

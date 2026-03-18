.class public final synthetic Lj2/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:Lj2/p;

.field public final synthetic e:Z

.field public final synthetic f:F

.field public final synthetic g:F

.field public final synthetic h:Le3/n0;


# direct methods
.method public synthetic constructor <init>(Lj2/p;ZFFLe3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj2/b;->d:Lj2/p;

    .line 5
    .line 6
    iput-boolean p2, p0, Lj2/b;->e:Z

    .line 7
    .line 8
    iput p3, p0, Lj2/b;->f:F

    .line 9
    .line 10
    iput p4, p0, Lj2/b;->g:F

    .line 11
    .line 12
    iput-object p5, p0, Lj2/b;->h:Le3/n0;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    .line 1
    check-cast p1, Lt3/s0;

    .line 2
    .line 3
    check-cast p2, Lt3/p0;

    .line 4
    .line 5
    check-cast p3, Lt4/a;

    .line 6
    .line 7
    iget-wide v0, p3, Lt4/a;->a:J

    .line 8
    .line 9
    invoke-interface {p2, v0, v1}, Lt3/p0;->L(J)Lt3/e1;

    .line 10
    .line 11
    .line 12
    move-result-object v3

    .line 13
    iget p2, v3, Lt3/e1;->d:I

    .line 14
    .line 15
    iget p3, v3, Lt3/e1;->e:I

    .line 16
    .line 17
    new-instance v2, Lj2/d;

    .line 18
    .line 19
    iget-object v4, p0, Lj2/b;->d:Lj2/p;

    .line 20
    .line 21
    iget-boolean v5, p0, Lj2/b;->e:Z

    .line 22
    .line 23
    iget v6, p0, Lj2/b;->f:F

    .line 24
    .line 25
    iget v7, p0, Lj2/b;->g:F

    .line 26
    .line 27
    iget-object v8, p0, Lj2/b;->h:Le3/n0;

    .line 28
    .line 29
    invoke-direct/range {v2 .. v8}, Lj2/d;-><init>(Lt3/e1;Lj2/p;ZFFLe3/n0;)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Lmx0/t;->d:Lmx0/t;

    .line 33
    .line 34
    invoke-interface {p1, p2, p3, p0, v2}, Lt3/s0;->c0(IILjava/util/Map;Lay0/k;)Lt3/r0;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    return-object p0
.end method

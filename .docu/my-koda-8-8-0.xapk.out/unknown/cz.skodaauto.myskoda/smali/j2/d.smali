.class public final synthetic Lj2/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:Lt3/e1;

.field public final synthetic e:Lj2/p;

.field public final synthetic f:Z

.field public final synthetic g:F

.field public final synthetic h:F

.field public final synthetic i:Le3/n0;


# direct methods
.method public synthetic constructor <init>(Lt3/e1;Lj2/p;ZFFLe3/n0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lj2/d;->d:Lt3/e1;

    .line 5
    .line 6
    iput-object p2, p0, Lj2/d;->e:Lj2/p;

    .line 7
    .line 8
    iput-boolean p3, p0, Lj2/d;->f:Z

    .line 9
    .line 10
    iput p4, p0, Lj2/d;->g:F

    .line 11
    .line 12
    iput p5, p0, Lj2/d;->h:F

    .line 13
    .line 14
    iput-object p6, p0, Lj2/d;->i:Le3/n0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    .line 1
    move-object v0, p1

    .line 2
    check-cast v0, Lt3/d1;

    .line 3
    .line 4
    new-instance v1, Lj2/e;

    .line 5
    .line 6
    iget-object v2, p0, Lj2/d;->e:Lj2/p;

    .line 7
    .line 8
    iget-boolean v3, p0, Lj2/d;->f:Z

    .line 9
    .line 10
    iget v4, p0, Lj2/d;->g:F

    .line 11
    .line 12
    iget v5, p0, Lj2/d;->h:F

    .line 13
    .line 14
    iget-object v6, p0, Lj2/d;->i:Le3/n0;

    .line 15
    .line 16
    invoke-direct/range {v1 .. v6}, Lj2/e;-><init>(Lj2/p;ZFFLe3/n0;)V

    .line 17
    .line 18
    .line 19
    const/4 v5, 0x4

    .line 20
    iget-object p0, p0, Lj2/d;->d:Lt3/e1;

    .line 21
    .line 22
    const/4 v2, 0x0

    .line 23
    const/4 v3, 0x0

    .line 24
    move-object v4, v1

    .line 25
    move-object v1, p0

    .line 26
    invoke-static/range {v0 .. v5}, Lt3/d1;->z(Lt3/d1;Lt3/e1;IILay0/k;I)V

    .line 27
    .line 28
    .line 29
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0
.end method

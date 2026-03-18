.class public final Lt3/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/r0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:I

.field public final synthetic c:Ljava/util/Map;

.field public final synthetic d:Lay0/k;

.field public final synthetic e:Lt3/h0;

.field public final synthetic f:Lt3/m0;

.field public final synthetic g:Lay0/k;


# direct methods
.method public constructor <init>(IILjava/util/Map;Lay0/k;Lt3/h0;Lt3/m0;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lt3/g0;->a:I

    .line 5
    .line 6
    iput p2, p0, Lt3/g0;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lt3/g0;->c:Ljava/util/Map;

    .line 9
    .line 10
    iput-object p4, p0, Lt3/g0;->d:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Lt3/g0;->e:Lt3/h0;

    .line 13
    .line 14
    iput-object p6, p0, Lt3/g0;->f:Lt3/m0;

    .line 15
    .line 16
    iput-object p7, p0, Lt3/g0;->g:Lay0/k;

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public final b()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/g0;->c:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()V
    .locals 2

    .line 1
    iget-object v0, p0, Lt3/g0;->f:Lt3/m0;

    .line 2
    .line 3
    iget-object v0, v0, Lt3/m0;->d:Lv3/h0;

    .line 4
    .line 5
    iget-object v1, p0, Lt3/g0;->e:Lt3/h0;

    .line 6
    .line 7
    invoke-virtual {v1}, Lt3/h0;->I()Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    iget-object p0, p0, Lt3/g0;->g:Lay0/k;

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object v1, v0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    iget-object v1, v1, Lg1/q;->d:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lv3/u;

    .line 20
    .line 21
    iget-object v1, v1, Lv3/u;->T:Lv3/t;

    .line 22
    .line 23
    if-eqz v1, :cond_0

    .line 24
    .line 25
    iget-object v0, v1, Lv3/p0;->o:Lt3/n0;

    .line 26
    .line 27
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    iget-object v0, v0, Lv3/h0;->H:Lg1/q;

    .line 32
    .line 33
    iget-object v0, v0, Lg1/q;->d:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lv3/u;

    .line 36
    .line 37
    iget-object v0, v0, Lv3/p0;->o:Lt3/n0;

    .line 38
    .line 39
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    return-void
.end method

.method public final d()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/g0;->d:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lt3/g0;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lt3/g0;->a:I

    .line 2
    .line 3
    return p0
.end method

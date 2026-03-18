.class public final Lrl/e;
.super Landroidx/collection/w;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic b:I

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(ILb81/c;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lrl/e;->b:I

    iput-object p2, p0, Lrl/e;->c:Ljava/lang/Object;

    .line 2
    invoke-direct {p0, p1}, Landroidx/collection/w;-><init>(I)V

    return-void
.end method

.method public constructor <init>(Lvp/a1;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lrl/e;->b:I

    .line 1
    iput-object p1, p0, Lrl/e;->c:Ljava/lang/Object;

    const/16 p1, 0x14

    invoke-direct {p0, p1}, Landroidx/collection/w;-><init>(I)V

    return-void
.end method


# virtual methods
.method public create(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lrl/e;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Landroidx/collection/w;->create(Ljava/lang/Object;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    check-cast p1, Ljava/lang/String;

    .line 12
    .line 13
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p0, p0, Lrl/e;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lvp/a1;

    .line 19
    .line 20
    invoke-virtual {p0}, Lvp/u3;->b0()V

    .line 21
    .line 22
    .line 23
    invoke-static {p1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lvp/q3;->f:Lvp/z3;

    .line 27
    .line 28
    iget-object v0, v0, Lvp/z3;->f:Lvp/n;

    .line 29
    .line 30
    invoke-static {v0}, Lvp/z3;->T(Lvp/u3;)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0, p1}, Lvp/n;->g1(Ljava/lang/String;)Lrn/i;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    if-nez v0, :cond_0

    .line 38
    .line 39
    const/4 p0, 0x0

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    iget-object v1, p0, Lap0/o;->e:Ljava/lang/Object;

    .line 42
    .line 43
    check-cast v1, Lvp/g1;

    .line 44
    .line 45
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 46
    .line 47
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 48
    .line 49
    .line 50
    iget-object v1, v1, Lvp/p0;->r:Lvp/n0;

    .line 51
    .line 52
    const-string v2, "Populate EES config from database on cache miss. appId"

    .line 53
    .line 54
    invoke-virtual {v1, p1, v2}, Lvp/n0;->b(Ljava/lang/Object;Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    iget-object v0, v0, Lrn/i;->f:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v0, [B

    .line 60
    .line 61
    invoke-virtual {p0, p1, v0}, Lvp/a1;->j0(Ljava/lang/String;[B)Lcom/google/android/gms/internal/measurement/f2;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    invoke-virtual {p0, p1, v0}, Lvp/a1;->i0(Ljava/lang/String;Lcom/google/android/gms/internal/measurement/f2;)V

    .line 66
    .line 67
    .line 68
    iget-object p0, p0, Lvp/a1;->n:Lrl/e;

    .line 69
    .line 70
    invoke-virtual {p0}, Landroidx/collection/w;->snapshot()Ljava/util/Map;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    check-cast p0, Lcom/google/android/gms/internal/measurement/e0;

    .line 79
    .line 80
    :goto_0
    return-object p0

    .line 81
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public entryRemoved(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lrl/e;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3, p4}, Landroidx/collection/w;->entryRemoved(ZLjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 7
    .line 8
    .line 9
    return-void

    .line 10
    :pswitch_0
    check-cast p2, Lrl/a;

    .line 11
    .line 12
    check-cast p3, Lrl/d;

    .line 13
    .line 14
    check-cast p4, Lrl/d;

    .line 15
    .line 16
    iget-object p0, p0, Lrl/e;->c:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lb81/c;

    .line 19
    .line 20
    iget-object p0, p0, Lb81/c;->e:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast p0, Lhm/g;

    .line 23
    .line 24
    iget-object p1, p3, Lrl/d;->a:Landroid/graphics/Bitmap;

    .line 25
    .line 26
    iget-object p4, p3, Lrl/d;->b:Ljava/util/Map;

    .line 27
    .line 28
    iget p3, p3, Lrl/d;->c:I

    .line 29
    .line 30
    invoke-virtual {p0, p2, p1, p4, p3}, Lhm/g;->d(Lrl/a;Landroid/graphics/Bitmap;Ljava/util/Map;I)V

    .line 31
    .line 32
    .line 33
    return-void

    .line 34
    nop

    .line 35
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public sizeOf(Ljava/lang/Object;Ljava/lang/Object;)I
    .locals 1

    .line 1
    iget v0, p0, Lrl/e;->b:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Landroidx/collection/w;->sizeOf(Ljava/lang/Object;Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    check-cast p1, Lrl/a;

    .line 12
    .line 13
    check-cast p2, Lrl/d;

    .line 14
    .line 15
    iget p0, p2, Lrl/d;->c:I

    .line 16
    .line 17
    return p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

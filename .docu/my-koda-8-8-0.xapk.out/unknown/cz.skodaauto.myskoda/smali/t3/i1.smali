.class public final Lt3/i1;
.super Lx2/r;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv3/y;
.implements Lv3/c2;


# instance fields
.field public r:Lt3/s;

.field public final s:Lb1/e;


# direct methods
.method public constructor <init>(Lt3/s;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Lx2/r;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/i1;->r:Lt3/s;

    .line 5
    .line 6
    new-instance v0, Lb1/e;

    .line 7
    .line 8
    const/16 v1, 0xa

    .line 9
    .line 10
    invoke-direct {v0, v1, p0, p1}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lt3/i1;->s:Lb1/e;

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final c(Lt3/s0;Lt3/p0;J)Lt3/r0;
    .locals 6

    .line 1
    invoke-interface {p2, p3, p4}, Lt3/p0;->L(J)Lt3/e1;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    iget v1, p2, Lt3/e1;->d:I

    .line 6
    .line 7
    iget v2, p2, Lt3/e1;->e:I

    .line 8
    .line 9
    new-instance v5, Lb1/y;

    .line 10
    .line 11
    const/4 p3, 0x5

    .line 12
    invoke-direct {v5, p2, p3}, Lb1/y;-><init>(Lt3/e1;I)V

    .line 13
    .line 14
    .line 15
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 16
    .line 17
    iget-object v4, p0, Lt3/i1;->s:Lb1/e;

    .line 18
    .line 19
    move-object v0, p1

    .line 20
    invoke-interface/range {v0 .. v5}, Lt3/s0;->N(IILjava/util/Map;Lay0/k;Lay0/k;)Lt3/r0;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final g()Ljava/lang/Object;
    .locals 0

    .line 1
    const-string p0, "androidx.compose.ui.layout.WindowInsetsRulers"

    .line 2
    .line 3
    return-object p0
.end method

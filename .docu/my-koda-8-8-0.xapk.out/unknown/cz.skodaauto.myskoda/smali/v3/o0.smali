.class public final Lv3/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/r0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:I

.field public final synthetic c:Ljava/util/Map;

.field public final synthetic d:Lay0/k;

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lv3/p0;


# direct methods
.method public constructor <init>(IILjava/util/Map;Lay0/k;Lay0/k;Lv3/p0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lv3/o0;->a:I

    .line 5
    .line 6
    iput p2, p0, Lv3/o0;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lv3/o0;->c:Ljava/util/Map;

    .line 9
    .line 10
    iput-object p4, p0, Lv3/o0;->d:Lay0/k;

    .line 11
    .line 12
    iput-object p5, p0, Lv3/o0;->e:Lay0/k;

    .line 13
    .line 14
    iput-object p6, p0, Lv3/o0;->f:Lv3/p0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final b()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/o0;->c:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()V
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/o0;->f:Lv3/p0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/p0;->o:Lt3/n0;

    .line 4
    .line 5
    iget-object p0, p0, Lv3/o0;->e:Lay0/k;

    .line 6
    .line 7
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final d()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/o0;->d:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lv3/o0;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lv3/o0;->a:I

    .line 2
    .line 3
    return p0
.end method

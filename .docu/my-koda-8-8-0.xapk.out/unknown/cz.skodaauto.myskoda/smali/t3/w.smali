.class public final Lt3/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/r0;


# instance fields
.field public final synthetic a:I

.field public final synthetic b:I

.field public final synthetic c:Ljava/util/Map;

.field public final synthetic d:Lay0/k;


# direct methods
.method public constructor <init>(IILjava/util/Map;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lt3/w;->a:I

    .line 5
    .line 6
    iput p2, p0, Lt3/w;->b:I

    .line 7
    .line 8
    iput-object p3, p0, Lt3/w;->c:Ljava/util/Map;

    .line 9
    .line 10
    iput-object p4, p0, Lt3/w;->d:Lay0/k;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final b()Ljava/util/Map;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/w;->c:Ljava/util/Map;

    .line 2
    .line 3
    return-object p0
.end method

.method public final c()V
    .locals 0

    .line 1
    return-void
.end method

.method public final d()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lt3/w;->d:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m()I
    .locals 0

    .line 1
    iget p0, p0, Lt3/w;->b:I

    .line 2
    .line 3
    return p0
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lt3/w;->a:I

    .line 2
    .line 3
    return p0
.end method

.class public final Lsu/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lsp/k;

.field public b:Lcom/google/android/gms/maps/model/LatLng;


# direct methods
.method public constructor <init>(Lsp/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsu/f;->a:Lsp/k;

    .line 5
    .line 6
    invoke-virtual {p1}, Lsp/k;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lsu/f;->b:Lcom/google/android/gms/maps/model/LatLng;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lsu/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Lsu/f;

    .line 6
    .line 7
    iget-object p1, p1, Lsu/f;->a:Lsp/k;

    .line 8
    .line 9
    iget-object p0, p0, Lsu/f;->a:Lsp/k;

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Lsp/k;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :cond_0
    const/4 p0, 0x0

    .line 17
    return p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lsu/f;->a:Lsp/k;

    .line 2
    .line 3
    invoke-virtual {p0}, Lsp/k;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

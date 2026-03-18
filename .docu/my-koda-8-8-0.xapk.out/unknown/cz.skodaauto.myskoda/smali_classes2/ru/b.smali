.class public final Lru/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqu/a;


# instance fields
.field public final a:Lzj0/c;

.field public final b:Lyu/a;

.field public final c:Lcom/google/android/gms/maps/model/LatLng;

.field public final d:Ljava/util/Set;


# direct methods
.method public constructor <init>(Lzj0/c;)V
    .locals 11

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lru/b;->a:Lzj0/c;

    .line 5
    .line 6
    invoke-virtual {p1}, Lzj0/c;->a()Lcom/google/android/gms/maps/model/LatLng;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    iput-object v0, p0, Lru/b;->c:Lcom/google/android/gms/maps/model/LatLng;

    .line 11
    .line 12
    iget-wide v1, v0, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 13
    .line 14
    const-wide v3, 0x4076800000000000L    # 360.0

    .line 15
    .line 16
    .line 17
    .line 18
    .line 19
    div-double/2addr v1, v3

    .line 20
    const-wide/high16 v3, 0x3fe0000000000000L    # 0.5

    .line 21
    .line 22
    add-double/2addr v1, v3

    .line 23
    iget-wide v5, v0, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 24
    .line 25
    invoke-static {v5, v6}, Ljava/lang/Math;->toRadians(D)D

    .line 26
    .line 27
    .line 28
    move-result-wide v5

    .line 29
    invoke-static {v5, v6}, Ljava/lang/Math;->sin(D)D

    .line 30
    .line 31
    .line 32
    move-result-wide v5

    .line 33
    const-wide/high16 v7, 0x3ff0000000000000L    # 1.0

    .line 34
    .line 35
    add-double v9, v5, v7

    .line 36
    .line 37
    sub-double v5, v7, v5

    .line 38
    .line 39
    div-double/2addr v9, v5

    .line 40
    invoke-static {v9, v10}, Ljava/lang/Math;->log(D)D

    .line 41
    .line 42
    .line 43
    move-result-wide v5

    .line 44
    mul-double/2addr v5, v3

    .line 45
    const-wide v9, -0x3fe6de04abbbd2e8L    # -6.283185307179586

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    div-double/2addr v5, v9

    .line 51
    add-double/2addr v5, v3

    .line 52
    new-instance v0, Lyu/a;

    .line 53
    .line 54
    mul-double/2addr v1, v7

    .line 55
    mul-double/2addr v5, v7

    .line 56
    invoke-direct {v0, v1, v2, v5, v6}, Lyu/a;-><init>(DD)V

    .line 57
    .line 58
    .line 59
    iput-object v0, p0, Lru/b;->b:Lyu/a;

    .line 60
    .line 61
    invoke-static {p1}, Ljava/util/Collections;->singleton(Ljava/lang/Object;)Ljava/util/Set;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    iput-object p1, p0, Lru/b;->d:Ljava/util/Set;

    .line 66
    .line 67
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final b()Ljava/util/Collection;
    .locals 0

    .line 1
    iget-object p0, p0, Lru/b;->d:Ljava/util/Set;

    .line 2
    .line 3
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Lru/b;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x0

    .line 6
    return p0

    .line 7
    :cond_0
    check-cast p1, Lru/b;

    .line 8
    .line 9
    iget-object p1, p1, Lru/b;->a:Lzj0/c;

    .line 10
    .line 11
    iget-object p0, p0, Lru/b;->a:Lzj0/c;

    .line 12
    .line 13
    invoke-virtual {p1, p0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final getPosition()Lcom/google/android/gms/maps/model/LatLng;
    .locals 0

    .line 1
    iget-object p0, p0, Lru/b;->c:Lcom/google/android/gms/maps/model/LatLng;

    .line 2
    .line 3
    return-object p0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Lru/b;->a:Lzj0/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

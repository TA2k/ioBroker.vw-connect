.class public final Lcom/google/android/gms/maps/model/LatLngBounds;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/google/android/gms/common/internal/ReflectedParcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/maps/model/LatLngBounds;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcom/google/android/gms/maps/model/LatLng;

.field public final e:Lcom/google/android/gms/maps/model/LatLng;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lpp/h;

    .line 2
    .line 3
    const/16 v1, 0x11

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpp/h;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/gms/maps/model/LatLngBounds;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;)V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "southwest must not be null."

    .line 5
    .line 6
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 7
    .line 8
    .line 9
    const-string v0, "northeast must not be null."

    .line 10
    .line 11
    invoke-static {p2, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    iget-wide v0, p2, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 15
    .line 16
    iget-wide v2, p1, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 17
    .line 18
    invoke-static {v2, v3}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 19
    .line 20
    .line 21
    move-result-object v4

    .line 22
    invoke-static {v0, v1}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 23
    .line 24
    .line 25
    move-result-object v5

    .line 26
    filled-new-array {v4, v5}, [Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    cmpl-double v0, v0, v2

    .line 31
    .line 32
    if-ltz v0, :cond_0

    .line 33
    .line 34
    const/4 v0, 0x1

    .line 35
    goto :goto_0

    .line 36
    :cond_0
    const/4 v0, 0x0

    .line 37
    :goto_0
    const-string v1, "southern latitude exceeds northern latitude (%s > %s)"

    .line 38
    .line 39
    invoke-static {v0, v1, v4}, Lno/c0;->c(ZLjava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iput-object p1, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 43
    .line 44
    iput-object p2, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 45
    .line 46
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Lcom/google/android/gms/maps/model/LatLng;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object p0, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 24
    .line 25
    iget-object p1, p1, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lcom/google/android/gms/maps/model/LatLng;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    return v0

    .line 34
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 4
    .line 5
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    new-instance v0, Lb81/c;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lb81/c;-><init>(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    const-string v1, "southwest"

    .line 7
    .line 8
    iget-object v2, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "northeast"

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 16
    .line 17
    invoke-virtual {v0, p0, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0}, Lb81/c;->toString()Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x2

    .line 8
    iget-object v2, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    iget-object p0, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 15
    .line 16
    invoke-static {p1, v1, p0, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final x0(Lcom/google/android/gms/maps/model/LatLng;)Z
    .locals 5

    .line 1
    const-string v0, "point must not be null."

    .line 2
    .line 3
    invoke-static {p1, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p1, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 7
    .line 8
    iget-object v2, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    iget-wide v3, v2, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 11
    .line 12
    cmpg-double v3, v3, v0

    .line 13
    .line 14
    if-gtz v3, :cond_2

    .line 15
    .line 16
    iget-object p0, p0, Lcom/google/android/gms/maps/model/LatLngBounds;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 17
    .line 18
    iget-wide v3, p0, Lcom/google/android/gms/maps/model/LatLng;->d:D

    .line 19
    .line 20
    cmpg-double v0, v0, v3

    .line 21
    .line 22
    if-gtz v0, :cond_2

    .line 23
    .line 24
    iget-wide v0, p1, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 25
    .line 26
    iget-wide v2, v2, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 27
    .line 28
    iget-wide p0, p0, Lcom/google/android/gms/maps/model/LatLng;->e:D

    .line 29
    .line 30
    cmpg-double v4, v2, p0

    .line 31
    .line 32
    cmpg-double v2, v2, v0

    .line 33
    .line 34
    if-gtz v4, :cond_0

    .line 35
    .line 36
    if-gtz v2, :cond_2

    .line 37
    .line 38
    cmpg-double p0, v0, p0

    .line 39
    .line 40
    if-gtz p0, :cond_2

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    if-lez v2, :cond_1

    .line 44
    .line 45
    cmpg-double p0, v0, p0

    .line 46
    .line 47
    if-gtz p0, :cond_2

    .line 48
    .line 49
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 50
    return p0

    .line 51
    :cond_2
    const/4 p0, 0x0

    .line 52
    return p0
.end method

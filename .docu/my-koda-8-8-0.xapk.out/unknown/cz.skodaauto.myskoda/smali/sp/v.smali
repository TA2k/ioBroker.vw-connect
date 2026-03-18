.class public final Lsp/v;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lsp/v;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcom/google/android/gms/maps/model/LatLng;

.field public final e:Lcom/google/android/gms/maps/model/LatLng;

.field public final f:Lcom/google/android/gms/maps/model/LatLng;

.field public final g:Lcom/google/android/gms/maps/model/LatLng;

.field public final h:Lcom/google/android/gms/maps/model/LatLngBounds;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lpp/h;

    .line 2
    .line 3
    const/16 v1, 0xe

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpp/h;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lsp/v;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLng;Lcom/google/android/gms/maps/model/LatLngBounds;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lsp/v;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 5
    .line 6
    iput-object p2, p0, Lsp/v;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 7
    .line 8
    iput-object p3, p0, Lsp/v;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    iput-object p4, p0, Lsp/v;->g:Lcom/google/android/gms/maps/model/LatLng;

    .line 11
    .line 12
    iput-object p5, p0, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 13
    .line 14
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
    instance-of v1, p1, Lsp/v;

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
    check-cast p1, Lsp/v;

    .line 12
    .line 13
    iget-object v1, p0, Lsp/v;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 14
    .line 15
    iget-object v3, p1, Lsp/v;->d:Lcom/google/android/gms/maps/model/LatLng;

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
    iget-object v1, p0, Lsp/v;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 24
    .line 25
    iget-object v3, p1, Lsp/v;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 26
    .line 27
    invoke-virtual {v1, v3}, Lcom/google/android/gms/maps/model/LatLng;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget-object v1, p0, Lsp/v;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 34
    .line 35
    iget-object v3, p1, Lsp/v;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 36
    .line 37
    invoke-virtual {v1, v3}, Lcom/google/android/gms/maps/model/LatLng;->equals(Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_2

    .line 42
    .line 43
    iget-object v1, p0, Lsp/v;->g:Lcom/google/android/gms/maps/model/LatLng;

    .line 44
    .line 45
    iget-object v3, p1, Lsp/v;->g:Lcom/google/android/gms/maps/model/LatLng;

    .line 46
    .line 47
    invoke-virtual {v1, v3}, Lcom/google/android/gms/maps/model/LatLng;->equals(Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-eqz v1, :cond_2

    .line 52
    .line 53
    iget-object p0, p0, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 54
    .line 55
    iget-object p1, p1, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lcom/google/android/gms/maps/model/LatLngBounds;->equals(Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result p0

    .line 61
    if-eqz p0, :cond_2

    .line 62
    .line 63
    return v0

    .line 64
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lsp/v;->g:Lcom/google/android/gms/maps/model/LatLng;

    .line 2
    .line 3
    iget-object v1, p0, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 4
    .line 5
    iget-object v2, p0, Lsp/v;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 6
    .line 7
    iget-object v3, p0, Lsp/v;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 8
    .line 9
    iget-object p0, p0, Lsp/v;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 10
    .line 11
    filled-new-array {v2, v3, p0, v0, v1}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
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
    const-string v1, "nearLeft"

    .line 7
    .line 8
    iget-object v2, p0, Lsp/v;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const-string v1, "nearRight"

    .line 14
    .line 15
    iget-object v2, p0, Lsp/v;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    const-string v1, "farLeft"

    .line 21
    .line 22
    iget-object v2, p0, Lsp/v;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 23
    .line 24
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const-string v1, "farRight"

    .line 28
    .line 29
    iget-object v2, p0, Lsp/v;->g:Lcom/google/android/gms/maps/model/LatLng;

    .line 30
    .line 31
    invoke-virtual {v0, v2, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string v1, "latLngBounds"

    .line 35
    .line 36
    iget-object p0, p0, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 37
    .line 38
    invoke-virtual {v0, p0, v1}, Lb81/c;->c(Ljava/lang/Object;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-virtual {v0}, Lb81/c;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
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
    iget-object v2, p0, Lsp/v;->d:Lcom/google/android/gms/maps/model/LatLng;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    iget-object v2, p0, Lsp/v;->e:Lcom/google/android/gms/maps/model/LatLng;

    .line 15
    .line 16
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 17
    .line 18
    .line 19
    const/4 v1, 0x4

    .line 20
    iget-object v2, p0, Lsp/v;->f:Lcom/google/android/gms/maps/model/LatLng;

    .line 21
    .line 22
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 23
    .line 24
    .line 25
    const/4 v1, 0x5

    .line 26
    iget-object v2, p0, Lsp/v;->g:Lcom/google/android/gms/maps/model/LatLng;

    .line 27
    .line 28
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 29
    .line 30
    .line 31
    const/4 v1, 0x6

    .line 32
    iget-object p0, p0, Lsp/v;->h:Lcom/google/android/gms/maps/model/LatLngBounds;

    .line 33
    .line 34
    invoke-static {p1, v1, p0, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 35
    .line 36
    .line 37
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

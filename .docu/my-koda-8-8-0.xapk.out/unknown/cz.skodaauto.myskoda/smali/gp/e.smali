.class public final Lgp/e;
.super Lbp/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lpp/m;


# static fields
.field public static final synthetic e:I


# instance fields
.field public final d:Lcom/google/android/gms/internal/measurement/i4;


# direct methods
.method public constructor <init>(Lcom/google/android/gms/internal/measurement/i4;)V
    .locals 2

    .line 1
    const-string v0, "com.google.android.gms.location.ILocationCallback"

    .line 2
    .line 3
    const/4 v1, 0x5

    .line 4
    invoke-direct {p0, v0, v1}, Lbp/j;-><init>(Ljava/lang/String;I)V

    .line 5
    .line 6
    .line 7
    iput-object p1, p0, Lgp/e;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final S(Landroid/os/Parcel;I)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lgp/e;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eq p2, v1, :cond_2

    .line 5
    .line 6
    const/4 v2, 0x2

    .line 7
    if-eq p2, v2, :cond_1

    .line 8
    .line 9
    const/4 p1, 0x3

    .line 10
    if-eq p2, p1, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    return p0

    .line 14
    :cond_0
    invoke-virtual {p0}, Lgp/e;->T()V

    .line 15
    .line 16
    .line 17
    return v1

    .line 18
    :cond_1
    sget-object p0, Lcom/google/android/gms/location/LocationAvailability;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 19
    .line 20
    invoke-static {p1, p0}, Lgp/b;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    check-cast p0, Lcom/google/android/gms/location/LocationAvailability;

    .line 25
    .line 26
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/i4;->z()Lis/b;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    new-instance p1, Lnm0/b;

    .line 34
    .line 35
    const/4 p2, 0x6

    .line 36
    invoke-direct {p1, p2}, Lnm0/b;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {p0, p1}, Lis/b;->a(Llo/l;)V

    .line 40
    .line 41
    .line 42
    return v1

    .line 43
    :cond_2
    sget-object p0, Lcom/google/android/gms/location/LocationResult;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 44
    .line 45
    invoke-static {p1, p0}, Lgp/b;->a(Landroid/os/Parcel;Landroid/os/Parcelable$Creator;)Landroid/os/Parcelable;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    check-cast p0, Lcom/google/android/gms/location/LocationResult;

    .line 50
    .line 51
    invoke-static {p1}, Lgp/b;->c(Landroid/os/Parcel;)V

    .line 52
    .line 53
    .line 54
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/i4;->z()Lis/b;

    .line 55
    .line 56
    .line 57
    move-result-object p1

    .line 58
    new-instance p2, Lbu/c;

    .line 59
    .line 60
    const/16 v0, 0x19

    .line 61
    .line 62
    invoke-direct {p2, p0, v0}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {p1, p2}, Lis/b;->a(Llo/l;)V

    .line 66
    .line 67
    .line 68
    return v1
.end method

.method public final T()V
    .locals 3

    .line 1
    iget-object v0, p0, Lgp/e;->d:Lcom/google/android/gms/internal/measurement/i4;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/google/android/gms/internal/measurement/i4;->z()Lis/b;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Laq/a;

    .line 8
    .line 9
    const/16 v2, 0x19

    .line 10
    .line 11
    invoke-direct {v1, p0, v2}, Laq/a;-><init>(Ljava/lang/Object;I)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0, v1}, Lis/b;->a(Llo/l;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

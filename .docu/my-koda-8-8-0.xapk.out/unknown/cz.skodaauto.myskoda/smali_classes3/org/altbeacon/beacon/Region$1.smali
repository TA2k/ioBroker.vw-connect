.class Lorg/altbeacon/beacon/Region$1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lorg/altbeacon/beacon/Region;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Landroid/os/Parcelable$Creator<",
        "Lorg/altbeacon/beacon/Region;",
        ">;"
    }
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public bridge synthetic createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/Region$1;->createFromParcel(Landroid/os/Parcel;)Lorg/altbeacon/beacon/Region;

    move-result-object p0

    return-object p0
.end method

.method public createFromParcel(Landroid/os/Parcel;)Lorg/altbeacon/beacon/Region;
    .locals 0

    .line 2
    new-instance p0, Lorg/altbeacon/beacon/Region;

    invoke-direct {p0, p1}, Lorg/altbeacon/beacon/Region;-><init>(Landroid/os/Parcel;)V

    return-object p0
.end method

.method public bridge synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lorg/altbeacon/beacon/Region$1;->newArray(I)[Lorg/altbeacon/beacon/Region;

    move-result-object p0

    return-object p0
.end method

.method public newArray(I)[Lorg/altbeacon/beacon/Region;
    .locals 0

    .line 2
    new-array p0, p1, [Lorg/altbeacon/beacon/Region;

    return-object p0
.end method

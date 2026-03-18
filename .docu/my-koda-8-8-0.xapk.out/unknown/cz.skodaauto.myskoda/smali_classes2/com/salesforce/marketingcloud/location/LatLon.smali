.class public final Lcom/salesforce/marketingcloud/location/LatLon;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/location/LatLon;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final latitude:D

.field public final longitude:D


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/location/LatLon$a;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/location/LatLon$a;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/location/LatLon;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(DD)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-wide p1, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 3
    iput-wide p3, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    return-void
.end method

.method public constructor <init>(Lorg/json/JSONObject;)V
    .locals 4

    const-string v0, "json"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    const-string v0, "latitude"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->getDouble(Ljava/lang/String;)D

    move-result-wide v0

    const-string v2, "longitude"

    invoke-virtual {p1, v2}, Lorg/json/JSONObject;->getDouble(Ljava/lang/String;)D

    move-result-wide v2

    invoke-direct {p0, v0, v1, v2, v3}, Lcom/salesforce/marketingcloud/location/LatLon;-><init>(DD)V

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/location/LatLon;DDILjava/lang/Object;)Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-wide p1, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p5, p5, 0x2

    .line 8
    .line 9
    if-eqz p5, :cond_1

    .line 10
    .line 11
    iget-wide p3, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/location/LatLon;->copy(DD)Lcom/salesforce/marketingcloud/location/LatLon;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component2()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final copy(DD)Lcom/salesforce/marketingcloud/location/LatLon;
    .locals 0

    .line 1
    new-instance p0, Lcom/salesforce/marketingcloud/location/LatLon;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/location/LatLon;-><init>(DD)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/location/LatLon;

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
    check-cast p1, Lcom/salesforce/marketingcloud/location/LatLon;

    .line 12
    .line 13
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 14
    .line 15
    iget-wide v5, p1, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 16
    .line 17
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 25
    .line 26
    iget-wide p0, p1, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 27
    .line 28
    invoke-static {v3, v4, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 2
    .line 3
    invoke-static {v0, v1}, Ljava/lang/Double;->hashCode(D)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 10
    .line 11
    invoke-static {v1, v2}, Ljava/lang/Double;->hashCode(D)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final latitude()D
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final longitude()D
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 2
    .line 3
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 4
    .line 5
    const-string p0, "LatLon(latitude="

    .line 6
    .line 7
    const-string v4, ", longitude="

    .line 8
    .line 9
    invoke-static {p0, v4, v0, v1}, Lp3/m;->r(Ljava/lang/String;Ljava/lang/String;D)Ljava/lang/StringBuilder;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    const-string v0, ")"

    .line 14
    .line 15
    invoke-static {p0, v2, v3, v0}, Lp3/m;->n(Ljava/lang/StringBuilder;DLjava/lang/String;)Ljava/lang/String;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const-string p2, "out"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->latitude:D

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/location/LatLon;->longitude:D

    .line 12
    .line 13
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 14
    .line 15
    .line 16
    return-void
.end method

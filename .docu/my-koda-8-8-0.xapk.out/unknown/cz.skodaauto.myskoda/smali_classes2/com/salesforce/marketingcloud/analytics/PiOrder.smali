.class public final Lcom/salesforce/marketingcloud/analytics/PiOrder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/analytics/PiOrder$a;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/analytics/PiOrder;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/analytics/PiOrder$a;


# instance fields
.field public final cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

.field public final discount:D

.field public final orderNumber:Ljava/lang/String;

.field public final shipping:D


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiOrder$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/PiOrder$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->Companion:Lcom/salesforce/marketingcloud/analytics/PiOrder$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiOrder$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/analytics/PiOrder$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DD)V
    .locals 1

    .line 1
    const-string v0, "cart"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "orderNumber"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 15
    .line 16
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 17
    .line 18
    iput-wide p3, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 19
    .line 20
    iput-wide p5, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 21
    .line 22
    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/analytics/PiOrder;Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DDILjava/lang/Object;)Lcom/salesforce/marketingcloud/analytics/PiOrder;
    .locals 0

    .line 1
    and-int/lit8 p8, p7, 0x1

    .line 2
    .line 3
    if-eqz p8, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p8, p7, 0x2

    .line 8
    .line 9
    if-eqz p8, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p8, p7, 0x4

    .line 14
    .line 15
    if-eqz p8, :cond_2

    .line 16
    .line 17
    iget-wide p3, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p7, p7, 0x8

    .line 20
    .line 21
    if-eqz p7, :cond_3

    .line 22
    .line 23
    iget-wide p5, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 24
    .line 25
    :cond_3
    move-wide p7, p5

    .line 26
    move-wide p5, p3

    .line 27
    move-object p3, p1

    .line 28
    move-object p4, p2

    .line 29
    move-object p2, p0

    .line 30
    invoke-virtual/range {p2 .. p8}, Lcom/salesforce/marketingcloud/analytics/PiOrder;->copy(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DD)Lcom/salesforce/marketingcloud/analytics/PiOrder;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final create(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DD)Lcom/salesforce/marketingcloud/analytics/PiOrder;
    .locals 7
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->Companion:Lcom/salesforce/marketingcloud/analytics/PiOrder$a;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    move-object v2, p1

    .line 5
    move-wide v3, p2

    .line 6
    move-wide v5, p4

    .line 7
    invoke-virtual/range {v0 .. v6}, Lcom/salesforce/marketingcloud/analytics/PiOrder$a;->a(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DD)Lcom/salesforce/marketingcloud/analytics/PiOrder;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final cart()Lcom/salesforce/marketingcloud/analytics/PiCart;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Lcom/salesforce/marketingcloud/analytics/PiCart;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component4()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final copy(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DD)Lcom/salesforce/marketingcloud/analytics/PiOrder;
    .locals 7

    .line 1
    const-string p0, "cart"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "orderNumber"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiOrder;

    .line 12
    .line 13
    move-object v1, p1

    .line 14
    move-object v2, p2

    .line 15
    move-wide v3, p3

    .line 16
    move-wide v5, p5

    .line 17
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/analytics/PiOrder;-><init>(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/lang/String;DD)V

    .line 18
    .line 19
    .line 20
    return-object v0
.end method

.method public describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final discount()D
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 2
    .line 3
    return-wide v0
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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/analytics/PiOrder;

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
    check-cast p1, Lcom/salesforce/marketingcloud/analytics/PiOrder;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 36
    .line 37
    iget-wide v5, p1, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 38
    .line 39
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-eqz v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 47
    .line 48
    iget-wide p0, p1, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 49
    .line 50
    invoke-static {v3, v4, p0, p1}, Ljava/lang/Double;->compare(DD)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    if-eqz p0, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    return v0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/analytics/PiCart;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 23
    .line 24
    invoke-static {v1, v2}, Ljava/lang/Double;->hashCode(D)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public final orderNumber()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final shipping()D
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final toJson$sdk_release()Lorg/json/JSONObject;
    .locals 4

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 7
    .line 8
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/PiCart;->toJson$sdk_release()Lorg/json/JSONArray;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    const-string v2, "cart"

    .line 13
    .line 14
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 15
    .line 16
    .line 17
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 18
    .line 19
    const-string v2, "order_number"

    .line 20
    .line 21
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 22
    .line 23
    .line 24
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 25
    .line 26
    const-string v3, "shipping"

    .line 27
    .line 28
    invoke-virtual {v0, v3, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    .line 29
    .line 30
    .line 31
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 32
    .line 33
    const-string p0, "discount"

    .line 34
    .line 35
    invoke-virtual {v0, p0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    .line 36
    .line 37
    .line 38
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 2
    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 4
    .line 5
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 6
    .line 7
    iget-wide v4, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 8
    .line 9
    new-instance p0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v6, "PiOrder(cart="

    .line 12
    .line 13
    invoke-direct {p0, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", orderNumber="

    .line 20
    .line 21
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", shipping="

    .line 28
    .line 29
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ", discount="

    .line 36
    .line 37
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {p0, v4, v5}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v0, ")"

    .line 44
    .line 45
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

.method public writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const-string v0, "out"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->cart:Lcom/salesforce/marketingcloud/analytics/PiCart;

    .line 7
    .line 8
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/PiCart;->writeToParcel(Landroid/os/Parcel;I)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->orderNumber:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->shipping:D

    .line 17
    .line 18
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 19
    .line 20
    .line 21
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiOrder;->discount:D

    .line 22
    .line 23
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

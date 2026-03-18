.class public final Lcom/salesforce/marketingcloud/analytics/PiCartItem;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;
    }
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/salesforce/marketingcloud/analytics/PiCartItem;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;


# instance fields
.field public final item:Ljava/lang/String;

.field public final price:D

.field public final quantity:I

.field public final uniqueId:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->Companion:Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem$b;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/analytics/PiCartItem$b;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ID)V
    .locals 7

    const-string v0, "item"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v6, 0x0

    move-object v1, p0

    move-object v2, p1

    move v3, p2

    move-wide v4, p3

    .line 6
    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/PiCartItem;-><init>(Ljava/lang/String;IDLjava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;IDLjava/lang/String;)V
    .locals 1

    const-string v0, "item"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 3
    iput p2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 4
    iput-wide p3, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 5
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    return-void
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/analytics/PiCartItem;Ljava/lang/String;IDLjava/lang/String;ILjava/lang/Object;)Lcom/salesforce/marketingcloud/analytics/PiCartItem;
    .locals 0

    .line 1
    and-int/lit8 p7, p6, 0x1

    .line 2
    .line 3
    if-eqz p7, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p7, p6, 0x2

    .line 8
    .line 9
    if-eqz p7, :cond_1

    .line 10
    .line 11
    iget p2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p7, p6, 0x4

    .line 14
    .line 15
    if-eqz p7, :cond_2

    .line 16
    .line 17
    iget-wide p3, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p6, p6, 0x8

    .line 20
    .line 21
    if-eqz p6, :cond_3

    .line 22
    .line 23
    iget-object p5, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 24
    .line 25
    :cond_3
    move-object p7, p5

    .line 26
    move-wide p5, p3

    .line 27
    move-object p3, p1

    .line 28
    move p4, p2

    .line 29
    move-object p2, p0

    .line 30
    invoke-virtual/range {p2 .. p7}, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->copy(Ljava/lang/String;IDLjava/lang/String;)Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0
.end method

.method public static final create(Ljava/lang/String;ID)Lcom/salesforce/marketingcloud/analytics/PiCartItem;
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->Companion:Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;

    invoke-virtual {v0, p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;->a(Ljava/lang/String;ID)Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    move-result-object p0

    return-object p0
.end method

.method public static final create(Ljava/lang/String;IDLjava/lang/String;)Lcom/salesforce/marketingcloud/analytics/PiCartItem;
    .locals 6
    .annotation runtime Llx0/c;
    .end annotation

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->Companion:Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;

    move-object v1, p0

    move v2, p1

    move-wide v3, p2

    move-object v5, p4

    invoke-virtual/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/PiCartItem$a;->a(Ljava/lang/String;IDLjava/lang/String;)Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 2
    .line 3
    return p0
.end method

.method public final component3()D
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ljava/lang/String;IDLjava/lang/String;)Lcom/salesforce/marketingcloud/analytics/PiCartItem;
    .locals 6

    .line 1
    const-string p0, "item"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    .line 7
    .line 8
    move-object v1, p1

    .line 9
    move v2, p2

    .line 10
    move-wide v3, p3

    .line 11
    move-object v5, p5

    .line 12
    invoke-direct/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/PiCartItem;-><init>(Ljava/lang/String;IDLjava/lang/String;)V

    .line 13
    .line 14
    .line 15
    return-object v0
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
    instance-of v1, p1, Lcom/salesforce/marketingcloud/analytics/PiCartItem;

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
    check-cast p1, Lcom/salesforce/marketingcloud/analytics/PiCartItem;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

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
    iget v1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 25
    .line 26
    iget v3, p1, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-wide v3, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 32
    .line 33
    iget-wide v5, p1, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 34
    .line 35
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Double;->compare(DD)I

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-eqz v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 43
    .line 44
    iget-object p1, p1, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    return v0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

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
    iget v2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 11
    .line 12
    invoke-static {v2, v0, v1}, Lc1/j0;->g(III)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 17
    .line 18
    invoke-static {v2, v3, v0, v1}, Lf2/m0;->a(DII)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 23
    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    :goto_0
    add-int/2addr v0, p0

    .line 33
    return v0
.end method

.method public final item()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final price()D
    .locals 2
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 2
    .line 3
    return-wide v0
.end method

.method public final quantity()I
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 2
    .line 3
    return p0
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
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 7
    .line 8
    const-string v2, "item"

    .line 9
    .line 10
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget v1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 14
    .line 15
    const-string v2, "quantity"

    .line 16
    .line 17
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    iget-wide v1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 21
    .line 22
    const-string v3, "price"

    .line 23
    .line 24
    invoke-virtual {v0, v3, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;D)Lorg/json/JSONObject;

    .line 25
    .line 26
    .line 27
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 28
    .line 29
    if-eqz p0, :cond_0

    .line 30
    .line 31
    const-string v1, "unique_id"

    .line 32
    .line 33
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 34
    .line 35
    .line 36
    :cond_0
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 2
    .line 3
    iget v1, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 4
    .line 5
    iget-wide v2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 6
    .line 7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 8
    .line 9
    const-string v4, ", quantity="

    .line 10
    .line 11
    const-string v5, ", price="

    .line 12
    .line 13
    const-string v6, "PiCartItem(item="

    .line 14
    .line 15
    invoke-static {v6, v1, v0, v4, v5}, La7/g0;->m(Ljava/lang/String;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    invoke-virtual {v0, v2, v3}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    const-string v1, ", uniqueId="

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, ")"

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0
.end method

.method public final uniqueId()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 2
    .line 3
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
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->item:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget p2, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->quantity:I

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->price:D

    .line 17
    .line 18
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeDouble(D)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/PiCartItem;->uniqueId:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

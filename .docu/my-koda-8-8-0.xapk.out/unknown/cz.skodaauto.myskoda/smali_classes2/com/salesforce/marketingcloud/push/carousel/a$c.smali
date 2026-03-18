.class public final Lcom/salesforce/marketingcloud/push/carousel/a$c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable$Creator;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/push/carousel/a;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "c"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Object;",
        "Landroid/os/Parcelable$Creator<",
        "Lcom/salesforce/marketingcloud/push/carousel/a;",
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
.method public final a(Landroid/os/Parcel;)Lcom/salesforce/marketingcloud/push/carousel/a;
    .locals 4

    .line 1
    const-string p0, "parcel"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result p0

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0, p0}, Ljava/util/ArrayList;-><init>(I)V

    const/4 v1, 0x0

    :goto_0
    if-eq v1, p0, :cond_0

    sget-object v2, Lcom/salesforce/marketingcloud/push/carousel/a$a;->CREATOR:Landroid/os/Parcelable$Creator;

    const/4 v3, 0x1

    .line 2
    invoke-static {v2, p1, v0, v1, v3}, Lvj/b;->a(Landroid/os/Parcelable$Creator;Landroid/os/Parcel;Ljava/util/ArrayList;II)I

    move-result v1

    goto :goto_0

    .line 3
    :cond_0
    invoke-virtual {p1}, Landroid/os/Parcel;->readInt()I

    move-result p0

    const-class v1, Lcom/salesforce/marketingcloud/push/carousel/a;

    invoke-virtual {v1}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    move-result-object v1

    invoke-virtual {p1, v1}, Landroid/os/Parcel;->readParcelable(Ljava/lang/ClassLoader;)Landroid/os/Parcelable;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/push/data/Style;

    new-instance v1, Lcom/salesforce/marketingcloud/push/carousel/a;

    invoke-direct {v1, v0, p0, p1}, Lcom/salesforce/marketingcloud/push/carousel/a;-><init>(Ljava/util/List;ILcom/salesforce/marketingcloud/push/data/Style;)V

    return-object v1
.end method

.method public final a(I)[Lcom/salesforce/marketingcloud/push/carousel/a;
    .locals 0

    .line 6
    new-array p0, p1, [Lcom/salesforce/marketingcloud/push/carousel/a;

    return-object p0
.end method

.method public bridge synthetic createFromParcel(Landroid/os/Parcel;)Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/push/carousel/a$c;->a(Landroid/os/Parcel;)Lcom/salesforce/marketingcloud/push/carousel/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public bridge synthetic newArray(I)[Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/push/carousel/a$c;->a(I)[Lcom/salesforce/marketingcloud/push/carousel/a;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

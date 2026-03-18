.class public final Lcom/salesforce/marketingcloud/messages/Region$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/messages/Region;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/Region$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final getTAG$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/messages/Region;->access$getTAG$cp()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final magicFence$sdk_release(Lcom/salesforce/marketingcloud/location/LatLon;I)Lcom/salesforce/marketingcloud/messages/Region;
    .locals 13

    .line 1
    const-string p0, "center"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/salesforce/marketingcloud/messages/Region;

    .line 7
    .line 8
    const/16 v11, 0x3b8

    .line 9
    .line 10
    const/4 v12, 0x0

    .line 11
    const-string v1, "~~m@g1c_f3nc3~~"

    .line 12
    .line 13
    const/4 v4, 0x0

    .line 14
    const/4 v5, 0x0

    .line 15
    const/4 v6, 0x0

    .line 16
    const/4 v7, -0x1

    .line 17
    const/4 v8, 0x0

    .line 18
    const/4 v9, 0x0

    .line 19
    const/4 v10, 0x0

    .line 20
    move-object v2, p1

    .line 21
    move v3, p2

    .line 22
    invoke-direct/range {v0 .. v12}, Lcom/salesforce/marketingcloud/messages/Region;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/location/LatLon;ILjava/lang/String;IIILjava/lang/String;Ljava/lang/String;Ljava/util/List;ILkotlin/jvm/internal/g;)V

    .line 23
    .line 24
    .line 25
    return-object v0
.end method

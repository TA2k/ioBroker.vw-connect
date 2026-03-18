.class public final Lcom/salesforce/marketingcloud/internal/l$a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/internal/l;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "a"
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
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/internal/l$a;-><init>()V

    return-void
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/location/LatLon;I)Lcom/salesforce/marketingcloud/messages/Region;
    .locals 0

    const-string p0, "center"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/messages/Region;->Companion:Lcom/salesforce/marketingcloud/messages/Region$Companion;

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/Region$Companion;->magicFence$sdk_release(Lcom/salesforce/marketingcloud/location/LatLon;I)Lcom/salesforce/marketingcloud/messages/Region;

    move-result-object p0

    return-object p0
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/Region;Z)V
    .locals 0

    const-string p0, "region"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/messages/Region;->setInside$sdk_release(Z)V

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/messages/Region;)Z
    .locals 0

    const-string p0, "region"

    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/Region;->isInside$sdk_release()Z

    move-result p0

    return p0
.end method

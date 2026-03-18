.class public final Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config$DefaultImpls;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "DefaultImpls"
.end annotation

.annotation runtime Lkotlin/Metadata;
    k = 0x3
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static getMAX_SUPPORTED_VERSION(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public static synthetic getMAX_SUPPORTED_VERSION$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static isModuleCompatible(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)Z
    .locals 1

    .line 1
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;->getVersion()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;->getMAX_SUPPORTED_VERSION()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-gt v0, p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

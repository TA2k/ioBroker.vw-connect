.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0004\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0003\u0008&\u0018\u00002\u00020\u0001B\r\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004R\u0014\u0010\u0002\u001a\u00020\u0003X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0005\u0010\u0006R\u0014\u0010\u0007\u001a\u00020\u0008X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\nR\u0014\u0010\u000b\u001a\u00020\u000cX\u0096D\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\u000e\u00a8\u0006\u000f"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
        "moduleApplicationId",
        "",
        "(Ljava/lang/String;)V",
        "getModuleApplicationId",
        "()Ljava/lang/String;",
        "moduleIdentifier",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "getModuleIdentifier",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "version",
        "",
        "getVersion",
        "()I",
        "sfmcsdk_release"
    }
    k = 0x1
    mv = {
        0x1,
        0x9,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final moduleApplicationId:Ljava/lang/String;

.field private final moduleIdentifier:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

.field private final version:I


# direct methods
.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "moduleApplicationId"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->moduleApplicationId:Ljava/lang/String;

    .line 10
    .line 11
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->CDP:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 12
    .line 13
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->moduleIdentifier:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 14
    .line 15
    const/4 p1, 0x1

    .line 16
    iput p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->version:I

    .line 17
    .line 18
    return-void
.end method


# virtual methods
.method public getMAX_SUPPORTED_VERSION()I
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config$DefaultImpls;->getMAX_SUPPORTED_VERSION(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public getModuleApplicationId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->moduleApplicationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getModuleIdentifier()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->moduleIdentifier:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 2
    .line 3
    return-object p0
.end method

.method public getVersion()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->version:I

    .line 2
    .line 3
    return p0
.end method

.method public isModuleCompatible()Z
    .locals 0

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config$DefaultImpls;->isModuleCompatible(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)Z

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

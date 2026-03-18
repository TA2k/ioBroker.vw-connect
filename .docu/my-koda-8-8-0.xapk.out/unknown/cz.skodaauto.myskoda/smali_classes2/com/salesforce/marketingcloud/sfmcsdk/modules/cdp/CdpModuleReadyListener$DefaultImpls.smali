.class public final Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener$DefaultImpls;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener;
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
.method public static ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 1

    .line 1
    const-string v0, "module"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleInterface;

    .line 7
    .line 8
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener;->ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleInterface;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

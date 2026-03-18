.class public interface abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0008f\u0018\u00002\u00020\u0001R\u0012\u0010\u0002\u001a\u00020\u0003X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0004\u0010\u0005R\u0012\u0010\u0006\u001a\u00020\u0007X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0008\u0010\t\u00a8\u0006\n"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "",
        "moduleIdentity",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
        "getModuleIdentity",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
        "state",
        "Lorg/json/JSONObject;",
        "getState",
        "()Lorg/json/JSONObject;",
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


# virtual methods
.method public abstract getModuleIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
.end method

.method public abstract getState()Lorg/json/JSONObject;
.end method

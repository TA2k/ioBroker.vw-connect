.class public interface abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u00e6\u0080\u0001\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H&\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0007H\u0016\u00a2\u0006\u0004\u0008\u0005\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;",
        "module",
        "Llx0/b0;",
        "ready",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V",
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
.method public abstract ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
.end method

.method public abstract ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;)V
.end method

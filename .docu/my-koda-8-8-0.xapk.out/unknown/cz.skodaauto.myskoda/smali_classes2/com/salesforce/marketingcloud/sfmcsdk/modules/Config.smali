.class public interface abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config$DefaultImpls;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000B\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010\u000b\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0002\u0008\u0008\u0008f\u0018\u00002\u00020\u0001J\'\u0010\t\u001a\u00020\u00082\u0006\u0010\u0003\u001a\u00020\u00022\u0006\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0007\u001a\u00020\u0006H&\u00a2\u0006\u0004\u0008\t\u0010\nJ\u000f\u0010\u000c\u001a\u00020\u000bH\u0016\u00a2\u0006\u0004\u0008\u000c\u0010\rR\u0014\u0010\u0011\u001a\u00020\u000e8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u000f\u0010\u0010R\u0014\u0010\u0015\u001a\u00020\u00128&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0013\u0010\u0014R\u0014\u0010\u0019\u001a\u00020\u00168&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008\u0017\u0010\u0018R\u001a\u0010\u001d\u001a\u00020\u00168VX\u0096\u0004\u00a2\u0006\u000c\u0012\u0004\u0008\u001b\u0010\u001c\u001a\u0004\u0008\u001a\u0010\u0018\u00a8\u0006\u001e"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
        "",
        "Landroid/content/Context;",
        "context",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;",
        "components",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;",
        "listener",
        "Llx0/b0;",
        "init",
        "(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V",
        "",
        "isModuleCompatible",
        "()Z",
        "",
        "getModuleApplicationId",
        "()Ljava/lang/String;",
        "moduleApplicationId",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "getModuleIdentifier",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;",
        "moduleIdentifier",
        "",
        "getVersion",
        "()I",
        "version",
        "getMAX_SUPPORTED_VERSION",
        "getMAX_SUPPORTED_VERSION$annotations",
        "()V",
        "MAX_SUPPORTED_VERSION",
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
.method public abstract getMAX_SUPPORTED_VERSION()I
.end method

.method public abstract getModuleApplicationId()Ljava/lang/String;
.end method

.method public abstract getModuleIdentifier()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;
.end method

.method public abstract getVersion()I
.end method

.method public abstract init(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
.end method

.method public abstract isModuleCompatible()Z
.end method

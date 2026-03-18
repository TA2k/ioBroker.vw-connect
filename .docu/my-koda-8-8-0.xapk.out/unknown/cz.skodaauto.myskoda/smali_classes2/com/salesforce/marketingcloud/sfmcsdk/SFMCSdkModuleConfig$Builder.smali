.class public final Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0018\u0000 \u00122\u00020\u0001:\u0001\u0012B\u0005\u00a2\u0006\u0002\u0010\u0002J\u0006\u0010\u0010\u001a\u00020\u0011R(\u0010\u0005\u001a\u0004\u0018\u00010\u00042\u0008\u0010\u0003\u001a\u0004\u0018\u00010\u0004@FX\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\"\u0004\u0008\u0008\u0010\tR(\u0010\u000b\u001a\u0004\u0018\u00010\n2\u0008\u0010\u0003\u001a\u0004\u0018\u00010\n@FX\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u000c\u0010\r\"\u0004\u0008\u000e\u0010\u000f\u00a8\u0006\u0013"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;",
        "",
        "()V",
        "value",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;",
        "cdpModuleConfig",
        "getCdpModuleConfig",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;",
        "setCdpModuleConfig",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;",
        "pushModuleConfig",
        "getPushModuleConfig",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;",
        "setPushModuleConfig",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;)V",
        "build",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;",
        "Companion",
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


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$Companion;

.field private static final TAG:Ljava/lang/String; = "~$SFMCSdkModuleConfig.Builder"


# instance fields
.field private cdpModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

.field private pushModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$Companion;

    .line 8
    .line 9
    return-void
.end method

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
.method public final build()Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, p0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    return-object v0
.end method

.method public final getCdpModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->cdpModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPushModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->pushModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setCdpModuleConfig(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;->isModuleCompatible()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 12
    .line 13
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$cdpModuleConfig$1;

    .line 14
    .line 15
    invoke-direct {v1, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$cdpModuleConfig$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;)V

    .line 16
    .line 17
    .line 18
    const-string p1, "~$SFMCSdkModuleConfig.Builder"

    .line 19
    .line 20
    invoke-virtual {v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 21
    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    :goto_0
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->cdpModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

    .line 25
    .line 26
    return-void
.end method

.method public final setPushModuleConfig(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;->isModuleCompatible()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x1

    .line 8
    if-ne v0, v1, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 12
    .line 13
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$pushModuleConfig$1;

    .line 14
    .line 15
    invoke-direct {v1, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder$pushModuleConfig$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;)V

    .line 16
    .line 17
    .line 18
    const-string p1, "~$SFMCSdkModuleConfig.Builder"

    .line 19
    .line 20
    invoke-virtual {v0, p1, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Lay0/a;)V

    .line 21
    .line 22
    .line 23
    const/4 p1, 0x0

    .line 24
    :goto_0
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->pushModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;

    .line 25
    .line 26
    return-void
.end method

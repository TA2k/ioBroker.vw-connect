.class public final Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;,
        Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0008\t\u0018\u0000 \u00162\u00020\u0001:\u0002\u0015\u0016B\u000f\u0008\u0012\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0002\u0010\u0004B\u001b\u0008\u0002\u0012\u0008\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u0012\u0008\u0010\u0007\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0002\u0010\tR\u0013\u0010\u0007\u001a\u0004\u0018\u00010\u0008\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR \u0010\u000c\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\rX\u0080\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010\"\u0004\u0008\u0011\u0010\u0012R\u0013\u0010\u0005\u001a\u0004\u0018\u00010\u0006\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0014\u00a8\u0006\u0017"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;",
        "",
        "builder",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;)V",
        "pushModuleConfig",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;",
        "cdpModuleConfig",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;)V",
        "getCdpModuleConfig",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;",
        "configs",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
        "getConfigs$sfmcsdk_release",
        "()Ljava/util/List;",
        "setConfigs$sfmcsdk_release",
        "(Ljava/util/List;)V",
        "getPushModuleConfig",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;",
        "Builder",
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
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;


# instance fields
.field private final cdpModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

.field private configs:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
            ">;"
        }
    .end annotation
.end field

.field private final pushModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;

    .line 8
    .line 9
    return-void
.end method

.method private constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;)V
    .locals 1

    .line 8
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->getPushModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;

    move-result-object v0

    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;->getCdpModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

    move-result-object p1

    .line 10
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;)V

    return-void
.end method

.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Builder;)V

    return-void
.end method

.method private constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->pushModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;

    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->cdpModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

    const/4 v0, 0x2

    .line 5
    new-array v0, v0, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    const/4 v1, 0x0

    aput-object p1, v0, v1

    const/4 p1, 0x1

    aput-object p2, v0, p1

    .line 6
    invoke-static {v0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    move-result-object p1

    .line 7
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->configs:Ljava/util/List;

    return-void
.end method

.method public static final build(Lay0/k;)Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lay0/k;",
            ")",
            "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;"
        }
    .end annotation

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig$Companion;->build(Lay0/k;)Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method


# virtual methods
.method public final getCdpModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->cdpModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getConfigs$sfmcsdk_release()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->configs:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPushModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->pushModuleConfig:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setConfigs$sfmcsdk_release(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "+",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
            ">;)V"
        }
    .end annotation

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->configs:Ljava/util/List;

    .line 7
    .line 8
    return-void
.end method

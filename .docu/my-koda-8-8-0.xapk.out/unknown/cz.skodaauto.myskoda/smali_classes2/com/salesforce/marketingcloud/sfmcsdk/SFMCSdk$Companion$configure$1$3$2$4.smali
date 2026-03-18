.class final Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->configure(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;Lay0/k;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lkotlin/jvm/internal/n;",
        "Lay0/a;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0008\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0010\u0003\u001a\u00020\u0000H\n\u00a2\u0006\u0004\u0008\u0001\u0010\u0002"
    }
    d2 = {
        "Llx0/b0;",
        "invoke",
        "()V",
        "<anonymous>"
    }
    k = 0x3
    mv = {
        0x1,
        0x9,
        0x0
    }
.end annotation


# instance fields
.field final synthetic $components:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field final synthetic $config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $moduleInitLatch:Ljava/util/concurrent/CountDownLatch;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Ljava/util/concurrent/CountDownLatch;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$context:Landroid/content/Context;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$components:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 6
    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$moduleInitLatch:Ljava/util/concurrent/CountDownLatch;

    .line 8
    .line 9
    const/4 p1, 0x0

    .line 10
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public static synthetic a(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->invoke$lambda$1(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final invoke$lambda$1(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 1

    .line 1
    const-string v0, "$moduleInitLatch"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "$config"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "module"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 17
    .line 18
    .line 19
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;

    .line 20
    .line 21
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity$Companion;->getInstance()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;->getModuleIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setModuleIdentity$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 33
    .line 34
    new-instance p2, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4$1$1$1;

    .line 35
    .line 36
    invoke-direct {p2, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4$1$1$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)V

    .line 37
    .line 38
    .line 39
    const-string p1, "~$SFMCSdk"

    .line 40
    .line 41
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 42
    .line 43
    .line 44
    return-void
.end method


# virtual methods
.method public bridge synthetic invoke()Ljava/lang/Object;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->invoke()V

    sget-object p0, Llx0/b0;->a:Llx0/b0;

    return-object p0
.end method

.method public final invoke()V
    .locals 6

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->getCdpModule$sfmcsdk_release()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    move-result-object v0

    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$context:Landroid/content/Context;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$components:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion$configure$1$3$2$4;->$moduleInitLatch:Ljava/util/concurrent/CountDownLatch;

    new-instance v4, Lcom/salesforce/marketingcloud/sfmcsdk/a;

    const/4 v5, 0x1

    invoke-direct {v4, p0, v2, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/a;-><init>(Ljava/util/concurrent/CountDownLatch;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;I)V

    invoke-virtual {v0, v1, v2, v3, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initModule(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    return-void
.end method

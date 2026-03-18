.class public final Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;,
        Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000V\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010\u0011\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0018\u0000 \'2\u00020\u0001:\u0001\'B\u0011\u0008\u0002\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\'\u0010\n\u001a\u00020\t2\u0016\u0010\u0008\u001a\u000c\u0012\u0008\u0008\u0001\u0012\u0004\u0018\u00010\u00070\u0006\"\u0004\u0018\u00010\u0007H\u0002\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\r\u0010\r\u001a\u00020\u000c\u00a2\u0006\u0004\u0008\r\u0010\u000eJ\u0015\u0010\u0011\u001a\u00020\t2\u0006\u0010\u0010\u001a\u00020\u000f\u00a2\u0006\u0004\u0008\u0011\u0010\u0012J\u0015\u0010\u0014\u001a\u00020\t2\u0006\u0010\u0010\u001a\u00020\u0013\u00a2\u0006\u0004\u0008\u0014\u0010\u0015R\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u0016\u001a\u0004\u0008\u0017\u0010\u0018R\u0014\u0010\u001a\u001a\u00020\u00198\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u001a\u0010\u001bR\u001a\u0010\u001e\u001a\u0008\u0012\u0004\u0012\u00020\u001d0\u001c8\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u001e\u0010\u001fR\"\u0010!\u001a\u00020 8\u0006@\u0006X\u0086.\u00a2\u0006\u0012\n\u0004\u0008!\u0010\"\u001a\u0004\u0008#\u0010$\"\u0004\u0008%\u0010&\u00a8\u0006("
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;",
        "config",
        "<init>",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;)V",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;",
        "events",
        "Llx0/b0;",
        "internalTrack",
        "([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V",
        "Lorg/json/JSONObject;",
        "getSdkState",
        "()Lorg/json/JSONObject;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;",
        "listener",
        "mp",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener;",
        "cdp",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;",
        "getConfig",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;",
        "executors",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;",
        "modules",
        "Ljava/util/List;",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;",
        "identity",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;",
        "getIdentity",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;",
        "setIdentity",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V",
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
.field public static final Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

.field private static final SDK_LOCK:Ljava/lang/Object;

.field public static final SDK_VERSION_NAME:Ljava/lang/String; = "1.0.5"

.field private static final TAG:Ljava/lang/String; = "~$SFMCSdk"

.field private static final UNIFIED_SDK_INSTANCE_REQUESTS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/WhenReadyHandler;",
            ">;"
        }
    .end annotation
.end field

.field private static final behaviorManager:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl;
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "StaticFieldLeak"
        }
    .end annotation
.end field

.field private static cdpModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

.field private static volatile initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

.field private static instance:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "StaticFieldLeak"
        }
    .end annotation
.end field

.field private static pushModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;


# instance fields
.field private final config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

.field private final executors:Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

.field public identity:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

.field private final modules:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 8
    .line 9
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;

    .line 10
    .line 11
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->pushModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;

    .line 15
    .line 16
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    .line 17
    .line 18
    invoke-direct {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;-><init>()V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->cdpModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    .line 22
    .line 23
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl;

    .line 24
    .line 25
    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    const-string v2, "newSingleThreadExecutor(...)"

    .line 30
    .line 31
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl;-><init>(Ljava/util/concurrent/ExecutorService;)V

    .line 35
    .line 36
    .line 37
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->behaviorManager:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl;

    .line 38
    .line 39
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->NONE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 40
    .line 41
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 42
    .line 43
    new-instance v0, Ljava/util/ArrayList;

    .line 44
    .line 45
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 46
    .line 47
    .line 48
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->UNIFIED_SDK_INSTANCE_REQUESTS:Ljava/util/List;

    .line 49
    .line 50
    new-instance v0, Ljava/lang/Object;

    .line 51
    .line 52
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    sput-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->SDK_LOCK:Ljava/lang/Object;

    .line 56
    .line 57
    return-void
.end method

.method private constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;)V
    .locals 4

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    .line 4
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

    invoke-static {}, Ljava/util/concurrent/Executors;->newCachedThreadPool()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    const-string v2, "newCachedThreadPool(...)"

    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v2, 0x0

    const/4 v3, 0x2

    invoke-direct {v0, v1, v2, v3, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;-><init>(Ljava/util/concurrent/ExecutorService;Ljava/util/concurrent/ExecutorService;ILkotlin/jvm/internal/g;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->executors:Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

    .line 5
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->modules:Ljava/util/List;

    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->getConfigs$sfmcsdk_release()Ljava/util/List;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    .line 7
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_0
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v0

    if-eqz v0, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 8
    invoke-interface {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;->getModuleIdentifier()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    move-result-object v0

    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$WhenMappings;->$EnumSwitchMapping$0:[I

    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    move-result v0

    aget v0, v1, v0

    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    if-eq v0, v3, :cond_1

    goto :goto_0

    .line 9
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->getCdpModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleConfig;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->modules:Ljava/util/List;

    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->cdpModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 11
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;->getPushModuleConfig()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 12
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->modules:Ljava/util/List;

    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->pushModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;

    invoke-interface {v0, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_3
    return-void
.end method

.method public synthetic constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;)V

    return-void
.end method

.method public static final synthetic access$getBehaviorManager$cp()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->behaviorManager:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManagerImpl;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getCdpModule$cp()Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->cdpModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getInitializationState$cp()Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getInstance$cp()Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->instance:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getModules$p(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)Ljava/util/List;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->modules:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public static final synthetic access$getPushModule$cp()Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->pushModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getSDK_LOCK$cp()Ljava/lang/Object;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->SDK_LOCK:Ljava/lang/Object;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final synthetic access$getUNIFIED_SDK_INSTANCE_REQUESTS$cp()Ljava/util/List;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->UNIFIED_SDK_INSTANCE_REQUESTS:Ljava/util/List;

    .line 2
    .line 3
    return-object v0
.end method

.method public static final varargs synthetic access$internalTrack(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->internalTrack([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final synthetic access$setCdpModule$cp(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;)V
    .locals 0

    .line 1
    sput-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->cdpModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$setInitializationState$cp(Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;)V
    .locals 0

    .line 1
    sput-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$setInstance$cp(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 0

    .line 1
    sput-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->instance:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;

    .line 2
    .line 3
    return-void
.end method

.method public static final synthetic access$setPushModule$cp(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;)V
    .locals 0

    .line 1
    sput-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->pushModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;

    .line 2
    .line 3
    return-void
.end method

.method public static final configure(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->configure(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;)V

    return-void
.end method

.method public static final configure(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;Lay0/k;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Landroid/content/Context;",
            "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;",
            "Lay0/k;",
            ")V"
        }
    .end annotation

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    invoke-virtual {v0, p0, p1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->configure(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;Lay0/k;)V

    return-void
.end method

.method private final varargs internalTrack([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 3

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 4
    .line 5
    const-string v1, "~$SFMCSdk"

    .line 6
    .line 7
    new-instance v2, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$internalTrack$1$1;

    .line 8
    .line 9
    invoke-direct {v2, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$internalTrack$1$1;-><init>([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 13
    .line 14
    .line 15
    :catch_0
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;

    .line 16
    .line 17
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->executors:Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

    .line 18
    .line 19
    array-length v1, p1

    .line 20
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    check-cast p1, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    .line 25
    .line 26
    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager$Companion;->publish$sfmcsdk_release(Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 27
    .line 28
    .line 29
    :cond_0
    return-void
.end method

.method public static final requestSdk(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->requestSdk(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static final setLogging(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->setLogging(Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogLevel;Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/LogListener;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public static final varargs track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->Companion:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->track([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final cdp(Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleReadyListener;)V
    .locals 0

    .line 1
    const-string p0, "listener"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->cdpModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModule;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->requestModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final getConfig()Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->config:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkModuleConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->identity:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "identity"

    .line 7
    .line 8
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    throw p0
.end method

.method public final getSdkState()Lorg/json/JSONObject;
    .locals 3

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "sfmcSDKVersion"

    .line 7
    .line 8
    const-string v2, "1.0.5"

    .line 9
    .line 10
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 11
    .line 12
    .line 13
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->modules:Ljava/util/List;

    .line 14
    .line 15
    check-cast p0, Ljava/lang/Iterable;

    .line 16
    .line 17
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;

    .line 32
    .line 33
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getName()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getState()Lorg/json/JSONObject;

    .line 38
    .line 39
    .line 40
    move-result-object v1

    .line 41
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    return-object v0
.end method

.method public final mp(Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleReadyListener;)V
    .locals 0

    .line 1
    const-string p0, "listener"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->pushModule:Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModule;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->requestModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final setIdentity(Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;->identity:Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    .line 7
    .line 8
    return-void
.end method

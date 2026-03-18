.class public abstract Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000b\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0010!\n\u0002\u0018\u0002\n\u0002\u0008\u0005\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0018\u0002\n\u0002\u0008\u0006\n\u0002\u0010\u000e\n\u0002\u0008\u0004\u0008 \u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0015\u0010\u0007\u001a\u00020\u00062\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\r\u0010\t\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\t\u0010\u0003J\r\u0010\u000b\u001a\u00020\n\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\r\u0010\u000e\u001a\u00020\r\u00a2\u0006\u0004\u0008\u000e\u0010\u000fJ-\u0010\u0016\u001a\u00020\u00062\u0006\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u0013\u001a\u00020\u00122\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0016\u0010\u0017R&\u0010\u001a\u001a\u0008\u0012\u0004\u0012\u00020\u00190\u00188\u0004X\u0084\u0004\u00a2\u0006\u0012\n\u0004\u0008\u001a\u0010\u001b\u0012\u0004\u0008\u001e\u0010\u0003\u001a\u0004\u0008\u001c\u0010\u001dR\"\u0010 \u001a\u00020\u001f8\u0004@\u0004X\u0084\u000e\u00a2\u0006\u0012\n\u0004\u0008 \u0010!\u001a\u0004\u0008\"\u0010#\"\u0004\u0008$\u0010%R$\u0010\'\u001a\u0004\u0018\u00010&8\u0004@\u0004X\u0084\u000e\u00a2\u0006\u0012\n\u0004\u0008\'\u0010(\u001a\u0004\u0008)\u0010*\"\u0004\u0008+\u0010,R\u0014\u00100\u001a\u00020-8&X\u00a6\u0004\u00a2\u0006\u0006\u001a\u0004\u0008.\u0010/\u00a8\u00061"
    }
    d2 = {
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;",
        "",
        "<init>",
        "()V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;",
        "listener",
        "Llx0/b0;",
        "requestModule",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V",
        "tearDown",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
        "getIdentity",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;",
        "Lorg/json/JSONObject;",
        "getState",
        "()Lorg/json/JSONObject;",
        "Landroid/content/Context;",
        "context",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;",
        "config",
        "Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;",
        "components",
        "initModule",
        "(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V",
        "",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;",
        "MODULE_INSTANCE_REQUESTS",
        "Ljava/util/List;",
        "getMODULE_INSTANCE_REQUESTS",
        "()Ljava/util/List;",
        "getMODULE_INSTANCE_REQUESTS$annotations",
        "Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;",
        "initializationState",
        "Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;",
        "getInitializationState",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;",
        "setInitializationState",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;)V",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "module",
        "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "getModule",
        "()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;",
        "setModule",
        "(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V",
        "",
        "getName",
        "()Ljava/lang/String;",
        "name",
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
.field private final MODULE_INSTANCE_REQUESTS:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;",
            ">;"
        }
    .end annotation
.end field

.field private initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

.field private module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->MODULE_INSTANCE_REQUESTS:Ljava/util/List;

    .line 10
    .line 11
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->NONE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 12
    .line 13
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 14
    .line 15
    return-void
.end method

.method public static synthetic getMODULE_INSTANCE_REQUESTS$annotations()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final getIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-interface {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;->getModuleIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    new-instance p0, Llx0/k;

    .line 13
    .line 14
    const-string v0, "An operation is not implemented: Your module must implement getIdentity()."

    .line 15
    .line 16
    invoke-direct {p0, v0}, Llx0/k;-><init>(Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    throw p0
.end method

.method public final getInitializationState()Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getMODULE_INSTANCE_REQUESTS()Ljava/util/List;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->MODULE_INSTANCE_REQUESTS:Ljava/util/List;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getModule()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 2
    .line 3
    return-object p0
.end method

.method public abstract getName()Ljava/lang/String;
.end method

.method public final getState()Lorg/json/JSONObject;
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    invoke-interface {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;->getState()Lorg/json/JSONObject;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    return-object v0

    .line 13
    :cond_1
    :goto_0
    new-instance v0, Lorg/json/JSONObject;

    .line 14
    .line 15
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 19
    .line 20
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 21
    .line 22
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    aget p0, v1, p0

    .line 27
    .line 28
    const/4 v1, 0x2

    .line 29
    const-string v2, "INITIALIZATION_STATUS"

    .line 30
    .line 31
    if-eq p0, v1, :cond_3

    .line 32
    .line 33
    const/4 v1, 0x3

    .line 34
    if-eq p0, v1, :cond_2

    .line 35
    .line 36
    const-string p0, "NOT READY"

    .line 37
    .line 38
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    goto :goto_1

    .line 43
    :cond_2
    const-string p0, "ERROR"

    .line 44
    .line 45
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    goto :goto_1

    .line 50
    :cond_3
    const-string p0, "NOT IMPLEMENTED OR NOT INITIALIZED"

    .line 51
    .line 52
    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    :goto_1
    const-string v0, "run(...)"

    .line 57
    .line 58
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 59
    .line 60
    .line 61
    return-object p0
.end method

.method public final initModule(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
    .locals 11

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "config"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "components"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "listener"

    .line 17
    .line 18
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    :try_start_0
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getExecutors()Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/SdkExecutors;->getDiskIO()Ljava/util/concurrent/ExecutorService;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;->getModuleIdentifier()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 30
    .line 31
    .line 32
    move-result-object v1

    .line 33
    invoke-virtual {v1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v1

    .line 37
    new-instance v2, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    const-string v1, "_init_thread"

    .line 46
    .line 47
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v9

    .line 54
    const/4 v1, 0x0

    .line 55
    new-array v10, v1, [Ljava/lang/Object;

    .line 56
    .line 57
    new-instance v3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_2

    .line 58
    .line 59
    move-object v4, p0

    .line 60
    move-object v6, p1

    .line 61
    move-object v5, p2

    .line 62
    move-object v7, p3

    .line 63
    move-object v8, p4

    .line 64
    :try_start_1
    invoke-direct/range {v3 .. v10}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    invoke-interface {v0, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1
    .catch Ljava/lang/Error; {:try_start_1 .. :try_end_1} :catch_0

    .line 68
    .line 69
    .line 70
    return-void

    .line 71
    :catch_0
    move-exception v0

    .line 72
    :goto_0
    move-object p0, v0

    .line 73
    goto :goto_2

    .line 74
    :catch_1
    move-exception v0

    .line 75
    :goto_1
    move-object p0, v0

    .line 76
    goto :goto_3

    .line 77
    :catch_2
    move-exception v0

    .line 78
    move-object v4, p0

    .line 79
    goto :goto_0

    .line 80
    :catch_3
    move-exception v0

    .line 81
    move-object v4, p0

    .line 82
    goto :goto_1

    .line 83
    :goto_2
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 84
    .line 85
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getName()Ljava/lang/String;

    .line 86
    .line 87
    .line 88
    move-result-object p2

    .line 89
    new-instance p3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$3;

    .line 90
    .line 91
    invoke-direct {p3, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$3;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;)V

    .line 92
    .line 93
    .line 94
    invoke-virtual {p1, p2, p0, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 95
    .line 96
    .line 97
    goto :goto_4

    .line 98
    :goto_3
    sget-object p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 99
    .line 100
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getName()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    new-instance p3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$2;

    .line 105
    .line 106
    invoke-direct {p3, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$2;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p1, p2, p0, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->w(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 110
    .line 111
    .line 112
    :goto_4
    return-void
.end method

.method public final requestModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
    .locals 4

    .line 1
    const-string v0, "listener"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;

    .line 7
    .line 8
    invoke-direct {v0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->MODULE_INSTANCE_REQUESTS:Ljava/util/List;

    .line 12
    .line 13
    monitor-enter p1

    .line 14
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 15
    .line 16
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 17
    .line 18
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    aget v1, v2, v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    const/4 v2, 0x1

    .line 25
    if-ne v1, v2, :cond_0

    .line 26
    .line 27
    :try_start_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 28
    .line 29
    if-eqz p0, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->deliverModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 32
    .line 33
    .line 34
    goto :goto_0

    .line 35
    :catchall_0
    move-exception p0

    .line 36
    goto :goto_1

    .line 37
    :catch_0
    move-exception p0

    .line 38
    :try_start_2
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 39
    .line 40
    const-string v2, "~$PushSdkModule"

    .line 41
    .line 42
    new-instance v3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$requestModule$1$2;

    .line 43
    .line 44
    invoke-direct {v3, v0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$requestModule$1$2;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;)V

    .line 45
    .line 46
    .line 47
    invoke-virtual {v1, v2, p0, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->MODULE_INSTANCE_REQUESTS:Ljava/util/List;

    .line 52
    .line 53
    invoke-interface {p0, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 54
    .line 55
    .line 56
    :cond_1
    :goto_0
    monitor-exit p1

    .line 57
    return-void

    .line 58
    :goto_1
    monitor-exit p1

    .line 59
    throw p0
.end method

.method public final setInitializationState(Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 7
    .line 8
    return-void
.end method

.method public final setModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 2
    .line 3
    return-void
.end method

.method public final tearDown()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->MODULE_INSTANCE_REQUESTS:Ljava/util/List;

    .line 2
    .line 3
    invoke-interface {v0}, Ljava/util/List;->clear()V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x0

    .line 7
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->module:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;

    .line 8
    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->NONE:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 10
    .line 11
    iput-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initializationState:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 12
    .line 13
    return-void
.end method

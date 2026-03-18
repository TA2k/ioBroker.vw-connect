.class public final Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;
.super Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingMethod;
    value = Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->initModule(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = null
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0011\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003*\u0001\u0000\u0008\n\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0014\u00a2\u0006\u0004\u0008\u0003\u0010\u0004\u00a8\u0006\u0005"
    }
    d2 = {
        "com/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1",
        "Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;",
        "Llx0/b0;",
        "execute",
        "()V",
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
.field final synthetic $components:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field final synthetic $config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

.field final synthetic $context:Landroid/content/Context;

.field final synthetic $listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

.field final synthetic this$0:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->this$0:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;

    .line 2
    .line 3
    iput-object p2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 4
    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$context:Landroid/content/Context;

    .line 6
    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$components:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 8
    .line 9
    iput-object p5, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 10
    .line 11
    invoke-direct {p0, p6, p7}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;-><init>(Ljava/lang/String;[Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->execute$lambda$2(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static final execute$lambda$2(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    .locals 4

    .line 1
    const-string v0, "this$0"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "this$1"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "$config"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    const-string v0, "$listener"

    .line 17
    .line 18
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    const-string v0, "it"

    .line 22
    .line 23
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 27
    .line 28
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;->getName()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    new-instance v1, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$execute$2$1;

    .line 33
    .line 34
    invoke-direct {v1, p2}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$execute$2$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, p0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 38
    .line 39
    .line 40
    invoke-interface {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;->getModuleIdentifier()Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    sget-object p2, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 45
    .line 46
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    aget p0, p2, p0

    .line 51
    .line 52
    const/4 p2, 0x1

    .line 53
    if-eq p0, p2, :cond_1

    .line 54
    .line 55
    const/4 p2, 0x2

    .line 56
    if-ne p0, p2, :cond_0

    .line 57
    .line 58
    move-object p0, p4

    .line 59
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/cdp/CdpModuleInterface;

    .line 60
    .line 61
    goto :goto_0

    .line 62
    :cond_0
    new-instance p0, La8/r0;

    .line 63
    .line 64
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 65
    .line 66
    .line 67
    throw p0

    .line 68
    :cond_1
    move-object p0, p4

    .line 69
    check-cast p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;

    .line 70
    .line 71
    :goto_0
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->setModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 72
    .line 73
    .line 74
    invoke-interface {p3, p4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;->ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 75
    .line 76
    .line 77
    sget-object p0, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->READY:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 78
    .line 79
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->setInitializationState(Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;)V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getMODULE_INSTANCE_REQUESTS()Ljava/util/List;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    monitor-enter p0

    .line 87
    :try_start_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getMODULE_INSTANCE_REQUESTS()Ljava/util/List;

    .line 88
    .line 89
    .line 90
    move-result-object p2

    .line 91
    check-cast p2, Ljava/lang/Iterable;

    .line 92
    .line 93
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 94
    .line 95
    .line 96
    move-result-object p2

    .line 97
    :goto_1
    invoke-interface {p2}, Ljava/util/Iterator;->hasNext()Z

    .line 98
    .line 99
    .line 100
    move-result p3

    .line 101
    if-eqz p3, :cond_2

    .line 102
    .line 103
    invoke-interface {p2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p3

    .line 107
    check-cast p3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 108
    .line 109
    :try_start_1
    invoke-virtual {p3, p4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;->deliverModule(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 110
    .line 111
    .line 112
    goto :goto_1

    .line 113
    :catchall_0
    move-exception p1

    .line 114
    goto :goto_2

    .line 115
    :catch_0
    move-exception v0

    .line 116
    :try_start_2
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 117
    .line 118
    const-string v2, "~$PushSdkModule"

    .line 119
    .line 120
    new-instance v3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$execute$2$2$1$1;

    .line 121
    .line 122
    invoke-direct {v3, p4, p3}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$execute$2$2$1$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyHandler;)V

    .line 123
    .line 124
    .line 125
    invoke-virtual {v1, v2, v0, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->e(Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;)V

    .line 126
    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_2
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->getMODULE_INSTANCE_REQUESTS()Ljava/util/List;

    .line 130
    .line 131
    .line 132
    move-result-object p1

    .line 133
    invoke-interface {p1}, Ljava/util/List;->clear()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 134
    .line 135
    .line 136
    monitor-exit p0

    .line 137
    return-void

    .line 138
    :goto_2
    monitor-exit p0

    .line 139
    throw p1
.end method


# virtual methods
.method public execute()V
    .locals 6

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->this$0:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;->INITIALIZING:Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;->setInitializationState(Lcom/salesforce/marketingcloud/sfmcsdk/InitializationState;)V

    .line 6
    .line 7
    .line 8
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->INSTANCE:Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;

    .line 9
    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/utils/NamedRunnable;->getName()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    new-instance v2, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$execute$1;

    .line 15
    .line 16
    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 17
    .line 18
    invoke-direct {v2, v3}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1$execute$1;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {v0, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/logging/SFMCSdkLogger;->d(Ljava/lang/String;Lay0/a;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$config:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;

    .line 25
    .line 26
    iget-object v1, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$context:Landroid/content/Context;

    .line 27
    .line 28
    iget-object v2, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$components:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 29
    .line 30
    iget-object v3, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->this$0:Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module;

    .line 31
    .line 32
    iget-object v4, p0, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Module$initModule$1;->$listener:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;

    .line 33
    .line 34
    new-instance v5, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;

    .line 35
    .line 36
    invoke-direct {v5, p0, v3, v0, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    invoke-interface {v0, v1, v2, v5}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/Config;->init(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 40
    .line 41
    .line 42
    return-void
.end method

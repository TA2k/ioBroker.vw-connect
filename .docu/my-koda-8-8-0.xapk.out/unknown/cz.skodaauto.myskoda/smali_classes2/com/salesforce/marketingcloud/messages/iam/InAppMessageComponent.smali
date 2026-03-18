.class public Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;
.implements Lcom/salesforce/marketingcloud/messages/iam/i;
.implements Lcom/salesforce/marketingcloud/k$f;
.implements Lcom/salesforce/marketingcloud/events/f;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation


# static fields
.field static final EXTRA_MESSAGE_HANDLER:Ljava/lang/String; = "messageHandler"


# instance fields
.field private final alarmScheduler:Lcom/salesforce/marketingcloud/alarms/b;

.field private final analyticsListener:Lcom/salesforce/marketingcloud/analytics/f;

.field private final behaviorManager:Lcom/salesforce/marketingcloud/behaviors/c;

.field private configComponent:Lcom/salesforce/marketingcloud/config/a;

.field private final context:Landroid/content/Context;

.field private executors:Lcom/salesforce/marketingcloud/internal/n;

.field private imageHandler:Lcom/salesforce/marketingcloud/media/o;

.field private final messageDelayHandler:Landroid/os/Handler;

.field realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

.field private final storage:Lcom/salesforce/marketingcloud/storage/h;

.field private final syncRouteComponent:Lcom/salesforce/marketingcloud/k;

.field private uSdkComponents:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field private final urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Lcom/salesforce/marketingcloud/config/a;)V
    .locals 12

    const/4 v10, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object/from16 v4, p4

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    move-object/from16 v9, p9

    move-object/from16 v11, p10

    .line 1
    invoke-direct/range {v0 .. v11}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/config/a;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/config/a;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v0, Landroid/os/Handler;

    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    move-result-object v1

    invoke-direct {v0, v1}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->messageDelayHandler:Landroid/os/Handler;

    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->context:Landroid/content/Context;

    .line 5
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->storage:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->alarmScheduler:Lcom/salesforce/marketingcloud/alarms/b;

    .line 7
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->syncRouteComponent:Lcom/salesforce/marketingcloud/k;

    .line 8
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->behaviorManager:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 9
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->imageHandler:Lcom/salesforce/marketingcloud/media/o;

    .line 10
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 11
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->analyticsListener:Lcom/salesforce/marketingcloud/analytics/f;

    .line 12
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->executors:Lcom/salesforce/marketingcloud/internal/n;

    .line 13
    iput-object p10, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->uSdkComponents:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 14
    iput-object p11, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->configComponent:Lcom/salesforce/marketingcloud/config/a;

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/iam/m;)V
    .locals 11

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    const/4 v6, 0x0

    const/4 v7, 0x0

    const/4 v8, 0x0

    move-object v0, p0

    .line 15
    invoke-direct/range {v0 .. v10}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Lcom/salesforce/marketingcloud/config/a;)V

    .line 16
    iput-object p1, v0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    return-void
.end method

.method private subscribeForBehaviours()V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->uSdkComponents:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getBehaviorManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManager;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APPLICATION_FOREGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 10
    .line 11
    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;->APPLICATION_BACKGROUNDED:Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorType;

    .line 12
    .line 13
    invoke-static {v1, v2}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-interface {v0, v1, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManager;->registerForBehaviors(Ljava/util/EnumSet;Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->behaviorManager:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 22
    .line 23
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 24
    .line 25
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 26
    .line 27
    invoke-static {v1, v2}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    invoke-virtual {v0, p0, v1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method private unSubscribeForBehaviours()V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->uSdkComponents:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getBehaviorManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManager;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-interface {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorManager;->unregisterForAllBehaviors(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/BehaviorListener;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->behaviorManager:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 13
    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    return-void
.end method


# virtual methods
.method public canDisplay(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->canDisplay(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "InAppMessageManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->a()Lorg/json/JSONObject;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public controlChannelInit(I)V
    .locals 10

    .line 1
    const/16 v0, 0x1000

    .line 2
    .line 3
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->syncRouteComponent:Lcom/salesforce/marketingcloud/k;

    .line 10
    .line 11
    sget-object v2, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 12
    .line 13
    const/4 v3, 0x0

    .line 14
    invoke-virtual {v1, v2, v3}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->unSubscribeForBehaviours()V

    .line 18
    .line 19
    .line 20
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 21
    .line 22
    if-eqz v1, :cond_0

    .line 23
    .line 24
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {v1, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->b(Z)V

    .line 29
    .line 30
    .line 31
    iput-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 32
    .line 33
    :cond_0
    return-void

    .line 34
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 35
    .line 36
    if-nez p1, :cond_2

    .line 37
    .line 38
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 39
    .line 40
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->context:Landroid/content/Context;

    .line 41
    .line 42
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->storage:Lcom/salesforce/marketingcloud/storage/h;

    .line 43
    .line 44
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->alarmScheduler:Lcom/salesforce/marketingcloud/alarms/b;

    .line 45
    .line 46
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->imageHandler:Lcom/salesforce/marketingcloud/media/o;

    .line 47
    .line 48
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 49
    .line 50
    iget-object v6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->executors:Lcom/salesforce/marketingcloud/internal/n;

    .line 51
    .line 52
    iget-object v7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->analyticsListener:Lcom/salesforce/marketingcloud/analytics/f;

    .line 53
    .line 54
    iget-object v8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->messageDelayHandler:Landroid/os/Handler;

    .line 55
    .line 56
    iget-object v9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->configComponent:Lcom/salesforce/marketingcloud/config/a;

    .line 57
    .line 58
    invoke-direct/range {v0 .. v9}, Lcom/salesforce/marketingcloud/messages/iam/m;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Landroid/os/Handler;Lcom/salesforce/marketingcloud/config/a;)V

    .line 59
    .line 60
    .line 61
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 62
    .line 63
    :cond_2
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->subscribeForBehaviours()V

    .line 64
    .line 65
    .line 66
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->syncRouteComponent:Lcom/salesforce/marketingcloud/k;

    .line 67
    .line 68
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 69
    .line 70
    invoke-virtual {p1, v0, p0}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    .line 71
    .line 72
    .line 73
    return-void
.end method

.method public getStatusBarColor()I
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->getStatusBarColor()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0
.end method

.method public getTypeface()Landroid/graphics/Typeface;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->getTypeface()Landroid/graphics/Typeface;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return-object p0
.end method

.method public handleMessageFinished(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/iam/m;->handleMessageFinished(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public handleOutcomes(Ljava/util/Collection;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->handleOutcomes(Ljava/util/Collection;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public imageHandler()Lcom/salesforce/marketingcloud/media/o;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/m;->imageHandler()Lcom/salesforce/marketingcloud/media/o;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->imageHandler:Lcom/salesforce/marketingcloud/media/o;

    .line 11
    .line 12
    return-object p0
.end method

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 10

    .line 1
    const/16 p1, 0x1000

    .line 2
    .line 3
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    if-eqz p1, :cond_0

    .line 8
    .line 9
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->syncRouteComponent:Lcom/salesforce/marketingcloud/k;

    .line 10
    .line 11
    sget-object p2, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 12
    .line 13
    invoke-virtual {p1, p2, p0}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 17
    .line 18
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->context:Landroid/content/Context;

    .line 19
    .line 20
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->storage:Lcom/salesforce/marketingcloud/storage/h;

    .line 21
    .line 22
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->alarmScheduler:Lcom/salesforce/marketingcloud/alarms/b;

    .line 23
    .line 24
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->imageHandler:Lcom/salesforce/marketingcloud/media/o;

    .line 25
    .line 26
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 27
    .line 28
    iget-object v6, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->executors:Lcom/salesforce/marketingcloud/internal/n;

    .line 29
    .line 30
    iget-object v7, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->analyticsListener:Lcom/salesforce/marketingcloud/analytics/f;

    .line 31
    .line 32
    iget-object v8, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->messageDelayHandler:Landroid/os/Handler;

    .line 33
    .line 34
    iget-object v9, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->configComponent:Lcom/salesforce/marketingcloud/config/a;

    .line 35
    .line 36
    invoke-direct/range {v0 .. v9}, Lcom/salesforce/marketingcloud/messages/iam/m;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Landroid/os/Handler;Lcom/salesforce/marketingcloud/config/a;)V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 40
    .line 41
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->subscribeForBehaviours()V

    .line 42
    .line 43
    .line 44
    :cond_0
    return-void
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    if-eqz p0, :cond_1

    .line 2
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    if-ne p1, p2, :cond_0

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->b()V

    return-void

    .line 4
    :cond_0
    sget-object p2, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    if-ne p1, p2, :cond_1

    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->c()V

    :cond_1
    return-void
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior;)V
    .locals 1

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    if-eqz p0, :cond_1

    .line 7
    instance-of v0, p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppForegrounded;

    if-eqz v0, :cond_0

    .line 8
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->b()V

    return-void

    .line 9
    :cond_0
    instance-of p1, p1, Lcom/salesforce/marketingcloud/sfmcsdk/components/behaviors/Behavior$AppBackgrounded;

    if-eqz p1, :cond_1

    .line 10
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/m;->c()V

    :cond_1
    return-void
.end method

.method public onSyncReceived(Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 6
    .line 7
    if-ne p1, v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Lorg/json/JSONObject;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method

.method public setInAppMessageListener(Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->setInAppMessageListener(Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public setStatusBarColor(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->setStatusBarColor(I)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public setTypeface(Landroid/graphics/Typeface;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->setTypeface(Landroid/graphics/Typeface;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public showMessage(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    if-eqz p0, :cond_0

    .line 4
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->d(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    :cond_0
    return-void
.end method

.method public showMessage(Ljava/lang/String;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    if-eqz p0, :cond_0

    .line 2
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->showMessage(Ljava/lang/String;)V

    :cond_0
    return-void
.end method

.method public tearDown(Z)V
    .locals 2

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    if-eqz p1, :cond_0

    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    invoke-virtual {p1, v1}, Lcom/salesforce/marketingcloud/messages/iam/m;->b(Z)V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 11
    .line 12
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->syncRouteComponent:Lcom/salesforce/marketingcloud/k;

    .line 13
    .line 14
    if-eqz p1, :cond_1

    .line 15
    .line 16
    sget-object v1, Lcom/salesforce/marketingcloud/k$e;->c:Lcom/salesforce/marketingcloud/k$e;

    .line 17
    .line 18
    invoke-virtual {p1, v1, v0}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    .line 19
    .line 20
    .line 21
    :cond_1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->unSubscribeForBehaviours()V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public urlHandler()Lcom/salesforce/marketingcloud/UrlHandler;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->realInAppMessageComponent:Lcom/salesforce/marketingcloud/messages/iam/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/m;->urlHandler()Lcom/salesforce/marketingcloud/UrlHandler;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 11
    .line 12
    return-object p0
.end method

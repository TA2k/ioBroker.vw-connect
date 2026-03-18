.class public final Lcom/salesforce/marketingcloud/MarketingCloudSdk;
.super Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/b$b;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;,
        Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;,
        Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;
    }
.end annotation


# static fields
.field private static volatile A:Z = false

.field private static volatile B:Z = false

.field private static volatile C:Z = false

.field static final t:Ljava/lang/String; = "MarketingCloudPrefs"

.field static final u:Ljava/lang/String; = "InitConfig"

.field static final v:Ljava/lang/String;

.field private static final w:Ljava/lang/Object;

.field private static final x:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;",
            ">;"
        }
    .end annotation
.end field

.field static y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

.field private static z:Landroid/content/Context;


# instance fields
.field private final a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field private final b:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/d;",
            ">;"
        }
    .end annotation
.end field

.field private final c:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field d:Lcom/salesforce/marketingcloud/location/f;

.field e:Lcom/salesforce/marketingcloud/behaviors/c;

.field private f:Lcom/salesforce/marketingcloud/b;

.field private g:Lcom/salesforce/marketingcloud/storage/h;

.field private h:Lcom/salesforce/marketingcloud/http/e;

.field private i:Lcom/salesforce/marketingcloud/messages/inbox/a;

.field private j:Lcom/salesforce/marketingcloud/registration/d;

.field private k:Lcom/salesforce/marketingcloud/notifications/a;

.field private l:Lcom/salesforce/marketingcloud/messages/push/a;

.field private m:Lcom/salesforce/marketingcloud/messages/d;

.field private n:Lcom/salesforce/marketingcloud/events/c;

.field private o:Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;

.field private p:Lcom/salesforce/marketingcloud/InitializationStatus;

.field private q:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;

.field private r:Lcom/salesforce/marketingcloud/internal/n;

.field private s:Lcom/salesforce/marketingcloud/media/o;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "MarketingCloudSdk"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 8
    .line 9
    new-instance v0, Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->w:Ljava/lang/Object;

    .line 15
    .line 16
    new-instance v0, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    .line 22
    .line 23
    const/4 v0, 0x1

    .line 24
    sput-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->C:Z

    .line 25
    .line 26
    return-void
.end method

.method private constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleInterface;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 5
    .line 6
    new-instance p1, Ljava/util/ArrayList;

    .line 7
    .line 8
    invoke-direct {p1}, Ljava/util/ArrayList;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    .line 12
    .line 13
    iput-object p2, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->c:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 14
    .line 15
    return-void
.end method

.method private a(Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Z)Lcom/salesforce/marketingcloud/InitializationStatus;
    .locals 28

    move-object/from16 v1, p0

    move-object/from16 v2, p1

    move-object/from16 v4, p2

    .line 35
    invoke-static {}, Lcom/salesforce/marketingcloud/util/a;->a()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 36
    invoke-static {}, Lcom/salesforce/marketingcloud/internal/e;->a()Lcom/salesforce/marketingcloud/InitializationStatus;

    move-result-object v0

    return-object v0

    .line 37
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/internal/e;->b()Lcom/salesforce/marketingcloud/InitializationStatus$a;

    move-result-object v15

    const/4 v11, 0x0

    .line 38
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-static {v0, v2}, Lcom/salesforce/marketingcloud/util/c;->a(Landroid/content/Context;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    if-nez p3, :cond_2

    .line 39
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved()Z

    move-result v0

    if-nez v0, :cond_2

    .line 40
    invoke-direct {v1, v4, v5}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;)Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v0

    if-nez v0, :cond_1

    .line 41
    invoke-static {}, Lcom/salesforce/marketingcloud/internal/e;->c()Lcom/salesforce/marketingcloud/InitializationStatus;

    move-result-object v0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    :catch_0
    move-exception v0

    goto/16 :goto_5

    :cond_1
    :goto_0
    move-object/from16 v22, v0

    goto :goto_1

    :cond_2
    const/4 v0, 0x0

    goto :goto_0

    .line 42
    :goto_1
    :try_start_1
    new-instance v0, Lcom/salesforce/marketingcloud/internal/n;

    invoke-direct {v0}, Lcom/salesforce/marketingcloud/internal/n;-><init>()V

    iput-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    .line 43
    new-instance v0, Lcom/salesforce/marketingcloud/util/h;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->c:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEncryptionManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;

    move-result-object v3

    invoke-direct {v0, v3}, Lcom/salesforce/marketingcloud/util/h;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/components/encryption/EncryptionManager;)V

    .line 44
    new-instance v16, Lcom/salesforce/marketingcloud/storage/h;

    sget-object v17, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    .line 45
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v19

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken()Ljava/lang/String;

    move-result-object v20

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    move/from16 v23, p3

    move-object/from16 v18, v0

    move-object/from16 v21, v3

    invoke-direct/range {v16 .. v23}, Lcom/salesforce/marketingcloud/storage/h;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/util/Crypto;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/util/Crypto;Z)V

    move-object/from16 v0, v16

    iput-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 46
    invoke-virtual {v0, v15}, Lcom/salesforce/marketingcloud/storage/h;->a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_2

    :catchall_0
    move-exception v0

    .line 47
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    const-string v6, "Unable to initialize SDK storage."

    new-array v7, v11, [Ljava/lang/Object;

    invoke-static {v3, v0, v6, v7}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 48
    invoke-virtual {v15, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/Throwable;)V

    .line 49
    :goto_2
    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->b()Z

    move-result v0

    if-nez v0, :cond_3

    .line 50
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-static {v4, v0, v5, v2}, Lcom/salesforce/marketingcloud/registration/d;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f;

    .line 51
    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a()Lcom/salesforce/marketingcloud/InitializationStatus;

    move-result-object v0

    return-object v0

    .line 52
    :cond_3
    new-instance v0, Lcom/salesforce/marketingcloud/behaviors/c;

    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-static {}, Ljava/util/concurrent/Executors;->newSingleThreadExecutor()Ljava/util/concurrent/ExecutorService;

    move-result-object v3

    invoke-direct {v0, v2, v3}, Lcom/salesforce/marketingcloud/behaviors/c;-><init>(Landroid/content/Context;Ljava/util/concurrent/ExecutorService;)V

    iput-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 53
    new-instance v0, Lcom/salesforce/marketingcloud/http/e;

    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v3

    iget-object v6, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    invoke-direct {v0, v2, v3, v6}, Lcom/salesforce/marketingcloud/http/e;-><init>(Landroid/content/Context;Landroid/content/SharedPreferences;Lcom/salesforce/marketingcloud/internal/n;)V

    iput-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    .line 54
    new-instance v8, Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    invoke-direct {v8, v0, v2, v3}, Lcom/salesforce/marketingcloud/alarms/b;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/behaviors/c;)V

    .line 55
    new-instance v22, Lcom/salesforce/marketingcloud/analytics/h;

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v7, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    move-object/from16 v19, v8

    iget-object v8, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    iget-object v9, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object/from16 v3, p2

    move-object/from16 v6, v19

    move-object/from16 v2, v22

    invoke-direct/range {v2 .. v9}, Lcom/salesforce/marketingcloud/analytics/h;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V

    move-object v10, v2

    move-object/from16 v19, v6

    .line 56
    iput-object v10, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->o:Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;

    .line 57
    new-instance v20, Lcom/salesforce/marketingcloud/k;

    move-object v3, v5

    iget-object v5, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v6, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    iget-object v7, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    iget-object v9, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object/from16 v4, p2

    move-object/from16 v8, v19

    move-object/from16 v2, v20

    invoke-direct/range {v2 .. v10}, Lcom/salesforce/marketingcloud/k;-><init>(Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/l;)V

    move-object v0, v2

    move-object v5, v3

    move-object/from16 v19, v8

    .line 58
    new-instance v2, Lcom/salesforce/marketingcloud/b;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    move-result-object v3

    invoke-direct {v2, v0, v3}, Lcom/salesforce/marketingcloud/b;-><init>(Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/storage/d;)V

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->f:Lcom/salesforce/marketingcloud/b;

    .line 59
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-static {v2, v4}, Lcom/salesforce/marketingcloud/location/f;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lcom/salesforce/marketingcloud/location/f;

    move-result-object v2

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->d:Lcom/salesforce/marketingcloud/location/f;

    .line 60
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-static {v2, v4}, Lcom/salesforce/marketingcloud/proximity/e;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Lcom/salesforce/marketingcloud/proximity/e;

    move-result-object v12

    .line 61
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 62
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions()Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    move-result-object v6

    invoke-static {v2, v3, v6, v10}, Lcom/salesforce/marketingcloud/notifications/a;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/analytics/j;)Lcom/salesforce/marketingcloud/notifications/a;

    move-result-object v2

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->k:Lcom/salesforce/marketingcloud/notifications/a;

    .line 63
    new-instance v2, Lcom/salesforce/marketingcloud/messages/inbox/a;

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v6, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    iget-object v8, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    iget-object v9, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object/from16 v3, p2

    move-object/from16 v7, v19

    invoke-direct/range {v2 .. v10}, Lcom/salesforce/marketingcloud/messages/inbox/a;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/g;)V

    move-object/from16 v19, v7

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->i:Lcom/salesforce/marketingcloud/messages/inbox/a;

    .line 64
    new-instance v2, Lcom/salesforce/marketingcloud/messages/d;

    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    move-object v6, v5

    iget-object v5, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v7, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->d:Lcom/salesforce/marketingcloud/location/f;

    iget-object v9, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    move v4, v11

    iget-object v11, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    move-object v8, v12

    iget-object v12, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->k:Lcom/salesforce/marketingcloud/notifications/a;

    iget-object v13, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object/from16 v4, p2

    move-object v14, v10

    move-object/from16 v10, v19

    invoke-direct/range {v2 .. v14}, Lcom/salesforce/marketingcloud/messages/d;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/location/f;Lcom/salesforce/marketingcloud/proximity/e;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/notifications/a;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;)V

    move-object v5, v6

    move-object v13, v8

    move-object/from16 v19, v10

    move-object v10, v14

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->m:Lcom/salesforce/marketingcloud/messages/d;

    .line 65
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-static {v2, v3}, Lcom/salesforce/marketingcloud/media/o;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;)Lcom/salesforce/marketingcloud/media/o;

    move-result-object v2

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->s:Lcom/salesforce/marketingcloud/media/o;

    .line 66
    new-instance v16, Lcom/salesforce/marketingcloud/messages/push/a;

    sget-object v17, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->k:Lcom/salesforce/marketingcloud/notifications/a;

    .line 67
    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId()Ljava/lang/String;

    move-result-object v21

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->s:Lcom/salesforce/marketingcloud/media/o;

    iget-object v6, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    move-object/from16 v18, v2

    move-object/from16 v23, v4

    move-object/from16 v24, v6

    move-object/from16 v22, v10

    move-object/from16 v20, v19

    move-object/from16 v19, v3

    invoke-direct/range {v16 .. v24}, Lcom/salesforce/marketingcloud/messages/push/a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/notifications/a;Lcom/salesforce/marketingcloud/alarms/b;Ljava/lang/String;Lcom/salesforce/marketingcloud/analytics/j;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/internal/n;)V

    move-object/from16 v2, v16

    move-object/from16 v19, v20

    move-object/from16 v14, v22

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->l:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 68
    new-instance v6, Lcom/salesforce/marketingcloud/registration/f;

    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v2

    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    .line 69
    invoke-static {v3}, Lcom/salesforce/marketingcloud/util/f;->a(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v3

    invoke-direct {v6, v5, v2, v3}, Lcom/salesforce/marketingcloud/registration/f;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 70
    new-instance v2, Lcom/salesforce/marketingcloud/registration/d;

    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v5, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v7, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    iget-object v9, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    iget-object v10, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->l:Lcom/salesforce/marketingcloud/messages/push/a;

    iget-object v11, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    iget-object v12, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->c:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    move-object/from16 v4, p2

    move-object/from16 v8, v19

    invoke-direct/range {v2 .. v12}, Lcom/salesforce/marketingcloud/registration/d;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V

    move-object/from16 v19, v8

    iput-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->j:Lcom/salesforce/marketingcloud/registration/d;

    .line 71
    new-instance v2, Lcom/salesforce/marketingcloud/config/a;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    invoke-direct {v2, v0, v3, v14}, Lcom/salesforce/marketingcloud/config/a;-><init>(Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/analytics/m;)V

    .line 72
    new-instance v16, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;

    sget-object v17, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    iget-object v5, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->s:Lcom/salesforce/marketingcloud/media/o;

    .line 73
    invoke-virtual/range {p2 .. p2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler()Lcom/salesforce/marketingcloud/UrlHandler;

    move-result-object v23

    iget-object v7, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    iget-object v8, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->c:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    move-object/from16 v20, v0

    move-object/from16 v27, v2

    move-object/from16 v18, v3

    move-object/from16 v21, v4

    move-object/from16 v22, v5

    move-object/from16 v24, v7

    move-object/from16 v26, v8

    move-object/from16 v25, v14

    invoke-direct/range {v16 .. v27}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/config/a;)V

    move-object/from16 v0, v16

    move-object/from16 v8, v19

    move-object/from16 v10, v25

    move-object/from16 v25, v27

    iput-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->q:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;

    .line 74
    new-instance v16, Lcom/salesforce/marketingcloud/events/c;

    sget-object v17, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->c:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    iget-object v5, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->q:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;

    move-object/from16 v19, v0

    move-object/from16 v21, v2

    move-object/from16 v23, v3

    move-object/from16 v24, v4

    move-object/from16 v26, v5

    move-object/from16 v18, v6

    move-object/from16 v22, v10

    invoke-direct/range {v16 .. v26}, Lcom/salesforce/marketingcloud/events/c;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/analytics/h;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/config/a;Lcom/salesforce/marketingcloud/events/f;)V

    move-object/from16 v3, v16

    move-object/from16 v0, v20

    move-object/from16 v10, v22

    move-object/from16 v2, v25

    iput-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->n:Lcom/salesforce/marketingcloud/events/c;

    .line 75
    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    invoke-interface {v3, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 76
    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    sget-object v4, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-virtual {v4}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v4

    check-cast v4, Landroid/app/Application;

    invoke-static {v4}, Lcom/salesforce/marketingcloud/behaviors/d;->a(Landroid/app/Application;)Lcom/salesforce/marketingcloud/behaviors/d;

    move-result-object v4

    invoke-interface {v3, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 77
    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v4, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    invoke-interface {v3, v4}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 78
    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v3, v8}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 79
    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v3, v10}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 80
    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 81
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->f:Lcom/salesforce/marketingcloud/b;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 82
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->d:Lcom/salesforce/marketingcloud/location/f;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 83
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v0, v13}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 84
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->i:Lcom/salesforce/marketingcloud/messages/inbox/a;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 85
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->k:Lcom/salesforce/marketingcloud/notifications/a;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 86
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->m:Lcom/salesforce/marketingcloud/messages/d;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 87
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->l:Lcom/salesforce/marketingcloud/messages/push/a;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 88
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v3, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->j:Lcom/salesforce/marketingcloud/registration/d;

    invoke-interface {v0, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 89
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 90
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->q:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 91
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->n:Lcom/salesforce/marketingcloud/events/c;

    invoke-interface {v0, v2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 92
    iget-object v0, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->f:Lcom/salesforce/marketingcloud/b;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/b;->a()I

    move-result v0

    .line 93
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    const-string v3, "Initializing all components with control channel flag [%d]"

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    invoke-static {v2, v3, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 94
    iget-object v1, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_3
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_6

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Lcom/salesforce/marketingcloud/d;

    .line 95
    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    const-string v4, "init called for %s"

    invoke-interface {v2}, Lcom/salesforce/marketingcloud/d;->componentName()Ljava/lang/String;

    move-result-object v5

    filled-new-array {v5}, [Ljava/lang/Object;

    move-result-object v5

    invoke-static {v3, v4, v5}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 96
    instance-of v3, v2, Lcom/salesforce/marketingcloud/e;

    if-eqz v3, :cond_4

    .line 97
    move-object v3, v2

    check-cast v3, Lcom/salesforce/marketingcloud/e;

    invoke-interface {v3, v15, v0}, Lcom/salesforce/marketingcloud/e;->init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V

    goto :goto_4

    .line 98
    :cond_4
    instance-of v3, v2, Lcom/salesforce/marketingcloud/f;

    if-eqz v3, :cond_5

    .line 99
    move-object v3, v2

    check-cast v3, Lcom/salesforce/marketingcloud/f;

    invoke-virtual {v3, v15}, Lcom/salesforce/marketingcloud/f;->a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V

    .line 100
    :cond_5
    :goto_4
    invoke-virtual {v15, v2}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Lcom/salesforce/marketingcloud/d;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    goto :goto_3

    .line 101
    :goto_5
    invoke-virtual {v15, v0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/Throwable;)V

    .line 102
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    const/4 v4, 0x0

    new-array v2, v4, [Ljava/lang/Object;

    const-string v3, "Something wrong with internal init"

    invoke-static {v1, v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 103
    :cond_6
    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a()Lcom/salesforce/marketingcloud/InitializationStatus;

    move-result-object v0

    return-object v0
.end method

.method private a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;)Lcom/salesforce/marketingcloud/util/Crypto;
    .locals 8
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "RestrictedApi"
        }
    .end annotation

    .line 104
    :try_start_0
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    const-string v0, "Checking for legacy hashing dependency"

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    invoke-static {p0, v0, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 105
    new-instance v7, Lcom/salesforce/marketingcloud/legacycrypto/OldSdkHash;

    invoke-direct {v7}, Lcom/salesforce/marketingcloud/legacycrypto/OldSdkHash;-><init>()V

    .line 106
    new-instance v2, Lcom/salesforce/marketingcloud/util/AesCrypto;

    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken()Ljava/lang/String;

    move-result-object v5

    move-object v6, p2

    invoke-direct/range {v2 .. v7}, Lcom/salesforce/marketingcloud/util/AesCrypto;-><init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lcom/salesforce/marketingcloud/legacycrypto/OldSdkHash;)V
    :try_end_0
    .catch Ljava/lang/Error; {:try_start_0 .. :try_end_0} :catch_0

    return-object v2

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 107
    sget-object p1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    filled-new-array {p0}, [Ljava/lang/Object;

    move-result-object p0

    const-string p2, "Legacy hashing is not available"

    invoke-static {p1, p2, p0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method public static a(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V
    .locals 5

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v0

    const-string v1, "executeInit %s"

    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->w:Ljava/lang/Object;

    monitor-enter v0

    .line 3
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    if-eqz v1, :cond_0

    .line 4
    iget-object v2, v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-static {p1, v2}, Lcom/salesforce/marketingcloud/internal/g;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Z

    move-result v2

    invoke-direct {v1, v2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b(Z)V

    goto :goto_0

    :catchall_0
    move-exception p0

    goto/16 :goto_5

    .line 5
    :cond_0
    :goto_0
    new-instance v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    invoke-direct {v1, p1, p2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V

    sput-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    const/4 v1, 0x0

    const/4 v2, 0x0

    if-eqz p2, :cond_1

    .line 6
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getRegistrationId()Ljava/lang/String;

    move-result-object v3

    .line 7
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEncryptionChanged()Z

    move-result p2

    goto :goto_1

    :cond_1
    move-object v3, v1

    move p2, v2

    .line 8
    :goto_1
    sget-object v4, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    invoke-direct {v4, v3, p1, p2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Z)Lcom/salesforce/marketingcloud/InitializationStatus;

    move-result-object p1

    .line 9
    const-string p2, "MarketingCloudSdk init finished with status: %s"

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object v3

    invoke-static {p0, p2, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/InitializationStatus;->isUsable()Z

    move-result p2

    sput-boolean p2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    .line 11
    sput-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z

    .line 12
    sget-boolean p2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    if-eqz p2, :cond_4

    .line 13
    sget-object p2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    invoke-direct {p2, p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a(Lcom/salesforce/marketingcloud/InitializationStatus;)V

    .line 14
    sget-object p2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    iget-object v1, p2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->f:Lcom/salesforce/marketingcloud/b;

    invoke-virtual {v1, p2}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/b$b;)V

    .line 15
    sget-object p2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    monitor-enter p2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    :try_start_1
    sput-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->C:Z

    .line 17
    const-string v1, "Delivering queued SDK requests to %s listeners"

    invoke-interface {p2}, Ljava/util/List;->size()I

    move-result v2

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    filled-new-array {v2}, [Ljava/lang/Object;

    move-result-object v2

    invoke-static {p0, v1, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    invoke-interface {p2}, Ljava/util/List;->isEmpty()Z

    move-result p0

    if-nez p0, :cond_3

    .line 19
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_2

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 20
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->a()V

    goto :goto_2

    :catchall_1
    move-exception p0

    goto :goto_3

    .line 21
    :cond_2
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 22
    :cond_3
    monitor-exit p2

    goto :goto_4

    :goto_3
    monitor-exit p2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    throw p0

    .line 23
    :cond_4
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    invoke-direct {p0, v2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a(Z)V

    .line 24
    sput-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 25
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    monitor-enter p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 26
    :try_start_3
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 27
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 28
    :goto_4
    :try_start_4
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->w:Ljava/lang/Object;

    invoke-virtual {p0}, Ljava/lang/Object;->notifyAll()V

    if-eqz p3, :cond_5

    .line 29
    invoke-interface {p3, p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;->complete(Lcom/salesforce/marketingcloud/InitializationStatus;)V

    .line 30
    :cond_5
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    return-void

    :catchall_2
    move-exception p1

    .line 31
    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_2

    :try_start_6
    throw p1

    .line 32
    :goto_5
    monitor-exit v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    throw p0
.end method

.method private a(Lcom/salesforce/marketingcloud/InitializationStatus;)V
    .locals 0

    .line 108
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->p:Lcom/salesforce/marketingcloud/InitializationStatus;

    return-void
.end method

.method private a(Z)V
    .locals 0

    .line 33
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b(Z)V

    const/4 p0, 0x0

    .line 34
    sput-boolean p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z

    return-void
.end method

.method public static b(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V
    .locals 5

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkVersionName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "~~ MarketingCloudSdk v%s init() ~~"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 2
    const-string v1, "Context cannot be null."

    invoke-static {p0, v1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 3
    const-string v1, "Config cannot be null."

    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId()Ljava/lang/String;

    move-result-object v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/internal/f;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 5
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->w:Ljava/lang/Object;

    monitor-enter v1

    .line 6
    :try_start_0
    sget-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    if-nez v2, :cond_0

    sget-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z

    if-eqz v2, :cond_3

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_2

    .line 7
    :cond_0
    :goto_0
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    if-eqz v2, :cond_3

    iget-object v2, v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-virtual {p1, v2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->equals(Ljava/lang/Object;)Z

    move-result v2

    if-eqz v2, :cond_3

    .line 8
    const-string p0, "MarketingCloudSdk is already %s"

    sget-boolean p1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    if-eqz p1, :cond_1

    const-string p1, "initialized"

    goto :goto_1

    .line 9
    :cond_1
    const-string p1, "initializing"

    :goto_1
    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    invoke-static {v0, p0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isReady()Z

    move-result p0

    if-eqz p0, :cond_2

    if-eqz p3, :cond_2

    .line 11
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->p:Lcom/salesforce/marketingcloud/InitializationStatus;

    invoke-interface {p3, p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;->complete(Lcom/salesforce/marketingcloud/InitializationStatus;)V

    .line 12
    :cond_2
    monitor-exit v1

    return-void

    .line 13
    :cond_3
    const-string v2, "Starting initialization"

    const/4 v3, 0x0

    new-array v4, v3, [Ljava/lang/Object;

    invoke-static {v0, v2, v4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    sput-boolean v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    const/4 v0, 0x1

    .line 15
    sput-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z

    .line 16
    sput-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->C:Z

    .line 17
    invoke-virtual {p0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v0

    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->z:Landroid/content/Context;

    .line 18
    new-instance v0, Ljava/lang/Thread;

    new-instance v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;

    invoke-direct {v2, p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$a;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V

    invoke-direct {v0, v2}, Ljava/lang/Thread;-><init>(Ljava/lang/Runnable;)V

    .line 19
    invoke-virtual {v0}, Ljava/lang/Thread;->start()V

    .line 20
    monitor-exit v1

    return-void

    .line 21
    :goto_2
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method private b(Z)V
    .locals 6

    .line 22
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    const/4 v1, 0x1

    sub-int/2addr v0, v1

    :goto_0
    const/4 v2, 0x0

    if-ltz v0, :cond_0

    .line 23
    :try_start_0
    iget-object v3, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v3, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/d;

    invoke-interface {v3, p1}, Lcom/salesforce/marketingcloud/d;->tearDown(Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v3

    .line 24
    sget-object v4, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    new-array v2, v2, [Ljava/lang/Object;

    const-string v5, "Error encountered tearing down component."

    invoke-static {v4, v3, v5, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_1
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    .line 25
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {p1}, Ljava/util/List;->clear()V

    .line 26
    iget-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->r:Lcom/salesforce/marketingcloud/internal/n;

    if-eqz p1, :cond_1

    .line 27
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->c()V

    .line 28
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    if-eqz p1, :cond_2

    .line 29
    :try_start_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->s()V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    goto :goto_2

    :catch_1
    move-exception p1

    .line 30
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    new-array v3, v2, [Ljava/lang/Object;

    const-string v4, "Error encountered tearing down storage."

    invoke-static {v0, p1, v4, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_2
    const/4 p1, 0x0

    .line 31
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    .line 32
    :cond_2
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    monitor-enter p0

    .line 33
    :try_start_2
    invoke-interface {p0}, Ljava/util/List;->clear()V

    .line 34
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 35
    sput-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    .line 36
    sput-boolean v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->C:Z

    return-void

    :catchall_0
    move-exception p1

    .line 37
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p1
.end method

.method public static c()V
    .locals 2

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a(Z)V

    .line 7
    .line 8
    .line 9
    :cond_0
    const/4 v0, 0x0

    .line 10
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 11
    .line 12
    return-void
.end method

.method public static getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;
    .locals 5
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    sget-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    sget-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v1, "MarketingCloudSdk#init must be called before calling MarketingCloudSdk#getInstance."

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw v0

    .line 18
    :cond_1
    :goto_0
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->w:Ljava/lang/Object;

    .line 19
    .line 20
    monitor-enter v0

    .line 21
    :try_start_0
    sget-boolean v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    .line 22
    .line 23
    if-eqz v1, :cond_2

    .line 24
    .line 25
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 26
    .line 27
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    return-object v1

    .line 29
    :catchall_0
    move-exception v1

    .line 30
    goto :goto_3

    .line 31
    :cond_2
    const/4 v1, 0x0

    .line 32
    :goto_1
    :try_start_1
    sget-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    .line 33
    .line 34
    if-nez v2, :cond_3

    .line 35
    .line 36
    sget-boolean v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 37
    .line 38
    if-eqz v2, :cond_3

    .line 39
    .line 40
    :try_start_2
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->w:Ljava/lang/Object;

    .line 41
    .line 42
    const-wide/16 v3, 0x0

    .line 43
    .line 44
    invoke-virtual {v2, v3, v4}, Ljava/lang/Object;->wait(J)V
    :try_end_2
    .catch Ljava/lang/InterruptedException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 45
    .line 46
    .line 47
    goto :goto_1

    .line 48
    :catchall_1
    move-exception v2

    .line 49
    goto :goto_2

    .line 50
    :catch_0
    const/4 v1, 0x1

    .line 51
    goto :goto_1

    .line 52
    :cond_3
    :try_start_3
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 53
    .line 54
    if-eqz v1, :cond_4

    .line 55
    .line 56
    :try_start_4
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 57
    .line 58
    .line 59
    move-result-object v1

    .line 60
    invoke-virtual {v1}, Ljava/lang/Thread;->interrupt()V

    .line 61
    .line 62
    .line 63
    :cond_4
    monitor-exit v0

    .line 64
    return-object v2

    .line 65
    :goto_2
    if-eqz v1, :cond_5

    .line 66
    .line 67
    invoke-static {}, Ljava/lang/Thread;->currentThread()Ljava/lang/Thread;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    invoke-virtual {v1}, Ljava/lang/Thread;->interrupt()V

    .line 72
    .line 73
    .line 74
    :cond_5
    throw v2

    .line 75
    :goto_3
    monitor-exit v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 76
    throw v1
.end method

.method public static getLogLevel()I
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .annotation runtime Lcom/salesforce/marketingcloud/MCLogListener$LogLevel;
    .end annotation

    .line 1
    invoke-static {}, Lcom/salesforce/marketingcloud/internal/f;->a()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    return v0
.end method

.method public static getSdkVersionCode()I
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    const v0, 0xf428e20

    .line 2
    .line 3
    .line 4
    return v0
.end method

.method public static getSdkVersionName()Ljava/lang/String;
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    const-string v0, "9.0.3"

    .line 2
    .line 3
    return-object v0
.end method

.method public static init(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-static {p0, p1, v0, p2}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public static isInitializing()Z
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    sget-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->A:Z

    .line 2
    .line 3
    return v0
.end method

.method public static isReady()Z
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    sget-boolean v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->B:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->y:Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    return v0

    .line 11
    :cond_0
    const/4 v0, 0x0

    .line 12
    return v0
.end method

.method public static requestSdk(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 2
    new-instance v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk$b;

    invoke-direct {v0, p0, p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$b;-><init>(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    monitor-enter p0

    .line 4
    :try_start_0
    sget-boolean p1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->C:Z

    if-eqz p1, :cond_0

    .line 5
    invoke-interface {p0, v0}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    .line 6
    :cond_0
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->a()V

    .line 7
    :goto_0
    monitor-exit p0

    return-void

    .line 8
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p1
.end method

.method public static requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    .locals 1
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    const/4 v0, 0x0

    .line 1
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Landroid/os/Looper;Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    return-void
.end method

.method public static setLogLevel(I)V
    .locals 0
    .param p0    # I
        .annotation runtime Lcom/salesforce/marketingcloud/MCLogListener$LogLevel;
        .end annotation
    .end param
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/f;->a(I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static setLogListener(Lcom/salesforce/marketingcloud/MCLogListener;)V
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/f;->a(Lcom/salesforce/marketingcloud/MCLogListener;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static unregisterWhenReadyListener(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V
    .locals 3
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    if-nez p0, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->x:Ljava/util/List;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    :cond_1
    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    if-eqz v2, :cond_2

    .line 16
    .line 17
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;

    .line 22
    .line 23
    iget-object v2, v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk$c;->b:Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;

    .line 24
    .line 25
    if-ne p0, v2, :cond_1

    .line 26
    .line 27
    invoke-interface {v1}, Ljava/util/Iterator;->remove()V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    goto :goto_1

    .line 33
    :cond_2
    monitor-exit v0

    .line 34
    return-void

    .line 35
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 36
    throw p0
.end method


# virtual methods
.method public a()Lcom/salesforce/marketingcloud/http/e;
    .locals 0

    .line 109
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->h:Lcom/salesforce/marketingcloud/http/e;

    return-object p0
.end method

.method public a(I)V
    .locals 5

    .line 110
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    add-int/lit8 v0, v0, -0x1

    :goto_0
    if-ltz v0, :cond_1

    .line 111
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    invoke-interface {v1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/d;

    .line 112
    instance-of v2, v1, Lcom/salesforce/marketingcloud/e;

    if-eqz v2, :cond_0

    .line 113
    check-cast v1, Lcom/salesforce/marketingcloud/e;

    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/e;->controlChannelInit(I)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_1

    :catch_0
    move-exception v1

    .line 114
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    const/4 v3, 0x0

    new-array v3, v3, [Ljava/lang/Object;

    const-string v4, "Error encountered during control channel init."

    invoke-static {v2, v1, v4, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    :goto_1
    add-int/lit8 v0, v0, -0x1

    goto :goto_0

    :cond_1
    return-void
.end method

.method public b()Lcom/salesforce/marketingcloud/storage/h;
    .locals 0

    .line 38
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->g:Lcom/salesforce/marketingcloud/storage/h;

    return-object p0
.end method

.method public getAnalyticsManager()Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->o:Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;

    .line 2
    .line 3
    return-object p0
.end method

.method public getEventManager()Lcom/salesforce/marketingcloud/events/EventManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->n:Lcom/salesforce/marketingcloud/events/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInAppMessageManager()Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->q:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageComponent;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInboxMessageManager()Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->i:Lcom/salesforce/marketingcloud/messages/inbox/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public getInitializationStatus()Lcom/salesforce/marketingcloud/InitializationStatus;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->p:Lcom/salesforce/marketingcloud/InitializationStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public getMarketingCloudConfig()Lcom/salesforce/marketingcloud/MarketingCloudConfig;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 2
    .line 3
    return-object p0
.end method

.method public getModuleIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getRegistrationManager()Lcom/salesforce/marketingcloud/registration/RegistrationManager;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-static {v0, p0}, Lcom/salesforce/marketingcloud/i;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/registration/RegistrationManager;)Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/ModuleIdentity;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public getNotificationManager()Lcom/salesforce/marketingcloud/notifications/NotificationManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->k:Lcom/salesforce/marketingcloud/notifications/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public getPushMessageManager()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->l:Lcom/salesforce/marketingcloud/messages/push/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRegionMessageManager()Lcom/salesforce/marketingcloud/messages/RegionMessageManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->m:Lcom/salesforce/marketingcloud/messages/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public getRegistrationManager()Lcom/salesforce/marketingcloud/registration/RegistrationManager;
    .locals 0
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->j:Lcom/salesforce/marketingcloud/registration/d;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSdkState()Lorg/json/JSONObject;
    .locals 5
    .annotation build Lcom/salesforce/marketingcloud/MCKeep;
    .end annotation

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "initConfig"

    .line 7
    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->a:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 9
    .line 10
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->toString()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 15
    .line 16
    .line 17
    const-string v1, "initStatus"

    .line 18
    .line 19
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->p:Lcom/salesforce/marketingcloud/InitializationStatus;

    .line 20
    .line 21
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/InitializationStatus;->toString()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 26
    .line 27
    .line 28
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b:Ljava/util/List;

    .line 29
    .line 30
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    :cond_0
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    check-cast v1, Lcom/salesforce/marketingcloud/d;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    .line 45
    .line 46
    if-eqz v1, :cond_0

    .line 47
    .line 48
    :try_start_1
    invoke-interface {v1}, Lcom/salesforce/marketingcloud/d;->componentName()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-interface {v1}, Lcom/salesforce/marketingcloud/d;->componentState()Lorg/json/JSONObject;

    .line 53
    .line 54
    .line 55
    move-result-object v3

    .line 56
    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 57
    .line 58
    .line 59
    goto :goto_0

    .line 60
    :catch_0
    move-exception v2

    .line 61
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 62
    .line 63
    const-string v4, "Failed to create component state for %s"

    .line 64
    .line 65
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v1

    .line 69
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 70
    .line 71
    .line 72
    goto :goto_0

    .line 73
    :catch_1
    move-exception p0

    .line 74
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 75
    .line 76
    const/4 v2, 0x0

    .line 77
    new-array v2, v2, [Ljava/lang/Object;

    .line 78
    .line 79
    const-string v3, "Unable to create Sdk state json"

    .line 80
    .line 81
    invoke-static {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    :cond_1
    return-object v0
.end method

.method public getState()Lorg/json/JSONObject;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkState()Lorg/json/JSONObject;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

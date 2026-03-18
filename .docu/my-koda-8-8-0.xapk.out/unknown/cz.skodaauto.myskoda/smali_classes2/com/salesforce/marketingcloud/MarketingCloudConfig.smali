.class public final Lcom/salesforce/marketingcloud/MarketingCloudConfig;
.super Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/salesforce/marketingcloud/MCKeep;
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;,
        Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;
    }
.end annotation


# static fields
.field public static final Companion:Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;

.field private static final TAG:Ljava/lang/String;


# instance fields
.field public final accessToken:Ljava/lang/String;

.field public final analyticsEnabled:Z

.field private final appPackageName:Ljava/lang/String;

.field private final appVersionName:Ljava/lang/String;

.field public final applicationId:Ljava/lang/String;

.field public final delayRegistrationUntilContactKeyIsSet:Z

.field public final geofencingEnabled:Z

.field public final inboxEnabled:Z

.field private final legacyEncryptionDependencyForciblyRemoved:Z

.field public final markMessageReadOnInboxNotificationOpen:Z

.field public final marketingCloudServerUrl:Ljava/lang/String;

.field public final mid:Ljava/lang/String;

.field public final notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

.field public final piAnalyticsEnabled:Z

.field private final predictiveIntelligenceServerUrl:Ljava/lang/String;

.field public final proximityEnabled:Z

.field public final proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

.field public final senderId:Ljava/lang/String;

.field public final urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

.field public final useLegacyPiIdentifier:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->Companion:Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;

    .line 8
    .line 9
    const-string v0, "MarketingCloudConfig"

    .line 10
    .line 11
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->TAG:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZLcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;Lcom/salesforce/marketingcloud/UrlHandler;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V
    .locals 5

    .line 1
    move-object/from16 v0, p14

    .line 2
    .line 3
    move-object/from16 v1, p17

    .line 4
    .line 5
    move-object/from16 v2, p18

    .line 6
    .line 7
    move-object/from16 v3, p19

    .line 8
    .line 9
    const-string v4, "applicationId"

    .line 10
    .line 11
    invoke-static {p1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    const-string v4, "accessToken"

    .line 15
    .line 16
    invoke-static {p2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    const-string v4, "marketingCloudServerUrl"

    .line 20
    .line 21
    invoke-static {p4, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    const-string v4, "notificationCustomizationOptions"

    .line 25
    .line 26
    invoke-static {v0, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v4, "appPackageName"

    .line 30
    .line 31
    invoke-static {v1, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const-string v4, "appVersionName"

    .line 35
    .line 36
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    const-string v4, "predictiveIntelligenceServerUrl"

    .line 40
    .line 41
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-direct/range {p0 .. p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/push/PushModuleConfig;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 48
    .line 49
    iput-object p2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 50
    .line 51
    iput-object p3, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 52
    .line 53
    iput-object p4, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 54
    .line 55
    iput-object p5, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 56
    .line 57
    iput-boolean p6, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 58
    .line 59
    iput-boolean p7, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 60
    .line 61
    iput-boolean p8, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 62
    .line 63
    iput-boolean p9, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 64
    .line 65
    iput-boolean p10, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 66
    .line 67
    move/from16 p1, p11

    .line 68
    .line 69
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 70
    .line 71
    move/from16 p1, p12

    .line 72
    .line 73
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 74
    .line 75
    move/from16 p1, p13

    .line 76
    .line 77
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 78
    .line 79
    iput-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 80
    .line 81
    move-object/from16 p1, p15

    .line 82
    .line 83
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 84
    .line 85
    move-object/from16 p1, p16

    .line 86
    .line 87
    iput-object p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 88
    .line 89
    iput-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 90
    .line 91
    iput-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 92
    .line 93
    iput-object v3, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 94
    .line 95
    move/from16 p1, p20

    .line 96
    .line 97
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 98
    .line 99
    return-void
.end method

.method public static synthetic a(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/InitializationStatus;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->init$lambda$1(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/InitializationStatus;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic b(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->init$lambda$1$lambda$0(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static final builder()Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->Companion:Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Companion;->builder()Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method public static synthetic copy$default(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZLcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;Lcom/salesforce/marketingcloud/UrlHandler;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZILjava/lang/Object;)Lcom/salesforce/marketingcloud/MarketingCloudConfig;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    move/from16 v1, p21

    and-int/lit8 v2, v1, 0x1

    if-eqz v2, :cond_0

    iget-object v2, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object/from16 v2, p1

    :goto_0
    and-int/lit8 v3, v1, 0x2

    if-eqz v3, :cond_1

    iget-object v3, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    goto :goto_1

    :cond_1
    move-object/from16 v3, p2

    :goto_1
    and-int/lit8 v4, v1, 0x4

    if-eqz v4, :cond_2

    iget-object v4, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    goto :goto_2

    :cond_2
    move-object/from16 v4, p3

    :goto_2
    and-int/lit8 v5, v1, 0x8

    if-eqz v5, :cond_3

    iget-object v5, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    goto :goto_3

    :cond_3
    move-object/from16 v5, p4

    :goto_3
    and-int/lit8 v6, v1, 0x10

    if-eqz v6, :cond_4

    iget-object v6, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    goto :goto_4

    :cond_4
    move-object/from16 v6, p5

    :goto_4
    and-int/lit8 v7, v1, 0x20

    if-eqz v7, :cond_5

    iget-boolean v7, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    goto :goto_5

    :cond_5
    move/from16 v7, p6

    :goto_5
    and-int/lit8 v8, v1, 0x40

    if-eqz v8, :cond_6

    iget-boolean v8, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    goto :goto_6

    :cond_6
    move/from16 v8, p7

    :goto_6
    and-int/lit16 v9, v1, 0x80

    if-eqz v9, :cond_7

    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    goto :goto_7

    :cond_7
    move/from16 v9, p8

    :goto_7
    and-int/lit16 v10, v1, 0x100

    if-eqz v10, :cond_8

    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    goto :goto_8

    :cond_8
    move/from16 v10, p9

    :goto_8
    and-int/lit16 v11, v1, 0x200

    if-eqz v11, :cond_9

    iget-boolean v11, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    goto :goto_9

    :cond_9
    move/from16 v11, p10

    :goto_9
    and-int/lit16 v12, v1, 0x400

    if-eqz v12, :cond_a

    iget-boolean v12, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    goto :goto_a

    :cond_a
    move/from16 v12, p11

    :goto_a
    and-int/lit16 v13, v1, 0x800

    if-eqz v13, :cond_b

    iget-boolean v13, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    goto :goto_b

    :cond_b
    move/from16 v13, p12

    :goto_b
    and-int/lit16 v14, v1, 0x1000

    if-eqz v14, :cond_c

    iget-boolean v14, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    goto :goto_c

    :cond_c
    move/from16 v14, p13

    :goto_c
    and-int/lit16 v15, v1, 0x2000

    if-eqz v15, :cond_d

    iget-object v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    goto :goto_d

    :cond_d
    move-object/from16 v15, p14

    :goto_d
    move-object/from16 p1, v2

    and-int/lit16 v2, v1, 0x4000

    if-eqz v2, :cond_e

    iget-object v2, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    goto :goto_e

    :cond_e
    move-object/from16 v2, p15

    :goto_e
    const v16, 0x8000

    and-int v16, v1, v16

    if-eqz v16, :cond_f

    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    goto :goto_f

    :cond_f
    move-object/from16 v1, p16

    :goto_f
    const/high16 v16, 0x10000

    and-int v16, p21, v16

    move-object/from16 p2, v1

    if-eqz v16, :cond_10

    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    goto :goto_10

    :cond_10
    move-object/from16 v1, p17

    :goto_10
    const/high16 v16, 0x20000

    and-int v16, p21, v16

    move-object/from16 p3, v1

    if-eqz v16, :cond_11

    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    goto :goto_11

    :cond_11
    move-object/from16 v1, p18

    :goto_11
    const/high16 v16, 0x40000

    and-int v16, p21, v16

    move-object/from16 p4, v1

    if-eqz v16, :cond_12

    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    goto :goto_12

    :cond_12
    move-object/from16 v1, p19

    :goto_12
    const/high16 v16, 0x80000

    and-int v16, p21, v16

    if-eqz v16, :cond_13

    move-object/from16 p5, v1

    iget-boolean v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    move-object/from16 p20, p5

    move/from16 p21, v1

    :goto_13
    move-object/from16 p17, p2

    move-object/from16 p18, p3

    move-object/from16 p19, p4

    move-object/from16 p16, v2

    move-object/from16 p3, v3

    move-object/from16 p4, v4

    move-object/from16 p5, v5

    move-object/from16 p6, v6

    move/from16 p7, v7

    move/from16 p8, v8

    move/from16 p9, v9

    move/from16 p10, v10

    move/from16 p11, v11

    move/from16 p12, v12

    move/from16 p13, v13

    move/from16 p14, v14

    move-object/from16 p15, v15

    move-object/from16 p2, p1

    move-object/from16 p1, v0

    goto :goto_14

    :cond_13
    move/from16 p21, p20

    move-object/from16 p20, v1

    goto :goto_13

    :goto_14
    invoke-virtual/range {p1 .. p21}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZLcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;Lcom/salesforce/marketingcloud/UrlHandler;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    move-result-object v0

    return-object v0
.end method

.method private static final init$lambda$1(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/InitializationStatus;)V
    .locals 7

    .line 1
    const-string v0, "$listener"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "it"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v1, Lcom/salesforce/marketingcloud/g;->a:Lcom/salesforce/marketingcloud/g;

    .line 12
    .line 13
    sget-object v2, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->TAG:Ljava/lang/String;

    .line 14
    .line 15
    new-instance v4, Lcom/salesforce/marketingcloud/MarketingCloudConfig$a;

    .line 16
    .line 17
    invoke-direct {v4, p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$a;-><init>(Lcom/salesforce/marketingcloud/InitializationStatus;)V

    .line 18
    .line 19
    .line 20
    const/4 v5, 0x2

    .line 21
    const/4 v6, 0x0

    .line 22
    const/4 v3, 0x0

    .line 23
    invoke-static/range {v1 .. v6}, Lcom/salesforce/marketingcloud/g;->e(Lcom/salesforce/marketingcloud/g;Ljava/lang/String;Ljava/lang/Throwable;Lay0/a;ILjava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    new-instance p1, Lcom/salesforce/marketingcloud/l;

    .line 27
    .line 28
    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/l;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 29
    .line 30
    .line 31
    invoke-static {p1}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method

.method private static final init$lambda$1$lambda$0(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 1

    .line 1
    const-string v0, "$listener"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "sdk"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;->ready(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleInterface;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final accessToken()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final analyticsEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final appPackageName()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final appVersionName()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final applicationChanged$sdk_release(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Z
    .locals 2

    .line 1
    const-string v0, "other"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v1, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 17
    .line 18
    iget-object p1, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    if-nez p0, :cond_0

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    const/4 p0, 0x0

    .line 28
    return p0

    .line 29
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 30
    return p0
.end method

.method public final applicationId()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component1()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component10()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component11()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component12()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component13()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component14()Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component15()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component16()Lcom/salesforce/marketingcloud/UrlHandler;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component17$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component18$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component19$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component20$sdk_release()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component4()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component5()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component6()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component7()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component8()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component9()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZLcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;Lcom/salesforce/marketingcloud/UrlHandler;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/MarketingCloudConfig;
    .locals 22

    .line 1
    const-string v0, "applicationId"

    .line 2
    .line 3
    move-object/from16 v2, p1

    .line 4
    .line 5
    invoke-static {v2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const-string v0, "accessToken"

    .line 9
    .line 10
    move-object/from16 v3, p2

    .line 11
    .line 12
    invoke-static {v3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    const-string v0, "marketingCloudServerUrl"

    .line 16
    .line 17
    move-object/from16 v5, p4

    .line 18
    .line 19
    invoke-static {v5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    const-string v0, "notificationCustomizationOptions"

    .line 23
    .line 24
    move-object/from16 v15, p14

    .line 25
    .line 26
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-string v0, "appPackageName"

    .line 30
    .line 31
    move-object/from16 v1, p17

    .line 32
    .line 33
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string v0, "appVersionName"

    .line 37
    .line 38
    move-object/from16 v4, p18

    .line 39
    .line 40
    invoke-static {v4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    const-string v0, "predictiveIntelligenceServerUrl"

    .line 44
    .line 45
    move-object/from16 v6, p19

    .line 46
    .line 47
    invoke-static {v6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    new-instance v1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 51
    .line 52
    move/from16 v7, p6

    .line 53
    .line 54
    move/from16 v8, p7

    .line 55
    .line 56
    move/from16 v9, p8

    .line 57
    .line 58
    move/from16 v10, p9

    .line 59
    .line 60
    move/from16 v11, p10

    .line 61
    .line 62
    move/from16 v12, p11

    .line 63
    .line 64
    move/from16 v13, p12

    .line 65
    .line 66
    move/from16 v14, p13

    .line 67
    .line 68
    move-object/from16 v16, p15

    .line 69
    .line 70
    move-object/from16 v17, p16

    .line 71
    .line 72
    move-object/from16 v18, p17

    .line 73
    .line 74
    move/from16 v21, p20

    .line 75
    .line 76
    move-object/from16 v19, v4

    .line 77
    .line 78
    move-object/from16 v20, v6

    .line 79
    .line 80
    move-object/from16 v4, p3

    .line 81
    .line 82
    move-object/from16 v6, p5

    .line 83
    .line 84
    invoke-direct/range {v1 .. v21}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZZZLcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;Lcom/salesforce/marketingcloud/UrlHandler;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Z)V

    .line 85
    .line 86
    .line 87
    return-object v1
.end method

.method public final delayRegistrationUntilContactKeyIsSet()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 2
    .line 3
    return p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 69
    .line 70
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 71
    .line 72
    if-eq v1, v3, :cond_7

    .line 73
    .line 74
    return v2

    .line 75
    :cond_7
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 76
    .line 77
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 78
    .line 79
    if-eq v1, v3, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 83
    .line 84
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 85
    .line 86
    if-eq v1, v3, :cond_9

    .line 87
    .line 88
    return v2

    .line 89
    :cond_9
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 90
    .line 91
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 92
    .line 93
    if-eq v1, v3, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 97
    .line 98
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 99
    .line 100
    if-eq v1, v3, :cond_b

    .line 101
    .line 102
    return v2

    .line 103
    :cond_b
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 104
    .line 105
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 106
    .line 107
    if-eq v1, v3, :cond_c

    .line 108
    .line 109
    return v2

    .line 110
    :cond_c
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 111
    .line 112
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 113
    .line 114
    if-eq v1, v3, :cond_d

    .line 115
    .line 116
    return v2

    .line 117
    :cond_d
    iget-boolean v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 118
    .line 119
    iget-boolean v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 120
    .line 121
    if-eq v1, v3, :cond_e

    .line 122
    .line 123
    return v2

    .line 124
    :cond_e
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 125
    .line 126
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 127
    .line 128
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    if-nez v1, :cond_f

    .line 133
    .line 134
    return v2

    .line 135
    :cond_f
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 136
    .line 137
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 138
    .line 139
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    if-nez v1, :cond_10

    .line 144
    .line 145
    return v2

    .line 146
    :cond_10
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 147
    .line 148
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 149
    .line 150
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    if-nez v1, :cond_11

    .line 155
    .line 156
    return v2

    .line 157
    :cond_11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 158
    .line 159
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 160
    .line 161
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 162
    .line 163
    .line 164
    move-result v1

    .line 165
    if-nez v1, :cond_12

    .line 166
    .line 167
    return v2

    .line 168
    :cond_12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 169
    .line 170
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 171
    .line 172
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 173
    .line 174
    .line 175
    move-result v1

    .line 176
    if-nez v1, :cond_13

    .line 177
    .line 178
    return v2

    .line 179
    :cond_13
    iget-object v1, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 180
    .line 181
    iget-object v3, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 182
    .line 183
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 184
    .line 185
    .line 186
    move-result v1

    .line 187
    if-nez v1, :cond_14

    .line 188
    .line 189
    return v2

    .line 190
    :cond_14
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 191
    .line 192
    iget-boolean p1, p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 193
    .line 194
    if-eq p0, p1, :cond_15

    .line 195
    .line 196
    return v2

    .line 197
    :cond_15
    return v0
.end method

.method public final geofencingEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getAppPackageName$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getAppVersionName$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getLegacyEncryptionDependencyForciblyRemoved$sdk_release()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getPredictiveIntelligenceServerUrl$sdk_release()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v3, 0x0

    .line 19
    if-nez v2, :cond_0

    .line 20
    .line 21
    move v2, v3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    :goto_0
    add-int/2addr v0, v2

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 30
    .line 31
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 36
    .line 37
    if-nez v2, :cond_1

    .line 38
    .line 39
    move v2, v3

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    :goto_1
    add-int/2addr v0, v2

    .line 46
    mul-int/2addr v0, v1

    .line 47
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 48
    .line 49
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 50
    .line 51
    .line 52
    move-result v0

    .line 53
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 54
    .line 55
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 60
    .line 61
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 62
    .line 63
    .line 64
    move-result v0

    .line 65
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 66
    .line 67
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 72
    .line 73
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 74
    .line 75
    .line 76
    move-result v0

    .line 77
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 78
    .line 79
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 84
    .line 85
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 86
    .line 87
    .line 88
    move-result v0

    .line 89
    iget-boolean v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 90
    .line 91
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 92
    .line 93
    .line 94
    move-result v0

    .line 95
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 96
    .line 97
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    add-int/2addr v2, v0

    .line 102
    mul-int/2addr v2, v1

    .line 103
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 104
    .line 105
    if-nez v0, :cond_2

    .line 106
    .line 107
    move v0, v3

    .line 108
    goto :goto_2

    .line 109
    :cond_2
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 110
    .line 111
    .line 112
    move-result v0

    .line 113
    :goto_2
    add-int/2addr v2, v0

    .line 114
    mul-int/2addr v2, v1

    .line 115
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 116
    .line 117
    if-nez v0, :cond_3

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v3

    .line 124
    :goto_3
    add-int/2addr v2, v3

    .line 125
    mul-int/2addr v2, v1

    .line 126
    iget-object v0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 127
    .line 128
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 129
    .line 130
    .line 131
    move-result v0

    .line 132
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 133
    .line 134
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 135
    .line 136
    .line 137
    move-result v0

    .line 138
    iget-object v2, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 139
    .line 140
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 141
    .line 142
    .line 143
    move-result v0

    .line 144
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 145
    .line 146
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    add-int/2addr p0, v0

    .line 151
    return p0
.end method

.method public final inboxEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public init(Landroid/content/Context;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "components"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "listener"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Lcom/salesforce/marketingcloud/l;

    .line 17
    .line 18
    invoke-direct {v0, p3}, Lcom/salesforce/marketingcloud/l;-><init>(Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleReadyListener;)V

    .line 19
    .line 20
    .line 21
    invoke-static {p1, p0, p2, v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->b(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;Lcom/salesforce/marketingcloud/MarketingCloudSdk$InitializationListener;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

.method public final legacyEncryptionDependencyForciblyRemoved()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 2
    .line 3
    return p0
.end method

.method public final markMessageReadOnInboxNotificationOpen()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 2
    .line 3
    return p0
.end method

.method public final marketingCloudServerUrl()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final mid()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final notificationCustomizationOptions()Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public final piAnalyticsEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final predictiveIntelligenceServerUrl()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final proximityEnabled()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final proximityNotificationCustomizationOptions()Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 2
    .line 3
    return-object p0
.end method

.method public final senderId()Ljava/lang/String;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final toBuilder()Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;
    .locals 1

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig$Builder;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.method public toString()Ljava/lang/String;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId:Ljava/lang/String;

    .line 4
    .line 5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->accessToken:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v3, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->senderId:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->marketingCloudServerUrl:Ljava/lang/String;

    .line 10
    .line 11
    iget-object v5, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->mid:Ljava/lang/String;

    .line 12
    .line 13
    iget-boolean v6, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled:Z

    .line 14
    .line 15
    iget-boolean v7, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->geofencingEnabled:Z

    .line 16
    .line 17
    iget-boolean v8, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled:Z

    .line 18
    .line 19
    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled:Z

    .line 20
    .line 21
    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityEnabled:Z

    .line 22
    .line 23
    iget-boolean v11, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->markMessageReadOnInboxNotificationOpen:Z

    .line 24
    .line 25
    iget-boolean v12, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet:Z

    .line 26
    .line 27
    iget-boolean v13, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 28
    .line 29
    iget-object v14, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->notificationCustomizationOptions:Lcom/salesforce/marketingcloud/notifications/NotificationCustomizationOptions;

    .line 30
    .line 31
    iget-object v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->proximityNotificationCustomizationOptions:Lcom/salesforce/marketingcloud/proximity/ProximityNotificationCustomizationOptions;

    .line 32
    .line 33
    move-object/from16 v16, v15

    .line 34
    .line 35
    iget-object v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 36
    .line 37
    move-object/from16 v17, v15

    .line 38
    .line 39
    iget-object v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appPackageName:Ljava/lang/String;

    .line 40
    .line 41
    move-object/from16 v18, v15

    .line 42
    .line 43
    iget-object v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->appVersionName:Ljava/lang/String;

    .line 44
    .line 45
    move-object/from16 v19, v15

    .line 46
    .line 47
    iget-object v15, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl:Ljava/lang/String;

    .line 48
    .line 49
    iget-boolean v0, v0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->legacyEncryptionDependencyForciblyRemoved:Z

    .line 50
    .line 51
    move/from16 p0, v0

    .line 52
    .line 53
    const-string v0, ", accessToken="

    .line 54
    .line 55
    move-object/from16 v20, v15

    .line 56
    .line 57
    const-string v15, ", senderId="

    .line 58
    .line 59
    move-object/from16 v21, v14

    .line 60
    .line 61
    const-string v14, "MarketingCloudConfig(applicationId="

    .line 62
    .line 63
    invoke-static {v14, v1, v0, v2, v15}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    move-result-object v0

    .line 67
    const-string v1, ", marketingCloudServerUrl="

    .line 68
    .line 69
    const-string v2, ", mid="

    .line 70
    .line 71
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    const-string v1, ", analyticsEnabled="

    .line 75
    .line 76
    const-string v2, ", geofencingEnabled="

    .line 77
    .line 78
    invoke-static {v5, v1, v2, v0, v6}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 79
    .line 80
    .line 81
    const-string v1, ", inboxEnabled="

    .line 82
    .line 83
    const-string v2, ", piAnalyticsEnabled="

    .line 84
    .line 85
    invoke-static {v0, v7, v1, v8, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 86
    .line 87
    .line 88
    const-string v1, ", proximityEnabled="

    .line 89
    .line 90
    const-string v2, ", markMessageReadOnInboxNotificationOpen="

    .line 91
    .line 92
    invoke-static {v0, v9, v1, v10, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 93
    .line 94
    .line 95
    const-string v1, ", delayRegistrationUntilContactKeyIsSet="

    .line 96
    .line 97
    const-string v2, ", useLegacyPiIdentifier="

    .line 98
    .line 99
    invoke-static {v0, v11, v1, v12, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v13}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    const-string v1, ", notificationCustomizationOptions="

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    move-object/from16 v1, v21

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v1, ", proximityNotificationCustomizationOptions="

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    move-object/from16 v1, v16

    .line 121
    .line 122
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    const-string v1, ", urlHandler="

    .line 126
    .line 127
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    move-object/from16 v1, v17

    .line 131
    .line 132
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    const-string v1, ", appPackageName="

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v1, ", appVersionName="

    .line 141
    .line 142
    const-string v2, ", predictiveIntelligenceServerUrl="

    .line 143
    .line 144
    move-object/from16 v3, v18

    .line 145
    .line 146
    move-object/from16 v4, v19

    .line 147
    .line 148
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    const-string v1, ", legacyEncryptionDependencyForciblyRemoved="

    .line 152
    .line 153
    const-string v2, ")"

    .line 154
    .line 155
    move/from16 v4, p0

    .line 156
    .line 157
    move-object/from16 v3, v20

    .line 158
    .line 159
    invoke-static {v3, v1, v2, v0, v4}, Lc1/j0;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)Ljava/lang/String;

    .line 160
    .line 161
    .line 162
    move-result-object v0

    .line 163
    return-object v0
.end method

.method public final urlHandler()Lcom/salesforce/marketingcloud/UrlHandler;
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->urlHandler:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 2
    .line 3
    return-object p0
.end method

.method public final useLegacyPiIdentifier()Z
    .locals 0
    .annotation runtime Llx0/c;
    .end annotation

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier:Z

    .line 2
    .line 3
    return p0
.end method

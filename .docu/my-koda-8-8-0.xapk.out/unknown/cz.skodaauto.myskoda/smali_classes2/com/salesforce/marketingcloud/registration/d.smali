.class public Lcom/salesforce/marketingcloud/registration/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/registration/RegistrationManager;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;
.implements Lcom/salesforce/marketingcloud/http/e$c;
.implements Lcom/salesforce/marketingcloud/registration/e$f;
.implements Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/registration/d$c;
    }
.end annotation


# static fields
.field private static final o:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/behaviors/a;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final d:Landroid/content/Context;

.field private final e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field private final f:Lcom/salesforce/marketingcloud/storage/h;

.field private final g:Lcom/salesforce/marketingcloud/behaviors/c;

.field private final h:Lcom/salesforce/marketingcloud/alarms/b;

.field private final i:Lcom/salesforce/marketingcloud/http/e;

.field private final j:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

.field private final k:Lcom/salesforce/marketingcloud/internal/n;

.field private final l:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field private final m:Lcom/salesforce/marketingcloud/registration/f;

.field private n:Lcom/salesforce/marketingcloud/registration/e;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->g:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 4
    .line 5
    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 6
    .line 7
    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/a;->m:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 8
    .line 9
    sget-object v4, Lcom/salesforce/marketingcloud/behaviors/a;->n:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 10
    .line 11
    sget-object v5, Lcom/salesforce/marketingcloud/behaviors/a;->o:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 12
    .line 13
    sget-object v6, Lcom/salesforce/marketingcloud/behaviors/a;->q:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 14
    .line 15
    sget-object v7, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 16
    .line 17
    filled-new-array/range {v1 .. v7}, [Lcom/salesforce/marketingcloud/behaviors/a;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    invoke-static {v0, v1}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;[Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Lcom/salesforce/marketingcloud/registration/d;->o:Ljava/util/EnumSet;

    .line 26
    .line 27
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 11

    const/4 v10, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object/from16 v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    move-object/from16 v9, p9

    .line 1
    invoke-direct/range {v0 .. v10}, Lcom/salesforce/marketingcloud/registration/d;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->d:Landroid/content/Context;

    .line 4
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/d;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 5
    iput-object p3, p0, Lcom/salesforce/marketingcloud/registration/d;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    iput-object p4, p0, Lcom/salesforce/marketingcloud/registration/d;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 7
    iput-object p5, p0, Lcom/salesforce/marketingcloud/registration/d;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 8
    iput-object p6, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 9
    iput-object p7, p0, Lcom/salesforce/marketingcloud/registration/d;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 10
    iput-object p8, p0, Lcom/salesforce/marketingcloud/registration/d;->j:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 11
    iput-object p9, p0, Lcom/salesforce/marketingcloud/registration/d;->k:Lcom/salesforce/marketingcloud/internal/n;

    .line 12
    iput-object p10, p0, Lcom/salesforce/marketingcloud/registration/d;->l:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/registration/e;Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 0

    .line 13
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 15
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/d;->d:Landroid/content/Context;

    .line 16
    iput-object p3, p0, Lcom/salesforce/marketingcloud/registration/d;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 17
    iput-object p4, p0, Lcom/salesforce/marketingcloud/registration/d;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 18
    iput-object p5, p0, Lcom/salesforce/marketingcloud/registration/d;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 19
    iput-object p6, p0, Lcom/salesforce/marketingcloud/registration/d;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 20
    iput-object p7, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 21
    iput-object p8, p0, Lcom/salesforce/marketingcloud/registration/d;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 22
    iput-object p9, p0, Lcom/salesforce/marketingcloud/registration/d;->j:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    .line 23
    iput-object p10, p0, Lcom/salesforce/marketingcloud/registration/d;->k:Lcom/salesforce/marketingcloud/internal/n;

    const/4 p1, 0x0

    .line 24
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->l:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/f;
    .locals 21

    .line 7
    new-instance v0, Lcom/salesforce/marketingcloud/registration/Registration;

    .line 8
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v2

    .line 9
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getSdkVersionName()Ljava/lang/String;

    move-result-object v6

    .line 10
    invoke-static/range {p1 .. p1}, Lcom/salesforce/marketingcloud/util/f;->a(Landroid/content/Context;)Ljava/lang/String;

    move-result-object v7

    .line 11
    invoke-static {}, Ljava/util/TimeZone;->getDefault()Ljava/util/TimeZone;

    move-result-object v1

    new-instance v3, Ljava/util/Date;

    invoke-direct {v3}, Ljava/util/Date;-><init>()V

    invoke-virtual {v1, v3}, Ljava/util/TimeZone;->inDaylightTime(Ljava/util/Date;)Z

    move-result v8

    sget-object v11, Landroid/os/Build$VERSION;->RELEASE:Ljava/lang/String;

    .line 12
    invoke-static {}, Lcom/salesforce/marketingcloud/util/j;->b()I

    move-result v13

    sget-object v1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    sget-object v1, Landroid/os/Build;->MANUFACTURER:Ljava/lang/String;

    sget-object v3, Landroid/os/Build;->MODEL:Ljava/lang/String;

    .line 13
    const-string v4, " "

    .line 14
    invoke-static {v1, v4, v3}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v16

    .line 15
    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v17

    .line 16
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Locale;->toString()Ljava/lang/String;

    move-result-object v18

    .line 17
    sget-object v19, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 18
    sget-object v20, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    const/4 v14, 0x0

    const-string v15, "Android"

    const/4 v1, 0x0

    const/4 v3, 0x0

    const/4 v5, 0x0

    const/4 v9, 0x0

    const/4 v10, 0x0

    const/4 v12, 0x0

    move-object/from16 v4, p2

    invoke-direct/range {v0 .. v20}, Lcom/salesforce/marketingcloud/registration/Registration;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V

    .line 19
    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    new-instance v2, Lcom/salesforce/marketingcloud/registration/d$a;

    invoke-direct {v2}, Lcom/salesforce/marketingcloud/registration/d$a;-><init>()V

    move-object/from16 v3, p3

    .line 20
    invoke-static {v0, v3}, Lcom/salesforce/marketingcloud/registration/d;->a(Lcom/salesforce/marketingcloud/registration/Registration;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    move-object/from16 v3, p0

    .line 21
    invoke-virtual {v1, v3, v2, v0}, Lcom/salesforce/marketingcloud/http/b;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/b;Ljava/lang/String;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object v0

    .line 22
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/http/c;->k()Lcom/salesforce/marketingcloud/http/f;

    move-result-object v0

    return-object v0
.end method

.method public static a(Lcom/salesforce/marketingcloud/registration/Registration;Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    const/4 v0, 0x0

    .line 1
    :try_start_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/internal/m;->c(Lcom/salesforce/marketingcloud/registration/Registration;)Lorg/json/JSONObject;

    move-result-object p0

    const-string v1, "registrationDateUtc"

    new-instance v2, Ljava/util/Date;

    invoke-direct {v2}, Ljava/util/Date;-><init>()V

    .line 2
    invoke-static {v2}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {p0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    move-result-object p0

    const-string v1, "quietPushEnabled"

    .line 3
    invoke-virtual {p0, v1, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    move-result-object p0

    const-string v1, "registrationId"

    .line 4
    invoke-virtual {p0, v1, p1}, Lorg/json/JSONObject;->putOpt(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    move-exception p0

    .line 6
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Unable to create registration request payload"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    const/4 p0, 0x0

    return-object p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;)Ljava/lang/String;
    .locals 2

    .line 29
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p0

    const-string v0, "et_subscriber_cache"

    const/4 v1, 0x0

    invoke-interface {p0, v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method

.method private a()V
    .locals 1

    .line 37
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->l:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    if-eqz v0, :cond_0

    .line 38
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEventManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;

    move-result-object v0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->unsubscribe(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V

    :cond_0
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 11

    .line 30
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    sget-object v1, Lcom/salesforce/marketingcloud/registration/d;->o:Ljava/util/EnumSet;

    invoke-virtual {v0, p0, v1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 31
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v1

    invoke-virtual {v0, p0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->i:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 33
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->l:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    if-eqz v0, :cond_0

    .line 34
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getEventManager()Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;

    move-result-object v0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventManager;->subscribe(Lcom/salesforce/marketingcloud/sfmcsdk/components/events/EventSubscriber;)V

    .line 35
    :cond_0
    :try_start_0
    new-instance v1, Lcom/salesforce/marketingcloud/registration/e;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/d;->d:Landroid/content/Context;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/d;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/d;->f:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/d;->m:Lcom/salesforce/marketingcloud/registration/f;

    iget-object v6, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    iget-object v7, p0, Lcom/salesforce/marketingcloud/registration/d;->i:Lcom/salesforce/marketingcloud/http/e;

    iget-object v8, p0, Lcom/salesforce/marketingcloud/registration/d;->j:Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    iget-object v9, p0, Lcom/salesforce/marketingcloud/registration/d;->k:Lcom/salesforce/marketingcloud/internal/n;

    iget-object v10, p0, Lcom/salesforce/marketingcloud/registration/d;->l:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    invoke-direct/range {v1 .. v10}, Lcom/salesforce/marketingcloud/registration/e;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V

    iput-object v1, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    if-eqz p1, :cond_1

    .line 36
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/InitializationStatus$a;->a(Ljava/lang/Throwable;)V

    :cond_1
    return-void
.end method


# virtual methods
.method public final a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 42
    sget-object v0, Lcom/salesforce/marketingcloud/registration/d$b;->b:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_0

    goto :goto_0

    .line 43
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    if-eqz p0, :cond_1

    .line 44
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->e()V

    :cond_1
    :goto_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 2

    .line 45
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    if-eqz v0, :cond_1

    .line 46
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result v0

    if-eqz v0, :cond_0

    .line 47
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    new-instance v1, Lorg/json/JSONObject;

    .line 48
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->p()Ljava/lang/String;

    move-result-object p1

    invoke-direct {v1, p1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/m;->a(Lorg/json/JSONObject;)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->m()Ljava/util/Map;

    move-result-object p2

    .line 49
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/Registration;Ljava/util/Map;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 50
    :catch_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    const/4 p1, -0x1

    const-string p2, "Failed to convert our Response Body into a Registration."

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/registration/e;->a(ILjava/lang/String;)V

    return-void

    .line 51
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/registration/e;->a(ILjava/lang/String;)V

    :cond_1
    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/util/Collection;Z)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;Z)V"
        }
    .end annotation

    .line 39
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    if-eqz p0, :cond_0

    .line 40
    :try_start_0
    invoke-virtual/range {p0 .. p5}, Lcom/salesforce/marketingcloud/registration/e;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/util/Collection;Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 41
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Error encountered while saving registration"

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "RegistrationManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public final componentState()Lorg/json/JSONObject;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->d()Lorg/json/JSONObject;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance p0, Lorg/json/JSONObject;

    .line 11
    .line 12
    invoke-direct {p0}, Lorg/json/JSONObject;-><init>()V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public controlChannelInit(I)V
    .locals 3

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 3
    .line 4
    .line 5
    move-result v1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iput-object v2, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 10
    .line 11
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/d;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 12
    .line 13
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 14
    .line 15
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    invoke-static {v1, v2, p1}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Z)V

    .line 20
    .line 21
    .line 22
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 25
    .line 26
    .line 27
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/registration/d;->a()V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 31
    .line 32
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 33
    .line 34
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 39
    .line 40
    .line 41
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 42
    .line 43
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    .line 44
    .line 45
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 46
    .line 47
    .line 48
    return-void

    .line 49
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 50
    .line 51
    if-nez p1, :cond_1

    .line 52
    .line 53
    invoke-direct {p0, v2}, Lcom/salesforce/marketingcloud/registration/d;->a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V

    .line 54
    .line 55
    .line 56
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 57
    .line 58
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->g()V

    .line 59
    .line 60
    .line 61
    :cond_1
    return-void
.end method

.method public edit()Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/e$f;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    new-instance p0, Lcom/salesforce/marketingcloud/registration/d$c;

    .line 11
    .line 12
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/registration/d$c;-><init>()V

    .line 13
    .line 14
    .line 15
    return-object p0
.end method

.method public getAttributes()Ljava/util/Map;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->getAttributes()Ljava/util/Map;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    sget-object p0, Ljava/util/Collections;->EMPTY_MAP:Ljava/util/Map;

    .line 11
    .line 12
    return-object p0
.end method

.method public getContactKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->getContactKey()Ljava/lang/String;

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

.method public getDeviceId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->getDeviceId()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    const-string p0, ""

    .line 11
    .line 12
    return-object p0
.end method

.method public getSignedString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->getSignedString()Ljava/lang/String;

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

.method public getSystemToken()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->getSystemToken()Ljava/lang/String;

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

.method public getTags()Ljava/util/Set;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->getTags()Ljava/util/Set;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0

    .line 10
    :cond_0
    sget-object p0, Ljava/util/Collections;->EMPTY_SET:Ljava/util/Set;

    .line 11
    .line 12
    return-object p0
.end method

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    .line 2
    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 3
    .line 4
    .line 5
    move-result p2

    .line 6
    if-eqz p2, :cond_0

    .line 7
    .line 8
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/d;->a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V

    .line 9
    .line 10
    .line 11
    :cond_0
    return-void
.end method

.method public final onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/registration/d$b;->a:[I

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    aget v0, v0, v1

    .line 12
    .line 13
    packed-switch v0, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object p0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 17
    .line 18
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    const-string p2, "Unhandled behavior: %s"

    .line 23
    .line 24
    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 29
    .line 30
    const-string p1, "com.salesforce.marketingcloud.push.TOKEN"

    .line 31
    .line 32
    const-string v0, ""

    .line 33
    .line 34
    invoke-virtual {p2, p1, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/registration/e;->a(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 43
    .line 44
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->a()V

    .line 45
    .line 46
    .line 47
    return-void

    .line 48
    :pswitch_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 49
    .line 50
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->b()V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :pswitch_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 55
    .line 56
    const-string p1, "com.salesforce.marketingcloud.notifications.PUSH_ENABLED"

    .line 57
    .line 58
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getBoolean(Ljava/lang/String;)Z

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/registration/e;->b(Z)V

    .line 63
    .line 64
    .line 65
    return-void

    .line 66
    :pswitch_4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 67
    .line 68
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->h()V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :pswitch_5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 73
    .line 74
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->c()V

    .line 75
    .line 76
    .line 77
    :cond_0
    return-void

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public varargs onEventPublished([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 10

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;->SFMC_SDK:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Producer;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sget-object v1, Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;->IDENTITY:Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event$Category;

    .line 8
    .line 9
    invoke-static {v1}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;)Ljava/util/EnumSet;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-static {p1, v0, v1}, Lcom/salesforce/marketingcloud/events/d;->a([Ljava/lang/Object;Ljava/util/EnumSet;Ljava/util/EnumSet;)[Lcom/salesforce/marketingcloud/events/Event;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    array-length v0, p1

    .line 18
    const/4 v1, 0x0

    .line 19
    move v2, v1

    .line 20
    :goto_0
    if-ge v2, v0, :cond_3

    .line 21
    .line 22
    aget-object v3, p1, v2

    .line 23
    .line 24
    :try_start_0
    invoke-interface {v3}, Lcom/salesforce/marketingcloud/events/Event;->attributes()Ljava/util/Map;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    const-string v4, "moduleIdentities"

    .line 29
    .line 30
    invoke-interface {v3, v4}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v3

    .line 34
    invoke-static {v3}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    check-cast v3, Lorg/json/JSONObject;

    .line 38
    .line 39
    sget-object v4, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    .line 40
    .line 41
    invoke-virtual {v4}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    invoke-virtual {v4}, Ljava/lang/String;->toLowerCase()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v4

    .line 49
    invoke-virtual {v3, v4}, Lorg/json/JSONObject;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v3

    .line 53
    check-cast v3, Lorg/json/JSONObject;

    .line 54
    .line 55
    const-string v4, "customProperties"

    .line 56
    .line 57
    invoke-virtual {v3, v4}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 58
    .line 59
    .line 60
    move-result-object v4

    .line 61
    const-string v5, "attributes"

    .line 62
    .line 63
    invoke-virtual {v4, v5}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 64
    .line 65
    .line 66
    move-result-object v4

    .line 67
    invoke-virtual {v4}, Lorg/json/JSONObject;->keys()Ljava/util/Iterator;

    .line 68
    .line 69
    .line 70
    move-result-object v5

    .line 71
    new-instance v6, Ljava/util/HashMap;

    .line 72
    .line 73
    invoke-direct {v6}, Ljava/util/HashMap;-><init>()V

    .line 74
    .line 75
    .line 76
    :goto_1
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-eqz v7, :cond_1

    .line 81
    .line 82
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    check-cast v7, Ljava/lang/String;

    .line 87
    .line 88
    invoke-virtual {v4, v7}, Lorg/json/JSONObject;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v8

    .line 92
    instance-of v9, v8, Ljava/lang/String;

    .line 93
    .line 94
    if-eqz v9, :cond_0

    .line 95
    .line 96
    check-cast v8, Ljava/lang/String;

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :catch_0
    move-exception v3

    .line 100
    goto :goto_3

    .line 101
    :cond_0
    const-string v8, ""

    .line 102
    .line 103
    :goto_2
    invoke-virtual {v6, v7, v8}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    goto :goto_1

    .line 107
    :cond_1
    const-string v4, "profileId"

    .line 108
    .line 109
    const/4 v5, 0x0

    .line 110
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object v3

    .line 114
    if-eqz v3, :cond_2

    .line 115
    .line 116
    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 117
    .line 118
    invoke-virtual {v4, p0}, Lcom/salesforce/marketingcloud/registration/e;->b(Lcom/salesforce/marketingcloud/registration/e$f;)Lcom/salesforce/marketingcloud/registration/c;

    .line 119
    .line 120
    .line 121
    move-result-object v4

    .line 122
    invoke-interface {v4, v3, v6, v1}, Lcom/salesforce/marketingcloud/registration/c;->a(Ljava/lang/String;Ljava/util/Map;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 123
    .line 124
    .line 125
    move-result-object v3

    .line 126
    invoke-interface {v3}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->commit()Z

    .line 127
    .line 128
    .line 129
    goto :goto_4

    .line 130
    :cond_2
    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 131
    .line 132
    invoke-virtual {v3, p0}, Lcom/salesforce/marketingcloud/registration/e;->b(Lcom/salesforce/marketingcloud/registration/e$f;)Lcom/salesforce/marketingcloud/registration/c;

    .line 133
    .line 134
    .line 135
    move-result-object v3

    .line 136
    invoke-interface {v3, v6, v1}, Lcom/salesforce/marketingcloud/registration/c;->a(Ljava/util/Map;Z)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    invoke-interface {v3}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;->commit()Z
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 141
    .line 142
    .line 143
    goto :goto_4

    .line 144
    :goto_3
    sget-object v4, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 145
    .line 146
    new-array v5, v1, [Ljava/lang/Object;

    .line 147
    .line 148
    const-string v6, "Failed to parse event for identity update."

    .line 149
    .line 150
    invoke-static {v4, v3, v6, v5}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    :goto_4
    add-int/lit8 v2, v2, 0x1

    .line 154
    .line 155
    goto/16 :goto_0

    .line 156
    .line 157
    :cond_3
    return-void
.end method

.method public registerForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/registration/e;->registerForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

.method public tearDown(Z)V
    .locals 2

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 2
    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 4
    .line 5
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    invoke-virtual {p1, v1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 10
    .line 11
    .line 12
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 13
    .line 14
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 15
    .line 16
    .line 17
    move-result-object v0

    .line 18
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/d;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 22
    .line 23
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 24
    .line 25
    .line 26
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/registration/d;->a()V

    .line 27
    .line 28
    .line 29
    return-void
.end method

.method public unregisterForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/d;->n:Lcom/salesforce/marketingcloud/registration/e;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/registration/e;->unregisterForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    return-void
.end method

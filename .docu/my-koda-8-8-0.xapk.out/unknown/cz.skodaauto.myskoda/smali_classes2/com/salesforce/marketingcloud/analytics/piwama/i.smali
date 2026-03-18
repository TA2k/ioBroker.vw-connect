.class public Lcom/salesforce/marketingcloud/analytics/piwama/i;
.super Lcom/salesforce/marketingcloud/analytics/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/http/e$c;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field static final h:Ljava/lang/String; = "user_id"

.field static final i:Ljava/lang/String; = "session_id"

.field static final j:I = 0x64

.field static final k:Ljava/lang/String;

.field private static final l:I = 0x1e

.field private static final m:Ljava/lang/String; = "et_background_time_cache"

.field private static final n:I = 0x1

.field private static final o:I = 0x3e7

.field private static p:Lcom/salesforce/marketingcloud/analytics/piwama/j;


# instance fields
.field final d:Lcom/salesforce/marketingcloud/storage/h;

.field final e:Lcom/salesforce/marketingcloud/http/e;

.field final f:Lcom/salesforce/marketingcloud/internal/n;

.field private final g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "PiWamaAnalytic"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/i;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "MarketingCloudConfig may not be null."

    .line 5
    .line 6
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    const-string v0, "MCStorage may not be null."

    .line 10
    .line 11
    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    check-cast v0, Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 18
    .line 19
    const-string v0, "RequestManager may not be null."

    .line 20
    .line 21
    invoke-static {p3, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    check-cast v0, Lcom/salesforce/marketingcloud/http/e;

    .line 26
    .line 27
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->e:Lcom/salesforce/marketingcloud/http/e;

    .line 28
    .line 29
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 30
    .line 31
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_0

    .line 36
    .line 37
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/k;

    .line 38
    .line 39
    invoke-direct {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/k;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/a;

    .line 44
    .line 45
    invoke-direct {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/a;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;)V

    .line 46
    .line 47
    .line 48
    :goto_0
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->p:Lcom/salesforce/marketingcloud/analytics/piwama/j;

    .line 49
    .line 50
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->j:Lcom/salesforce/marketingcloud/http/b;

    .line 51
    .line 52
    invoke-virtual {p3, p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 53
    .line 54
    .line 55
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    .line 56
    .line 57
    return-void
.end method

.method private static synthetic a(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/analytics/b;)I
    .locals 1

    .line 29
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_1

    .line 30
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_0

    const/4 p0, 0x0

    return p0

    :cond_0
    const/4 p0, -0x1

    return p0

    .line 31
    :cond_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_2

    const/4 p0, 0x1

    return p0

    .line 32
    :cond_2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object p1

    invoke-virtual {p0, p1}, Ljava/lang/String;->compareTo(Ljava/lang/String;)I

    move-result p0

    return p0
.end method

.method public static a(Ljava/util/List;)Ljava/util/List;
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;)",
            "Ljava/util/List<",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;>;"
        }
    .end annotation

    .line 17
    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 18
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/piwama/m;

    const/4 v2, 0x0

    invoke-direct {v1, v2}, Lcom/salesforce/marketingcloud/analytics/piwama/m;-><init>(I)V

    invoke-static {p0, v1}, Ljava/util/Collections;->sort(Ljava/util/List;Ljava/util/Comparator;)V

    .line 19
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 20
    invoke-interface {p0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p0

    const/4 v2, 0x0

    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    move-result v3

    if-eqz v3, :cond_4

    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v3

    check-cast v3, Lcom/salesforce/marketingcloud/analytics/b;

    if-eqz v2, :cond_0

    .line 21
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v4

    if-nez v4, :cond_1

    :cond_0
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v4

    if-nez v4, :cond_2

    .line 22
    :cond_1
    invoke-interface {v1, v3}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 23
    :cond_2
    invoke-interface {v1}, Ljava/util/List;->isEmpty()Z

    move-result v2

    if-nez v2, :cond_3

    .line 24
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 25
    :cond_3
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/analytics/b;->f()Ljava/lang/String;

    move-result-object v2

    .line 26
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    .line 27
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    .line 28
    :cond_4
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    return-object v0
.end method

.method private a(Lcom/salesforce/marketingcloud/analytics/piwama/c;J)V
    .locals 2

    .line 55
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->c()Lorg/json/JSONObject;

    move-result-object v0

    if-eqz v0, :cond_1

    .line 56
    :try_start_0
    new-instance v1, Ljava/util/Date;

    invoke-direct {v1, p2, p3}, Ljava/util/Date;-><init>(J)V

    .line 57
    invoke-interface {p1}, Lcom/salesforce/marketingcloud/analytics/piwama/c;->b()I

    move-result p1

    const/4 p2, 0x1

    invoke-static {v1, p2, p1}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;II)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    .line 58
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p1, p3}, Lcom/salesforce/marketingcloud/analytics/b;->d(Ljava/lang/String;)V

    .line 59
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p3

    invoke-virtual {p1, p3}, Lcom/salesforce/marketingcloud/analytics/b;->c(Ljava/lang/String;)V

    .line 60
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/b;->a(Z)V

    .line 61
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/b;->e()Ljava/lang/String;

    move-result-object p2

    invoke-static {p2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p2

    if-nez p2, :cond_0

    .line 62
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance p3, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 63
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v0

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    invoke-direct {p3, v0, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 64
    invoke-interface {p2, p3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_0
    return-void

    :catch_0
    move-exception p0

    .line 65
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string p3, "Failed to record PiWamaItem in local storage."

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 66
    new-instance p0, Ljava/lang/IllegalArgumentException;

    invoke-direct {p0, p3}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 67
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Failed to convert your input type to a JSON Object."

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/http/e;Ljava/util/List;)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/http/e;",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;)V"
        }
    .end annotation

    .line 5
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isReady()Z

    move-result v0

    if-nez v0, :cond_0

    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->isInitializing()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_1

    .line 6
    :cond_0
    invoke-static {}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getInstance()Lcom/salesforce/marketingcloud/MarketingCloudSdk;

    move-result-object v0

    if-nez v0, :cond_1

    goto :goto_1

    .line 7
    :cond_1
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v1

    if-nez v1, :cond_3

    .line 8
    invoke-static {p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    .line 9
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_3

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Ljava/util/List;

    .line 10
    invoke-static {v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->b(Ljava/util/List;)Ljava/util/List;

    move-result-object v1

    .line 11
    invoke-interface {v1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    move-result-object v1

    :goto_0
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    move-result v2

    if-eqz v2, :cond_2

    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Ljava/util/List;

    .line 12
    sget-object v3, Lcom/salesforce/marketingcloud/analytics/piwama/i;->p:Lcom/salesforce/marketingcloud/analytics/piwama/j;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getRegistrationManager()Lcom/salesforce/marketingcloud/registration/RegistrationManager;

    move-result-object v4

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getPushMessageManager()Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;

    move-result-object v5

    .line 13
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->getRegionMessageManager()Lcom/salesforce/marketingcloud/messages/RegionMessageManager;

    move-result-object v6

    .line 14
    invoke-virtual {v3, v4, v5, v6, v2}, Lcom/salesforce/marketingcloud/analytics/piwama/j;->a(Lcom/salesforce/marketingcloud/registration/RegistrationManager;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/messages/RegionMessageManager;Ljava/util/List;)Lcom/salesforce/marketingcloud/http/c;

    move-result-object v3

    .line 15
    invoke-static {v2}, Lcom/salesforce/marketingcloud/analytics/c;->a(Ljava/util/List;)Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v3, v2}, Lcom/salesforce/marketingcloud/http/c;->a(Ljava/lang/String;)V

    .line 16
    invoke-virtual {p0, v3}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/c;)V

    goto :goto_0

    :cond_3
    :goto_1
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Z)V
    .locals 0

    if-eqz p3, :cond_0

    .line 1
    invoke-static {p0, p2}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 2
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p0

    const-string p2, "predictive_intelligence_identifier"

    invoke-interface {p0, p2}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 3
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/http/b;->j:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    return-void
.end method

.method private static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 3

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/i$a;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "deleting_pi_analytics"

    invoke-direct {v0, v2, v1, p0}, Lcom/salesforce/marketingcloud/analytics/piwama/i$a;-><init>(Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/storage/h;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method private a([Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 2

    .line 52
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object v0

    const-string v1, "et_user_id_cache"

    invoke-interface {v0, v1, p2}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 53
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p2

    const-string v0, "et_session_id_cache"

    invoke-interface {p2, v0, p3}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    if-eqz p1, :cond_0

    .line 54
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance p3, Lcom/salesforce/marketingcloud/analytics/d;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object p0

    invoke-direct {p3, p0, p1}, Lcom/salesforce/marketingcloud/analytics/d;-><init>(Lcom/salesforce/marketingcloud/storage/a;[Ljava/lang/String;)V

    invoke-interface {p2, p3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/MarketingCloudConfig;)Z
    .locals 0

    .line 48
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->predictiveIntelligenceServerUrl()Ljava/lang/String;

    move-result-object p0

    sget-object p1, Ljava/util/Locale;->ENGLISH:Ljava/util/Locale;

    invoke-virtual {p0, p1}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p0}, Ljava/lang/String;->trim()Ljava/lang/String;

    move-result-object p0

    .line 49
    const-string p1, "https://stage.app.igodigital.com/api/v1/collect/qa/qa1s1/process_batch"

    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result p1

    if-nez p1, :cond_0

    .line 50
    const-string p1, "https://stage.app.igodigital.com/api/v1/collect/qa/qa3s1/process_batch"

    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result p1

    if-nez p1, :cond_0

    .line 51
    const-string p1, "https://app.igodigital.com/api/v1/collect/process_batch"

    invoke-virtual {p0, p1}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    move-result p0

    if-nez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public static b(Ljava/util/List;)Ljava/util/List;
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;)",
            "Ljava/util/List<",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/analytics/b;",
            ">;>;"
        }
    .end annotation

    .line 1
    invoke-interface {p0}, Ljava/util/List;->size()I

    move-result v0

    .line 2
    new-instance v1, Ljava/util/ArrayList;

    invoke-direct {v1}, Ljava/util/ArrayList;-><init>()V

    const/4 v2, 0x0

    move v3, v0

    :goto_0
    if-lez v3, :cond_1

    mul-int/lit8 v4, v2, 0x64

    add-int/lit8 v2, v2, 0x1

    mul-int/lit8 v5, v2, 0x64

    if-le v5, v0, :cond_0

    add-int v5, v3, v4

    .line 3
    :cond_0
    new-instance v6, Ljava/util/ArrayList;

    invoke-interface {p0, v4, v5}, Ljava/util/List;->subList(II)Ljava/util/List;

    move-result-object v4

    invoke-direct {v6, v4}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    invoke-virtual {v1, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v3, v3, -0x64

    goto :goto_0

    :cond_1
    return-object v1
.end method

.method private b()V
    .locals 6

    .line 16
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    const-string v1, "et_background_time_cache"

    const-wide/16 v2, -0x1

    invoke-interface {v0, v1, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide v4

    cmp-long v0, v4, v2

    if-eqz v0, :cond_0

    .line 17
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 18
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v0

    .line 19
    invoke-virtual {v0, v4, v5}, Ljava/util/Calendar;->setTimeInMillis(J)V

    .line 20
    invoke-static {}, Ljava/util/Calendar;->getInstance()Ljava/util/Calendar;

    move-result-object v1

    const/16 v2, 0xc

    const/16 v3, -0x1e

    .line 21
    invoke-virtual {v1, v2, v3}, Ljava/util/Calendar;->add(II)V

    .line 22
    invoke-virtual {v0, v1}, Ljava/util/Calendar;->before(Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 23
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p0

    const-string v0, "et_session_id_cache"

    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    :cond_0
    return-void
.end method

.method public static synthetic d(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/analytics/b;)I
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/analytics/b;Lcom/salesforce/marketingcloud/analytics/b;)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method


# virtual methods
.method public a()Ljava/lang/String;
    .locals 2

    .line 68
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->getPiIdentifier()Ljava/lang/String;

    move-result-object v0

    if-nez v0, :cond_0

    .line 69
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->g:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->useLegacyPiIdentifier()Z

    move-result v1

    if-eqz v1, :cond_0

    .line 70
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-static {p0}, Lcom/salesforce/marketingcloud/registration/d;->a(Lcom/salesforce/marketingcloud/storage/h;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :cond_0
    return-object v0
.end method

.method public a(J)V
    .locals 7

    .line 36
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    const-string v1, "et_background_time_cache"

    invoke-interface {v0, v1, p1, p2}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 37
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v0

    new-instance v1, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;

    const/4 v2, 0x0

    new-array v4, v2, [Ljava/lang/Object;

    const-string v3, "end_time_in_app"

    move-object v2, p0

    move-wide v5, p1

    invoke-direct/range {v1 .. v6}, Lcom/salesforce/marketingcloud/analytics/piwama/i$b;-><init>(Lcom/salesforce/marketingcloud/analytics/piwama/i;Ljava/lang/String;[Ljava/lang/Object;J)V

    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 2

    .line 40
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 41
    :try_start_0
    new-instance v0, Lorg/json/JSONObject;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->j()Ljava/lang/String;

    move-result-object p2

    invoke-direct {v0, p2}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 42
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p2

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->r()Ljava/lang/String;

    move-result-object p1

    goto :goto_0

    .line 43
    :cond_0
    const-string p1, ""

    :goto_0
    invoke-static {p1}, Lcom/salesforce/marketingcloud/analytics/c;->a(Ljava/lang/String;)[Ljava/lang/String;

    move-result-object p1

    const-string p2, "user_id"

    .line 44
    invoke-virtual {v0, p2}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p2

    const-string v1, "session_id"

    invoke-virtual {v0, v1}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    .line 45
    invoke-direct {p0, p1, p2, v0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a([Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 46
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    const/4 p2, 0x0

    new-array p2, p2, [Ljava/lang/Object;

    const-string v0, "Error parsing response."

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 47
    :cond_1
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p1

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "Request failed: %d - %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 5

    const/4 v0, 0x0

    .line 38
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v1

    new-instance v2, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;

    const-string v3, "notification_opened"

    new-array v4, v0, [Ljava/lang/Object;

    invoke-direct {v2, p0, v3, v4, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i$c;-><init>(Lcom/salesforce/marketingcloud/analytics/piwama/i;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    invoke-interface {v1, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 39
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "Failed to store our WamaItem for message opened."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Z)V
    .locals 1

    if-eqz p1, :cond_0

    .line 33
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 34
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->e:Lcom/salesforce/marketingcloud/http/e;

    if-eqz p0, :cond_1

    .line 35
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->j:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    :cond_1
    return-void
.end method

.method public b(J)V
    .locals 3

    .line 4
    new-instance v0, Ljava/util/Date;

    invoke-direct {v0, p1, p2}, Ljava/util/Date;-><init>(J)V

    .line 5
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->b()V

    .line 6
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 7
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object p1

    const/4 p2, 0x1

    invoke-interface {p1, p2}, Lcom/salesforce/marketingcloud/storage/a;->c(I)Z

    move-result p1

    if-nez p1, :cond_0

    const/4 p1, 0x5

    const/4 v1, 0x0

    .line 8
    :try_start_0
    invoke-static {v0, p2, p1}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;II)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p1

    .line 9
    new-instance p2, Lcom/salesforce/marketingcloud/analytics/piwama/e;

    .line 10
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-direct {p2, v0, v1, v2}, Lcom/salesforce/marketingcloud/analytics/piwama/e;-><init>(Ljava/util/Date;ZLjava/util/List;)V

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/analytics/piwama/e;->c()Lorg/json/JSONObject;

    move-result-object p2

    invoke-virtual {p2}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p2

    .line 11
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/b;->c(Ljava/lang/String;)V

    .line 12
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p2

    new-instance v0, Lcom/salesforce/marketingcloud/analytics/a;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 13
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->h()Lcom/salesforce/marketingcloud/storage/a;

    move-result-object v2

    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    invoke-direct {v0, v2, p0, p1}, Lcom/salesforce/marketingcloud/analytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/a;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/analytics/b;)V

    .line 14
    invoke-interface {p2, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 15
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    new-array p2, v1, [Ljava/lang/Object;

    const-string v0, "Failed to create WamaItem for TimeInApp."

    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_0
    return-void
.end method

.method public c()V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->f:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/piwama/i$d;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "send_pi_analytics"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2}, Lcom/salesforce/marketingcloud/analytics/piwama/i$d;-><init>(Lcom/salesforce/marketingcloud/analytics/piwama/i;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public getPiIdentifier()Ljava/lang/String;
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    const-string v0, "predictive_intelligence_identifier"

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    invoke-interface {p0, v0, v1}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public setPiIdentifier(Ljava/lang/String;)V
    .locals 1

    .line 1
    const-string v0, "predictive_intelligence_identifier"

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-interface {p0, v0}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/piwama/i;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    invoke-virtual {p1}, Ljava/lang/String;->trim()Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    invoke-interface {p0, v0, p1}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V
    .locals 4

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    :try_start_0
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/piwama/f;

    .line 8
    .line 9
    new-instance v3, Ljava/util/Date;

    .line 10
    .line 11
    invoke-direct {v3, v0, v1}, Ljava/util/Date;-><init>(J)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v2, p1, v3}, Lcom/salesforce/marketingcloud/analytics/piwama/f;-><init>(Lcom/salesforce/marketingcloud/analytics/PiCart;Ljava/util/Date;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/analytics/piwama/c;J)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    new-array v0, v0, [Ljava/lang/Object;

    .line 26
    .line 27
    const-string v1, "Failed to add PiWamaAnalytic for trackCartContents.  See LogCat for details."

    .line 28
    .line 29
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method public trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V
    .locals 4

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    :try_start_0
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/piwama/g;

    .line 8
    .line 9
    new-instance v3, Ljava/util/Date;

    .line 10
    .line 11
    invoke-direct {v3, v0, v1}, Ljava/util/Date;-><init>(J)V

    .line 12
    .line 13
    .line 14
    invoke-direct {v2, p1, v3}, Lcom/salesforce/marketingcloud/analytics/piwama/g;-><init>(Lcom/salesforce/marketingcloud/analytics/PiOrder;Ljava/util/Date;)V

    .line 15
    .line 16
    .line 17
    invoke-direct {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/analytics/piwama/c;J)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_0
    move-exception p0

    .line 22
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    new-array v0, v0, [Ljava/lang/Object;

    .line 26
    .line 27
    const-string v1, "Failed to add PiWamaAnalytic for trackCartConversion.  See LogCat for details."

    .line 28
    .line 29
    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    :cond_0
    return-void
.end method

.method public trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 8

    .line 1
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    :try_start_0
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/piwama/h;

    .line 6
    .line 7
    new-instance v7, Ljava/util/Date;

    .line 8
    .line 9
    invoke-direct {v7, v0, v1}, Ljava/util/Date;-><init>(J)V

    .line 10
    .line 11
    .line 12
    move-object v3, p1

    .line 13
    move-object v4, p2

    .line 14
    move-object v5, p3

    .line 15
    move-object v6, p4

    .line 16
    invoke-direct/range {v2 .. v7}, Lcom/salesforce/marketingcloud/analytics/piwama/h;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;)V

    .line 17
    .line 18
    .line 19
    invoke-direct {p0, v2, v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/analytics/piwama/c;J)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :catch_0
    move-exception v0

    .line 24
    move-object p0, v0

    .line 25
    sget-object p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;->k:Ljava/lang/String;

    .line 26
    .line 27
    const/4 p2, 0x0

    .line 28
    new-array p2, p2, [Ljava/lang/Object;

    .line 29
    .line 30
    const-string p3, "Failed to record PiWamaItem for trackPageView."

    .line 31
    .line 32
    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

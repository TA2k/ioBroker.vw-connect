.class Lcom/salesforce/marketingcloud/registration/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/registration/RegistrationManager;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/registration/e$d;,
        Lcom/salesforce/marketingcloud/registration/e$f;,
        Lcom/salesforce/marketingcloud/registration/e$e;
    }
.end annotation


# static fields
.field public static final w:Ljava/lang/String; = "Android"

.field static final x:Ljava/lang/String; = "previousRegistrationHash"

.field static final y:Ljava/lang/String; = "lastRegistrationSendTimestamp"


# instance fields
.field final d:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field final e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field final f:Lcom/salesforce/marketingcloud/storage/h;

.field final g:Lcom/salesforce/marketingcloud/alarms/b;

.field final h:Lcom/salesforce/marketingcloud/http/e;

.field final i:Lcom/salesforce/marketingcloud/internal/n;

.field final j:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

.field private final k:Landroid/content/Context;

.field private final l:Ljava/util/Set;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Set<",
            "Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;",
            ">;"
        }
    .end annotation
.end field

.field private final m:Lcom/salesforce/marketingcloud/registration/f;

.field private n:Ljava/util/concurrent/ConcurrentHashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentHashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private o:Ljava/util/concurrent/ConcurrentSkipListSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/concurrent/ConcurrentSkipListSet<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private p:Z

.field private q:Z

.field private r:Z

.field private s:Z

.field private t:Ljava/lang/String;

.field private u:Ljava/lang/String;

.field private v:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 10

    const/4 v9, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    move-object/from16 v6, p6

    move-object/from16 v7, p7

    move-object/from16 v8, p8

    .line 1
    invoke-direct/range {v0 .. v9}, Lcom/salesforce/marketingcloud/registration/e;-><init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/registration/f;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;)V
    .locals 3

    .line 2
    const-string v0, ""

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    new-instance v1, Landroidx/collection/g;

    const/4 v2, 0x0

    .line 4
    invoke-direct {v1, v2}, Landroidx/collection/g;-><init>(Ljava/lang/Object;)V

    .line 5
    iput-object v1, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    .line 6
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->k:Landroid/content/Context;

    .line 7
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 8
    iput-object p3, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 9
    iput-object p4, p0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 10
    iput-object p5, p0, Lcom/salesforce/marketingcloud/registration/e;->g:Lcom/salesforce/marketingcloud/alarms/b;

    .line 11
    iput-object p6, p0, Lcom/salesforce/marketingcloud/registration/e;->h:Lcom/salesforce/marketingcloud/http/e;

    .line 12
    iput-object p8, p0, Lcom/salesforce/marketingcloud/registration/e;->i:Lcom/salesforce/marketingcloud/internal/n;

    .line 13
    iput-object p9, p0, Lcom/salesforce/marketingcloud/registration/e;->j:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    .line 14
    new-instance p4, Ljava/util/TreeSet;

    invoke-direct {p4}, Ljava/util/TreeSet;-><init>()V

    .line 15
    const-string p5, "ALL"

    invoke-virtual {p4, p5}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    .line 16
    const-string p5, "Android"

    invoke-virtual {p4, p5}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    .line 17
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/j;->a(Landroid/content/Context;)Z

    move-result p5

    if-eqz p5, :cond_0

    .line 18
    const-string p5, "DEBUG"

    invoke-virtual {p4, p5}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    .line 19
    :cond_0
    invoke-static {p4}, Ljava/util/Collections;->unmodifiableSet(Ljava/util/Set;)Ljava/util/Set;

    move-result-object p4

    iput-object p4, p0, Lcom/salesforce/marketingcloud/registration/e;->d:Ljava/util/Set;

    .line 20
    invoke-virtual {p7}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->isPushEnabled()Z

    move-result p5

    iput-boolean p5, p0, Lcom/salesforce/marketingcloud/registration/e;->s:Z

    .line 21
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result p5

    iput-boolean p5, p0, Lcom/salesforce/marketingcloud/registration/e;->p:Z

    const/4 p6, 0x1

    const/4 p9, 0x0

    if-eqz p5, :cond_1

    .line 22
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/f;->c(Landroid/content/Context;)Z

    move-result p5

    if-eqz p5, :cond_1

    move p5, p6

    goto :goto_0

    :cond_1
    move p5, p9

    :goto_0
    iput-boolean p5, p0, Lcom/salesforce/marketingcloud/registration/e;->q:Z

    .line 23
    new-instance p5, Landroidx/core/app/h0;

    invoke-direct {p5, p1}, Landroidx/core/app/h0;-><init>(Landroid/content/Context;)V

    .line 24
    iget-object p1, p5, Landroidx/core/app/h0;->a:Landroid/app/NotificationManager;

    .line 25
    invoke-virtual {p1}, Landroid/app/NotificationManager;->areNotificationsEnabled()Z

    move-result p1

    .line 26
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/e;->r:Z

    .line 27
    invoke-virtual {p7}, Lcom/salesforce/marketingcloud/messages/push/PushMessageManager;->getPushToken()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->u:Ljava/lang/String;

    .line 28
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p1

    .line 29
    :try_start_0
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/storage/h;->p()Lcom/salesforce/marketingcloud/storage/k;

    move-result-object p5

    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p7

    invoke-interface {p5, p7}, Lcom/salesforce/marketingcloud/storage/k;->k(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object p5

    if-nez p5, :cond_3

    .line 30
    iput-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    .line 31
    const-string p5, "et_subscriber_cache"

    invoke-interface {p1, p5, v2}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p5

    iput-object p5, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    .line 32
    new-instance p5, Ljava/util/concurrent/ConcurrentHashMap;

    const-string p6, "et_attributes_cache"

    .line 33
    invoke-interface {p1, p6, v0}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p6

    invoke-static {p6}, Lcom/salesforce/marketingcloud/util/j;->b(Ljava/lang/String;)Ljava/util/Map;

    move-result-object p6

    invoke-direct {p5, p6}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(Ljava/util/Map;)V

    iput-object p5, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 34
    new-instance p5, Ljava/util/concurrent/ConcurrentSkipListSet;

    const-string p6, "et_tags_cache"

    .line 35
    invoke-interface {p1, p6, v0}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/j;->c(Ljava/lang/String;)Ljava/util/Set;

    move-result-object p1

    invoke-direct {p5, p1}, Ljava/util/concurrent/ConcurrentSkipListSet;-><init>(Ljava/util/Collection;)V

    .line 36
    invoke-virtual {p5}, Ljava/util/concurrent/ConcurrentSkipListSet;->isEmpty()Z

    move-result p1

    if-eqz p1, :cond_2

    new-instance p1, Ljava/util/concurrent/ConcurrentSkipListSet;

    invoke-direct {p1, p4}, Ljava/util/concurrent/ConcurrentSkipListSet;-><init>(Ljava/util/Collection;)V

    goto :goto_1

    :catch_0
    move-exception p1

    goto :goto_3

    .line 37
    :cond_2
    invoke-static {p5, p4}, Lcom/salesforce/marketingcloud/registration/e;->a(Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)Ljava/util/concurrent/ConcurrentSkipListSet;

    move-result-object p1

    :goto_1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    .line 38
    invoke-direct {p0, p9}, Lcom/salesforce/marketingcloud/registration/e;->a(I)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object p1

    move p6, p9

    goto :goto_2

    .line 39
    :cond_3
    invoke-virtual {p5}, Lcom/salesforce/marketingcloud/registration/Registration;->signedString()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    .line 40
    invoke-virtual {p5}, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey()Ljava/lang/String;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    .line 41
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {p5}, Lcom/salesforce/marketingcloud/registration/Registration;->attributes()Ljava/util/Map;

    move-result-object p7

    invoke-direct {p1, p7}, Ljava/util/concurrent/ConcurrentHashMap;-><init>(Ljava/util/Map;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 42
    new-instance p1, Ljava/util/concurrent/ConcurrentSkipListSet;

    invoke-virtual {p5}, Lcom/salesforce/marketingcloud/registration/Registration;->tags()Ljava/util/Set;

    move-result-object p7

    invoke-direct {p1, p7}, Ljava/util/concurrent/ConcurrentSkipListSet;-><init>(Ljava/util/Collection;)V

    invoke-static {p1, p4}, Lcom/salesforce/marketingcloud/registration/e;->a(Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)Ljava/util/concurrent/ConcurrentSkipListSet;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    .line 43
    invoke-static {p5}, Lcom/salesforce/marketingcloud/internal/m;->b(Lcom/salesforce/marketingcloud/registration/Registration;)I

    move-result p1

    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/registration/e;->a(I)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object p1

    .line 44
    invoke-static {p5, p1}, Lcom/salesforce/marketingcloud/util/j;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/registration/Registration;)Z

    move-result p4

    if-eqz p4, :cond_4

    move-object p5, p1

    :cond_4
    move-object p1, p5

    .line 45
    :goto_2
    iget-object p4, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    invoke-direct {p0, p3, p4}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    move p9, p6

    goto :goto_4

    .line 46
    :goto_3
    sget-object p4, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    new-array p5, p9, [Ljava/lang/Object;

    const-string p6, "Error trying to get, update or add a registration to local storage."

    invoke-static {p4, p1, p6, p5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 47
    new-instance p1, Ljava/util/concurrent/ConcurrentSkipListSet;

    iget-object p4, p0, Lcom/salesforce/marketingcloud/registration/e;->d:Ljava/util/Set;

    invoke-direct {p1, p4}, Ljava/util/concurrent/ConcurrentSkipListSet;-><init>(Ljava/util/Collection;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    .line 48
    new-instance p1, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {p1}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 49
    iput-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    .line 50
    iput-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    .line 51
    invoke-direct {p0, p9}, Lcom/salesforce/marketingcloud/registration/e;->a(I)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object p1

    .line 52
    :goto_4
    invoke-virtual {p8}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p4

    new-instance p5, Lcom/salesforce/marketingcloud/registration/a;

    .line 53
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/storage/h;->p()Lcom/salesforce/marketingcloud/storage/k;

    move-result-object p6

    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p7

    invoke-direct {p5, p6, p7, p1, p9}, Lcom/salesforce/marketingcloud/registration/a;-><init>(Lcom/salesforce/marketingcloud/storage/k;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/registration/Registration;Z)V

    invoke-interface {p4, p5}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 54
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet()Z

    move-result p2

    invoke-static {p1, p3, p2}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/storage/h;Z)Z

    move-result p1

    if-eqz p1, :cond_5

    .line 55
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->e()V

    :cond_5
    return-void
.end method

.method private a(I)Lcom/salesforce/marketingcloud/registration/Registration;
    .locals 21

    move-object/from16 v0, p0

    .line 17
    new-instance v1, Lcom/salesforce/marketingcloud/registration/Registration;

    .line 18
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v2

    invoke-virtual {v2}, Ljava/util/UUID;->toString()Ljava/lang/String;

    move-result-object v2

    iget-object v3, v0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    iget-object v4, v0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 19
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/registration/f;->f()Ljava/lang/String;

    move-result-object v4

    iget-object v5, v0, Lcom/salesforce/marketingcloud/registration/e;->u:Ljava/lang/String;

    iget-object v6, v0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 20
    invoke-virtual {v6}, Lcom/salesforce/marketingcloud/registration/f;->j()Ljava/lang/String;

    move-result-object v6

    iget-object v7, v0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 21
    invoke-virtual {v7}, Lcom/salesforce/marketingcloud/registration/f;->e()Ljava/lang/String;

    move-result-object v7

    .line 22
    invoke-static {}, Ljava/util/TimeZone;->getDefault()Ljava/util/TimeZone;

    move-result-object v8

    new-instance v9, Ljava/util/Date;

    invoke-direct {v9}, Ljava/util/Date;-><init>()V

    invoke-virtual {v8, v9}, Ljava/util/TimeZone;->inDaylightTime(Ljava/util/Date;)Z

    move-result v8

    iget-boolean v9, v0, Lcom/salesforce/marketingcloud/registration/e;->p:Z

    iget-boolean v10, v0, Lcom/salesforce/marketingcloud/registration/e;->q:Z

    iget-object v11, v0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 23
    invoke-virtual {v11}, Lcom/salesforce/marketingcloud/registration/f;->i()Ljava/lang/String;

    move-result-object v11

    .line 24
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/registration/e;->f()Z

    move-result v12

    .line 25
    invoke-static {}, Lcom/salesforce/marketingcloud/util/j;->b()I

    move-result v13

    iget-object v14, v0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    iget-object v15, v0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 26
    invoke-virtual {v15}, Lcom/salesforce/marketingcloud/registration/f;->h()Ljava/lang/String;

    move-result-object v15

    move-object/from16 v16, v1

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 27
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/f;->g()Ljava/lang/String;

    move-result-object v1

    move-object/from16 v17, v1

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 28
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->applicationId()Ljava/lang/String;

    move-result-object v1

    .line 29
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    move-result-object v18

    invoke-virtual/range {v18 .. v18}, Ljava/util/Locale;->toString()Ljava/lang/String;

    move-result-object v18

    move-object/from16 v19, v1

    iget-object v1, v0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    iget-object v0, v0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    move-object/from16 v20, v0

    move-object/from16 v0, v16

    move-object/from16 v16, v17

    move-object/from16 v17, v19

    move-object/from16 v19, v1

    move/from16 v1, p1

    invoke-direct/range {v0 .. v20}, Lcom/salesforce/marketingcloud/registration/Registration;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZLjava/lang/String;ZILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/util/Set;Ljava/util/Map;)V

    return-object v0
.end method

.method private static a(Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)Ljava/util/concurrent/ConcurrentSkipListSet;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/concurrent/ConcurrentSkipListSet<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;)",
            "Ljava/util/concurrent/ConcurrentSkipListSet<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->containsAll(Ljava/util/Collection;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 2
    invoke-virtual {p0, p1}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    :cond_0
    return-object p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Z)V
    .locals 0

    if-eqz p2, :cond_0

    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->p()Lcom/salesforce/marketingcloud/storage/k;

    move-result-object p2

    invoke-interface {p2}, Lcom/salesforce/marketingcloud/storage/k;->n()I

    .line 4
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p0

    const-string p2, "et_subscriber_cache"

    invoke-interface {p0, p2}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;)V

    .line 5
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p0

    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;)V
    .locals 0

    .line 14
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p0

    .line 15
    const-string p1, "et_subscriber_cache"

    invoke-interface {p0, p1, p2}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/storage/h;Z)Z
    .locals 2

    const/4 v0, 0x0

    if-nez p0, :cond_0

    return v0

    .line 9
    :cond_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey()Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_1

    if-eqz p2, :cond_1

    .line 10
    sget-object p0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    new-array p1, v0, [Ljava/lang/Object;

    const-string p2, "You have delayRegistrationUntilContactKeyIsSet set to `true.`  The SDK will not send a registration to the Marketing Cloud until a contact key has been set."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v0

    .line 11
    :cond_1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p1

    const-string p2, "previousRegistrationHash"

    const/4 v1, 0x0

    invoke-interface {p1, p2, v1}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_3

    .line 12
    invoke-static {p0}, Lcom/salesforce/marketingcloud/util/j;->a(Lcom/salesforce/marketingcloud/registration/Registration;)Ljava/lang/String;

    move-result-object p0

    .line 13
    invoke-virtual {p0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p0

    if-nez p0, :cond_2

    goto :goto_0

    :cond_2
    return v0

    :cond_3
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/h;Z)Z
    .locals 3

    .line 6
    :try_start_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->p()Lcom/salesforce/marketingcloud/storage/k;

    move-result-object v0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v1

    invoke-interface {v0, v1}, Lcom/salesforce/marketingcloud/storage/k;->k(Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object v0

    .line 7
    invoke-static {v0, p0, p1}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/storage/h;Z)Z

    move-result p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return p0

    :catch_0
    move-exception p0

    .line 8
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    const/4 v0, 0x0

    new-array v1, v0, [Ljava/lang/Object;

    const-string v2, "Failed to get Registration from local storage or we can not determine if this Registration contains any changes."

    invoke-static {p1, p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return v0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/registration/e$f;)Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 7

    .line 16
    new-instance v0, Lcom/salesforce/marketingcloud/registration/e$d;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    iget-object v6, p0, Lcom/salesforce/marketingcloud/registration/e;->d:Ljava/util/Set;

    move-object v1, p1

    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/registration/e$d;-><init>(Lcom/salesforce/marketingcloud/registration/e$f;Ljava/lang/String;Ljava/lang/String;Ljava/util/concurrent/ConcurrentHashMap;Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)V

    return-object v0
.end method

.method public a()V
    .locals 3

    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    new-instance v1, Ljava/lang/StringBuilder;

    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    sget-object v2, Lcom/salesforce/marketingcloud/http/b;->p:Lcom/salesforce/marketingcloud/http/b;

    iget-object v2, v2, Lcom/salesforce/marketingcloud/http/b;->d:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v2, "_device"

    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-interface {v0, v1}, Landroid/content/SharedPreferences$Editor;->remove(Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object v0

    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    const/4 v0, 0x0

    .line 62
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/registration/e;->a(Z)V

    return-void
.end method

.method public a(ILjava/lang/String;)V
    .locals 2

    .line 59
    sget-object v0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "%s: %s"

    invoke-static {v0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 60
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->i:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance p2, Lcom/salesforce/marketingcloud/registration/e$c;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "schedule_registration_retry"

    invoke-direct {p2, p0, v1, v0}, Lcom/salesforce/marketingcloud/registration/e$c;-><init>(Lcom/salesforce/marketingcloud/registration/e;Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-interface {p1, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/registration/Registration;Ljava/util/Map;)V
    .locals 5
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/registration/Registration;",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;)V"
        }
    .end annotation

    .line 40
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object v0

    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/http/b;->a(Ljava/util/Map;Lcom/salesforce/marketingcloud/storage/b;)V

    .line 41
    iget-object p2, p0, Lcom/salesforce/marketingcloud/registration/e;->g:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p2, v0}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 42
    iget-object p2, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    monitor-enter p2

    .line 43
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    move-result-object v0

    :cond_0
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    move-result v1

    if-eqz v1, :cond_1

    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    if-eqz v1, :cond_0

    .line 44
    :try_start_1
    invoke-interface {v1, p1}, Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;->onRegistrationReceived(Lcom/salesforce/marketingcloud/registration/Registration;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    :catch_0
    move-exception v2

    .line 45
    :try_start_2
    sget-object v3, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    const-string v4, "%s threw an exception while processing the registration response"

    .line 46
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    .line 47
    invoke-static {v3, v2, v4, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    goto :goto_0

    .line 48
    :cond_1
    monitor-exit p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 49
    iget-object p2, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object p2

    .line 50
    invoke-static {p1}, Lcom/salesforce/marketingcloud/internal/m;->c(Lcom/salesforce/marketingcloud/registration/Registration;)Lorg/json/JSONObject;

    move-result-object v0

    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object v0

    .line 51
    const-string v1, "mc_last_sent_registration"

    invoke-interface {p2, v1, v0}, Lcom/salesforce/marketingcloud/storage/b;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 52
    iget-object p2, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p2

    .line 53
    invoke-interface {p2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p2

    .line 54
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    const-string v2, "lastRegistrationSendTimestamp"

    invoke-interface {p2, v2, v0, v1}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object p2

    .line 55
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/j;->a(Lcom/salesforce/marketingcloud/registration/Registration;)Ljava/lang/String;

    move-result-object p1

    const-string v0, "previousRegistrationHash"

    invoke-interface {p2, v0, p1}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    .line 56
    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 57
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->i:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance p2, Lcom/salesforce/marketingcloud/registration/e$b;

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "delete_old_registrations"

    invoke-direct {p2, p0, v1, v0}, Lcom/salesforce/marketingcloud/registration/e$b;-><init>(Lcom/salesforce/marketingcloud/registration/e;Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-interface {p1, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    return-void

    .line 58
    :goto_1
    :try_start_3
    monitor-exit p2
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    throw p0
.end method

.method public a(Ljava/lang/String;)V
    .locals 1

    .line 63
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->u:Ljava/lang/String;

    invoke-virtual {p1, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    .line 64
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->u:Ljava/lang/String;

    .line 65
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->g()V

    :cond_0
    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/util/Collection;)V
    .locals 6
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
            ">;)V"
        }
    .end annotation

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    .line 30
    invoke-virtual/range {v0 .. v5}, Lcom/salesforce/marketingcloud/registration/e;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/util/Collection;Z)V

    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/util/Map;Ljava/util/Collection;Z)V
    .locals 0
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

    .line 31
    iput-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    .line 32
    iput-object p2, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    .line 33
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {p1}, Ljava/util/concurrent/ConcurrentHashMap;->clear()V

    .line 34
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {p1, p3}, Ljava/util/concurrent/ConcurrentHashMap;->putAll(Ljava/util/Map;)V

    .line 35
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    invoke-virtual {p1}, Ljava/util/concurrent/ConcurrentSkipListSet;->clear()V

    .line 36
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    invoke-virtual {p1, p4}, Ljava/util/AbstractCollection;->addAll(Ljava/util/Collection;)Z

    .line 37
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->g:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p2

    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 38
    invoke-virtual {p0, p5}, Lcom/salesforce/marketingcloud/registration/e;->c(Z)V

    return-void
.end method

.method public a(Z)V
    .locals 1

    .line 39
    new-instance v0, Lcom/salesforce/marketingcloud/registration/e$a;

    invoke-direct {v0, p0, p1}, Lcom/salesforce/marketingcloud/registration/e$a;-><init>(Lcom/salesforce/marketingcloud/registration/e;Z)V

    invoke-static {v0}, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->requestSdk(Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;)V

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/registration/e$f;)Lcom/salesforce/marketingcloud/registration/c;
    .locals 7

    .line 1
    new-instance v0, Lcom/salesforce/marketingcloud/registration/e$d;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    iget-object v6, p0, Lcom/salesforce/marketingcloud/registration/e;->d:Ljava/util/Set;

    move-object v1, p1

    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/registration/e$d;-><init>(Lcom/salesforce/marketingcloud/registration/e$f;Ljava/lang/String;Ljava/lang/String;Ljava/util/concurrent/ConcurrentHashMap;Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)V

    return-object v0
.end method

.method public b()V
    .locals 4

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->k:Landroid/content/Context;

    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/f;->b(Landroid/content/Context;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 3
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e;->k:Landroid/content/Context;

    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/f;->c(Landroid/content/Context;)Z

    move-result v1

    if-eqz v1, :cond_0

    const/4 v1, 0x1

    goto :goto_0

    :cond_0
    const/4 v1, 0x0

    .line 4
    :goto_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->k:Landroid/content/Context;

    .line 5
    new-instance v3, Landroidx/core/app/h0;

    invoke-direct {v3, v2}, Landroidx/core/app/h0;-><init>(Landroid/content/Context;)V

    .line 6
    iget-object v2, v3, Landroidx/core/app/h0;->a:Landroid/app/NotificationManager;

    .line 7
    invoke-virtual {v2}, Landroid/app/NotificationManager;->areNotificationsEnabled()Z

    move-result v2

    .line 8
    iget-boolean v3, p0, Lcom/salesforce/marketingcloud/registration/e;->p:Z

    if-ne v0, v3, :cond_2

    iget-boolean v3, p0, Lcom/salesforce/marketingcloud/registration/e;->q:Z

    if-ne v1, v3, :cond_2

    iget-boolean v3, p0, Lcom/salesforce/marketingcloud/registration/e;->r:Z

    if-eq v2, v3, :cond_1

    goto :goto_1

    :cond_1
    return-void

    .line 9
    :cond_2
    :goto_1
    iput-boolean v0, p0, Lcom/salesforce/marketingcloud/registration/e;->p:Z

    .line 10
    iput-boolean v1, p0, Lcom/salesforce/marketingcloud/registration/e;->q:Z

    .line 11
    iput-boolean v2, p0, Lcom/salesforce/marketingcloud/registration/e;->r:Z

    .line 12
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->g()V

    return-void
.end method

.method public b(Z)V
    .locals 0

    .line 13
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/registration/e;->s:Z

    .line 14
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->g()V

    return-void
.end method

.method public c()V
    .locals 2

    .line 12
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->g:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->c:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v1

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 13
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->g()V

    return-void
.end method

.method public c(Z)V
    .locals 6

    const/4 v0, 0x0

    .line 1
    :try_start_0
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/registration/e;->a(I)Lcom/salesforce/marketingcloud/registration/Registration;

    move-result-object v1

    .line 2
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->i:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object v2

    new-instance v3, Lcom/salesforce/marketingcloud/registration/a;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 3
    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->p()Lcom/salesforce/marketingcloud/storage/k;

    move-result-object v4

    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v5

    invoke-direct {v3, v4, v5, v1, v0}, Lcom/salesforce/marketingcloud/registration/a;-><init>(Lcom/salesforce/marketingcloud/storage/k;Lcom/salesforce/marketingcloud/util/Crypto;Lcom/salesforce/marketingcloud/registration/Registration;Z)V

    invoke-interface {v2, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 4
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/registration/Registration;->contactKey()Ljava/lang/String;

    move-result-object v3

    invoke-direct {p0, v2, v3}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;)V

    .line 5
    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet()Z

    move-result v3

    invoke-static {v1, v2, v3}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/storage/h;Z)Z

    move-result v1

    if-eqz v1, :cond_2

    .line 6
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e;->j:Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;

    if-eqz v1, :cond_1

    if-eqz p1, :cond_1

    .line 7
    iget-object p1, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    if-eqz p1, :cond_0

    .line 8
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    move-result-object p1

    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    sget-object v3, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    new-array v4, v0, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    invoke-virtual {p1, v1, v2, v3, v4}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfile(Ljava/lang/String;Ljava/util/Map;Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 9
    :cond_0
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkComponents;->getIdentity()Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;

    move-result-object p1

    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    sget-object v2, Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;->PUSH:Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;

    move-result-object v2

    invoke-virtual {p1, v1, v2}, Lcom/salesforce/marketingcloud/sfmcsdk/components/identity/Identity;->setProfileAttributes(Ljava/util/Map;[Lcom/salesforce/marketingcloud/sfmcsdk/modules/ModuleIdentifier;)V

    .line 10
    :cond_1
    :goto_0
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->e()V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    :cond_2
    return-void

    .line 11
    :goto_1
    sget-object p1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    new-array v0, v0, [Ljava/lang/Object;

    const-string v1, "An error occurred trying to save our Registration."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public d()Lorg/json/JSONObject;
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/registration/e;->a(I)Lcom/salesforce/marketingcloud/registration/Registration;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    const/4 v2, 0x0

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    return-object v2

    .line 10
    :cond_0
    new-instance v3, Lorg/json/JSONObject;

    .line 11
    .line 12
    invoke-direct {v3}, Lorg/json/JSONObject;-><init>()V

    .line 13
    .line 14
    .line 15
    :try_start_0
    const-string v4, "current_registration"

    .line 16
    .line 17
    invoke-static {v1}, Lcom/salesforce/marketingcloud/internal/m;->c(Lcom/salesforce/marketingcloud/registration/Registration;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    invoke-virtual {v3, v4, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 22
    .line 23
    .line 24
    iget-object v4, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 25
    .line 26
    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/e;->e:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 27
    .line 28
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->delayRegistrationUntilContactKeyIsSet()Z

    .line 29
    .line 30
    .line 31
    move-result v5

    .line 32
    invoke-static {v1, v4, v5}, Lcom/salesforce/marketingcloud/registration/e;->a(Lcom/salesforce/marketingcloud/registration/Registration;Lcom/salesforce/marketingcloud/storage/h;Z)Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_1

    .line 37
    .line 38
    iget-object v1, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 39
    .line 40
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    .line 41
    .line 42
    .line 43
    move-result-object v1

    .line 44
    const-string v4, "mc_last_sent_registration"

    .line 45
    .line 46
    invoke-interface {v1, v4, v2}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    if-eqz v1, :cond_1

    .line 51
    .line 52
    const-string v2, "last_registration_sent"

    .line 53
    .line 54
    new-instance v4, Lorg/json/JSONObject;

    .line 55
    .line 56
    invoke-direct {v4, v1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v3, v2, v4}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :catch_0
    move-exception p0

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    :goto_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->f:Lcom/salesforce/marketingcloud/storage/h;

    .line 66
    .line 67
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 68
    .line 69
    .line 70
    move-result-object p0

    .line 71
    const-string v1, "lastRegistrationSendTimestamp"

    .line 72
    .line 73
    const-wide/16 v4, 0x0

    .line 74
    .line 75
    invoke-interface {p0, v1, v4, v5}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 76
    .line 77
    .line 78
    move-result-wide v1

    .line 79
    cmp-long p0, v1, v4

    .line 80
    .line 81
    if-lez p0, :cond_2

    .line 82
    .line 83
    const-string p0, "last_sent_timestamp"

    .line 84
    .line 85
    new-instance v4, Ljava/util/Date;

    .line 86
    .line 87
    invoke-direct {v4, v1, v2}, Ljava/util/Date;-><init>(J)V

    .line 88
    .line 89
    .line 90
    invoke-static {v4}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    invoke-virtual {v3, p0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 95
    .line 96
    .line 97
    :cond_2
    return-object v3

    .line 98
    :goto_1
    sget-object v1, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 99
    .line 100
    new-array v0, v0, [Ljava/lang/Object;

    .line 101
    .line 102
    const-string v2, "Failed to build our component state JSONObject."

    .line 103
    .line 104
    invoke-static {v1, p0, v2, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 105
    .line 106
    .line 107
    return-object v3
.end method

.method public e()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/registration/e;->a(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public edit()Lcom/salesforce/marketingcloud/registration/RegistrationManager$Editor;
    .locals 10

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/registration/RegistrationManager;->a:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v1, v1, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v2, "Changes with this editor will not be saved."

    .line 7
    .line 8
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    new-instance v3, Lcom/salesforce/marketingcloud/registration/e$d;

    .line 12
    .line 13
    iget-object v5, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v6, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    .line 16
    .line 17
    iget-object v7, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 18
    .line 19
    iget-object v8, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    .line 20
    .line 21
    iget-object v9, p0, Lcom/salesforce/marketingcloud/registration/e;->d:Ljava/util/Set;

    .line 22
    .line 23
    const/4 v4, 0x0

    .line 24
    invoke-direct/range {v3 .. v9}, Lcom/salesforce/marketingcloud/registration/e$d;-><init>(Lcom/salesforce/marketingcloud/registration/e$f;Ljava/lang/String;Ljava/lang/String;Ljava/util/concurrent/ConcurrentHashMap;Ljava/util/concurrent/ConcurrentSkipListSet;Ljava/util/Set;)V

    .line 25
    .line 26
    .line 27
    return-object v3
.end method

.method public f()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lcom/salesforce/marketingcloud/registration/e;->s:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->k:Landroid/content/Context;

    .line 6
    .line 7
    new-instance v0, Landroidx/core/app/h0;

    .line 8
    .line 9
    invoke-direct {v0, p0}, Landroidx/core/app/h0;-><init>(Landroid/content/Context;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, v0, Landroidx/core/app/h0;->a:Landroid/app/NotificationManager;

    .line 13
    .line 14
    invoke-virtual {p0}, Landroid/app/NotificationManager;->areNotificationsEnabled()Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x1

    .line 21
    return p0

    .line 22
    :cond_0
    const/4 p0, 0x0

    .line 23
    return p0
.end method

.method public g()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/registration/e;->c(Z)V

    .line 3
    .line 4
    .line 5
    return-void
.end method

.method public getAttributes()Ljava/util/Map;
    .locals 1
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
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->n:Ljava/util/concurrent/ConcurrentHashMap;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Ljava/util/HashMap;-><init>(Ljava/util/Map;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public getContactKey()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->t:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getDeviceId()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->m:Lcom/salesforce/marketingcloud/registration/f;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/f;->f()Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public getSignedString()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->v:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getSystemToken()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->u:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public getTags()Ljava/util/Set;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/Set<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    new-instance v0, Ljava/util/TreeSet;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->o:Ljava/util/concurrent/ConcurrentSkipListSet;

    .line 4
    .line 5
    invoke-direct {v0, p0}, Ljava/util/TreeSet;-><init>(Ljava/util/SortedSet;)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public h()V
    .locals 0

    .line 1
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/registration/e;->g()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public registerForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    .line 5
    .line 6
    monitor-enter v0

    .line 7
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 10
    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 16
    throw p0
.end method

.method public unregisterForRegistrationEvents(Lcom/salesforce/marketingcloud/registration/RegistrationManager$RegistrationEventListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/registration/e;->l:Ljava/util/Set;

    .line 5
    .line 6
    invoke-interface {p0, p1}, Ljava/util/Set;->remove(Ljava/lang/Object;)Z

    .line 7
    .line 8
    .line 9
    monitor-exit v0

    .line 10
    return-void

    .line 11
    :catchall_0
    move-exception p0

    .line 12
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    throw p0
.end method

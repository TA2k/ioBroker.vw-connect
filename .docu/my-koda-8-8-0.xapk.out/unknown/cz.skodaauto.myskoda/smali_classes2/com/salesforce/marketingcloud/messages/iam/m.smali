.class Lcom/salesforce/marketingcloud/messages/iam/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager;
.implements Lcom/salesforce/marketingcloud/messages/iam/i;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;
.implements Lcom/salesforce/marketingcloud/media/b$a;
.implements Lcom/salesforce/marketingcloud/events/f;


# static fields
.field private static final A:Ljava/lang/String; = "minDurationBetweenMessages"

.field static final v:Ljava/lang/String;

.field private static final w:I = 0x1

.field private static final x:I = 0x6f

.field private static final y:Ljava/lang/String; = "messagesAttemptedInSession"

.field private static final z:Ljava/lang/String; = "maxMessagesPerSession"


# instance fields
.field final d:Landroid/content/Context;

.field final e:Lcom/salesforce/marketingcloud/storage/h;

.field final f:Lcom/salesforce/marketingcloud/analytics/f;

.field final g:Ljava/lang/Object;

.field final h:Ljava/util/concurrent/atomic/AtomicInteger;

.field final i:Landroid/os/Handler;

.field private final j:Lcom/salesforce/marketingcloud/alarms/b;

.field private final k:Lcom/salesforce/marketingcloud/UrlHandler;

.field private final l:Lcom/salesforce/marketingcloud/internal/n;

.field private final m:Lcom/salesforce/marketingcloud/config/a;

.field private final n:Ljava/util/concurrent/atomic/AtomicInteger;

.field private final o:Landroid/os/Handler;

.field p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;

.field q:Lcom/salesforce/marketingcloud/media/o;

.field private r:Landroid/graphics/Typeface;

.field private s:I

.field private t:Lcom/salesforce/marketingcloud/media/b;

.field private u:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "InAppMessageManager"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/media/o;Lcom/salesforce/marketingcloud/UrlHandler;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/f;Landroid/os/Handler;Lcom/salesforce/marketingcloud/config/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/lang/Object;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->g:Ljava/lang/Object;

    .line 10
    .line 11
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->d:Landroid/content/Context;

    .line 12
    .line 13
    iput-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    iput-object p3, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 16
    .line 17
    iput-object p4, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->q:Lcom/salesforce/marketingcloud/media/o;

    .line 18
    .line 19
    iput-object p5, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->k:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 20
    .line 21
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->f:Lcom/salesforce/marketingcloud/analytics/f;

    .line 22
    .line 23
    iput-object p6, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 24
    .line 25
    iput-object p9, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->m:Lcom/salesforce/marketingcloud/config/a;

    .line 26
    .line 27
    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->i:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 28
    .line 29
    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-virtual {p3, p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 37
    .line 38
    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    .line 39
    .line 40
    .line 41
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->h:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 42
    .line 43
    new-instance p1, Ljava/util/concurrent/atomic/AtomicInteger;

    .line 44
    .line 45
    invoke-direct {p1}, Ljava/util/concurrent/atomic/AtomicInteger;-><init>()V

    .line 46
    .line 47
    .line 48
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->n:Ljava/util/concurrent/atomic/AtomicInteger;

    .line 49
    .line 50
    new-instance p1, Landroid/os/Handler;

    .line 51
    .line 52
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-direct {p1, p2}, Landroid/os/Handler;-><init>(Landroid/os/Looper;)V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->i:Landroid/os/Handler;

    .line 60
    .line 61
    iput-object p8, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->o:Landroid/os/Handler;

    .line 62
    .line 63
    return-void
.end method

.method private a(Ljava/lang/String;)Z
    .locals 0

    .line 41
    :try_start_0
    invoke-static {p1}, Lcom/salesforce/marketingcloud/util/j;->d(Ljava/lang/String;)Ljava/util/Date;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    const/4 p0, 0x0

    return p0

    :catch_0
    const/4 p0, 0x1

    return p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Ljava/lang/Class;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;",
            ")",
            "Ljava/lang/Class<",
            "+",
            "Lcom/salesforce/marketingcloud/messages/iam/f;",
            ">;"
        }
    .end annotation

    .line 36
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/m$e;->a:[I

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object p1

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p0, p0, p1

    const/4 p1, 0x1

    if-eq p0, p1, :cond_3

    const/4 p1, 0x2

    if-eq p0, p1, :cond_3

    const/4 p1, 0x3

    if-eq p0, p1, :cond_2

    const/4 p1, 0x4

    if-eq p0, p1, :cond_1

    const/4 p1, 0x5

    if-eq p0, p1, :cond_0

    const/4 p0, 0x0

    return-object p0

    .line 37
    :cond_0
    const-class p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;

    return-object p0

    .line 38
    :cond_1
    const-class p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullImageFillActivity;

    return-object p0

    .line 39
    :cond_2
    const-class p0, Lcom/salesforce/marketingcloud/messages/iam/IamModalActivity;

    return-object p0

    .line 40
    :cond_3
    const-class p0, Lcom/salesforce/marketingcloud/messages/iam/IamBannerActivity;

    return-object p0
.end method

.method public a()Lorg/json/JSONObject;
    .locals 6

    .line 47
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    const/4 v1, 0x0

    .line 48
    :try_start_0
    const-string v2, "messages"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    move-result-object v3

    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v4

    invoke-interface {v3, v4}, Lcom/salesforce/marketingcloud/storage/e;->c(Lcom/salesforce/marketingcloud/util/Crypto;)Lorg/json/JSONArray;

    move-result-object v3

    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 49
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;

    if-eqz v2, :cond_0

    .line 50
    const-string v3, "eventListener"

    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    move-result-object v2

    invoke-virtual {v2}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object v2

    invoke-virtual {v0, v3, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_2

    .line 51
    :cond_0
    :goto_0
    const-string v2, "subscriberToken"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 52
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->c()Lcom/salesforce/marketingcloud/storage/b;

    move-result-object v3

    const-string v4, "subscriber_jwt"

    const-string v5, "null"

    invoke-interface {v3, v4, v5}, Lcom/salesforce/marketingcloud/storage/b;->b(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v3

    .line 53
    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 54
    const-string v2, "custom_font_set"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->r:Landroid/graphics/Typeface;

    if-eqz v3, :cond_1

    const/4 v3, 0x1

    goto :goto_1

    :cond_1
    move v3, v1

    :goto_1
    invoke-virtual {v0, v2, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 55
    const-string v2, "status_bar_color"

    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->s:I

    invoke-virtual {v0, v2, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object v0

    .line 56
    :goto_2
    sget-object v2, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    new-array v1, v1, [Ljava/lang/Object;

    const-string v3, "Unable to compile componentState for InAppMessageManager"

    invoke-static {v2, p0, v3, v1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-object v0
.end method

.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 3

    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->i:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-ne p1, v0, :cond_0

    .line 4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->l:Lcom/salesforce/marketingcloud/internal/n;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    move-result-object p1

    new-instance v0, Lcom/salesforce/marketingcloud/messages/iam/m$c;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "iam_image_cache"

    invoke-direct {v0, p0, v2, v1}, Lcom/salesforce/marketingcloud/messages/iam/m$c;-><init>(Lcom/salesforce/marketingcloud/messages/iam/m;Ljava/lang/String;[Ljava/lang/Object;)V

    invoke-interface {p1, v0}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    :cond_0
    return-void
.end method

.method public a(Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 42
    invoke-interface {p1}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    .line 43
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->t:Lcom/salesforce/marketingcloud/media/b;

    if-eqz v0, :cond_1

    .line 44
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/b;->b()V

    .line 45
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->q:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/util/List;)Lcom/salesforce/marketingcloud/media/b;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->t:Lcom/salesforce/marketingcloud/media/b;

    const/4 v0, 0x1

    .line 46
    invoke-virtual {p1, p0, v0}, Lcom/salesforce/marketingcloud/media/b;->a(Lcom/salesforce/marketingcloud/media/b$a;Z)V

    return-void
.end method

.method public a(Lorg/json/JSONObject;)V
    .locals 13

    .line 5
    const-string v0, "version"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;)I

    move-result v0

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-eq v0, v2, :cond_0

    .line 6
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "Unable to handle sync payload due to version mismatch"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 7
    :cond_0
    :try_start_0
    const-string v0, "items"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->getJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    .line 8
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v0

    .line 9
    sget-object v3, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    const-string v4, "%d in app message(s) received from sync."

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v5

    filled-new-array {v5}, [Ljava/lang/Object;

    move-result-object v5

    invoke-static {v3, v4, v5}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 10
    new-instance v3, Ljava/util/TreeSet;

    invoke-direct {v3}, Ljava/util/TreeSet;-><init>()V

    .line 11
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v4}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    move-result-object v4

    .line 12
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object v5

    .line 13
    invoke-interface {v4, v5}, Lcom/salesforce/marketingcloud/storage/e;->d(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object v6
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_1

    move v7, v1

    :goto_0
    if-ge v7, v0, :cond_4

    .line 14
    :try_start_1
    invoke-virtual {p1, v7}, Lorg/json/JSONArray;->getJSONObject(I)Lorg/json/JSONObject;

    move-result-object v8

    .line 15
    invoke-virtual {p0, v8}, Lcom/salesforce/marketingcloud/messages/iam/m;->b(Lorg/json/JSONObject;)Ljava/lang/String;

    move-result-object v9

    if-nez v9, :cond_2

    .line 16
    new-instance v9, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    invoke-direct {v9, v8}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;-><init>(Lorg/json/JSONObject;)V

    .line 17
    invoke-interface {v4, v9, v5}, Lcom/salesforce/marketingcloud/storage/e;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/util/Crypto;)I

    move-result v10

    if-ne v10, v2, :cond_1

    .line 18
    invoke-virtual {p0, v9}, Lcom/salesforce/marketingcloud/messages/iam/m;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    goto :goto_1

    :catch_0
    move-exception v8

    goto :goto_2

    .line 19
    :cond_1
    :goto_1
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v10

    const-string v11, "displayCount"

    invoke-virtual {v8, v11, v1}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    move-result v8

    invoke-interface {v4, v10, v8}, Lcom/salesforce/marketingcloud/storage/e;->b(Ljava/lang/String;I)V

    .line 20
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object v8

    invoke-virtual {v3, v8}, Ljava/util/TreeSet;->add(Ljava/lang/Object;)Z

    goto :goto_3

    .line 21
    :cond_2
    invoke-virtual {v9}, Ljava/lang/String;->isEmpty()Z

    move-result v10

    if-nez v10, :cond_3

    .line 22
    iget-object v10, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->f:Lcom/salesforce/marketingcloud/analytics/f;

    const-string v11, "id"

    invoke-virtual {v8, v11}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v11

    const-string v12, "activityInstanceId"

    .line 23
    invoke-virtual {v8, v12}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v8

    invoke-static {v9}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v9

    .line 24
    invoke-interface {v10, v11, v8, v9}, Lcom/salesforce/marketingcloud/analytics/f;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_3

    .line 25
    :goto_2
    :try_start_2
    sget-object v9, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    const-string v10, "Unable to parse in app message payload"

    new-array v11, v1, [Ljava/lang/Object;

    invoke-static {v9, v8, v10, v11}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_3
    :goto_3
    add-int/lit8 v7, v7, 0x1

    goto :goto_0

    :catch_1
    move-exception p0

    goto :goto_4

    .line 26
    :cond_4
    invoke-interface {v4, v3}, Lcom/salesforce/marketingcloud/storage/e;->a(Ljava/util/Collection;)I

    .line 27
    invoke-interface {v4, v5}, Lcom/salesforce/marketingcloud/storage/e;->d(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p1

    .line 28
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Ljava/util/List;)V

    .line 29
    new-instance v0, Ljava/util/TreeSet;

    invoke-direct {v0, v6}, Ljava/util/TreeSet;-><init>(Ljava/util/Collection;)V

    .line 30
    invoke-virtual {v0, p1}, Ljava/util/AbstractCollection;->removeAll(Ljava/util/Collection;)Z

    .line 31
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->q:Lcom/salesforce/marketingcloud/media/o;

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/util/Collection;)V
    :try_end_2
    .catch Lorg/json/JSONException; {:try_start_2 .. :try_end_2} :catch_1

    goto :goto_5

    .line 32
    :goto_4
    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "Unable to get InAppMessages from sync payload"

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    :goto_5
    return-void
.end method

.method public a(Z)V
    .locals 0

    if-eqz p1, :cond_0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->i:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void

    .line 2
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object p1, Lcom/salesforce/marketingcloud/alarms/a$a;->i:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object p1

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    return-void
.end method

.method public a(Ljava/lang/Class;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Landroid/content/Context;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "+",
            "Lcom/salesforce/marketingcloud/messages/iam/f;",
            ">;",
            "Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;",
            "Landroid/content/Context;",
            ")Z"
        }
    .end annotation

    .line 33
    const-class p0, Lcom/salesforce/marketingcloud/messages/iam/IamFullscreenActivity;

    invoke-virtual {p0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    move-result-object p0

    const/4 v0, 0x1

    if-eq p1, p0, :cond_0

    return v0

    .line 34
    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->type()Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    move-result-object p0

    sget-object p1, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->fullImageFill:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;

    if-ne p0, p1, :cond_2

    .line 35
    invoke-virtual {p3}, Landroid/content/Context;->getResources()Landroid/content/res/Resources;

    move-result-object p0

    invoke-virtual {p0}, Landroid/content/res/Resources;->getConfiguration()Landroid/content/res/Configuration;

    move-result-object p0

    iget p0, p0, Landroid/content/res/Configuration;->orientation:I

    if-ne p0, v0, :cond_1

    goto :goto_0

    :cond_1
    const/4 p0, 0x0

    return p0

    :cond_2
    :goto_0
    return v0
.end method

.method public b(Lorg/json/JSONObject;)Ljava/lang/String;
    .locals 8

    .line 11
    const-string v0, "id"

    invoke-virtual {p1, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    .line 12
    const-string v2, "activityInstanceId"

    invoke-virtual {p1, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v2

    .line 13
    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-nez v1, :cond_e

    invoke-static {v2}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_0

    goto/16 :goto_2

    .line 14
    :cond_0
    const-string v1, "endDateUtc"

    const/4 v2, 0x0

    invoke-virtual {p1, v1, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    const-string v3, "InvalidDate"

    if-eqz v1, :cond_1

    .line 15
    :try_start_0
    invoke-static {v1}, Lcom/salesforce/marketingcloud/util/j;->d(Ljava/lang/String;)Ljava/util/Date;

    move-result-object v1

    invoke-virtual {v1}, Ljava/util/Date;->getTime()J

    move-result-wide v4

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v6

    cmp-long v1, v4, v6

    if-gez v1, :cond_1

    .line 16
    const-string p0, "ExpiredMessage"
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-object p0

    :catch_0
    return-object v3

    .line 17
    :cond_1
    const-string v1, "startDateUtc"

    invoke-virtual {p1, v1, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-eqz v1, :cond_2

    .line 18
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Ljava/lang/String;)Z

    move-result v1

    if-eqz v1, :cond_2

    return-object v3

    .line 19
    :cond_2
    const-string v1, "modifiedDateUtc"

    invoke-virtual {p1, v1, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    if-nez v1, :cond_3

    .line 20
    const-string p0, "NoModifiedDate"

    return-object p0

    .line 21
    :cond_3
    invoke-direct {p0, v1}, Lcom/salesforce/marketingcloud/messages/iam/m;->a(Ljava/lang/String;)Z

    move-result p0

    if-eqz p0, :cond_4

    return-object v3

    .line 22
    :cond_4
    :try_start_1
    const-string p0, "type"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    invoke-static {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage$Type;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 23
    const-string p0, "media"

    invoke-virtual {p1, p0}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object p0

    .line 24
    const-string v1, "title"

    invoke-virtual {p1, v1}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v1

    .line 25
    const-string v3, "body"

    invoke-virtual {p1, v3}, Lorg/json/JSONObject;->optJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    move-result-object v3

    .line 26
    const-string v4, "buttons"

    invoke-virtual {p1, v4}, Lorg/json/JSONObject;->optJSONArray(Ljava/lang/String;)Lorg/json/JSONArray;

    move-result-object p1

    if-nez p0, :cond_6

    if-nez v1, :cond_6

    if-nez v3, :cond_6

    if-eqz p1, :cond_5

    .line 27
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v4

    if-nez v4, :cond_6

    .line 28
    :cond_5
    const-string p0, "NoContent"

    return-object p0

    :cond_6
    if-eqz p0, :cond_8

    .line 29
    const-string v4, "url"

    invoke-virtual {p0, v4}, Lorg/json/JSONObject;->opt(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p0

    .line 30
    instance-of v4, p0, Ljava/lang/String;

    if-eqz v4, :cond_7

    check-cast p0, Ljava/lang/String;

    invoke-static {p0}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p0

    if-eqz p0, :cond_8

    .line 31
    :cond_7
    const-string p0, "InvalidMedia"

    return-object p0

    :cond_8
    const-string p0, "text"

    if-eqz v1, :cond_9

    .line 32
    invoke-virtual {v1, p0, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_9

    .line 33
    const-string p0, "InvalidTitle"

    return-object p0

    :cond_9
    if-eqz v3, :cond_a

    .line 34
    invoke-virtual {v3, p0, v2}, Lorg/json/JSONObject;->optString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v1

    invoke-static {v1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v1

    if-eqz v1, :cond_a

    .line 35
    const-string p0, "InvalidBody"

    return-object p0

    :cond_a
    if-eqz p1, :cond_d

    .line 36
    invoke-virtual {p1}, Lorg/json/JSONArray;->length()I

    move-result v1

    const/4 v3, 0x0

    :goto_0
    if-ge v3, v1, :cond_d

    .line 37
    invoke-virtual {p1, v3}, Lorg/json/JSONArray;->optJSONObject(I)Lorg/json/JSONObject;

    move-result-object v4

    if-eqz v4, :cond_c

    .line 38
    invoke-virtual {v4, v0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v5

    invoke-static {v5}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v5

    if-nez v5, :cond_c

    .line 39
    invoke-virtual {v4, p0}, Lorg/json/JSONObject;->optString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object v4

    .line 40
    invoke-static {v4}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v4

    if-eqz v4, :cond_b

    goto :goto_1

    :cond_b
    add-int/lit8 v3, v3, 0x1

    goto :goto_0

    .line 41
    :cond_c
    :goto_1
    const-string p0, "InvalidButton"

    return-object p0

    :cond_d
    return-object v2

    .line 42
    :catch_1
    const-string p0, "NoMessageType"

    return-object p0

    .line 43
    :cond_e
    :goto_2
    const-string p0, ""

    return-object p0
.end method

.method public b()V
    .locals 2

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->h:Ljava/util/concurrent/atomic/AtomicInteger;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->n:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v0, v1}, Ljava/util/concurrent/atomic/AtomicInteger;->set(I)V

    .line 10
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->i:Landroid/os/Handler;

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 2

    .line 44
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->f:Lcom/salesforce/marketingcloud/analytics/f;

    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/analytics/f;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception p0

    .line 45
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v1, "Failed to log download analytics for IAM %s"

    invoke-static {v0, p0, v1, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->i:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v1

    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->i:Landroid/os/Handler;

    const/4 v1, 0x0

    invoke-virtual {v0, v1}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->t:Lcom/salesforce/marketingcloud/media/b;

    if-eqz v0, :cond_0

    .line 4
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/media/b;->b()V

    :cond_0
    if-eqz p1, :cond_1

    .line 5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    move-result-object p1

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->q:Lcom/salesforce/marketingcloud/media/o;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    move-result-object p0

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/storage/e;->d(Lcom/salesforce/marketingcloud/util/Crypto;)Ljava/util/List;

    move-result-object p0

    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/media/o;->a(Ljava/util/Collection;)V

    .line 7
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    invoke-interface {p1, p0}, Lcom/salesforce/marketingcloud/storage/e;->a(Ljava/util/Collection;)I

    :cond_1
    return-void
.end method

.method public c()V
    .locals 1

    .line 21
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->o:Landroid/os/Handler;

    const/4 v0, 0x0

    invoke-virtual {p0, v0}, Landroid/os/Handler;->removeCallbacksAndMessages(Ljava/lang/Object;)V

    return-void
.end method

.method public c(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z
    .locals 7

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->displayLimitOverride()Z

    move-result v0

    const/4 v1, 0x0

    if-eqz v0, :cond_0

    .line 2
    sget-object p0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 4
    const-string v0, "InAppMessage [%s] has displayLimit Override set. The message will not honour displayLimit settings"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 5
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    const v2, 0x7fffffff

    .line 6
    const-string v3, "event_max_display_in_session"

    invoke-interface {v0, v3, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result v0

    .line 7
    :try_start_0
    new-instance v2, Lorg/json/JSONObject;

    invoke-direct {v2}, Lorg/json/JSONObject;-><init>()V

    .line 8
    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->h:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v4}, Ljava/util/concurrent/atomic/AtomicInteger;->get()I

    move-result v4
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_1

    const-string v5, "maxMessagesPerSession"

    const/4 v6, 0x1

    if-lt v4, v0, :cond_1

    .line 9
    :try_start_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 10
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    invoke-interface {v0, v3, v1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result v0

    .line 11
    invoke-virtual {v2, v5, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 12
    const-string v0, "messagesAttemptedInSession"

    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->n:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v1}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    move-result v1

    invoke-virtual {v2, v0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    goto :goto_0

    :catch_0
    move-exception p0

    move v1, v6

    goto :goto_1

    .line 13
    :cond_1
    :try_start_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->i:Landroid/os/Handler;

    const/16 v3, 0x6f

    invoke-virtual {v0, v3}, Landroid/os/Handler;->hasMessages(I)Z

    move-result v0
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    if-eqz v0, :cond_2

    .line 14
    :try_start_3
    const-string v0, "minDurationBetweenMessages"

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v3

    const-string v4, "event_min_time_sec_in_session"

    .line 15
    invoke-interface {v3, v4, v1}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result v1

    .line 16
    invoke-virtual {v2, v0, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;

    .line 17
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->n:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    move-result v0

    invoke-virtual {v2, v5, v0}, Lorg/json/JSONObject;->put(Ljava/lang/String;I)Lorg/json/JSONObject;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    :goto_0
    move v1, v6

    :cond_2
    if-eqz v1, :cond_3

    .line 18
    :try_start_4
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->m:Lcom/salesforce/marketingcloud/config/a;

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/config/a;->j()Z

    move-result v0

    if-eqz v0, :cond_3

    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->f:Lcom/salesforce/marketingcloud/analytics/f;

    invoke-interface {p0, p1, v2}, Lcom/salesforce/marketingcloud/analytics/f;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V
    :try_end_4
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_1

    return v1

    :catch_1
    move-exception p0

    goto :goto_1

    :cond_3
    return v1

    .line 20
    :goto_1
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v2, "Failed to log message Debug Analytics for IAM %s"

    invoke-static {v0, p0, v2, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method

.method public canDisplay(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->u:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x1

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 8
    .line 9
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    new-instance v3, Lcom/salesforce/marketingcloud/messages/iam/m$b;

    .line 14
    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v4, "can_display"

    .line 18
    .line 19
    invoke-direct {v3, p0, v4, v1, p1}, Lcom/salesforce/marketingcloud/messages/iam/m$b;-><init>(Lcom/salesforce/marketingcloud/messages/iam/m;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 20
    .line 21
    .line 22
    invoke-interface {v0, v3}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->u:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 26
    .line 27
    return v2

    .line 28
    :cond_0
    if-eq p1, v0, :cond_1

    .line 29
    .line 30
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 31
    .line 32
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->u:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 37
    .line 38
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    filled-new-array {p1, p0}, [Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    const-string p1, "In App Message [%s] not displayed because [%s] is currently being displayed"

    .line 47
    .line 48
    invoke-static {v0, p1, p0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return v1

    .line 52
    :cond_1
    return v2
.end method

.method public d()V
    .locals 5

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->h:Ljava/util/concurrent/atomic/AtomicInteger;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicInteger;->incrementAndGet()I

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    const-string v1, "event_min_time_sec_in_session"

    const/4 v2, 0x0

    invoke-interface {v0, v1, v2}, Landroid/content/SharedPreferences;->getInt(Ljava/lang/String;I)I

    move-result v0

    if-lez v0, :cond_0

    .line 8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->i:Landroid/os/Handler;

    const/16 v2, 0x6f

    invoke-virtual {v1, v2}, Landroid/os/Handler;->obtainMessage(I)Landroid/os/Message;

    move-result-object v1

    .line 9
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->i:Landroid/os/Handler;

    sget-object v2, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    int-to-long v3, v0

    invoke-virtual {v2, v3, v4}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide v2

    invoke-virtual {p0, v1, v2, v3}, Landroid/os/Handler;->sendMessageDelayed(Landroid/os/Message;J)Z

    :cond_0
    return-void
.end method

.method public d(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 4

    if-nez p1, :cond_0

    goto :goto_0

    .line 1
    :cond_0
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->c(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)Z

    move-result v0

    if-eqz v0, :cond_1

    :goto_0
    return-void

    .line 2
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->o:Landroid/os/Handler;

    new-instance v1, Lcom/salesforce/marketingcloud/messages/iam/m$d;

    invoke-direct {v1, p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m$d;-><init>(Lcom/salesforce/marketingcloud/messages/iam/m;Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    sget-object p0, Ljava/util/concurrent/TimeUnit;->SECONDS:Ljava/util/concurrent/TimeUnit;

    .line 3
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->messageDelaySec()I

    move-result p1

    int-to-long v2, p1

    invoke-virtual {p0, v2, v3}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    move-result-wide p0

    .line 4
    invoke-virtual {v0, v1, p0, p1}, Landroid/os/Handler;->postDelayed(Ljava/lang/Runnable;J)Z

    return-void
.end method

.method public getStatusBarColor()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->s:I

    .line 2
    .line 3
    return p0
.end method

.method public getTypeface()Landroid/graphics/Typeface;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->r:Landroid/graphics/Typeface;

    .line 2
    .line 3
    return-object p0
.end method

.method public handleMessageFinished(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->u:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-eqz v0, :cond_2

    .line 18
    .line 19
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->f:Lcom/salesforce/marketingcloud/analytics/f;

    .line 20
    .line 21
    if-eqz v0, :cond_0

    .line 22
    .line 23
    invoke-interface {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/f;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 24
    .line 25
    .line 26
    :cond_0
    iget-object p2, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->g:Ljava/lang/Object;

    .line 27
    .line 28
    monitor-enter p2

    .line 29
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    if-eqz v0, :cond_1

    .line 32
    .line 33
    :try_start_1
    invoke-interface {v0, p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;->didCloseMessage(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 34
    .line 35
    .line 36
    goto :goto_0

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    goto :goto_1

    .line 39
    :catch_0
    move-exception p1

    .line 40
    :try_start_2
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 41
    .line 42
    const-string v1, "InAppMessageEventListener threw an exception"

    .line 43
    .line 44
    const/4 v2, 0x0

    .line 45
    new-array v2, v2, [Ljava/lang/Object;

    .line 46
    .line 47
    invoke-static {v0, p1, v1, v2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    :cond_1
    :goto_0
    monitor-exit p2

    .line 51
    goto :goto_2

    .line 52
    :goto_1
    monitor-exit p2
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 53
    throw p0

    .line 54
    :cond_2
    :goto_2
    const/4 p1, 0x0

    .line 55
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->u:Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 56
    .line 57
    return-void
.end method

.method public handleOutcomes(Ljava/util/Collection;)V
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Collection<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    invoke-interface {p1}, Ljava/util/Collection;->isEmpty()Z

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/messages/iam/m;->v:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    const-string v2, "Resolving IAM from outcomes %s"

    .line 20
    .line 21
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 25
    .line 26
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->k()Lcom/salesforce/marketingcloud/storage/e;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 31
    .line 32
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->b()Lcom/salesforce/marketingcloud/util/Crypto;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    invoke-interface {v1, p1, v2}, Lcom/salesforce/marketingcloud/storage/e;->a(Ljava/util/Collection;Lcom/salesforce/marketingcloud/util/Crypto;)Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    if-eqz p1, :cond_0

    .line 41
    .line 42
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;->id()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    filled-new-array {v1}, [Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v1

    .line 50
    const-string v2, "Outcomes resolved to message[%s]"

    .line 51
    .line 52
    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/iam/m;->d(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_0
    const/4 p0, 0x0

    .line 60
    new-array p0, p0, [Ljava/lang/Object;

    .line 61
    .line 62
    const-string p1, "No message resolved."

    .line 63
    .line 64
    invoke-static {v0, p1, p0}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    return-void
.end method

.method public imageHandler()Lcom/salesforce/marketingcloud/media/o;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->q:Lcom/salesforce/marketingcloud/media/o;

    .line 2
    .line 3
    return-object p0
.end method

.method public setInAppMessageListener(Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->g:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->p:Lcom/salesforce/marketingcloud/messages/iam/InAppMessageManager$EventListener;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-void

    .line 8
    :catchall_0
    move-exception p0

    .line 9
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 10
    throw p0
.end method

.method public setStatusBarColor(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->s:I

    .line 2
    .line 3
    return-void
.end method

.method public setTypeface(Landroid/graphics/Typeface;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->r:Landroid/graphics/Typeface;

    .line 2
    .line 3
    return-void
.end method

.method public showMessage(Ljava/lang/String;)V
    .locals 4

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 5
    .line 6
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Lcom/salesforce/marketingcloud/messages/iam/m$a;

    .line 11
    .line 12
    const/4 v2, 0x0

    .line 13
    new-array v2, v2, [Ljava/lang/Object;

    .line 14
    .line 15
    const-string v3, "iam_showMessage"

    .line 16
    .line 17
    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/messages/iam/m$a;-><init>(Lcom/salesforce/marketingcloud/messages/iam/m;Ljava/lang/String;[Ljava/lang/Object;Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 21
    .line 22
    .line 23
    return-void
.end method

.method public urlHandler()Lcom/salesforce/marketingcloud/UrlHandler;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/iam/m;->k:Lcom/salesforce/marketingcloud/UrlHandler;

    .line 2
    .line 3
    return-object p0
.end method

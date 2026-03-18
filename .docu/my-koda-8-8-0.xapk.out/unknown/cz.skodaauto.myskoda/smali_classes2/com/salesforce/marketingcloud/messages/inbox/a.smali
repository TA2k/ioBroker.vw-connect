.class public Lcom/salesforce/marketingcloud/messages/inbox/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/http/e$c;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field protected static final n:Ljava/lang/String; = "8"

.field private static final o:Ljava/lang/String; = "InboxMessagingEnabled"

.field private static final p:Ljava/lang/Object;


# instance fields
.field private final d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field private final e:Lcom/salesforce/marketingcloud/storage/h;

.field private final f:Ljava/lang/String;

.field private final g:Lcom/salesforce/marketingcloud/behaviors/c;

.field private final h:Lcom/salesforce/marketingcloud/alarms/b;

.field private final i:Lcom/salesforce/marketingcloud/http/e;

.field private final j:Lcom/salesforce/marketingcloud/analytics/g;

.field private k:Lcom/salesforce/marketingcloud/messages/inbox/c;

.field private l:Lcom/salesforce/marketingcloud/internal/n;

.field private m:Lcom/salesforce/marketingcloud/toggles/a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a;->p:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/g;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    const-string v0, "MarketingCloudConfig is null."

    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 3
    const-string p1, "Storage is null."

    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/storage/h;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 4
    const-string p1, "You must provide the Device ID."

    invoke-static {p3, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/CharSequence;Ljava/lang/String;)Ljava/lang/CharSequence;

    move-result-object p1

    check-cast p1, Ljava/lang/String;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->f:Ljava/lang/String;

    .line 5
    const-string p1, "BehaviorManager is null."

    invoke-static {p4, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/behaviors/c;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 6
    const-string p1, "AlarmScheduler is null."

    invoke-static {p5, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/alarms/b;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 7
    const-string p1, "RequestManager is null."

    invoke-static {p6, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/http/e;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 8
    const-string p1, "InboxAnalyticEventListener is null."

    invoke-static {p8, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Lcom/salesforce/marketingcloud/analytics/g;

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->j:Lcom/salesforce/marketingcloud/analytics/g;

    .line 9
    iput-object p7, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->l:Lcom/salesforce/marketingcloud/internal/n;

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/messages/inbox/c;)V
    .locals 1

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 11
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 12
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 13
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->f:Ljava/lang/String;

    .line 14
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 15
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 16
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->j:Lcom/salesforce/marketingcloud/analytics/g;

    .line 18
    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;
    .locals 1

    if-nez p1, :cond_1

    .line 29
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    const-string p1, "InboxMessagingEnabled"

    const/4 v0, 0x0

    invoke-interface {p0, p1, v0}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_0

    .line 30
    sget-object p0, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    return-object p0

    .line 31
    :cond_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/toggles/a;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/toggles/a;

    move-result-object p0

    return-object p0

    :cond_1
    return-object p1
.end method

.method private a()V
    .locals 8

    .line 5
    new-instance v0, Lcom/salesforce/marketingcloud/messages/inbox/c;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->f:Ljava/lang/String;

    iget-object v4, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    iget-object v6, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->j:Lcom/salesforce/marketingcloud/analytics/g;

    iget-object v7, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->l:Lcom/salesforce/marketingcloud/internal/n;

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/messages/inbox/c;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/analytics/g;Lcom/salesforce/marketingcloud/internal/n;)V

    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->k:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 7
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->l:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 8
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    sget-object v1, Lcom/salesforce/marketingcloud/http/b;->m:Lcom/salesforce/marketingcloud/http/b;

    invoke-virtual {v0, v1, p0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;Lcom/salesforce/marketingcloud/http/e$c;)V

    .line 9
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v1

    invoke-virtual {v0, p0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 10
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->l:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v4, Lcom/salesforce/marketingcloud/behaviors/a;->p:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 11
    invoke-static {v1, v2, v3, v4}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    move-result-object v1

    .line 12
    invoke-virtual {v0, p0, v1}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    return-void
.end method

.method private a(I)Z
    .locals 2

    const/16 v0, 0x80

    .line 24
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    return v0

    .line 25
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    if-nez p1, :cond_1

    const/4 p1, 0x0

    .line 26
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a(Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    move-result-object p1

    iput-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    .line 27
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    sget-object v1, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    if-eq p1, v1, :cond_3

    sget-object v1, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    if-ne p1, v1, :cond_2

    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->d:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 28
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->inboxEnabled()Z

    move-result p0

    if-eqz p0, :cond_2

    goto :goto_0

    :cond_2
    return v0

    :cond_3
    :goto_0
    const/4 p0, 0x1

    return p0
.end method

.method private static a(Landroid/os/Bundle;)Z
    .locals 1

    .line 3
    const-string v0, "_mt"

    invoke-virtual {p0, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    .line 4
    const-string v0, "8"

    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method

.method public static a(Ljava/util/Map;)Z
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)Z"
        }
    .end annotation

    .line 1
    const-string v0, "_mt"

    invoke-interface {p0, v0}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Ljava/lang/String;

    .line 2
    const-string v0, "8"

    invoke-virtual {v0, p0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result p0

    return p0
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 21
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    if-eqz v0, :cond_1

    .line 22
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->c:[I

    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    move-result p1

    aget p1, v0, p1

    const/4 v0, 0x1

    if-eq p1, v0, :cond_0

    goto :goto_0

    .line 23
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->e()V

    :cond_1
    :goto_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/http/c;Lcom/salesforce/marketingcloud/http/f;)V
    .locals 2

    .line 13
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    if-eqz v0, :cond_4

    .line 14
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->b:[I

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/http/c;->q()Lcom/salesforce/marketingcloud/http/b;

    move-result-object v1

    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v1

    aget v0, v0, v1

    const/4 v1, 0x1

    if-eq v0, v1, :cond_2

    const/4 v1, 0x2

    if-eq v0, v1, :cond_2

    const/4 v1, 0x3

    if-eq v0, v1, :cond_0

    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result v0

    if-eqz v0, :cond_1

    .line 16
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/http/c;)V

    return-void

    .line 17
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/c;->b(ILjava/lang/String;)V

    return-void

    .line 18
    :cond_2
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->p()Z

    move-result p1

    if-eqz p1, :cond_3

    .line 19
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/http/f;)V

    return-void

    .line 20
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->k()I

    move-result p1

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/http/f;->n()Ljava/lang/String;

    move-result-object p2

    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(ILjava/lang/String;)V

    :cond_4
    :goto_0
    return-void
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "InboxMessageManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 2

    .line 1
    :try_start_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->c()Lorg/json/JSONObject;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    new-instance v0, Lorg/json/JSONObject;

    .line 11
    .line 12
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 13
    .line 14
    .line 15
    :goto_0
    const-string v1, "inboxEnabled"

    .line 16
    .line 17
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/a;->isInboxEnabled()Z

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    return-object v0

    .line 25
    :catch_0
    move-exception p0

    .line 26
    new-instance v0, Ljava/lang/RuntimeException;

    .line 27
    .line 28
    invoke-direct {v0, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/Throwable;)V

    .line 29
    .line 30
    .line 31
    throw v0
.end method

.method public controlChannelInit(I)V
    .locals 4

    .line 1
    const/16 v0, 0x80

    .line 2
    .line 3
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iput-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 11
    .line 12
    iget-object v1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 13
    .line 14
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 15
    .line 16
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->l:Lcom/salesforce/marketingcloud/internal/n;

    .line 17
    .line 18
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    invoke-static {v1, v2, v3, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;Z)V

    .line 23
    .line 24
    .line 25
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 26
    .line 27
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 31
    .line 32
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

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
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 42
    .line 43
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->k:Lcom/salesforce/marketingcloud/http/b;

    .line 44
    .line 45
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 46
    .line 47
    .line 48
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 49
    .line 50
    sget-object v0, Lcom/salesforce/marketingcloud/http/b;->l:Lcom/salesforce/marketingcloud/http/b;

    .line 51
    .line 52
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 53
    .line 54
    .line 55
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->i:Lcom/salesforce/marketingcloud/http/e;

    .line 56
    .line 57
    sget-object p1, Lcom/salesforce/marketingcloud/http/b;->m:Lcom/salesforce/marketingcloud/http/b;

    .line 58
    .line 59
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/http/e;->a(Lcom/salesforce/marketingcloud/http/b;)V

    .line 60
    .line 61
    .line 62
    return-void

    .line 63
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 64
    .line 65
    if-nez p1, :cond_1

    .line 66
    .line 67
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/a;->isInboxEnabled()Z

    .line 68
    .line 69
    .line 70
    move-result p1

    .line 71
    if-eqz p1, :cond_1

    .line 72
    .line 73
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a()V

    .line 74
    .line 75
    .line 76
    :cond_1
    return-void
.end method

.method public deleteMessage(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    if-eqz p0, :cond_0

    .line 2
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->deleteMessage(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    return-void

    .line 3
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Inbox messaging is disabled.  Call to deleteMessage() was ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public deleteMessage(Ljava/lang/String;)V
    .locals 1

    .line 4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    if-eqz p0, :cond_0

    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->deleteMessage(Ljava/lang/String;)V

    return-void

    .line 6
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Inbox messaging is disabled.  Call to deleteMessage() was ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public disableInbox()V
    .locals 6

    .line 1
    const-string v0, "Inbox runtime toggle set to "

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/a;->p:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->d:Lcom/salesforce/marketingcloud/toggles/a;

    .line 7
    .line 8
    iput-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    .line 9
    .line 10
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 11
    .line 12
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 13
    .line 14
    .line 15
    move-result-object v3

    .line 16
    invoke-interface {v3}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 17
    .line 18
    .line 19
    move-result-object v3

    .line 20
    const-string v4, "InboxMessagingEnabled"

    .line 21
    .line 22
    iget-object v5, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    .line 23
    .line 24
    invoke-virtual {v5}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v5

    .line 28
    invoke-interface {v3, v4, v5}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 29
    .line 30
    .line 31
    move-result-object v3

    .line 32
    invoke-interface {v3}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 33
    .line 34
    .line 35
    sget-object v3, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 36
    .line 37
    new-instance v4, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object v0

    .line 53
    const/4 v2, 0x0

    .line 54
    new-array v4, v2, [Ljava/lang/Object;

    .line 55
    .line 56
    invoke-static {v3, v0, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    const/4 v0, 0x0

    .line 60
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 61
    .line 62
    invoke-virtual {p0, v2}, Lcom/salesforce/marketingcloud/messages/inbox/a;->tearDown(Z)V

    .line 63
    .line 64
    .line 65
    monitor-exit v1

    .line 66
    return-void

    .line 67
    :catchall_0
    move-exception p0

    .line 68
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 69
    throw p0
.end method

.method public enableInbox()V
    .locals 5

    .line 1
    const-string v0, "Inbox runtime toggle set to "

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/messages/inbox/a;->p:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 7
    .line 8
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    .line 9
    .line 10
    .line 11
    move-result-object v2

    .line 12
    invoke-static {v2}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    const/16 v3, 0x80

    .line 17
    .line 18
    invoke-static {v2, v3}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    if-eqz v2, :cond_0

    .line 23
    .line 24
    monitor-exit v1

    .line 25
    return-void

    .line 26
    :catchall_0
    move-exception p0

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    sget-object v2, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 29
    .line 30
    new-instance v3, Ljava/lang/StringBuilder;

    .line 31
    .line 32
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sget-object v0, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 36
    .line 37
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v4

    .line 41
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    const/4 v4, 0x0

    .line 49
    new-array v4, v4, [Ljava/lang/Object;

    .line 50
    .line 51
    invoke-static {v2, v3, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    iput-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    .line 55
    .line 56
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 57
    .line 58
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    const-string v2, "InboxMessagingEnabled"

    .line 67
    .line 68
    iget-object v3, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->m:Lcom/salesforce/marketingcloud/toggles/a;

    .line 69
    .line 70
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 71
    .line 72
    .line 73
    move-result-object v3

    .line 74
    invoke-interface {v0, v2, v3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 75
    .line 76
    .line 77
    move-result-object v0

    .line 78
    invoke-interface {v0}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 79
    .line 80
    .line 81
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a()V

    .line 82
    .line 83
    .line 84
    monitor-exit v1

    .line 85
    return-void

    .line 86
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 87
    throw p0
.end method

.method public getDeletedMessageCount()I
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getDeletedMessageCount()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    new-array v1, v0, [Ljava/lang/Object;

    .line 14
    .line 15
    const-string v2, "Inbox messaging is disabled.  Call to getDeletedMessageCount() was ignored."

    .line 16
    .line 17
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return v0
.end method

.method public getDeletedMessages()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getDeletedMessages()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v2, "Inbox messaging is disabled.  Call to getDeletedMessages() was ignored."

    .line 18
    .line 19
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public getMessageCount()I
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getMessageCount()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    new-array v1, v0, [Ljava/lang/Object;

    .line 14
    .line 15
    const-string v2, "Inbox messaging is disabled.  Call to getMessageCount() was ignored."

    .line 16
    .line 17
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return v0
.end method

.method public getMessages()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getMessages()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v2, "Inbox messaging is disabled.  Call to getMessages() was ignored."

    .line 18
    .line 19
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public getReadMessageCount()I
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getReadMessageCount()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    new-array v1, v0, [Ljava/lang/Object;

    .line 14
    .line 15
    const-string v2, "Inbox messaging is disabled.  Call to getReadMessageCount() was ignored."

    .line 16
    .line 17
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return v0
.end method

.method public getReadMessages()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getReadMessages()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v2, "Inbox messaging is disabled.  Call to getReadMessages() was ignored."

    .line 18
    .line 19
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public getUnreadMessageCount()I
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getUnreadMessageCount()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0

    .line 10
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v0, 0x0

    .line 13
    new-array v1, v0, [Ljava/lang/Object;

    .line 14
    .line 15
    const-string v2, "Inbox messaging is disabled.  Call to getUnreadMessageCount() was ignored."

    .line 16
    .line 17
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    return v0
.end method

.method public getUnreadMessages()Ljava/util/List;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 2
    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->getUnreadMessages()Ljava/util/List;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 13
    .line 14
    const/4 v1, 0x0

    .line 15
    new-array v1, v1, [Ljava/lang/Object;

    .line 16
    .line 17
    const-string v2, "Inbox messaging is disabled.  Call to getUnreadMessages() was ignored."

    .line 18
    .line 19
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    return-object v0
.end method

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a(I)Z

    .line 2
    .line 3
    .line 4
    move-result p1

    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a()V

    .line 8
    .line 9
    .line 10
    :cond_0
    return-void
.end method

.method public isInboxEnabled()Z
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->e:Lcom/salesforce/marketingcloud/storage/h;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-static {v0}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    invoke-direct {p0, v0}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a(I)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0
.end method

.method public markAllMessagesDeleted()V
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->markAllMessagesDeleted()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    new-array v0, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v1, "Inbox messaging is disabled.  Call to markAllMessagesDeleted() was ignored."

    .line 15
    .line 16
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public markAllMessagesRead()V
    .locals 2

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->markAllMessagesRead()V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    new-array v0, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v1, "Inbox messaging is disabled.  Call to markAllMessagesRead() was ignored."

    .line 15
    .line 16
    invoke-static {p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz v0, :cond_4

    .line 4
    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/messages/inbox/a$a;->a:[I

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p1

    .line 11
    aget p1, v0, p1

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    if-eq p1, v0, :cond_3

    .line 15
    .line 16
    const/4 v0, 0x2

    .line 17
    if-eq p1, v0, :cond_2

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    if-eq p1, v0, :cond_1

    .line 21
    .line 22
    const/4 v0, 0x4

    .line 23
    if-eq p1, v0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const-string p1, "com.salesforce.marketingcloud.notifications.MESSAGE"

    .line 27
    .line 28
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->get(Ljava/lang/String;)Ljava/lang/Object;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    check-cast p1, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;

    .line 33
    .line 34
    if-eqz p1, :cond_4

    .line 35
    .line 36
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 37
    .line 38
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :cond_1
    invoke-static {p2}, Lcom/salesforce/marketingcloud/messages/inbox/a;->a(Landroid/os/Bundle;)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_4

    .line 47
    .line 48
    :try_start_0
    new-instance p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;

    .line 49
    .line 50
    invoke-direct {p1, p2}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;-><init>(Landroid/os/Bundle;)V

    .line 51
    .line 52
    .line 53
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 54
    .line 55
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :catch_0
    move-exception p0

    .line 60
    sget-object p1, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 61
    .line 62
    const-string v0, "_m"

    .line 63
    .line 64
    invoke-virtual {p2, v0}, Landroid/os/BaseBundle;->getString(Ljava/lang/String;)Ljava/lang/String;

    .line 65
    .line 66
    .line 67
    move-result-object p2

    .line 68
    filled-new-array {p2}, [Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p2

    .line 72
    const-string v0, "Failed to seed inbox_messages table with message: %s."

    .line 73
    .line 74
    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 79
    .line 80
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->a()V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 85
    .line 86
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/messages/inbox/c;->b()V

    .line 87
    .line 88
    .line 89
    :cond_4
    :goto_0
    return-void
.end method

.method public refreshInbox(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;)V
    .locals 3

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->refreshInbox(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const/4 v0, 0x0

    .line 12
    new-array v1, v0, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v2, "Inbox messaging is disabled.  Call to refreshInbox() was ignored."

    .line 15
    .line 16
    invoke-static {p0, v2, v1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    if-eqz p1, :cond_1

    .line 20
    .line 21
    :try_start_0
    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxRefreshListener;->onRefreshComplete(Z)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 22
    .line 23
    .line 24
    return-void

    .line 25
    :catch_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 26
    .line 27
    new-array p1, v0, [Ljava/lang/Object;

    .line 28
    .line 29
    const-string v0, "InboxRefreshListener threw an exception."

    .line 30
    .line 31
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    .line 33
    .line 34
    :cond_1
    return-void
.end method

.method public registerInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->registerInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    new-array p1, p1, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v0, "Inbox messaging is disabled.  Call to registerInboxResponseListener() was ignored."

    .line 15
    .line 16
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

.method public setMessageRead(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    if-eqz p0, :cond_0

    .line 2
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->setMessageRead(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    return-void

    .line 3
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Inbox messaging is disabled.  Call to setMessageRead() was ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public setMessageRead(Ljava/lang/String;)V
    .locals 1

    .line 4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    if-eqz p0, :cond_0

    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->setMessageRead(Ljava/lang/String;)V

    return-void

    .line 6
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Inbox messaging is disabled.  Call to setMessageRead() was ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public tearDown(Z)V
    .locals 1

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->h:Lcom/salesforce/marketingcloud/alarms/b;

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->g:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 6
    .line 7
    filled-new-array {v0}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 12
    .line 13
    .line 14
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->g:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 15
    .line 16
    if-eqz p1, :cond_1

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 19
    .line 20
    .line 21
    :cond_1
    return-void
.end method

.method public unregisterInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V
    .locals 1

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/messages/inbox/a;->k:Lcom/salesforce/marketingcloud/messages/inbox/c;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/messages/inbox/c;->unregisterInboxResponseListener(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager$InboxResponseListener;)V

    .line 6
    .line 7
    .line 8
    return-void

    .line 9
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/messages/inbox/InboxMessageManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    new-array p1, p1, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v0, "Inbox messaging is disabled.  Call to unregisterInboxResponseListener() was ignored."

    .line 15
    .line 16
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method

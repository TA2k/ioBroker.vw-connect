.class public final Lcom/salesforce/marketingcloud/analytics/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/e;
.implements Lcom/salesforce/marketingcloud/behaviors/b;
.implements Lcom/salesforce/marketingcloud/analytics/j;
.implements Lcom/salesforce/marketingcloud/messages/RegionMessageManager$RegionTransitionEventListener;
.implements Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;
.implements Lcom/salesforce/marketingcloud/analytics/g;
.implements Lcom/salesforce/marketingcloud/analytics/f;
.implements Lcom/salesforce/marketingcloud/analytics/m;
.implements Lcom/salesforce/marketingcloud/analytics/n;
.implements Lcom/salesforce/marketingcloud/analytics/l;
.implements Lcom/salesforce/marketingcloud/alarms/b$b;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation


# static fields
.field private static final s:Ljava/lang/String; = "ETAnalyticsEnabled"

.field private static final t:Ljava/lang/String; = "PIAnalyticsEnabled"

.field private static final u:Ljava/lang/Object;


# instance fields
.field final d:Lcom/salesforce/marketingcloud/storage/h;

.field private final e:Lcom/salesforce/marketingcloud/behaviors/c;

.field private final f:Ljava/util/EnumSet;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/EnumSet<",
            "Lcom/salesforce/marketingcloud/behaviors/a;",
            ">;"
        }
    .end annotation
.end field

.field private final g:Lcom/salesforce/marketingcloud/http/e;

.field private final h:Ljava/lang/String;

.field private final i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

.field private final j:Lcom/salesforce/marketingcloud/alarms/b;

.field k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

.field l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

.field m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

.field n:Lcom/salesforce/marketingcloud/analytics/stats/c;

.field private o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

.field private p:Lcom/salesforce/marketingcloud/internal/n;

.field private q:Lcom/salesforce/marketingcloud/toggles/a;

.field private r:Lcom/salesforce/marketingcloud/toggles/a;


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
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/h;->u:Ljava/lang/Object;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/analytics/etanalytics/a;Lcom/salesforce/marketingcloud/analytics/etanalytics/b;Lcom/salesforce/marketingcloud/analytics/piwama/i;Lcom/salesforce/marketingcloud/internal/n;Lcom/salesforce/marketingcloud/analytics/stats/c;Lcom/salesforce/marketingcloud/analytics/etanalytics/c;)V
    .locals 8

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move-object v4, p4

    move-object v5, p5

    move-object v6, p6

    move-object/from16 v7, p10

    .line 11
    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/analytics/h;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 12
    iput-object p7, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    move-object/from16 p1, p8

    .line 13
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    move-object/from16 p1, p9

    .line 14
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    move-object/from16 p1, p11

    .line 15
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    move-object/from16 p1, p12

    .line 16
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    return-void
.end method

.method public constructor <init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Ljava/lang/String;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/behaviors/c;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->j:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->i:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v2, Lcom/salesforce/marketingcloud/behaviors/a;->e:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v3, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 3
    invoke-static {v0, v1, v2, v3}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    move-result-object v0

    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->f:Ljava/util/EnumSet;

    .line 4
    const-string v0, "MCStorage may not be null."

    invoke-static {p2, v0}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lcom/salesforce/marketingcloud/storage/h;

    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    const-string p2, "BehaviorManager may not be null."

    invoke-static {p5, p2}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Lcom/salesforce/marketingcloud/behaviors/c;

    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 6
    iput-object p6, p0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 7
    iput-object p3, p0, Lcom/salesforce/marketingcloud/analytics/h;->h:Ljava/lang/String;

    .line 8
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 9
    iput-object p4, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 10
    iput-object p7, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    return-void
.end method

.method private a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;
    .locals 0

    if-nez p2, :cond_1

    .line 6
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object p0

    const/4 p2, 0x0

    invoke-interface {p0, p1, p2}, Landroid/content/SharedPreferences;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-nez p0, :cond_0

    .line 7
    sget-object p0, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    return-object p0

    .line 8
    :cond_0
    invoke-static {p0}, Lcom/salesforce/marketingcloud/toggles/a;->valueOf(Ljava/lang/String;)Lcom/salesforce/marketingcloud/toggles/a;

    move-result-object p0

    return-object p0

    :cond_1
    return-object p2
.end method

.method private a()V
    .locals 3

    .line 40
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 v1, 0x0

    new-array v1, v1, [Ljava/lang/Object;

    const-string v2, "attempt to send pending events Immediate"

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 41
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz v0, :cond_0

    .line 42
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a()V

    .line 43
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    if-eqz p0, :cond_1

    .line 44
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a()V

    :cond_1
    return-void
.end method

.method private a(Landroid/os/Bundle;)V
    .locals 5

    .line 9
    const-string v0, "timestamp"

    const-wide/16 v1, 0x0

    invoke-virtual {p1, v0, v1, v2}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;J)J

    move-result-wide v0

    .line 10
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-virtual {p1, v2, v3, v4}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;J)Z

    move-result p1

    if-eqz p1, :cond_0

    .line 11
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v2

    invoke-virtual {p1, v2}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 12
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz p1, :cond_1

    .line 13
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->a(J)V

    .line 14
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz p1, :cond_2

    .line 15
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(J)V

    .line 16
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz p1, :cond_3

    .line 17
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(J)V

    .line 18
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->c()V

    .line 19
    :cond_3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p1, :cond_4

    .line 20
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(J)V

    .line 21
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a()V

    .line 22
    :cond_4
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    if-eqz p0, :cond_5

    .line 23
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a()V

    :cond_5
    return-void
.end method

.method private b(ILcom/salesforce/marketingcloud/toggles/a;)V
    .locals 3

    const/16 v0, 0x200

    .line 1
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    .line 2
    :cond_0
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 3
    sget-object p1, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    if-eq p2, p1, :cond_2

    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled()Z

    move-result p1

    if-eqz p1, :cond_1

    sget-object p1, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    if-ne p2, p1, :cond_1

    goto :goto_1

    :cond_1
    :goto_0
    return-void

    .line 5
    :cond_2
    :goto_1
    new-instance p1, Lcom/salesforce/marketingcloud/analytics/piwama/i;

    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    invoke-direct {p1, p2, v0, v1, v2}, Lcom/salesforce/marketingcloud/analytics/piwama/i;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    return-void
.end method

.method private b(Landroid/os/Bundle;)V
    .locals 5

    .line 6
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    const-string v2, "timestamp"

    invoke-virtual {p1, v2, v0, v1}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;J)J

    move-result-wide v0

    .line 7
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    invoke-virtual {p1, v2, v3, v4}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;J)Z

    move-result p1

    if-eqz p1, :cond_0

    .line 8
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v2

    invoke-virtual {p1, v2}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 9
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    if-eqz p1, :cond_1

    .line 10
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->a()V

    .line 11
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz p1, :cond_2

    .line 12
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->b(J)V

    .line 13
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz p1, :cond_3

    .line 14
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->b(J)V

    .line 15
    :cond_3
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz p1, :cond_4

    .line 16
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->c()V

    .line 17
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->b(J)V

    .line 18
    :cond_4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p1, :cond_5

    .line 19
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a()V

    .line 20
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->b(J)V

    :cond_5
    return-void
.end method

.method private c(Landroid/os/Bundle;)V
    .locals 3

    .line 1
    const-string v0, "timestamp"

    .line 2
    .line 3
    const-wide/16 v1, 0x0

    .line 4
    .line 5
    invoke-virtual {p1, v0, v1, v2}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;J)J

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 10
    .line 11
    if-eqz p1, :cond_0

    .line 12
    .line 13
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->c(J)V

    .line 14
    .line 15
    .line 16
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 17
    .line 18
    if-eqz p1, :cond_1

    .line 19
    .line 20
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->c(J)V

    .line 21
    .line 22
    .line 23
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 24
    .line 25
    if-eqz p1, :cond_2

    .line 26
    .line 27
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->c(J)V

    .line 28
    .line 29
    .line 30
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 31
    .line 32
    if-eqz p0, :cond_3

    .line 33
    .line 34
    invoke-virtual {p0, v0, v1}, Lcom/salesforce/marketingcloud/analytics/i;->c(J)V

    .line 35
    .line 36
    .line 37
    :cond_3
    return-void
.end method


# virtual methods
.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 2

    .line 149
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    if-ne p1, v0, :cond_0

    .line 150
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v1, "Handling alarm of type [%s]"

    invoke-static {v0, v1, p1}, Lcom/salesforce/marketingcloud/g;->c(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 151
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/analytics/h;->a()V

    :cond_0
    return-void
.end method

.method public varargs a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V
    .locals 1

    .line 133
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 134
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 135
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 136
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 137
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 138
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    .line 139
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 140
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/analytics/e;[Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;)V

    :cond_3
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V
    .locals 1

    .line 141
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 142
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V

    .line 143
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 144
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V

    .line 145
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 146
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V

    .line 147
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 148
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/analytics/l$a;Lorg/json/JSONObject;)V

    :cond_3
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 1

    if-nez p1, :cond_0

    .line 124
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "InAppMessage is null.  Call to onIamDisplayed() ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 125
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 126
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 127
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 128
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 129
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 130
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 131
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 132
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    :cond_4
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V
    .locals 1

    if-eqz p1, :cond_5

    if-nez p2, :cond_0

    goto :goto_0

    .line 76
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 77
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 78
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 79
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 80
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 81
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    .line 82
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 83
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lcom/salesforce/marketingcloud/messages/iam/j;)V

    :cond_4
    return-void

    .line 84
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "InAppMessage or MessageCompletedEvent is null.  Call to onInAppMessageCompleted() ignored."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V
    .locals 1

    if-eqz p1, :cond_5

    if-eqz p2, :cond_5

    .line 114
    invoke-virtual {p2}, Lorg/json/JSONObject;->length()I

    move-result v0

    if-gtz v0, :cond_0

    goto :goto_0

    .line 115
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 116
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V

    .line 117
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 118
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V

    .line 119
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 120
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V

    .line 121
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 122
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;Lorg/json/JSONObject;)V

    :cond_4
    return-void

    .line 123
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "Message and/or Information not valid. Call to onInAppMessageThrottled() ignored"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 1

    if-nez p1, :cond_0

    .line 67
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "InboxMessage is null.  Call to onMessageDownloaded() ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 68
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 69
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 70
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 71
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 72
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 73
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 74
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 75
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    :cond_4
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 1

    .line 45
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 46
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 47
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 48
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 49
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 50
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 51
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 52
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    :cond_3
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 32
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 33
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V

    .line 34
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 35
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V

    .line 36
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 37
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V

    .line 38
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 39
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;ILjava/lang/String;Ljava/lang/String;)V

    :cond_3
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)V
    .locals 1

    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 62
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)V

    .line 63
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 64
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)V

    .line 65
    :cond_1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz p0, :cond_2

    .line 66
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)V

    :cond_2
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V
    .locals 1

    .line 53
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 54
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    .line 55
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 56
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    .line 57
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 58
    invoke-virtual {v0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    .line 59
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 60
    invoke-virtual {p0, p1, p2}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/push/f;Ljava/lang/String;)V

    :cond_3
    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    if-eqz p1, :cond_5

    if-eqz p2, :cond_5

    if-nez p3, :cond_0

    goto :goto_0

    .line 85
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 86
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 87
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 88
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 89
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 90
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 91
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 92
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    :cond_4
    return-void

    .line 93
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "triggerId, outcomeId or outcomeType is null.  Call to onTriggerSuccessEvent() ignored."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    if-eqz p1, :cond_5

    if-eqz p2, :cond_5

    if-eqz p3, :cond_5

    .line 104
    invoke-interface {p3}, Ljava/util/List;->isEmpty()Z

    move-result v0

    if-eqz v0, :cond_0

    goto :goto_0

    .line 105
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 106
    invoke-virtual {v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/analytics/i;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 107
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 108
    invoke-virtual {v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/analytics/i;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 109
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 110
    invoke-virtual {v0, p1, p2, p3}, Lcom/salesforce/marketingcloud/analytics/i;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    .line 111
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 112
    invoke-virtual {p0, p1, p2, p3}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;)V

    :cond_4
    return-void

    .line 113
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "messageId, activityInstanceId or reasons is null.  Call to onInAppMessageValidationError() ignored."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(Ljava/util/Map;)V
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Map<",
            "Ljava/lang/String;",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    .line 24
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 25
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Ljava/util/Map;)V

    .line 26
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 27
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Ljava/util/Map;)V

    .line 28
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 29
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Ljava/util/Map;)V

    .line 30
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 31
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->b(Ljava/util/Map;)V

    :cond_3
    return-void
.end method

.method public a(Lorg/json/JSONObject;)V
    .locals 1

    if-eqz p1, :cond_5

    .line 94
    invoke-virtual {p1}, Lorg/json/JSONObject;->length()I

    move-result v0

    if-gtz v0, :cond_0

    goto :goto_0

    .line 95
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 96
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lorg/json/JSONObject;)V

    .line 97
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 98
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lorg/json/JSONObject;)V

    .line 99
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 100
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lorg/json/JSONObject;)V

    .line 101
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 102
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lorg/json/JSONObject;)V

    :cond_4
    return-void

    .line 103
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Information not valid. Call to onInvalidConfigEvent() ignored"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public a(ILcom/salesforce/marketingcloud/toggles/a;)Z
    .locals 2

    const/16 v0, 0x100

    .line 1
    invoke-static {p1, v0}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result p1

    const/4 v0, 0x0

    if-eqz p1, :cond_0

    return v0

    .line 2
    :cond_0
    iput-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 3
    sget-object p1, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    if-eq p2, p1, :cond_1

    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled()Z

    move-result p1

    if-eqz p1, :cond_2

    sget-object p1, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    if-ne p2, p1, :cond_2

    :cond_1
    const/4 v0, 0x1

    :cond_2
    if-eqz v0, :cond_3

    .line 5
    new-instance p1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    invoke-direct {p1, p2, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    :cond_3
    return v0
.end method

.method public areAnalyticsEnabled()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

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
    const/16 v1, 0x100

    .line 12
    .line 13
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return v1

    .line 21
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "ETAnalyticsEnabled"

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-direct {p0, v0, v2}, Lcom/salesforce/marketingcloud/analytics/h;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 33
    .line 34
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 35
    .line 36
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 37
    .line 38
    if-eq v0, v2, :cond_3

    .line 39
    .line 40
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    .line 41
    .line 42
    if-ne v0, v2, :cond_2

    .line 43
    .line 44
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 45
    .line 46
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return v1

    .line 54
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 55
    return p0
.end method

.method public arePiAnalyticsEnabled()Z
    .locals 3

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

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
    const/16 v1, 0x200

    .line 12
    .line 13
    invoke-static {v0, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x0

    .line 18
    if-eqz v0, :cond_0

    .line 19
    .line 20
    return v1

    .line 21
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 22
    .line 23
    if-nez v0, :cond_1

    .line 24
    .line 25
    const-string v0, "PIAnalyticsEnabled"

    .line 26
    .line 27
    const/4 v2, 0x0

    .line 28
    invoke-direct {p0, v0, v2}, Lcom/salesforce/marketingcloud/analytics/h;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 33
    .line 34
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 35
    .line 36
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 37
    .line 38
    if-eq v0, v2, :cond_3

    .line 39
    .line 40
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->b:Lcom/salesforce/marketingcloud/toggles/a;

    .line 41
    .line 42
    if-ne v0, v2, :cond_2

    .line 43
    .line 44
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 45
    .line 46
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled()Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_2
    return v1

    .line 54
    :cond_3
    :goto_0
    const/4 p0, 0x1

    .line 55
    return p0
.end method

.method public b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V
    .locals 1

    if-nez p1, :cond_0

    .line 29
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "InAppMessage is null.  Call to onInAppMessageDownloaded() ignored."

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 30
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 31
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 32
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 33
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 34
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 35
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    .line 36
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 37
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->b(Lcom/salesforce/marketingcloud/messages/iam/InAppMessage;)V

    :cond_4
    return-void
.end method

.method public b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V
    .locals 1

    .line 21
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_0

    .line 22
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 23
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_1

    .line 24
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 25
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_2

    .line 26
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    .line 27
    :cond_2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_3

    .line 28
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/notifications/NotificationMessage;)V

    :cond_3
    return-void
.end method

.method public b(Lorg/json/JSONObject;)V
    .locals 1

    if-eqz p1, :cond_5

    .line 38
    invoke-virtual {p1}, Lorg/json/JSONObject;->length()I

    move-result v0

    if-gtz v0, :cond_0

    goto :goto_0

    .line 39
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 40
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lorg/json/JSONObject;)V

    .line 41
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 42
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lorg/json/JSONObject;)V

    .line 43
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 44
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lorg/json/JSONObject;)V

    .line 45
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 46
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->b(Lorg/json/JSONObject;)V

    :cond_4
    return-void

    .line 47
    :cond_5
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "Information not valid. Call to onSyncGateTimeOutEvent() ignored"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "AnalyticsManager"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 5

    .line 1
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    const-string v1, "bet_analytics"

    .line 7
    .line 8
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 9
    .line 10
    const/4 v3, 0x0

    .line 11
    const/4 v4, 0x1

    .line 12
    if-eqz v2, :cond_0

    .line 13
    .line 14
    move v2, v4

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    move v2, v3

    .line 17
    :goto_0
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    const-string v1, "et_analytics"

    .line 21
    .line 22
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 23
    .line 24
    if-eqz v2, :cond_1

    .line 25
    .line 26
    move v2, v4

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v2, v3

    .line 29
    :goto_1
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 30
    .line 31
    .line 32
    const-string v1, "pi_analytics"

    .line 33
    .line 34
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 35
    .line 36
    if-eqz v2, :cond_2

    .line 37
    .line 38
    move v2, v4

    .line 39
    goto :goto_2

    .line 40
    :cond_2
    move v2, v3

    .line 41
    :goto_2
    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 42
    .line 43
    .line 44
    const-string v1, "device_stats"

    .line 45
    .line 46
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 47
    .line 48
    if-eqz v2, :cond_3

    .line 49
    .line 50
    move v3, v4

    .line 51
    :cond_3
    invoke-virtual {v0, v1, v3}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;

    .line 52
    .line 53
    .line 54
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 55
    .line 56
    if-eqz v1, :cond_4

    .line 57
    .line 58
    const-string v2, "predictive_intelligence_identifier"

    .line 59
    .line 60
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->getPiIdentifier()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-virtual {v0, v2, v1}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 65
    .line 66
    .line 67
    :cond_4
    const-string v1, "analyticsEnabled"

    .line 68
    .line 69
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/h;->areAnalyticsEnabled()Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Z)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 74
    .line 75
    .line 76
    :catch_0
    return-object v0
.end method

.method public controlChannelInit(I)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p1

    .line 4
    .line 5
    const/16 v2, 0x100

    .line 6
    .line 7
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 8
    .line 9
    .line 10
    move-result v3

    .line 11
    const/16 v4, 0x800

    .line 12
    .line 13
    invoke-static {v1, v4}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 14
    .line 15
    .line 16
    move-result v5

    .line 17
    const/4 v6, 0x0

    .line 18
    const/4 v7, 0x0

    .line 19
    if-eqz v5, :cond_2

    .line 20
    .line 21
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 22
    .line 23
    if-eqz v5, :cond_0

    .line 24
    .line 25
    invoke-virtual {v5, v7}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Z)V

    .line 26
    .line 27
    .line 28
    iput-object v6, v0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 29
    .line 30
    :cond_0
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 31
    .line 32
    iget-object v8, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 33
    .line 34
    invoke-static {v1, v4}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 35
    .line 36
    .line 37
    move-result v9

    .line 38
    invoke-static {v5, v8, v9}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;Z)V

    .line 39
    .line 40
    .line 41
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 42
    .line 43
    if-eqz v5, :cond_1

    .line 44
    .line 45
    invoke-virtual {v5, v7}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Z)V

    .line 46
    .line 47
    .line 48
    iput-object v6, v0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 49
    .line 50
    :cond_1
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 51
    .line 52
    invoke-static {v1, v4}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    invoke-static {v5, v4}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Lcom/salesforce/marketingcloud/storage/h;Z)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_2
    new-instance v4, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 61
    .line 62
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 63
    .line 64
    iget-object v8, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 65
    .line 66
    invoke-direct {v4, v5, v8}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 67
    .line 68
    .line 69
    iput-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 70
    .line 71
    new-instance v9, Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 72
    .line 73
    iget-object v10, v0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 74
    .line 75
    iget-object v11, v0, Lcom/salesforce/marketingcloud/analytics/h;->h:Ljava/lang/String;

    .line 76
    .line 77
    invoke-virtual {v10}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled()Z

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    if-eqz v4, :cond_3

    .line 82
    .line 83
    if-nez v3, :cond_3

    .line 84
    .line 85
    const/4 v4, 0x1

    .line 86
    move v12, v4

    .line 87
    goto :goto_0

    .line 88
    :cond_3
    move v12, v7

    .line 89
    :goto_0
    iget-object v13, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 90
    .line 91
    iget-object v14, v0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 92
    .line 93
    iget-object v15, v0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 94
    .line 95
    iget-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 96
    .line 97
    move-object/from16 v16, v4

    .line 98
    .line 99
    invoke-direct/range {v9 .. v16}, Lcom/salesforce/marketingcloud/analytics/stats/c;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;ZLcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 100
    .line 101
    .line 102
    iput-object v9, v0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 103
    .line 104
    :goto_1
    if-eqz v3, :cond_5

    .line 105
    .line 106
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 107
    .line 108
    if-eqz v3, :cond_4

    .line 109
    .line 110
    invoke-virtual {v3, v7}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Z)V

    .line 111
    .line 112
    .line 113
    iput-object v6, v0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 114
    .line 115
    :cond_4
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 116
    .line 117
    iget-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 118
    .line 119
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    invoke-static {v3, v4, v2}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;Z)V

    .line 124
    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_5
    iget-object v2, v0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 128
    .line 129
    if-nez v2, :cond_6

    .line 130
    .line 131
    iget-object v2, v0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 132
    .line 133
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->analyticsEnabled()Z

    .line 134
    .line 135
    .line 136
    move-result v2

    .line 137
    if-eqz v2, :cond_6

    .line 138
    .line 139
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 140
    .line 141
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 142
    .line 143
    iget-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 144
    .line 145
    invoke-direct {v2, v3, v4}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 146
    .line 147
    .line 148
    iput-object v2, v0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 149
    .line 150
    :cond_6
    :goto_2
    const/16 v2, 0x200

    .line 151
    .line 152
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 153
    .line 154
    .line 155
    move-result v3

    .line 156
    if-eqz v3, :cond_8

    .line 157
    .line 158
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 159
    .line 160
    if-eqz v3, :cond_7

    .line 161
    .line 162
    invoke-virtual {v3, v7}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Z)V

    .line 163
    .line 164
    .line 165
    iput-object v6, v0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 166
    .line 167
    :cond_7
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 168
    .line 169
    iget-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 170
    .line 171
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 172
    .line 173
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/b;->c(II)Z

    .line 174
    .line 175
    .line 176
    move-result v1

    .line 177
    invoke-static {v3, v4, v5, v1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;Z)V

    .line 178
    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_8
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 182
    .line 183
    if-nez v1, :cond_9

    .line 184
    .line 185
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 186
    .line 187
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/MarketingCloudConfig;->piAnalyticsEnabled()Z

    .line 188
    .line 189
    .line 190
    move-result v1

    .line 191
    if-eqz v1, :cond_9

    .line 192
    .line 193
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 194
    .line 195
    iget-object v2, v0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 196
    .line 197
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 198
    .line 199
    iget-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 200
    .line 201
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 202
    .line 203
    invoke-direct {v1, v2, v3, v4, v5}, Lcom/salesforce/marketingcloud/analytics/piwama/i;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 204
    .line 205
    .line 206
    iput-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 207
    .line 208
    :cond_9
    :goto_3
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 209
    .line 210
    if-nez v1, :cond_b

    .line 211
    .line 212
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 213
    .line 214
    if-eqz v1, :cond_a

    .line 215
    .line 216
    goto :goto_4

    .line 217
    :cond_a
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 218
    .line 219
    sget-object v2, Lcom/salesforce/marketingcloud/alarms/a$a;->d:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 220
    .line 221
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 222
    .line 223
    .line 224
    move-result-object v2

    .line 225
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 226
    .line 227
    .line 228
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 229
    .line 230
    if-eqz v1, :cond_c

    .line 231
    .line 232
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->b()V

    .line 233
    .line 234
    .line 235
    iput-object v6, v0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 236
    .line 237
    return-void

    .line 238
    :cond_b
    :goto_4
    iget-object v1, v0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 239
    .line 240
    if-nez v1, :cond_c

    .line 241
    .line 242
    new-instance v2, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 243
    .line 244
    iget-object v3, v0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 245
    .line 246
    iget-object v4, v0, Lcom/salesforce/marketingcloud/analytics/h;->h:Ljava/lang/String;

    .line 247
    .line 248
    iget-object v5, v0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 249
    .line 250
    iget-object v6, v0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 251
    .line 252
    iget-object v7, v0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 253
    .line 254
    iget-object v8, v0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 255
    .line 256
    invoke-direct/range {v2 .. v8}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 257
    .line 258
    .line 259
    iput-object v2, v0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 260
    .line 261
    :cond_c
    return-void
.end method

.method public disableAnalytics()V
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/h;->u:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    sget-object v1, Lcom/salesforce/marketingcloud/toggles/a;->d:Lcom/salesforce/marketingcloud/toggles/a;

    .line 5
    .line 6
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 7
    .line 8
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 9
    .line 10
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    const-string v2, "ETAnalyticsEnabled"

    .line 19
    .line 20
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 21
    .line 22
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 31
    .line 32
    .line 33
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 34
    .line 35
    if-eqz v1, :cond_0

    .line 36
    .line 37
    const/4 v2, 0x1

    .line 38
    invoke-virtual {v1, v2}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Z)V

    .line 39
    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :catchall_0
    move-exception p0

    .line 46
    goto :goto_1

    .line 47
    :cond_0
    :goto_0
    monitor-exit v0

    .line 48
    return-void

    .line 49
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 50
    throw p0
.end method

.method public disablePiAnalytics()V
    .locals 5

    .line 1
    const-string v0, "Pi Analytics runtime toggle set to "

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/h;->u:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->d:Lcom/salesforce/marketingcloud/toggles/a;

    .line 7
    .line 8
    iput-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 9
    .line 10
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 11
    .line 12
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 13
    .line 14
    .line 15
    move-result-object v2

    .line 16
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 17
    .line 18
    .line 19
    move-result-object v2

    .line 20
    const-string v3, "PIAnalyticsEnabled"

    .line 21
    .line 22
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v4

    .line 28
    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 33
    .line 34
    .line 35
    sget-object v2, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 36
    .line 37
    new-instance v3, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 43
    .line 44
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v0

    .line 48
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    const/4 v3, 0x0

    .line 56
    new-array v3, v3, [Ljava/lang/Object;

    .line 57
    .line 58
    invoke-static {v2, v0, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 62
    .line 63
    if-eqz v0, :cond_0

    .line 64
    .line 65
    const/4 v2, 0x1

    .line 66
    invoke-virtual {v0, v2}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Z)V

    .line 67
    .line 68
    .line 69
    const/4 v0, 0x0

    .line 70
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :catchall_0
    move-exception p0

    .line 74
    goto :goto_1

    .line 75
    :cond_0
    :goto_0
    monitor-exit v1

    .line 76
    return-void

    .line 77
    :goto_1
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    throw p0
.end method

.method public enableAnalytics()V
    .locals 4

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/h;->u:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 5
    .line 6
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->j()Lcom/salesforce/marketingcloud/storage/d;

    .line 7
    .line 8
    .line 9
    move-result-object v1

    .line 10
    invoke-static {v1}, Lcom/salesforce/marketingcloud/b;->a(Lcom/salesforce/marketingcloud/storage/d;)I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    const/16 v2, 0x100

    .line 15
    .line 16
    invoke-static {v1, v2}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    .line 17
    .line 18
    .line 19
    move-result v1

    .line 20
    if-eqz v1, :cond_0

    .line 21
    .line 22
    monitor-exit v0

    .line 23
    return-void

    .line 24
    :catchall_0
    move-exception p0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    sget-object v1, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 27
    .line 28
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 29
    .line 30
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 31
    .line 32
    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 33
    .line 34
    .line 35
    move-result-object v1

    .line 36
    invoke-interface {v1}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    const-string v2, "ETAnalyticsEnabled"

    .line 41
    .line 42
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 43
    .line 44
    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    invoke-interface {v1, v2, v3}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 49
    .line 50
    .line 51
    move-result-object v1

    .line 52
    invoke-interface {v1}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 53
    .line 54
    .line 55
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 56
    .line 57
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 58
    .line 59
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 60
    .line 61
    invoke-direct {v1, v2, v3}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 62
    .line 63
    .line 64
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 65
    .line 66
    monitor-exit v0

    .line 67
    return-void

    .line 68
    :goto_0
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 69
    throw p0
.end method

.method public enablePiAnalytics()V
    .locals 6

    .line 1
    const-string v0, "Pi Analytics runtime toggle set to "

    .line 2
    .line 3
    sget-object v1, Lcom/salesforce/marketingcloud/analytics/h;->u:Ljava/lang/Object;

    .line 4
    .line 5
    monitor-enter v1

    .line 6
    :try_start_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

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
    const/16 v3, 0x200

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
    sget-object v2, Lcom/salesforce/marketingcloud/toggles/a;->c:Lcom/salesforce/marketingcloud/toggles/a;

    .line 29
    .line 30
    iput-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 31
    .line 32
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 33
    .line 34
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 35
    .line 36
    .line 37
    move-result-object v2

    .line 38
    invoke-interface {v2}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    const-string v3, "PIAnalyticsEnabled"

    .line 43
    .line 44
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 45
    .line 46
    invoke-virtual {v4}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v4

    .line 50
    invoke-interface {v2, v3, v4}, Landroid/content/SharedPreferences$Editor;->putString(Ljava/lang/String;Ljava/lang/String;)Landroid/content/SharedPreferences$Editor;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    .line 55
    .line 56
    .line 57
    sget-object v2, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 58
    .line 59
    new-instance v3, Ljava/lang/StringBuilder;

    .line 60
    .line 61
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 65
    .line 66
    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v0

    .line 77
    const/4 v3, 0x0

    .line 78
    new-array v3, v3, [Ljava/lang/Object;

    .line 79
    .line 80
    invoke-static {v2, v0, v3}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 84
    .line 85
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 86
    .line 87
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 88
    .line 89
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 90
    .line 91
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 92
    .line 93
    invoke-direct {v0, v2, v3, v4, v5}, Lcom/salesforce/marketingcloud/analytics/piwama/i;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 94
    .line 95
    .line 96
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 97
    .line 98
    monitor-exit v1

    .line 99
    return-void

    .line 100
    :goto_0
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 101
    throw p0
.end method

.method public getPiIdentifier()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->getPiIdentifier()Ljava/lang/String;

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

.method public init(Lcom/salesforce/marketingcloud/InitializationStatus$a;I)V
    .locals 8

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->q:Lcom/salesforce/marketingcloud/toggles/a;

    .line 2
    .line 3
    const-string v0, "ETAnalyticsEnabled"

    .line 4
    .line 5
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/analytics/h;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    invoke-virtual {p0, p2, p1}, Lcom/salesforce/marketingcloud/analytics/h;->a(ILcom/salesforce/marketingcloud/toggles/a;)Z

    .line 10
    .line 11
    .line 12
    move-result v3

    .line 13
    const/16 p1, 0x800

    .line 14
    .line 15
    invoke-static {p2, p1}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 16
    .line 17
    .line 18
    move-result p1

    .line 19
    if-eqz p1, :cond_0

    .line 20
    .line 21
    new-instance p1, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 22
    .line 23
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 24
    .line 25
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 26
    .line 27
    invoke-direct {p1, v0, v1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;-><init>(Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 28
    .line 29
    .line 30
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 31
    .line 32
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 33
    .line 34
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 35
    .line 36
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->h:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 39
    .line 40
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 41
    .line 42
    iget-object v6, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 43
    .line 44
    iget-object v7, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 45
    .line 46
    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/analytics/stats/c;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;ZLcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 47
    .line 48
    .line 49
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 50
    .line 51
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->r:Lcom/salesforce/marketingcloud/toggles/a;

    .line 52
    .line 53
    const-string v0, "PIAnalyticsEnabled"

    .line 54
    .line 55
    invoke-direct {p0, v0, p1}, Lcom/salesforce/marketingcloud/analytics/h;->a(Ljava/lang/String;Lcom/salesforce/marketingcloud/toggles/a;)Lcom/salesforce/marketingcloud/toggles/a;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    invoke-direct {p0, p2, p1}, Lcom/salesforce/marketingcloud/analytics/h;->b(ILcom/salesforce/marketingcloud/toggles/a;)V

    .line 60
    .line 61
    .line 62
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 63
    .line 64
    if-nez p1, :cond_1

    .line 65
    .line 66
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 67
    .line 68
    if-eqz p1, :cond_2

    .line 69
    .line 70
    :cond_1
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 71
    .line 72
    iget-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->i:Lcom/salesforce/marketingcloud/MarketingCloudConfig;

    .line 73
    .line 74
    iget-object v2, p0, Lcom/salesforce/marketingcloud/analytics/h;->h:Ljava/lang/String;

    .line 75
    .line 76
    iget-object v3, p0, Lcom/salesforce/marketingcloud/analytics/h;->d:Lcom/salesforce/marketingcloud/storage/h;

    .line 77
    .line 78
    iget-object v4, p0, Lcom/salesforce/marketingcloud/analytics/h;->g:Lcom/salesforce/marketingcloud/http/e;

    .line 79
    .line 80
    iget-object v5, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 81
    .line 82
    iget-object v6, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 83
    .line 84
    invoke-direct/range {v0 .. v6}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;-><init>(Lcom/salesforce/marketingcloud/MarketingCloudConfig;Ljava/lang/String;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/http/e;Lcom/salesforce/marketingcloud/alarms/b;Lcom/salesforce/marketingcloud/internal/n;)V

    .line 85
    .line 86
    .line 87
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 88
    .line 89
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 90
    .line 91
    iget-object p2, p0, Lcom/salesforce/marketingcloud/analytics/h;->f:Ljava/util/EnumSet;

    .line 92
    .line 93
    invoke-virtual {p1, p0, p2}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 94
    .line 95
    .line 96
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 97
    .line 98
    sget-object p2, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 99
    .line 100
    filled-new-array {p2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    invoke-virtual {p1, p0, p2}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 105
    .line 106
    .line 107
    return-void
.end method

.method public onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/analytics/h$b;->a:[I

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    aget p1, v0, p1

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p1, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p1, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x3

    .line 16
    if-eq p1, v0, :cond_0

    .line 17
    .line 18
    const/4 v0, 0x4

    .line 19
    if-eq p1, v0, :cond_0

    .line 20
    .line 21
    return-void

    .line 22
    :cond_0
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/analytics/h;->c(Landroid/os/Bundle;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :cond_1
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/analytics/h;->b(Landroid/os/Bundle;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    :cond_2
    invoke-direct {p0, p2}, Lcom/salesforce/marketingcloud/analytics/h;->a(Landroid/os/Bundle;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method

.method public onTransitionEvent(ILcom/salesforce/marketingcloud/messages/Region;)V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    if-eq p1, v0, :cond_4

    .line 3
    .line 4
    const/4 v0, 0x2

    .line 5
    if-eq p1, v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 9
    .line 10
    if-eqz p1, :cond_1

    .line 11
    .line 12
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 13
    .line 14
    .line 15
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 16
    .line 17
    if-eqz p1, :cond_2

    .line 18
    .line 19
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->b(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 20
    .line 21
    .line 22
    :cond_2
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 23
    .line 24
    if-eqz p1, :cond_3

    .line 25
    .line 26
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 27
    .line 28
    .line 29
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 30
    .line 31
    if-eqz p0, :cond_8

    .line 32
    .line 33
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/analytics/i;->b(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :cond_4
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 38
    .line 39
    if-eqz p1, :cond_5

    .line 40
    .line 41
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 42
    .line 43
    .line 44
    :cond_5
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 45
    .line 46
    if-eqz p1, :cond_6

    .line 47
    .line 48
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 49
    .line 50
    .line 51
    :cond_6
    iget-object p1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 52
    .line 53
    if-eqz p1, :cond_7

    .line 54
    .line 55
    invoke-virtual {p1, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 56
    .line 57
    .line 58
    :cond_7
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 59
    .line 60
    if-eqz p0, :cond_8

    .line 61
    .line 62
    invoke-virtual {p0, p2}, Lcom/salesforce/marketingcloud/analytics/i;->a(Lcom/salesforce/marketingcloud/messages/Region;)V

    .line 63
    .line 64
    .line 65
    :cond_8
    :goto_0
    return-void
.end method

.method public setPiIdentifier(Ljava/lang/String;)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-static {p1}, Landroid/text/TextUtils;->getTrimmedLength(Ljava/lang/CharSequence;)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 10
    .line 11
    const/4 p1, 0x0

    .line 12
    new-array p1, p1, [Ljava/lang/Object;

    .line 13
    .line 14
    const-string v0, "Call to setPiIdentifier() ignored. Predictive Intelligence Identifier contained only whitespace."

    .line 15
    .line 16
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :cond_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 21
    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->setPiIdentifier(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    :cond_1
    return-void
.end method

.method public tearDown(Z)V
    .locals 2

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->j:Lcom/salesforce/marketingcloud/alarms/b;

    .line 7
    .line 8
    sget-object v1, Lcom/salesforce/marketingcloud/alarms/a$a;->l:Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 9
    .line 10
    filled-new-array {v1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 11
    .line 12
    .line 13
    move-result-object v1

    .line 14
    invoke-virtual {v0, v1}, Lcom/salesforce/marketingcloud/alarms/b;->e([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 18
    .line 19
    const/4 v1, 0x0

    .line 20
    if-eqz v0, :cond_0

    .line 21
    .line 22
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/a;->a(Z)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 26
    .line 27
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 28
    .line 29
    if-eqz v0, :cond_1

    .line 30
    .line 31
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/etanalytics/b;->a(Z)V

    .line 32
    .line 33
    .line 34
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 35
    .line 36
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 37
    .line 38
    if-eqz v0, :cond_2

    .line 39
    .line 40
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/analytics/etanalytics/c;->b()V

    .line 41
    .line 42
    .line 43
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->o:Lcom/salesforce/marketingcloud/analytics/etanalytics/c;

    .line 44
    .line 45
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 46
    .line 47
    if-eqz v0, :cond_3

    .line 48
    .line 49
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/stats/c;->a(Z)V

    .line 50
    .line 51
    .line 52
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 53
    .line 54
    :cond_3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 55
    .line 56
    if-eqz v0, :cond_4

    .line 57
    .line 58
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->a(Z)V

    .line 59
    .line 60
    .line 61
    iput-object v1, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 62
    .line 63
    :cond_4
    return-void
.end method

.method public trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string v0, "PiCart may not be null.  We could not complete your trackCartContents() request."

    .line 9
    .line 10
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V

    .line 19
    .line 20
    .line 21
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 29
    .line 30
    if-eqz v0, :cond_3

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V

    .line 33
    .line 34
    .line 35
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 36
    .line 37
    if-eqz p0, :cond_4

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->trackCartContents(Lcom/salesforce/marketingcloud/analytics/PiCart;)V

    .line 40
    .line 41
    .line 42
    :cond_4
    return-void
.end method

.method public trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    new-array p1, p1, [Ljava/lang/Object;

    .line 7
    .line 8
    const-string v0, "PiOrder may not be null.  We could not complete your trackCartConversion() request."

    .line 9
    .line 10
    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    .line 15
    .line 16
    if-eqz v0, :cond_1

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V

    .line 19
    .line 20
    .line 21
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    .line 22
    .line 23
    if-eqz v0, :cond_2

    .line 24
    .line 25
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V

    .line 26
    .line 27
    .line 28
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    .line 29
    .line 30
    if-eqz v0, :cond_3

    .line 31
    .line 32
    invoke-virtual {v0, p1}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V

    .line 33
    .line 34
    .line 35
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    .line 36
    .line 37
    if-eqz p0, :cond_4

    .line 38
    .line 39
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/analytics/i;->trackCartConversion(Lcom/salesforce/marketingcloud/analytics/PiOrder;)V

    .line 40
    .line 41
    .line 42
    :cond_4
    return-void
.end method

.method public trackInboxOpenEvent(Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->p:Lcom/salesforce/marketingcloud/internal/n;

    .line 2
    .line 3
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/internal/n;->b()Ljava/util/concurrent/ExecutorService;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    new-instance v1, Lcom/salesforce/marketingcloud/analytics/h$a;

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    new-array v2, v2, [Ljava/lang/Object;

    .line 11
    .line 12
    const-string v3, "track_inbox_open"

    .line 13
    .line 14
    invoke-direct {v1, p0, v3, v2, p1}, Lcom/salesforce/marketingcloud/analytics/h$a;-><init>(Lcom/salesforce/marketingcloud/analytics/h;Ljava/lang/String;[Ljava/lang/Object;Lcom/salesforce/marketingcloud/messages/inbox/InboxMessage;)V

    .line 15
    .line 16
    .line 17
    invoke-interface {v0, v1}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public trackPageView(Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    invoke-virtual {p0, p1, v0, v0, v0}, Lcom/salesforce/marketingcloud/analytics/h;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public trackPageView(Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, p1, p2, v0, v0}, Lcom/salesforce/marketingcloud/analytics/h;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const/4 v0, 0x0

    .line 3
    invoke-virtual {p0, p1, p2, p3, v0}, Lcom/salesforce/marketingcloud/analytics/h;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    return-void
.end method

.method public trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    .line 4
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_0

    .line 5
    sget-object p0, Lcom/salesforce/marketingcloud/analytics/AnalyticsManager;->TAG:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string p2, "url may not be null or empty.  We could not complete your trackPageView() request."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->l:Lcom/salesforce/marketingcloud/analytics/etanalytics/a;

    if-eqz v0, :cond_1

    .line 7
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 8
    :cond_1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->k:Lcom/salesforce/marketingcloud/analytics/etanalytics/b;

    if-eqz v0, :cond_2

    .line 9
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    :cond_2
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/h;->m:Lcom/salesforce/marketingcloud/analytics/piwama/i;

    if-eqz v0, :cond_3

    .line 11
    invoke-virtual {v0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/piwama/i;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 12
    :cond_3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/h;->n:Lcom/salesforce/marketingcloud/analytics/stats/c;

    if-eqz p0, :cond_4

    .line 13
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/salesforce/marketingcloud/analytics/i;->trackPageView(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    :cond_4
    return-void
.end method

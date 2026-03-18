.class public final Lcom/salesforce/marketingcloud/analytics/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/analytics/b$b;,
        Lcom/salesforce/marketingcloud/analytics/b$a;
    }
.end annotation


# static fields
.field public static final A:Ljava/lang/String; = "objectIds"

.field public static final B:Ljava/lang/String; = "platform"

.field public static final C:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field public static final D:I = 0x0

.field public static final E:I = 0x1

.field private static final F:Ljava/lang/String; = "~!AnalyticItem"

.field public static final a:I = 0x2

.field public static final b:I = 0x3

.field public static final c:I = 0x4

.field public static final d:I = 0x5

.field public static final e:I = 0x5

.field public static final f:I = 0x6

.field public static final g:I = 0x7

.field public static final h:I = 0xa

.field public static final i:I = 0xb

.field public static final j:I = 0xc

.field public static final k:I = 0xd

.field public static final l:I = 0xe

.field public static final m:I = 0xf

.field public static final n:I = 0x10

.field public static final o:I = 0x11

.field public static final p:I = 0x15b38

.field public static final q:I = 0x378

.field public static final r:I = 0x22b8

.field public static final s:Ljava/lang/String; = "uuid"

.field public static final t:Ljava/lang/String; = "requestId"

.field public static final u:Ljava/lang/String; = "propertyBag"

.field public static final v:Ljava/lang/String; = "etAppId"

.field public static final w:Ljava/lang/String; = "deviceId"

.field public static final x:Ljava/lang/String; = "eventDate"

.field public static final y:Ljava/lang/String; = "value"

.field public static final z:Ljava/lang/String; = "analyticTypes"


# instance fields
.field private final G:Ljava/util/Date;

.field private final H:I

.field private final I:I

.field private final J:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field private final K:Ljava/lang/String;

.field private L:Ljava/lang/String;

.field private M:I

.field private N:I

.field private O:Z

.field private P:Ljava/lang/String;

.field private Q:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    const/4 v0, 0x3

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    const/16 v1, 0xe

    .line 7
    .line 8
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    filled-new-array {v0, v1}, [Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    sput-object v0, Lcom/salesforce/marketingcloud/analytics/b;->C:Ljava/util/List;

    .line 25
    .line 26
    return-void
.end method

.method private constructor <init>(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;ZLjava/lang/String;)V
    .locals 4
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Date;",
            "II",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Z",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/analytics/b;->J:Ljava/util/List;

    .line 10
    .line 11
    const-string v1, "The Date is null."

    .line 12
    .line 13
    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    check-cast p1, Ljava/util/Date;

    .line 18
    .line 19
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->G:Ljava/util/Date;

    .line 20
    .line 21
    const/4 p1, 0x0

    .line 22
    const/4 v1, 0x1

    .line 23
    if-eqz p2, :cond_1

    .line 24
    .line 25
    if-ne p2, v1, :cond_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v2, p1

    .line 29
    goto :goto_1

    .line 30
    :cond_1
    :goto_0
    move v2, v1

    .line 31
    :goto_1
    const-string v3, "The Product Type must be one of AnalyticProductType"

    .line 32
    .line 33
    invoke-static {v2, v3}, Lcom/salesforce/marketingcloud/util/g;->a(ZLjava/lang/String;)Z

    .line 34
    .line 35
    .line 36
    iput p2, p0, Lcom/salesforce/marketingcloud/analytics/b;->H:I

    .line 37
    .line 38
    if-lez p3, :cond_2

    .line 39
    .line 40
    move p1, v1

    .line 41
    :cond_2
    const-string p2, "AnalyticType must be a valid int > 0."

    .line 42
    .line 43
    invoke-static {p1, p2}, Lcom/salesforce/marketingcloud/util/g;->a(ZLjava/lang/String;)Z

    .line 44
    .line 45
    .line 46
    iput p3, p0, Lcom/salesforce/marketingcloud/analytics/b;->I:I

    .line 47
    .line 48
    if-eqz p4, :cond_3

    .line 49
    .line 50
    invoke-interface {p4}, Ljava/util/List;->isEmpty()Z

    .line 51
    .line 52
    .line 53
    move-result p1

    .line 54
    if-nez p1, :cond_3

    .line 55
    .line 56
    invoke-virtual {v0, p4}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 57
    .line 58
    .line 59
    :cond_3
    iput-object p5, p0, Lcom/salesforce/marketingcloud/analytics/b;->K:Ljava/lang/String;

    .line 60
    .line 61
    invoke-direct {p0, p7}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->Q:Ljava/lang/String;

    .line 66
    .line 67
    iput-boolean p6, p0, Lcom/salesforce/marketingcloud/analytics/b;->O:Z

    .line 68
    .line 69
    return-void
.end method

.method public static a(Ljava/util/Date;II)Lcom/salesforce/marketingcloud/analytics/b;
    .locals 6

    .line 1
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move v1, p1

    move v2, p2

    invoke-static/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p0

    return-object p0
.end method

.method public static a(Ljava/util/Date;IILcom/salesforce/marketingcloud/notifications/NotificationMessage;Z)Lcom/salesforce/marketingcloud/analytics/b;
    .locals 8

    .line 4
    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4}, Ljava/util/ArrayList;-><init>()V

    .line 5
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->id()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->region()Lcom/salesforce/marketingcloud/messages/Region;

    move-result-object v0

    if-eqz v0, :cond_0

    .line 7
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/messages/Region;->id()Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 8
    :cond_0
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/b;

    .line 9
    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->requestId()Ljava/lang/String;

    move-result-object v5

    invoke-virtual {p3}, Lcom/salesforce/marketingcloud/notifications/NotificationMessage;->propertyBag()Ljava/lang/String;

    move-result-object v7

    move-object v1, p0

    move v2, p1

    move v3, p2

    move v6, p4

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/analytics/b;-><init>(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    return-object v0
.end method

.method public static a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;
    .locals 8
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Date;",
            "II",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;",
            "Ljava/lang/String;",
            "Z)",
            "Lcom/salesforce/marketingcloud/analytics/b;"
        }
    .end annotation

    .line 3
    new-instance v0, Lcom/salesforce/marketingcloud/analytics/b;

    const/4 v7, 0x0

    move-object v1, p0

    move v2, p1

    move v3, p2

    move-object v4, p3

    move-object v5, p4

    move v6, p5

    invoke-direct/range {v0 .. v7}, Lcom/salesforce/marketingcloud/analytics/b;-><init>(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;ZLjava/lang/String;)V

    return-object v0
.end method

.method public static a(Ljava/util/Date;IILjava/util/List;Z)Lcom/salesforce/marketingcloud/analytics/b;
    .locals 6
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/Date;",
            "II",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;Z)",
            "Lcom/salesforce/marketingcloud/analytics/b;"
        }
    .end annotation

    const/4 v4, 0x0

    move-object v0, p0

    move v1, p1

    move v2, p2

    move-object v3, p3

    move v5, p4

    .line 2
    invoke-static/range {v0 .. v5}, Lcom/salesforce/marketingcloud/analytics/b;->a(Ljava/util/Date;IILjava/util/List;Ljava/lang/String;Z)Lcom/salesforce/marketingcloud/analytics/b;

    move-result-object p0

    return-object p0
.end method

.method private a(Ljava/lang/String;)Ljava/lang/String;
    .locals 3

    .line 10
    new-instance v0, Lorg/json/JSONObject;

    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 11
    :try_start_0
    const-string v1, "uuid"

    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v2

    invoke-virtual {v0, v1, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 12
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->K:Ljava/lang/String;

    if-eqz p0, :cond_0

    .line 13
    const-string v1, "requestId"

    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 14
    :cond_0
    :goto_0
    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result p0

    if-eqz p0, :cond_1

    .line 15
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0

    .line 16
    :cond_1
    new-instance p0, Lorg/json/JSONObject;

    invoke-direct {p0, p1}, Lorg/json/JSONObject;-><init>(Ljava/lang/String;)V

    .line 17
    const-string p1, "propertyBag"

    invoke-virtual {v0, p1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    goto :goto_2

    :goto_1
    const/4 p1, 0x0

    .line 18
    new-array p1, p1, [Ljava/lang/Object;

    const-string v1, "~!AnalyticItem"

    const-string v2, "unable to build et json payload"

    invoke-static {v1, p0, v2, p1}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 19
    :goto_2
    invoke-virtual {v0}, Lorg/json/JSONObject;->toString()Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method


# virtual methods
.method public a()I
    .locals 0

    .line 21
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->I:I

    return p0
.end method

.method public a(I)V
    .locals 0

    .line 20
    iput p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->M:I

    return-void
.end method

.method public a(Z)V
    .locals 0

    .line 22
    iput-boolean p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->O:Z

    return-void
.end method

.method public b()Ljava/util/Date;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->G:Ljava/util/Date;

    return-object p0
.end method

.method public b(I)V
    .locals 0

    .line 2
    iput p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->N:I

    return-void
.end method

.method public b(Ljava/lang/String;)V
    .locals 0

    .line 3
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->Q:Ljava/lang/String;

    return-void
.end method

.method public c()Ljava/lang/String;
    .locals 0

    .line 2
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->Q:Ljava/lang/String;

    return-object p0
.end method

.method public c(Ljava/lang/String;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->P:Ljava/lang/String;

    return-void
.end method

.method public d()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->M:I

    return p0
.end method

.method public d(Ljava/lang/String;)V
    .locals 0

    .line 2
    iput-object p1, p0, Lcom/salesforce/marketingcloud/analytics/b;->L:Ljava/lang/String;

    return-void
.end method

.method public e()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->P:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public f()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->L:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public g()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->N:I

    .line 2
    .line 3
    return p0
.end method

.method public h()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->O:Z

    .line 2
    .line 3
    return p0
.end method

.method public i()Ljava/util/List;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/analytics/b;->J:Ljava/util/List;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->J:Ljava/util/List;

    .line 5
    .line 6
    monitor-exit v0

    .line 7
    return-object p0

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

.method public j()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->H:I

    .line 2
    .line 3
    return p0
.end method

.method public k()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/analytics/b;->K:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.class public Lcom/salesforce/marketingcloud/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/d;
.implements Lcom/salesforce/marketingcloud/k$f;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/b$c;,
        Lcom/salesforce/marketingcloud/b$b;,
        Lcom/salesforce/marketingcloud/b$a;
    }
.end annotation


# static fields
.field public static final i:I = 0x0

.field public static final j:I = 0x1

.field public static final k:I = 0x2

.field public static final l:I = 0x4

.field public static final m:I = 0x8

.field public static final n:I = 0x10

.field public static final o:I = 0x20

.field public static final p:I = 0x40

.field public static final q:I = 0x80

.field public static final r:I = 0x100

.field public static final s:I = 0x200

.field public static final t:I = 0x400

.field public static final u:I = 0x800

.field public static final v:I = 0x1000

.field private static final w:I = 0x1


# instance fields
.field private final d:Lcom/salesforce/marketingcloud/storage/d;

.field private final e:Lcom/salesforce/marketingcloud/k;

.field private f:Lcom/salesforce/marketingcloud/b$b;

.field private g:Lcom/salesforce/marketingcloud/b$c;

.field private h:Lcom/salesforce/marketingcloud/b$c;


# direct methods
.method public constructor <init>(Lcom/salesforce/marketingcloud/k;Lcom/salesforce/marketingcloud/storage/d;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/b;->e:Lcom/salesforce/marketingcloud/k;

    .line 5
    .line 6
    iput-object p2, p0, Lcom/salesforce/marketingcloud/b;->d:Lcom/salesforce/marketingcloud/storage/d;

    .line 7
    .line 8
    invoke-static {p2}, Lcom/salesforce/marketingcloud/b;->b(Lcom/salesforce/marketingcloud/storage/d;)Lcom/salesforce/marketingcloud/b$c;

    .line 9
    .line 10
    .line 11
    move-result-object p2

    .line 12
    iput-object p2, p0, Lcom/salesforce/marketingcloud/b;->h:Lcom/salesforce/marketingcloud/b$c;

    .line 13
    .line 14
    sget-object v0, Lcom/salesforce/marketingcloud/b$c;->c:Lcom/salesforce/marketingcloud/b$c;

    .line 15
    .line 16
    if-eq p2, v0, :cond_0

    .line 17
    .line 18
    sget-object p2, Lcom/salesforce/marketingcloud/k$e;->b:Lcom/salesforce/marketingcloud/k$e;

    .line 19
    .line 20
    invoke-virtual {p1, p2, p0}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    .line 21
    .line 22
    .line 23
    :cond_0
    return-void
.end method

.method public static a(Lcom/salesforce/marketingcloud/storage/d;)I
    .locals 0

    .line 2
    invoke-static {p0}, Lcom/salesforce/marketingcloud/b;->b(Lcom/salesforce/marketingcloud/storage/d;)Lcom/salesforce/marketingcloud/b$c;

    move-result-object p0

    iget p0, p0, Lcom/salesforce/marketingcloud/b$c;->b:I

    return p0
.end method

.method private declared-synchronized a(I)V
    .locals 3

    monitor-enter p0

    .line 9
    :try_start_0
    sget-object v0, Lcom/salesforce/marketingcloud/b$c;->c:Lcom/salesforce/marketingcloud/b$c;

    iget v1, v0, Lcom/salesforce/marketingcloud/b$c;->b:I

    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result v1

    if-eqz v1, :cond_0

    goto :goto_0

    .line 10
    :cond_0
    sget-object v0, Lcom/salesforce/marketingcloud/b$c;->d:Lcom/salesforce/marketingcloud/b$c;

    iget v1, v0, Lcom/salesforce/marketingcloud/b$c;->b:I

    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result v1

    if-eqz v1, :cond_1

    goto :goto_0

    .line 11
    :cond_1
    sget-object v0, Lcom/salesforce/marketingcloud/b$c;->e:Lcom/salesforce/marketingcloud/b$c;

    iget v1, v0, Lcom/salesforce/marketingcloud/b$c;->b:I

    invoke-static {p1, v1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result v1

    if-eqz v1, :cond_2

    goto :goto_0

    .line 12
    :cond_2
    sget-object v0, Lcom/salesforce/marketingcloud/b$c;->f:Lcom/salesforce/marketingcloud/b$c;

    .line 13
    :goto_0
    sget-object v1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    const-string v2, "Control Channel blocked value %d received"

    invoke-static {v1, v2, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 14
    iget-object p1, p0, Lcom/salesforce/marketingcloud/b;->d:Lcom/salesforce/marketingcloud/storage/d;

    invoke-virtual {v0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v1

    invoke-virtual {p1, v1}, Lcom/salesforce/marketingcloud/storage/d;->b(Ljava/lang/String;)V

    .line 15
    iget-object p1, p0, Lcom/salesforce/marketingcloud/b;->h:Lcom/salesforce/marketingcloud/b$c;

    if-eq v0, p1, :cond_4

    .line 16
    iget-object p1, p0, Lcom/salesforce/marketingcloud/b;->f:Lcom/salesforce/marketingcloud/b$b;

    if-eqz p1, :cond_3

    .line 17
    iput-object v0, p0, Lcom/salesforce/marketingcloud/b;->h:Lcom/salesforce/marketingcloud/b$c;

    .line 18
    iget v0, v0, Lcom/salesforce/marketingcloud/b$c;->b:I

    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/b$b;->a(I)V

    goto :goto_1

    :catchall_0
    move-exception p1

    goto :goto_2

    .line 19
    :cond_3
    iput-object v0, p0, Lcom/salesforce/marketingcloud/b;->g:Lcom/salesforce/marketingcloud/b$c;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    :cond_4
    :goto_1
    monitor-exit p0

    return-void

    :goto_2
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public static a(II)Z
    .locals 0

    .line 1
    and-int/2addr p0, p1

    if-ne p0, p1, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method private static b(Lcom/salesforce/marketingcloud/storage/d;)Lcom/salesforce/marketingcloud/b$c;
    .locals 1

    const/4 v0, 0x0

    .line 2
    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/storage/d;->a(Ljava/lang/String;)Ljava/lang/String;

    move-result-object p0

    if-eqz p0, :cond_0

    .line 3
    invoke-static {p0}, Lcom/salesforce/marketingcloud/b$c;->a(Ljava/lang/String;)Lcom/salesforce/marketingcloud/b$c;

    move-result-object p0

    return-object p0

    .line 4
    :cond_0
    sget-object p0, Lcom/salesforce/marketingcloud/b$c;->f:Lcom/salesforce/marketingcloud/b$c;

    return-object p0
.end method

.method public static b(II)Z
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/b;->a(II)Z

    move-result p0

    xor-int/lit8 p0, p0, 0x1

    return p0
.end method

.method public static c(II)Z
    .locals 2

    .line 1
    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/b;->b(II)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_0

    .line 7
    .line 8
    return v1

    .line 9
    :cond_0
    const/4 v0, 0x1

    .line 10
    sparse-switch p1, :sswitch_data_0

    .line 11
    .line 12
    .line 13
    return v1

    .line 14
    :sswitch_0
    return v0

    .line 15
    :sswitch_1
    sget-object p1, Lcom/salesforce/marketingcloud/b$c;->d:Lcom/salesforce/marketingcloud/b$c;

    .line 16
    .line 17
    iget p1, p1, Lcom/salesforce/marketingcloud/b$c;->b:I

    .line 18
    .line 19
    if-eq p1, p0, :cond_1

    .line 20
    .line 21
    return v0

    .line 22
    :cond_1
    return v1

    .line 23
    :sswitch_data_0
    .sparse-switch
        0x2 -> :sswitch_1
        0x4 -> :sswitch_0
        0x8 -> :sswitch_0
        0x10 -> :sswitch_0
        0x20 -> :sswitch_0
        0x40 -> :sswitch_0
        0x80 -> :sswitch_0
        0x100 -> :sswitch_1
        0x200 -> :sswitch_1
        0x800 -> :sswitch_1
        0x1000 -> :sswitch_0
    .end sparse-switch
.end method


# virtual methods
.method public a()I
    .locals 0

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/b;->h:Lcom/salesforce/marketingcloud/b$c;

    iget p0, p0, Lcom/salesforce/marketingcloud/b$c;->b:I

    return p0
.end method

.method public declared-synchronized a(Lcom/salesforce/marketingcloud/b$b;)V
    .locals 2

    monitor-enter p0

    .line 4
    :try_start_0
    iput-object p1, p0, Lcom/salesforce/marketingcloud/b;->f:Lcom/salesforce/marketingcloud/b$b;

    if-eqz p1, :cond_0

    .line 5
    iget-object v0, p0, Lcom/salesforce/marketingcloud/b;->g:Lcom/salesforce/marketingcloud/b$c;

    if-eqz v0, :cond_0

    .line 6
    iput-object v0, p0, Lcom/salesforce/marketingcloud/b;->h:Lcom/salesforce/marketingcloud/b$c;

    const/4 v1, 0x0

    .line 7
    iput-object v1, p0, Lcom/salesforce/marketingcloud/b;->g:Lcom/salesforce/marketingcloud/b$c;

    .line 8
    iget v0, v0, Lcom/salesforce/marketingcloud/b$c;->b:I

    invoke-interface {p1, v0}, Lcom/salesforce/marketingcloud/b$b;->a(I)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    monitor-exit p0

    return-void

    :goto_1
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    throw p1
.end method

.method public componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "ControlChannel"

    .line 2
    .line 3
    return-object p0
.end method

.method public componentState()Lorg/json/JSONObject;
    .locals 2

    .line 1
    :try_start_0
    new-instance v0, Lorg/json/JSONObject;

    .line 2
    .line 3
    invoke-direct {v0}, Lorg/json/JSONObject;-><init>()V

    .line 4
    .line 5
    .line 6
    const-string v1, "flag"

    .line 7
    .line 8
    iget-object p0, p0, Lcom/salesforce/marketingcloud/b;->h:Lcom/salesforce/marketingcloud/b$c;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {v0, v1, p0}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 15
    .line 16
    .line 17
    move-result-object p0
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 18
    return-object p0

    .line 19
    :catch_0
    const/4 p0, 0x0

    .line 20
    return-object p0
.end method

.method public onSyncReceived(Lcom/salesforce/marketingcloud/k$e;Lorg/json/JSONObject;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->b:Lcom/salesforce/marketingcloud/k$e;

    .line 2
    .line 3
    if-ne p1, v0, :cond_0

    .line 4
    .line 5
    const-string p1, "version"

    .line 6
    .line 7
    const/4 v0, -0x1

    .line 8
    invoke-virtual {p2, p1, v0}, Lorg/json/JSONObject;->optInt(Ljava/lang/String;I)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    const/4 v0, 0x1

    .line 13
    if-ne p1, v0, :cond_0

    .line 14
    .line 15
    :try_start_0
    const-string p1, "items"

    .line 16
    .line 17
    invoke-virtual {p2, p1}, Lorg/json/JSONObject;->getJSONObject(Ljava/lang/String;)Lorg/json/JSONObject;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    const-string p2, "blocked"

    .line 22
    .line 23
    invoke-virtual {p1, p2}, Lorg/json/JSONObject;->getInt(Ljava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result p1

    .line 27
    invoke-direct {p0, p1}, Lcom/salesforce/marketingcloud/b;->a(I)V
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 28
    .line 29
    .line 30
    return-void

    .line 31
    :catch_0
    move-exception p0

    .line 32
    sget-object p1, Lcom/salesforce/marketingcloud/MarketingCloudSdk;->v:Ljava/lang/String;

    .line 33
    .line 34
    const/4 p2, 0x0

    .line 35
    new-array p2, p2, [Ljava/lang/Object;

    .line 36
    .line 37
    const-string v0, "Failed to parse [blocked] sync data."

    .line 38
    .line 39
    invoke-static {p1, p0, v0, p2}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    :cond_0
    return-void
.end method

.method public tearDown(Z)V
    .locals 2

    .line 1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/b;->e:Lcom/salesforce/marketingcloud/k;

    .line 2
    .line 3
    sget-object v0, Lcom/salesforce/marketingcloud/k$e;->b:Lcom/salesforce/marketingcloud/k$e;

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-virtual {p1, v0, v1}, Lcom/salesforce/marketingcloud/k;->a(Lcom/salesforce/marketingcloud/k$e;Lcom/salesforce/marketingcloud/k$f;)V

    .line 7
    .line 8
    .line 9
    iput-object v1, p0, Lcom/salesforce/marketingcloud/b;->f:Lcom/salesforce/marketingcloud/b$b;

    .line 10
    .line 11
    return-void
.end method

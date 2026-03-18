.class public Lcom/salesforce/marketingcloud/alarms/b;
.super Lcom/salesforce/marketingcloud/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcom/salesforce/marketingcloud/behaviors/b;


# annotations
.annotation build Landroid/annotation/SuppressLint;
    value = {
        "UnknownNullness"
    }
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/salesforce/marketingcloud/alarms/b$c;,
        Lcom/salesforce/marketingcloud/alarms/b$b;
    }
.end annotation


# static fields
.field public static final j:Ljava/lang/String; = "com.salesforce.marketingcloud.ACTION_ALARM_WAKE_EVENT"

.field public static final k:Ljava/lang/String; = "com.salesforce.marketingcloud.WAKE_FOR_ALARM"

.field static final l:Ljava/lang/String; = "pending_alarms"

.field static final m:Ljava/lang/String;

.field private static final n:J


# instance fields
.field private final d:Ljava/util/Map;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/Map<",
            "Lcom/salesforce/marketingcloud/alarms/a$a;",
            "Lcom/salesforce/marketingcloud/alarms/b$b;",
            ">;"
        }
    .end annotation
.end field

.field private final e:Lcom/salesforce/marketingcloud/behaviors/c;

.field f:Landroid/content/BroadcastReceiver;

.field private g:Landroid/content/Context;

.field private h:Lcom/salesforce/marketingcloud/storage/h;

.field private i:Landroid/content/SharedPreferences;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "AlarmScheduler"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lcom/salesforce/marketingcloud/storage/h;Lcom/salesforce/marketingcloud/behaviors/c;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Lcom/salesforce/marketingcloud/f;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/HashMap;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->d:Ljava/util/Map;

    .line 10
    .line 11
    iput-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    .line 12
    .line 13
    iput-object p2, p0, Lcom/salesforce/marketingcloud/alarms/b;->h:Lcom/salesforce/marketingcloud/storage/h;

    .line 14
    .line 15
    const-string p1, "BehaviorManager is null"

    .line 16
    .line 17
    invoke-static {p3, p1}, Lcom/salesforce/marketingcloud/util/g;->a(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Lcom/salesforce/marketingcloud/behaviors/c;

    .line 22
    .line 23
    iput-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 24
    .line 25
    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    .line 30
    .line 31
    return-void
.end method

.method private static a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/Integer;)Landroid/app/PendingIntent;
    .locals 1

    const/high16 v0, 0x8000000

    .line 1
    invoke-static {v0}, Lcom/salesforce/marketingcloud/util/j;->a(I)I

    move-result v0

    .line 2
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    move-result p2

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/MCReceiver;->a(Landroid/content/Context;Ljava/lang/String;)Landroid/content/Intent;

    move-result-object p1

    invoke-static {p0, p2, p1, v0}, Landroid/app/PendingIntent;->getBroadcast(Landroid/content/Context;ILandroid/content/Intent;I)Landroid/app/PendingIntent;

    move-result-object p0

    return-object p0
.end method

.method private a(J)V
    .locals 11

    .line 51
    invoke-static {}, Lcom/salesforce/marketingcloud/alarms/a$a;->values()[Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    array-length v1, v0

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_2

    aget-object v5, v0, v2

    .line 52
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v3

    .line 53
    iget-object v4, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/alarms/a;->a()Ljava/lang/String;

    move-result-object v6

    const-wide/16 v7, 0x0

    invoke-interface {v4, v6, v7, v8}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide v9

    cmp-long v4, v9, v7

    if-lez v4, :cond_1

    .line 54
    invoke-virtual {p0, v5, p1, p2}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;J)Z

    move-result v4

    if-eqz v4, :cond_0

    .line 55
    iget-object v4, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/alarms/a;->c()Ljava/lang/String;

    move-result-object v6

    .line 56
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/alarms/a;->d()J

    move-result-wide v7

    .line 57
    invoke-interface {v4, v6, v7, v8}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide v6

    .line 58
    iget-object v4, p0, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    move-object v3, p0

    move-wide v8, v9

    invoke-virtual/range {v3 .. v9}, Lcom/salesforce/marketingcloud/alarms/b;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/alarms/a$a;JJ)V

    goto :goto_1

    :cond_0
    move-object v3, p0

    .line 59
    invoke-virtual {v3, v5}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;)V

    goto :goto_1

    :cond_1
    move-object v3, p0

    :goto_1
    add-int/lit8 v2, v2, 0x1

    move-object p0, v3

    goto :goto_0

    :cond_2
    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/alarms/a$a;JJ)V
    .locals 3

    .line 31
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "Setting the %s Alarm Flag ..."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 32
    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    invoke-interface {p0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    .line 33
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/alarms/a;->a()Ljava/lang/String;

    move-result-object v0

    invoke-interface {p0, v0, p2, p3}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    .line 34
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a;->c()Ljava/lang/String;

    move-result-object p1

    invoke-interface {p0, p1, p4, p5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object p0

    .line 35
    invoke-interface {p0}, Landroid/content/SharedPreferences$Editor;->apply()V

    return-void
.end method

.method private a(Lcom/salesforce/marketingcloud/alarms/a$a;Z)Z
    .locals 11

    .line 15
    iget-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->h:Lcom/salesforce/marketingcloud/storage/h;

    invoke-virtual {p1, v0}, Lcom/salesforce/marketingcloud/alarms/a$a;->a(Lcom/salesforce/marketingcloud/storage/h;)Z

    move-result v0

    const/4 v1, 0x0

    if-nez v0, :cond_0

    .line 16
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    .line 17
    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    filled-new-array {p1}, [Ljava/lang/Object;

    move-result-object p1

    .line 18
    const-string p2, "shouldCreateAlarm() for %s Alarm was FALSE.  Aborting alarm creation."

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1

    .line 19
    :cond_0
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v4

    .line 20
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->b(Lcom/salesforce/marketingcloud/alarms/a$a;)J

    move-result-wide v6

    .line 21
    invoke-virtual {p0, p1, v4, v5}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;J)Z

    move-result v0

    if-nez v0, :cond_2

    .line 22
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v1

    filled-new-array {v1}, [Ljava/lang/Object;

    move-result-object v1

    const-string v2, "No pending %s Alarm. Creating one ..."

    invoke-static {v0, v2, v1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    move-object v2, p0

    move-object v3, p1

    .line 23
    invoke-direct/range {v2 .. v7}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;JJ)V

    .line 24
    iget-object p0, v2, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    if-eqz p2, :cond_1

    const-wide/16 v6, 0x3e8

    :cond_1
    move-wide v9, v6

    move-wide v7, v4

    move-wide v5, v9

    move-object v4, v3

    move-object v3, p0

    invoke-virtual/range {v2 .. v8}, Lcom/salesforce/marketingcloud/alarms/b;->a(Landroid/content/Context;Lcom/salesforce/marketingcloud/alarms/a$a;JJ)V

    const/4 p0, 0x1

    return p0

    :cond_2
    move-object v2, p0

    move-object v3, p1

    if-eqz p2, :cond_3

    return v1

    .line 25
    :cond_3
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {v3}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    new-instance p2, Ljava/util/Date;

    iget-object v0, v2, Lcom/salesforce/marketingcloud/alarms/b;->h:Lcom/salesforce/marketingcloud/storage/h;

    .line 26
    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/storage/h;->e()Landroid/content/SharedPreferences;

    move-result-object v0

    .line 27
    invoke-virtual {v3}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v2

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/alarms/a;->a()Ljava/lang/String;

    move-result-object v2

    const-wide/16 v3, 0x0

    invoke-interface {v0, v2, v3, v4}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide v2

    add-long/2addr v2, v6

    invoke-direct {p2, v2, v3}, Ljava/util/Date;-><init>(J)V

    .line 28
    invoke-static {p2}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p2

    filled-new-array {p1, p2}, [Ljava/lang/Object;

    move-result-object p1

    const-string p2, "%s Send Pending ... will send at %s"

    invoke-static {p0, p2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return v1
.end method


# virtual methods
.method public a(Landroid/content/Context;Lcom/salesforce/marketingcloud/alarms/a$a;JJ)V
    .locals 2
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "MissingPermission"
        }
    .end annotation

    .line 41
    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {p2}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/alarms/a;->b()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {p1, p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/Integer;)Landroid/app/PendingIntent;

    move-result-object p0

    .line 42
    const-string v0, "alarm"

    invoke-virtual {p1, v0}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Landroid/app/AlarmManager;

    add-long/2addr p5, p3

    .line 43
    new-instance p3, Ljava/util/Date;

    invoke-direct {p3, p5, p6}, Ljava/util/Date;-><init>(J)V

    invoke-static {p3}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    move-result-object p3

    .line 44
    :try_start_0
    sget p4, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v0, 0x1f

    const/4 v1, 0x0

    if-lt p4, v0, :cond_1

    .line 45
    invoke-static {p1}, Lc4/a;->A(Landroid/app/AlarmManager;)Z

    move-result p4

    if-eqz p4, :cond_0

    .line 46
    invoke-virtual {p1, v1, p5, p6, p0}, Landroid/app/AlarmManager;->setExact(IJLandroid/app/PendingIntent;)V

    goto :goto_0

    :catch_0
    move-exception p0

    goto :goto_1

    .line 47
    :cond_0
    invoke-virtual {p1, v1, p5, p6, p0}, Landroid/app/AlarmManager;->set(IJLandroid/app/PendingIntent;)V

    goto :goto_0

    .line 48
    :cond_1
    invoke-virtual {p1, v1, p5, p6, p0}, Landroid/app/AlarmManager;->setExact(IJLandroid/app/PendingIntent;)V

    .line 49
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    const-string p1, "%s Alarm scheduled to wake at %s."

    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p4

    filled-new-array {p4, p3}, [Ljava/lang/Object;

    move-result-object p4

    invoke-static {p0, p1, p4}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    .line 50
    :goto_1
    sget-object p1, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {p2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p2

    filled-new-array {p2, p3}, [Ljava/lang/Object;

    move-result-object p2

    const-string p3, "Failed to schedule alarm %s for %s"

    invoke-static {p1, p0, p3, p2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public final a(Lcom/salesforce/marketingcloud/InitializationStatus$a;)V
    .locals 2

    .line 8
    iget-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    sget-object v0, Lcom/salesforce/marketingcloud/behaviors/a;->f:Lcom/salesforce/marketingcloud/behaviors/a;

    sget-object v1, Lcom/salesforce/marketingcloud/behaviors/a;->h:Lcom/salesforce/marketingcloud/behaviors/a;

    .line 9
    invoke-static {v0, v1}, Ljava/util/EnumSet;->of(Ljava/lang/Enum;Ljava/lang/Enum;)Ljava/util/EnumSet;

    move-result-object v0

    .line 10
    invoke-virtual {p1, p0, v0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;Ljava/util/EnumSet;)V

    .line 11
    new-instance p1, Lcom/salesforce/marketingcloud/alarms/b$c;

    invoke-direct {p1, p0}, Lcom/salesforce/marketingcloud/alarms/b$c;-><init>(Lcom/salesforce/marketingcloud/alarms/b;)V

    iput-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->f:Landroid/content/BroadcastReceiver;

    .line 12
    new-instance p1, Landroid/content/IntentFilter;

    invoke-direct {p1}, Landroid/content/IntentFilter;-><init>()V

    .line 13
    const-string v0, "com.salesforce.marketingcloud.ACTION_ALARM_WAKE_EVENT"

    invoke-virtual {p1, v0}, Landroid/content/IntentFilter;->addAction(Ljava/lang/String;)V

    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/b;->f:Landroid/content/BroadcastReceiver;

    const/4 v1, 0x4

    invoke-static {v0, p0, p1, v1}, Ln5/a;->d(Landroid/content/Context;Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;I)V

    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 1

    .line 60
    filled-new-array {p1}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    move-result-object v0

    invoke-virtual {p0, v0}, Lcom/salesforce/marketingcloud/alarms/b;->a([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 61
    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/b;->d:Ljava/util/Map;

    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lcom/salesforce/marketingcloud/alarms/b$b;

    if-eqz p0, :cond_0

    .line 62
    invoke-interface {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b$b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;)V

    :cond_0
    return-void
.end method

.method public varargs a(Lcom/salesforce/marketingcloud/alarms/b$b;[Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 5
    .annotation build Landroid/annotation/SuppressLint;
        value = {
            "LambdaLast"
        }
    .end annotation

    .line 3
    iget-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->d:Ljava/util/Map;

    monitor-enter v0

    .line 4
    :try_start_0
    array-length v1, p2

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v1, :cond_0

    aget-object v3, p2, v2

    .line 5
    iget-object v4, p0, Lcom/salesforce/marketingcloud/alarms/b;->d:Ljava/util/Map;

    invoke-interface {v4, v3, p1}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :catchall_0
    move-exception p0

    goto :goto_1

    .line 6
    :cond_0
    monitor-exit v0

    return-void

    .line 7
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw p0
.end method

.method public varargs a([Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 6

    .line 36
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    aget-object v2, p1, v1

    .line 37
    sget-object v3, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    const-string v5, "Resetting %s Alarm Active Flag to FALSE"

    invoke-static {v3, v5, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 38
    iget-object v3, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    invoke-interface {v3}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v3

    .line 39
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v2

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/alarms/a;->a()Ljava/lang/String;

    move-result-object v2

    const-wide/16 v4, 0x0

    invoke-interface {v3, v2, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object v2

    .line 40
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public a(Lcom/salesforce/marketingcloud/alarms/a$a;J)Z
    .locals 4

    .line 29
    iget-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v1

    invoke-virtual {v1}, Lcom/salesforce/marketingcloud/alarms/a;->a()Ljava/lang/String;

    move-result-object v1

    const-wide/16 v2, 0x0

    invoke-interface {v0, v1, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide v0

    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    .line 30
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object p1

    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a;->c()Ljava/lang/String;

    move-result-object p1

    invoke-interface {p0, p1, v2, v3}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide p0

    sub-long/2addr p2, p0

    cmp-long p0, v0, p2

    if-lez p0, :cond_0

    const/4 p0, 0x1

    return p0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final b(Lcom/salesforce/marketingcloud/alarms/a$a;)J
    .locals 5

    .line 3
    iget-object p0, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    .line 4
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/alarms/a;->c()Ljava/lang/String;

    move-result-object v0

    const-wide/16 v1, 0x0

    invoke-interface {p0, v0, v1, v2}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    move-result-wide v3

    cmp-long p0, v3, v1

    if-nez p0, :cond_0

    .line 5
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/alarms/a;->d()J

    move-result-wide v0

    goto :goto_0

    :cond_0
    long-to-double v0, v3

    .line 6
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/alarms/a;->e()D

    move-result-wide v2

    mul-double/2addr v2, v0

    double-to-long v0, v2

    .line 7
    :goto_0
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/alarms/a;->f()J

    move-result-wide v2

    cmp-long p0, v0, v2

    if-lez p0, :cond_1

    .line 8
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object p0

    invoke-virtual {p0}, Lcom/salesforce/marketingcloud/alarms/a;->f()J

    move-result-wide v0

    .line 9
    sget-object p0, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {p1}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object p1

    .line 10
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v2

    filled-new-array {p1, v2}, [Ljava/lang/Object;

    move-result-object p1

    .line 11
    const-string v2, "%s MAX INTERVAL exceeded. Setting interval to %s milliseconds."

    invoke-static {p0, v2, p1}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    :cond_1
    return-wide v0
.end method

.method public varargs b([Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 4

    .line 1
    array-length v0, p1

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    if-ge v2, v0, :cond_0

    aget-object v3, p1, v2

    .line 2
    invoke-direct {p0, v3, v1}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;Z)Z

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public varargs c([Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 6

    .line 2
    array-length v0, p1

    const/4 v1, 0x0

    :goto_0
    if-ge v1, v0, :cond_0

    aget-object v2, p1, v1

    .line 3
    sget-object v3, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    move-result-object v4

    filled-new-array {v4}, [Ljava/lang/Object;

    move-result-object v4

    const-string v5, "Resetting %s Alarm Interval."

    invoke-static {v3, v5, v4}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 4
    iget-object v3, p0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    invoke-interface {v3}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object v3

    .line 5
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v2

    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/alarms/a;->c()Ljava/lang/String;

    move-result-object v2

    const-wide/16 v4, 0x0

    invoke-interface {v3, v2, v4, v5}, Landroid/content/SharedPreferences$Editor;->putLong(Ljava/lang/String;J)Landroid/content/SharedPreferences$Editor;

    move-result-object v2

    .line 6
    invoke-interface {v2}, Landroid/content/SharedPreferences$Editor;->apply()V

    add-int/lit8 v1, v1, 0x1

    goto :goto_0

    :cond_0
    return-void
.end method

.method public c(Lcom/salesforce/marketingcloud/alarms/a$a;)Z
    .locals 1

    .line 1
    invoke-virtual {p1}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    move-result-object v0

    invoke-virtual {v0}, Lcom/salesforce/marketingcloud/alarms/a;->g()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    invoke-direct {p0, p1, v0}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;Z)Z

    move-result p0

    if-eqz p0, :cond_0

    return v0

    :cond_0
    const/4 p0, 0x0

    return p0
.end method

.method public final componentName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "AlarmScheduler"

    .line 2
    .line 3
    return-object p0
.end method

.method public final componentState()Lorg/json/JSONObject;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lorg/json/JSONObject;

    .line 4
    .line 5
    invoke-direct {v1}, Lorg/json/JSONObject;-><init>()V

    .line 6
    .line 7
    .line 8
    new-instance v2, Lorg/json/JSONObject;

    .line 9
    .line 10
    invoke-direct {v2}, Lorg/json/JSONObject;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 14
    .line 15
    .line 16
    move-result-wide v3

    .line 17
    :try_start_0
    invoke-static {}, Lcom/salesforce/marketingcloud/alarms/a$a;->values()[Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 18
    .line 19
    .line 20
    move-result-object v6

    .line 21
    array-length v7, v6

    .line 22
    const/4 v8, 0x0

    .line 23
    :goto_0
    if-ge v8, v7, :cond_1

    .line 24
    .line 25
    aget-object v9, v6, v8

    .line 26
    .line 27
    invoke-virtual {v0, v9, v3, v4}, Lcom/salesforce/marketingcloud/alarms/b;->a(Lcom/salesforce/marketingcloud/alarms/a$a;J)Z

    .line 28
    .line 29
    .line 30
    move-result v10

    .line 31
    if-eqz v10, :cond_0

    .line 32
    .line 33
    invoke-virtual {v9}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v10

    .line 37
    new-instance v11, Ljava/util/Date;

    .line 38
    .line 39
    iget-object v12, v0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    .line 40
    .line 41
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    .line 42
    .line 43
    .line 44
    move-result-object v13

    .line 45
    invoke-virtual {v13}, Lcom/salesforce/marketingcloud/alarms/a;->a()Ljava/lang/String;

    .line 46
    .line 47
    .line 48
    move-result-object v13

    .line 49
    const-wide/16 v14, 0x0

    .line 50
    .line 51
    invoke-interface {v12, v13, v14, v15}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 52
    .line 53
    .line 54
    move-result-wide v12

    .line 55
    iget-object v5, v0, Lcom/salesforce/marketingcloud/alarms/b;->i:Landroid/content/SharedPreferences;

    .line 56
    .line 57
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    .line 58
    .line 59
    .line 60
    move-result-object v9

    .line 61
    invoke-virtual {v9}, Lcom/salesforce/marketingcloud/alarms/a;->c()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v9

    .line 65
    invoke-interface {v5, v9, v14, v15}, Landroid/content/SharedPreferences;->getLong(Ljava/lang/String;J)J

    .line 66
    .line 67
    .line 68
    move-result-wide v14

    .line 69
    add-long/2addr v12, v14

    .line 70
    invoke-direct {v11, v12, v13}, Ljava/util/Date;-><init>(J)V

    .line 71
    .line 72
    .line 73
    invoke-static {v11}, Lcom/salesforce/marketingcloud/util/j;->a(Ljava/util/Date;)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v5

    .line 77
    invoke-virtual {v2, v10, v5}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;

    .line 78
    .line 79
    .line 80
    goto :goto_1

    .line 81
    :catch_0
    move-exception v0

    .line 82
    goto :goto_2

    .line 83
    :cond_0
    :goto_1
    add-int/lit8 v8, v8, 0x1

    .line 84
    .line 85
    goto :goto_0

    .line 86
    :cond_1
    const-string v0, "pending_alarms"

    .line 87
    .line 88
    invoke-virtual {v1, v0, v2}, Lorg/json/JSONObject;->put(Ljava/lang/String;Ljava/lang/Object;)Lorg/json/JSONObject;
    :try_end_0
    .catch Lorg/json/JSONException; {:try_start_0 .. :try_end_0} :catch_0

    .line 89
    .line 90
    .line 91
    return-object v1

    .line 92
    :goto_2
    sget-object v2, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    .line 93
    .line 94
    const/4 v3, 0x0

    .line 95
    new-array v3, v3, [Ljava/lang/Object;

    .line 96
    .line 97
    const-string v4, "Failed to generate Component State JSONObject."

    .line 98
    .line 99
    invoke-static {v2, v0, v4, v3}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    return-object v1
.end method

.method public varargs d([Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 6

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    :goto_0
    if-ge v1, v0, :cond_0

    .line 4
    .line 5
    aget-object v2, p1, v1

    .line 6
    .line 7
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    invoke-virtual {p0, v3}, Lcom/salesforce/marketingcloud/alarms/b;->c([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 12
    .line 13
    .line 14
    filled-new-array {v2}, [Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 15
    .line 16
    .line 17
    move-result-object v3

    .line 18
    invoke-virtual {p0, v3}, Lcom/salesforce/marketingcloud/alarms/b;->a([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 19
    .line 20
    .line 21
    iget-object v3, p0, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v4

    .line 27
    invoke-virtual {v2}, Lcom/salesforce/marketingcloud/alarms/a$a;->b()Lcom/salesforce/marketingcloud/alarms/a;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/alarms/a;->b()I

    .line 32
    .line 33
    .line 34
    move-result v5

    .line 35
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object v5

    .line 39
    invoke-static {v3, v4, v5}, Lcom/salesforce/marketingcloud/alarms/b;->a(Landroid/content/Context;Ljava/lang/String;Ljava/lang/Integer;)Landroid/app/PendingIntent;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    :try_start_0
    iget-object v4, p0, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    .line 44
    .line 45
    const-string v5, "alarm"

    .line 46
    .line 47
    invoke-virtual {v4, v5}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v4

    .line 51
    check-cast v4, Landroid/app/AlarmManager;

    .line 52
    .line 53
    invoke-virtual {v4, v3}, Landroid/app/AlarmManager;->cancel(Landroid/app/PendingIntent;)V

    .line 54
    .line 55
    .line 56
    sget-object v3, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    .line 57
    .line 58
    const-string v4, "Reset %s alarm."

    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v5

    .line 64
    filled-new-array {v5}, [Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object v5

    .line 68
    invoke-static {v3, v4, v5}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 69
    .line 70
    .line 71
    goto :goto_1

    .line 72
    :catch_0
    move-exception v3

    .line 73
    sget-object v4, Lcom/salesforce/marketingcloud/alarms/b;->m:Ljava/lang/String;

    .line 74
    .line 75
    invoke-virtual {v2}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    filled-new-array {v2}, [Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v2

    .line 83
    const-string v5, "Could not cancel %s alarm."

    .line 84
    .line 85
    invoke-static {v4, v3, v5, v2}, Lcom/salesforce/marketingcloud/g;->e(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 86
    .line 87
    .line 88
    :goto_1
    add-int/lit8 v1, v1, 0x1

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_0
    return-void
.end method

.method public varargs e([Lcom/salesforce/marketingcloud/alarms/a$a;)V
    .locals 5

    .line 1
    iget-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->d:Ljava/util/Map;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    array-length v1, p1

    .line 5
    const/4 v2, 0x0

    .line 6
    :goto_0
    if-ge v2, v1, :cond_0

    .line 7
    .line 8
    aget-object v3, p1, v2

    .line 9
    .line 10
    iget-object v4, p0, Lcom/salesforce/marketingcloud/alarms/b;->d:Ljava/util/Map;

    .line 11
    .line 12
    invoke-interface {v4, v3}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    add-int/lit8 v2, v2, 0x1

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    goto :goto_1

    .line 20
    :cond_0
    monitor-exit v0

    .line 21
    return-void

    .line 22
    :goto_1
    monitor-exit v0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    throw p0
.end method

.method public final onBehavior(Lcom/salesforce/marketingcloud/behaviors/a;Landroid/os/Bundle;)V
    .locals 1

    .line 1
    sget-object v0, Lcom/salesforce/marketingcloud/alarms/b$a;->a:[I

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
    if-eq p1, v0, :cond_0

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p1, v0, :cond_0

    .line 14
    .line 15
    return-void

    .line 16
    :cond_0
    const-string p1, "timestamp"

    .line 17
    .line 18
    invoke-virtual {p2, p1}, Landroid/os/BaseBundle;->getLong(Ljava/lang/String;)J

    .line 19
    .line 20
    .line 21
    move-result-wide p1

    .line 22
    invoke-direct {p0, p1, p2}, Lcom/salesforce/marketingcloud/alarms/b;->a(J)V

    .line 23
    .line 24
    .line 25
    return-void
.end method

.method public final tearDown(Z)V
    .locals 1

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    invoke-static {}, Lcom/salesforce/marketingcloud/alarms/a$a;->values()[Lcom/salesforce/marketingcloud/alarms/a$a;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p0, p1}, Lcom/salesforce/marketingcloud/alarms/b;->d([Lcom/salesforce/marketingcloud/alarms/a$a;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->g:Landroid/content/Context;

    .line 11
    .line 12
    if-eqz p1, :cond_1

    .line 13
    .line 14
    iget-object v0, p0, Lcom/salesforce/marketingcloud/alarms/b;->f:Landroid/content/BroadcastReceiver;

    .line 15
    .line 16
    invoke-virtual {p1, v0}, Landroid/content/Context;->unregisterReceiver(Landroid/content/BroadcastReceiver;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    iget-object p1, p0, Lcom/salesforce/marketingcloud/alarms/b;->e:Lcom/salesforce/marketingcloud/behaviors/c;

    .line 20
    .line 21
    invoke-virtual {p1, p0}, Lcom/salesforce/marketingcloud/behaviors/c;->a(Lcom/salesforce/marketingcloud/behaviors/b;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method

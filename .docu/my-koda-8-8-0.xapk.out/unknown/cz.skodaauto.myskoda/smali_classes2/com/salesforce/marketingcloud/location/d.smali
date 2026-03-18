.class Lcom/salesforce/marketingcloud/location/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/f;


# static fields
.field static final e:Ljava/lang/String;


# instance fields
.field private final a:Landroid/content/Context;

.field volatile b:Z

.field c:I

.field d:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "GmsLocationProvider"

    .line 2
    .line 3
    invoke-static {v0}, Lcom/salesforce/marketingcloud/g;->a(Ljava/lang/String;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    .line 5
    .line 6
    sget-object v0, Ljo/e;->d:Ljo/e;

    .line 7
    .line 8
    sget v1, Ljo/f;->a:I

    .line 9
    .line 10
    invoke-virtual {v0, p1, v1}, Ljo/f;->c(Landroid/content/Context;I)I

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    iput p1, p0, Lcom/salesforce/marketingcloud/location/d;->c:I

    .line 15
    .line 16
    sget-object v0, Ljo/h;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    .line 17
    .line 18
    invoke-static {p1}, Ljo/b;->x0(I)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    iput-object p1, p0, Lcom/salesforce/marketingcloud/location/d;->d:Ljava/lang/String;

    .line 23
    .line 24
    iget p1, p0, Lcom/salesforce/marketingcloud/location/d;->c:I

    .line 25
    .line 26
    if-eqz p1, :cond_1

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    if-eq p1, v0, :cond_1

    .line 30
    .line 31
    const/4 v0, 0x2

    .line 32
    if-eq p1, v0, :cond_1

    .line 33
    .line 34
    const/4 v0, 0x3

    .line 35
    if-eq p1, v0, :cond_1

    .line 36
    .line 37
    const/16 v0, 0x9

    .line 38
    .line 39
    if-ne p1, v0, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    new-instance p1, Lcom/salesforce/marketingcloud/location/g;

    .line 43
    .line 44
    iget p0, p0, Lcom/salesforce/marketingcloud/location/d;->c:I

    .line 45
    .line 46
    invoke-static {p0}, Ljo/b;->x0(I)Ljava/lang/String;

    .line 47
    .line 48
    .line 49
    move-result-object v0

    .line 50
    invoke-direct {p1, p0, v0}, Lcom/salesforce/marketingcloud/location/g;-><init>(ILjava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p1

    .line 54
    :cond_1
    :goto_0
    return-void
.end method

.method private static a(Lcom/salesforce/marketingcloud/location/b;)Lpp/a;
    .locals 16

    .line 1
    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->j()I

    move-result v0

    const/4 v1, 0x1

    and-int/2addr v0, v1

    const/4 v2, 0x0

    if-ne v0, v1, :cond_0

    move v0, v1

    goto :goto_0

    :cond_0
    move v0, v2

    .line 2
    :goto_0
    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->j()I

    move-result v3

    const/4 v4, 0x2

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_1

    or-int/lit8 v0, v0, 0x2

    .line 3
    :cond_1
    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->j()I

    move-result v3

    const/4 v4, 0x4

    and-int/2addr v3, v4

    if-ne v3, v4, :cond_2

    or-int/lit8 v0, v0, 0x4

    :cond_2
    move v5, v0

    .line 4
    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->f()Ljava/lang/String;

    move-result-object v4

    .line 5
    const-string v0, "Request ID can\'t be set to null"

    invoke-static {v4, v0}, Lno/c0;->i(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->g()D

    move-result-wide v7

    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->h()D

    move-result-wide v9

    invoke-virtual/range {p0 .. p0}, Lcom/salesforce/marketingcloud/location/b;->i()F

    move-result v11

    const-wide v12, -0x3fa9800000000000L    # -90.0

    cmpg-double v0, v7, v12

    if-ltz v0, :cond_3

    const-wide v12, 0x4056800000000000L    # 90.0

    cmpg-double v0, v7, v12

    if-gtz v0, :cond_3

    move v0, v1

    goto :goto_1

    :cond_3
    move v0, v2

    .line 7
    :goto_1
    invoke-static {v7, v8}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    new-instance v6, Ljava/lang/StringBuilder;

    add-int/lit8 v3, v3, 0x12

    invoke-direct {v6, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v3, "Invalid latitude: "

    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v7, v8}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v0, v3}, Lno/c0;->b(ZLjava/lang/String;)V

    const-wide v12, -0x3f99800000000000L    # -180.0

    cmpg-double v0, v9, v12

    if-ltz v0, :cond_4

    const-wide v12, 0x4066800000000000L    # 180.0

    cmpg-double v0, v9, v12

    if-gtz v0, :cond_4

    move v0, v1

    goto :goto_2

    :cond_4
    move v0, v2

    .line 8
    :goto_2
    invoke-static {v9, v10}, Ljava/lang/String;->valueOf(D)Ljava/lang/String;

    move-result-object v3

    invoke-virtual {v3}, Ljava/lang/String;->length()I

    move-result v3

    new-instance v6, Ljava/lang/StringBuilder;

    add-int/lit8 v3, v3, 0x13

    invoke-direct {v6, v3}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v3, "Invalid longitude: "

    invoke-virtual {v6, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v9, v10}, Ljava/lang/StringBuilder;->append(D)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v3

    invoke-static {v0, v3}, Lno/c0;->b(ZLjava/lang/String;)V

    const/4 v0, 0x0

    cmpl-float v0, v11, v0

    if-lez v0, :cond_5

    goto :goto_3

    :cond_5
    move v1, v2

    .line 9
    :goto_3
    invoke-static {v11}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/String;->length()I

    move-result v0

    new-instance v2, Ljava/lang/StringBuilder;

    add-int/lit8 v0, v0, 0x10

    invoke-direct {v2, v0}, Ljava/lang/StringBuilder;-><init>(I)V

    const-string v0, "Invalid radius: "

    invoke-virtual {v2, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v11}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-static {v1, v0}, Lno/c0;->b(ZLjava/lang/String;)V

    if-eqz v5, :cond_7

    and-int/lit8 v0, v5, 0x4

    if-nez v0, :cond_6

    .line 10
    new-instance v3, Lgp/k;

    const/4 v14, 0x0

    const/4 v15, -0x1

    const/4 v6, 0x1

    const-wide/16 v12, -0x1

    invoke-direct/range {v3 .. v15}, Lgp/k;-><init>(Ljava/lang/String;ISDDFJII)V

    return-object v3

    .line 11
    :cond_6
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Non-negative loitering delay needs to be set when transition types include GEOFENCE_TRANSITION_DWELL."

    .line 12
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    .line 13
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    const-string v1, "Transitions types not set."

    .line 14
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0
.end method


# virtual methods
.method public a()V
    .locals 6

    .line 54
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    sget v0, Lpp/d;->a:I

    .line 55
    new-instance v0, Lgp/a;

    .line 56
    sget-object v5, Lko/h;->c:Lko/h;

    const/4 v2, 0x0

    .line 57
    sget-object v3, Lgp/a;->n:Lc2/k;

    sget-object v4, Lko/b;->a:Lko/a;

    invoke-direct/range {v0 .. v5}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 58
    iget-object v1, p0, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    .line 59
    invoke-static {v1}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->b(Landroid/content/Context;)Landroid/app/PendingIntent;

    move-result-object v1

    .line 60
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    move-result-object v2

    new-instance v3, Lbu/c;

    const/16 v4, 0x18

    invoke-direct {v3, v1, v4}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 61
    iput-object v3, v2, Lh6/i;->d:Ljava/lang/Object;

    const/16 v1, 0x979

    .line 62
    iput v1, v2, Lh6/i;->b:I

    .line 63
    invoke-virtual {v2}, Lh6/i;->a()Lbp/s;

    move-result-object v1

    const/4 v2, 0x1

    .line 64
    invoke-virtual {v0, v2, v1}, Lko/i;->e(ILhr/b0;)Laq/t;

    move-result-object v0

    .line 65
    invoke-virtual {v0, p0}, Laq/t;->l(Laq/f;)Laq/t;

    return-void
.end method

.method public a(Ljava/util/List;)V
    .locals 7
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;)V"
        }
    .end annotation

    if-eqz p1, :cond_1

    .line 42
    invoke-interface {p1}, Ljava/util/List;->size()I

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    .line 43
    :cond_0
    iget-object v2, p0, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    sget v0, Lpp/d;->a:I

    .line 44
    new-instance v1, Lgp/a;

    .line 45
    sget-object v6, Lko/h;->c:Lko/h;

    const/4 v3, 0x0

    .line 46
    sget-object v4, Lgp/a;->n:Lc2/k;

    sget-object v5, Lko/b;->a:Lko/a;

    invoke-direct/range {v1 .. v6}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 47
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    move-result-object v0

    new-instance v2, Ld01/s;

    invoke-direct {v2, p1}, Ld01/s;-><init>(Ljava/util/List;)V

    .line 48
    iput-object v2, v0, Lh6/i;->d:Ljava/lang/Object;

    const/16 p1, 0x979

    .line 49
    iput p1, v0, Lh6/i;->b:I

    .line 50
    invoke-virtual {v0}, Lh6/i;->a()Lbp/s;

    move-result-object p1

    const/4 v0, 0x1

    .line 51
    invoke-virtual {v1, v0, p1}, Lko/i;->e(ILhr/b0;)Laq/t;

    move-result-object p1

    .line 52
    invoke-virtual {p1, p0}, Laq/t;->l(Laq/f;)Laq/t;

    return-void

    .line 53
    :cond_1
    :goto_0
    sget-object p0, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    const/4 p1, 0x0

    new-array p1, p1, [Ljava/lang/Object;

    const-string v0, "No GeofenceRegions provided"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public varargs a([Lcom/salesforce/marketingcloud/location/b;)V
    .locals 11

    const/4 v1, 0x0

    if-eqz p1, :cond_2

    .line 15
    array-length v0, p1

    if-nez v0, :cond_0

    goto/16 :goto_1

    .line 16
    :cond_0
    iget-object v0, p0, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    invoke-static {v0}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->b(Landroid/content/Context;)Landroid/app/PendingIntent;

    move-result-object v0

    .line 17
    new-instance v2, Ljava/util/ArrayList;

    invoke-direct {v2}, Ljava/util/ArrayList;-><init>()V

    .line 18
    array-length v3, p1

    move v4, v1

    :goto_0
    if-ge v4, v3, :cond_1

    aget-object v5, p1, v4

    .line 19
    sget-object v6, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    invoke-virtual {v5}, Lcom/salesforce/marketingcloud/location/b;->f()Ljava/lang/String;

    move-result-object v7

    filled-new-array {v7}, [Ljava/lang/Object;

    move-result-object v7

    const-string v8, "Adding %s to geofence request"

    invoke-static {v6, v8, v7}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 20
    invoke-static {v5}, Lcom/salesforce/marketingcloud/location/d;->a(Lcom/salesforce/marketingcloud/location/b;)Lpp/a;

    move-result-object v5

    .line 21
    instance-of v6, v5, Lgp/k;

    const-string v7, "Geofence must be created using Geofence.Builder."

    invoke-static {v6, v7}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 22
    check-cast v5, Lgp/k;

    invoke-virtual {v2, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v4, v4, 0x1

    goto :goto_0

    .line 23
    :cond_1
    :try_start_0
    iget-object v6, p0, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    sget p1, Lpp/d;->a:I

    .line 24
    new-instance v5, Lgp/a;

    .line 25
    sget-object v8, Lgp/a;->n:Lc2/k;

    sget-object v9, Lko/b;->a:Lko/a;

    sget-object v10, Lko/h;->c:Lko/h;

    const/4 v7, 0x0

    .line 26
    invoke-direct/range {v5 .. v10}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 27
    invoke-virtual {v2}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p1

    const/4 v3, 0x1

    xor-int/2addr p1, v3

    const-string v4, "No geofence has been added to this request."

    .line 28
    invoke-static {p1, v4}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 29
    new-instance p1, Lpp/c;

    new-instance v4, Ljava/util/ArrayList;

    invoke-direct {v4, v2}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    const/4 v2, 0x0

    invoke-direct {p1, v3, v2, v4}, Lpp/c;-><init>(ILjava/lang/String;Ljava/util/ArrayList;)V

    .line 30
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    move-result-object v2

    new-instance v4, Lc2/k;

    const/4 v6, 0x7

    invoke-direct {v4, v6, p1, v0}, Lc2/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 31
    iput-object v4, v2, Lh6/i;->d:Ljava/lang/Object;

    const/16 p1, 0x978

    .line 32
    iput p1, v2, Lh6/i;->b:I

    .line 33
    invoke-virtual {v2}, Lh6/i;->a()Lbp/s;

    move-result-object p1

    .line 34
    invoke-virtual {v5, v3, p1}, Lko/i;->e(ILhr/b0;)Laq/t;

    move-result-object p1

    .line 35
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 36
    sget-object v0, Laq/l;->a:Lj0/e;

    invoke-virtual {p1, v0, p0}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 37
    new-instance v0, Lcom/salesforce/marketingcloud/location/d$b;

    invoke-direct {v0, p0}, Lcom/salesforce/marketingcloud/location/d$b;-><init>(Lcom/salesforce/marketingcloud/location/d;)V

    .line 38
    invoke-virtual {p1, v0}, Laq/t;->k(Laq/e;)Laq/t;
    :try_end_0
    .catch Ljava/lang/SecurityException; {:try_start_0 .. :try_end_0} :catch_0

    return-void

    :catch_0
    move-exception v0

    move-object p0, v0

    .line 39
    sget-object p1, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    new-array v0, v1, [Ljava/lang/Object;

    const-string v1, "ACCESS_FINE_LOCATION needed to request location."

    invoke-static {p1, p0, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 40
    throw p0

    .line 41
    :cond_2
    :goto_1
    sget-object p0, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    new-array p1, v1, [Ljava/lang/Object;

    const-string v0, "No GeofenceRegions provided"

    invoke-static {p0, v0, p1}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public b()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/salesforce/marketingcloud/location/d;->d:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public c()I
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/location/d;->c:I

    .line 2
    .line 3
    return p0
.end method

.method public d()Z
    .locals 0

    .line 1
    iget p0, p0, Lcom/salesforce/marketingcloud/location/d;->c:I

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public e()V
    .locals 25

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    monitor-enter p0

    .line 4
    :try_start_0
    iget-boolean v0, v1, Lcom/salesforce/marketingcloud/location/d;->b:Z

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    sget-object v0, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    .line 10
    .line 11
    const-string v3, "Location request already being made."

    .line 12
    .line 13
    new-array v2, v2, [Ljava/lang/Object;

    .line 14
    .line 15
    invoke-static {v0, v3, v2}, Lcom/salesforce/marketingcloud/g;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    monitor-exit p0

    .line 19
    return-void

    .line 20
    :catchall_0
    move-exception v0

    .line 21
    goto/16 :goto_0

    .line 22
    .line 23
    :cond_0
    const/4 v0, 0x1

    .line 24
    iput-boolean v0, v1, Lcom/salesforce/marketingcloud/location/d;->b:Z

    .line 25
    .line 26
    new-instance v3, Lcom/google/android/gms/location/LocationRequest;

    .line 27
    .line 28
    new-instance v23, Landroid/os/WorkSource;

    .line 29
    .line 30
    invoke-direct/range {v23 .. v23}, Landroid/os/WorkSource;-><init>()V

    .line 31
    .line 32
    .line 33
    const/16 v24, 0x0

    .line 34
    .line 35
    const/16 v4, 0x66

    .line 36
    .line 37
    const-wide/32 v5, 0x36ee80

    .line 38
    .line 39
    .line 40
    const-wide/32 v7, 0x927c0

    .line 41
    .line 42
    .line 43
    const-wide/16 v9, 0x0

    .line 44
    .line 45
    const-wide v11, 0x7fffffffffffffffL

    .line 46
    .line 47
    .line 48
    .line 49
    .line 50
    const v15, 0x7fffffff

    .line 51
    .line 52
    .line 53
    const/16 v16, 0x0

    .line 54
    .line 55
    const/16 v17, 0x1

    .line 56
    .line 57
    const-wide/32 v18, 0x36ee80

    .line 58
    .line 59
    .line 60
    const/16 v20, 0x0

    .line 61
    .line 62
    const/16 v21, 0x0

    .line 63
    .line 64
    const/16 v22, 0x0

    .line 65
    .line 66
    move-wide v13, v11

    .line 67
    invoke-direct/range {v3 .. v24}, Lcom/google/android/gms/location/LocationRequest;-><init>(IJJJJJIFZJIIZLandroid/os/WorkSource;Lgp/g;)V

    .line 68
    .line 69
    .line 70
    iput v0, v3, Lcom/google/android/gms/location/LocationRequest;->i:I

    .line 71
    .line 72
    const/16 v4, 0x64

    .line 73
    .line 74
    invoke-static {v4}, Lpp/k;->a(I)V

    .line 75
    .line 76
    .line 77
    iput v4, v3, Lcom/google/android/gms/location/LocationRequest;->d:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 78
    .line 79
    :try_start_1
    iget-object v6, v1, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    .line 80
    .line 81
    sget v4, Lpp/d;->a:I

    .line 82
    .line 83
    new-instance v5, Lgp/a;

    .line 84
    .line 85
    sget-object v8, Lgp/a;->n:Lc2/k;

    .line 86
    .line 87
    sget-object v9, Lko/b;->a:Lko/a;

    .line 88
    .line 89
    sget-object v10, Lko/h;->c:Lko/h;

    .line 90
    .line 91
    const/4 v7, 0x0

    .line 92
    invoke-direct/range {v5 .. v10}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 93
    .line 94
    .line 95
    iget-object v4, v1, Lcom/salesforce/marketingcloud/location/d;->a:Landroid/content/Context;

    .line 96
    .line 97
    invoke-static {v4}, Lcom/salesforce/marketingcloud/location/LocationReceiver;->c(Landroid/content/Context;)Landroid/app/PendingIntent;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    invoke-static {}, Lhr/b0;->e()Lh6/i;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    new-instance v7, Lb81/c;

    .line 106
    .line 107
    const/4 v8, 0x7

    .line 108
    invoke-direct {v7, v8, v4, v3}, Lb81/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 109
    .line 110
    .line 111
    iput-object v7, v6, Lh6/i;->d:Ljava/lang/Object;

    .line 112
    .line 113
    const/16 v3, 0x971

    .line 114
    .line 115
    iput v3, v6, Lh6/i;->b:I

    .line 116
    .line 117
    invoke-virtual {v6}, Lh6/i;->a()Lbp/s;

    .line 118
    .line 119
    .line 120
    move-result-object v3

    .line 121
    invoke-virtual {v5, v0, v3}, Lko/i;->e(ILhr/b0;)Laq/t;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    sget-object v3, Laq/l;->a:Lj0/e;

    .line 129
    .line 130
    invoke-virtual {v0, v3, v1}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 131
    .line 132
    .line 133
    new-instance v3, Lcom/salesforce/marketingcloud/location/d$a;

    .line 134
    .line 135
    invoke-direct {v3, v1}, Lcom/salesforce/marketingcloud/location/d$a;-><init>(Lcom/salesforce/marketingcloud/location/d;)V

    .line 136
    .line 137
    .line 138
    invoke-virtual {v0, v3}, Laq/t;->k(Laq/e;)Laq/t;
    :try_end_1
    .catch Ljava/lang/SecurityException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 139
    .line 140
    .line 141
    :try_start_2
    monitor-exit p0

    .line 142
    return-void

    .line 143
    :catch_0
    move-exception v0

    .line 144
    sget-object v3, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    .line 145
    .line 146
    const-string v4, "ACCESS_FINE_LOCATION needed to request location."

    .line 147
    .line 148
    new-array v5, v2, [Ljava/lang/Object;

    .line 149
    .line 150
    invoke-static {v3, v0, v4, v5}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 151
    .line 152
    .line 153
    iput-boolean v2, v1, Lcom/salesforce/marketingcloud/location/d;->b:Z

    .line 154
    .line 155
    throw v0

    .line 156
    :goto_0
    monitor-exit p0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 157
    throw v0
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 2

    .line 1
    sget-object p0, Lcom/salesforce/marketingcloud/location/d;->e:Ljava/lang/String;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    new-array v0, v0, [Ljava/lang/Object;

    .line 5
    .line 6
    const-string v1, "LocationServices failure"

    .line 7
    .line 8
    invoke-static {p0, p1, v1, v0}, Lcom/salesforce/marketingcloud/g;->b(Ljava/lang/String;Ljava/lang/Throwable;Ljava/lang/String;[Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

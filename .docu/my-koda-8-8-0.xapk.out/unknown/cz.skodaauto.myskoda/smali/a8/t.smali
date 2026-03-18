.class public final synthetic La8/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lw7/j;
.implements Lt01/b;
.implements Ly4/i;
.implements Lb0/d0;
.implements Lh0/b1;
.implements Laq/e;
.implements Lcom/google/gson/internal/m;
.implements Lcom/salesforce/marketingcloud/MarketingCloudSdk$WhenReadyListener;
.implements Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdkReadyListener;
.implements Laq/i;
.implements Lf8/v;
.implements Landroidx/sqlite/db/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Lb8/a;Ljava/lang/Object;I)V
    .locals 0

    .line 1
    iput p3, p0, La8/t;->d:I

    iput-object p2, p0, La8/t;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 2
    iput p2, p0, La8/t;->d:I

    iput-object p1, p0, La8/t;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public a()Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, La8/t;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/lang/Class;

    .line 9
    .line 10
    :try_start_0
    sget-object v0, Lcom/google/gson/internal/r;->a:Lcom/google/gson/internal/r;

    .line 11
    .line 12
    invoke-virtual {v0, p0}, Lcom/google/gson/internal/r;->a(Ljava/lang/Class;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 16
    return-object p0

    .line 17
    :catch_0
    move-exception v0

    .line 18
    new-instance v1, Ljava/lang/RuntimeException;

    .line 19
    .line 20
    new-instance v2, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    const-string v3, "Unable to create instance of "

    .line 23
    .line 24
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string p0, ". Registering an InstanceCreator or a TypeAdapter for this type, or adding a no-args constructor may fix this problem."

    .line 31
    .line 32
    invoke-virtual {v2, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    invoke-direct {v1, p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 40
    .line 41
    .line 42
    throw v1

    .line 43
    :pswitch_0
    check-cast p0, Ljava/lang/reflect/Constructor;

    .line 44
    .line 45
    const-string v0, "\' with no args"

    .line 46
    .line 47
    const-string v1, "Failed to invoke constructor \'"

    .line 48
    .line 49
    const/4 v2, 0x0

    .line 50
    :try_start_1
    invoke-virtual {p0, v2}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 51
    .line 52
    .line 53
    move-result-object p0
    :try_end_1
    .catch Ljava/lang/InstantiationException; {:try_start_1 .. :try_end_1} :catch_3
    .catch Ljava/lang/reflect/InvocationTargetException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/IllegalAccessException; {:try_start_1 .. :try_end_1} :catch_1

    .line 54
    return-object p0

    .line 55
    :catch_1
    move-exception p0

    .line 56
    sget-object v0, Lou/c;->a:Ljp/fc;

    .line 57
    .line 58
    new-instance v0, Ljava/lang/RuntimeException;

    .line 59
    .line 60
    const-string v1, "Unexpected IllegalAccessException occurred (Gson 2.13.1). Certain ReflectionAccessFilter features require Java >= 9 to work correctly. If you are not using ReflectionAccessFilter, report this to the Gson maintainers."

    .line 61
    .line 62
    invoke-direct {v0, v1, p0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 63
    .line 64
    .line 65
    throw v0

    .line 66
    :catch_2
    move-exception v2

    .line 67
    new-instance v3, Ljava/lang/RuntimeException;

    .line 68
    .line 69
    new-instance v4, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    invoke-direct {v4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 72
    .line 73
    .line 74
    invoke-static {p0}, Lou/c;->b(Ljava/lang/reflect/Constructor;)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    invoke-virtual {v2}, Ljava/lang/reflect/InvocationTargetException;->getCause()Ljava/lang/Throwable;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    invoke-direct {v3, p0, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 93
    .line 94
    .line 95
    throw v3

    .line 96
    :catch_3
    move-exception v2

    .line 97
    new-instance v3, Ljava/lang/RuntimeException;

    .line 98
    .line 99
    new-instance v4, Ljava/lang/StringBuilder;

    .line 100
    .line 101
    invoke-direct {v4, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    invoke-static {p0}, Lou/c;->b(Ljava/lang/reflect/Constructor;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object p0

    .line 108
    invoke-virtual {v4, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object p0

    .line 118
    invoke-direct {v3, p0, v2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 119
    .line 120
    .line 121
    throw v3

    .line 122
    nop

    .line 123
    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_0
    .end packed-switch
.end method

.method public b(Ljava/lang/Object;)I
    .locals 3

    .line 1
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lt7/o;

    .line 4
    .line 5
    check-cast p1, Lf8/p;

    .line 6
    .line 7
    iget-object v0, p1, Lf8/p;->b:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v1, p0, Lt7/o;->n:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v1

    .line 15
    const/4 v2, 0x0

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    invoke-static {p0}, Lf8/w;->b(Lt7/o;)Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result v0

    .line 26
    if-eqz v0, :cond_0

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_0
    return v2

    .line 30
    :cond_1
    :goto_0
    invoke-virtual {p1, p0, v2}, Lf8/p;->c(Lt7/o;Z)Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    invoke-virtual {p1, p0}, Lf8/p;->d(Lt7/o;)Z

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    if-eqz p0, :cond_2

    .line 41
    .line 42
    const/4 p0, 0x1

    .line 43
    return p0

    .line 44
    :cond_2
    return v2
.end method

.method public c(Lh0/c1;)V
    .locals 2

    .line 1
    iget v0, p0, La8/t;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lgw0/c;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    :try_start_0
    invoke-interface {p1}, Lh0/c1;->b()Lb0/a1;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    if-eqz p0, :cond_0

    .line 18
    .line 19
    invoke-static {}, Llp/k1;->a()V

    .line 20
    .line 21
    .line 22
    const-string p1, "CaptureNode"

    .line 23
    .line 24
    new-instance v0, Ljava/lang/StringBuilder;

    .line 25
    .line 26
    const-string v1, "Discarding ImageProxy which was inadvertently acquired: "

    .line 27
    .line 28
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-static {p1, v0}, Ljp/v1;->k(Ljava/lang/String;Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    invoke-interface {p0}, Ljava/lang/AutoCloseable;->close()V
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_0

    .line 42
    .line 43
    .line 44
    :catch_0
    :cond_0
    return-void

    .line 45
    :pswitch_0
    check-cast p0, Lb0/f1;

    .line 46
    .line 47
    iget-object v0, p0, Lb0/f1;->d:Ljava/lang/Object;

    .line 48
    .line 49
    monitor-enter v0

    .line 50
    :try_start_1
    iget v1, p0, Lb0/f1;->f:I

    .line 51
    .line 52
    add-int/lit8 v1, v1, 0x1

    .line 53
    .line 54
    iput v1, p0, Lb0/f1;->f:I

    .line 55
    .line 56
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 57
    invoke-virtual {p0, p1}, Lb0/f1;->j(Lh0/c1;)V

    .line 58
    .line 59
    .line 60
    return-void

    .line 61
    :catchall_0
    move-exception p0

    .line 62
    :try_start_2
    monitor-exit v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 63
    throw p0

    .line 64
    nop

    .line 65
    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method

.method public create(Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;)Landroidx/sqlite/db/SupportSQLiteOpenHelper;
    .locals 6

    .line 1
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v1, p0

    .line 4
    check-cast v1, Landroid/content/Context;

    .line 5
    .line 6
    iget-object v2, p1, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->b:Ljava/lang/String;

    .line 7
    .line 8
    iget-object v3, p1, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;->c:Lb11/a;

    .line 9
    .line 10
    const-string p0, "callback"

    .line 11
    .line 12
    invoke-static {v3, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    if-eqz v2, :cond_0

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    if-eqz p0, :cond_0

    .line 22
    .line 23
    new-instance v0, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;

    .line 24
    .line 25
    const/4 v4, 0x1

    .line 26
    move v5, v4

    .line 27
    invoke-direct/range {v0 .. v5}, Landroidx/sqlite/db/SupportSQLiteOpenHelper$Configuration;-><init>(Landroid/content/Context;Ljava/lang/String;Lb11/a;ZZ)V

    .line 28
    .line 29
    .line 30
    new-instance v0, Lwa/g;

    .line 31
    .line 32
    invoke-direct/range {v0 .. v5}, Lwa/g;-><init>(Landroid/content/Context;Ljava/lang/String;Lb11/a;ZZ)V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 37
    .line 38
    const-string p1, "Must set a non-null database name to a configuration that uses the no backup directory."

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0
.end method

.method public d(Lb0/p1;)V
    .locals 0

    .line 1
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb0/d0;

    .line 4
    .line 5
    invoke-interface {p0, p1}, Lb0/d0;->d(Lb0/p1;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public f(Ljava/lang/String;)V
    .locals 1

    .line 1
    iget v0, p0, La8/t;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    sparse-switch v0, :sswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lcz/myskoda/api/bff_widgets/v2/infrastructure/ApiClient;

    .line 9
    .line 10
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_widgets/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_widgets/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :sswitch_0
    check-cast p0, Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/ApiClient;

    .line 15
    .line 16
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 17
    .line 18
    .line 19
    return-void

    .line 20
    :sswitch_1
    check-cast p0, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;

    .line 21
    .line 22
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;->b(Lcz/myskoda/api/bff_vehicle_maintenance/v3/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    return-void

    .line 26
    :sswitch_2
    check-cast p0, Lcz/myskoda/api/bff_test_drive/v2/infrastructure/ApiClient;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_test_drive/v2/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_test_drive/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    return-void

    .line 32
    :sswitch_3
    check-cast p0, Lcz/myskoda/api/bff_shop/v2/infrastructure/ApiClient;

    .line 33
    .line 34
    invoke-static {p0, p1}, Lcz/myskoda/api/bff_shop/v2/infrastructure/ApiClient;->e(Lcz/myskoda/api/bff_shop/v2/infrastructure/ApiClient;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :sswitch_data_0
    .sparse-switch
        0x6 -> :sswitch_3
        0x14 -> :sswitch_2
        0x16 -> :sswitch_1
        0x17 -> :sswitch_0
    .end sparse-switch
.end method

.method public g(Ljava/lang/Object;)Laq/t;
    .locals 0

    .line 1
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ldu/h;

    .line 4
    .line 5
    check-cast p1, Ldu/e;

    .line 6
    .line 7
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, La8/t;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Lvy0/i0;

    .line 9
    .line 10
    const-string v0, "Deferred.asListenableFuture"

    .line 11
    .line 12
    new-instance v1, Lb1/e;

    .line 13
    .line 14
    const/4 v2, 0x3

    .line 15
    invoke-direct {v1, v2, p1, p0}, Lb1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v1}, Lvy0/p1;->E(Lay0/k;)Lvy0/r0;

    .line 19
    .line 20
    .line 21
    return-object v0

    .line 22
    :pswitch_0
    check-cast p0, Lb0/u;

    .line 23
    .line 24
    iget-object v0, p0, Lb0/u;->n:Lh0/e0;

    .line 25
    .line 26
    invoke-virtual {v0}, Lh0/e0;->e()V

    .line 27
    .line 28
    .line 29
    iget-object v0, p0, Lb0/u;->a:Lh0/i0;

    .line 30
    .line 31
    iget-object v1, v0, Lh0/i0;->a:Ljava/lang/Object;

    .line 32
    .line 33
    monitor-enter v1

    .line 34
    :try_start_0
    iget-object v2, v0, Lh0/i0;->b:Ljava/util/LinkedHashMap;

    .line 35
    .line 36
    invoke-interface {v2}, Ljava/util/Map;->isEmpty()Z

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    if-eqz v2, :cond_1

    .line 41
    .line 42
    iget-object v0, v0, Lh0/i0;->d:Ly4/k;

    .line 43
    .line 44
    if-nez v0, :cond_0

    .line 45
    .line 46
    sget-object v0, Lk0/j;->f:Lk0/j;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :catchall_0
    move-exception p0

    .line 50
    goto :goto_3

    .line 51
    :cond_0
    :goto_0
    monitor-exit v1

    .line 52
    goto :goto_2

    .line 53
    :cond_1
    iget-object v2, v0, Lh0/i0;->d:Ly4/k;

    .line 54
    .line 55
    if-nez v2, :cond_2

    .line 56
    .line 57
    new-instance v2, Lgr/k;

    .line 58
    .line 59
    const/4 v3, 0x2

    .line 60
    invoke-direct {v2, v0, v3}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 61
    .line 62
    .line 63
    invoke-static {v2}, Llp/uf;->b(Ly4/i;)Ly4/k;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    iput-object v2, v0, Lh0/i0;->d:Ly4/k;

    .line 68
    .line 69
    :cond_2
    iget-object v3, v0, Lh0/i0;->c:Ljava/util/HashSet;

    .line 70
    .line 71
    iget-object v4, v0, Lh0/i0;->b:Ljava/util/LinkedHashMap;

    .line 72
    .line 73
    invoke-virtual {v4}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-interface {v3, v4}, Ljava/util/Set;->addAll(Ljava/util/Collection;)Z

    .line 78
    .line 79
    .line 80
    iget-object v3, v0, Lh0/i0;->b:Ljava/util/LinkedHashMap;

    .line 81
    .line 82
    invoke-virtual {v3}, Ljava/util/LinkedHashMap;->values()Ljava/util/Collection;

    .line 83
    .line 84
    .line 85
    move-result-object v3

    .line 86
    invoke-interface {v3}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 87
    .line 88
    .line 89
    move-result-object v3

    .line 90
    :goto_1
    invoke-interface {v3}, Ljava/util/Iterator;->hasNext()Z

    .line 91
    .line 92
    .line 93
    move-result v4

    .line 94
    if-eqz v4, :cond_3

    .line 95
    .line 96
    invoke-interface {v3}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v4

    .line 100
    check-cast v4, Lh0/b0;

    .line 101
    .line 102
    invoke-interface {v4}, Lh0/b0;->b()Lcom/google/common/util/concurrent/ListenableFuture;

    .line 103
    .line 104
    .line 105
    move-result-object v5

    .line 106
    new-instance v6, Lh0/h0;

    .line 107
    .line 108
    const/4 v7, 0x0

    .line 109
    invoke-direct {v6, v7, v0, v4}, Lh0/h0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    invoke-static {}, Llp/hb;->a()Lj0/a;

    .line 113
    .line 114
    .line 115
    move-result-object v4

    .line 116
    invoke-interface {v5, v4, v6}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 117
    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_3
    iget-object v0, v0, Lh0/i0;->b:Ljava/util/LinkedHashMap;

    .line 121
    .line 122
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->clear()V

    .line 123
    .line 124
    .line 125
    monitor-exit v1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 126
    move-object v0, v2

    .line 127
    :goto_2
    new-instance v1, La8/z;

    .line 128
    .line 129
    const/4 v2, 0x5

    .line 130
    invoke-direct {v1, v2, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    iget-object p0, p0, Lb0/u;->d:Ljava/util/concurrent/Executor;

    .line 134
    .line 135
    invoke-interface {v0, p0, v1}, Lcom/google/common/util/concurrent/ListenableFuture;->a(Ljava/util/concurrent/Executor;Ljava/lang/Runnable;)V

    .line 136
    .line 137
    .line 138
    const-string p0, "CameraX shutdownInternal"

    .line 139
    .line 140
    return-object p0

    .line 141
    :goto_3
    :try_start_1
    monitor-exit v1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 142
    throw p0

    .line 143
    :pswitch_data_0
    .packed-switch 0x7
        :pswitch_0
    .end packed-switch
.end method

.method public invoke(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget v0, p0, La8/t;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    :pswitch_0
    check-cast p0, La8/g;

    .line 9
    .line 10
    check-cast p1, Lb8/j;

    .line 11
    .line 12
    iget v0, p1, Lb8/j;->y:I

    .line 13
    .line 14
    iget v1, p0, La8/g;->g:I

    .line 15
    .line 16
    add-int/2addr v0, v1

    .line 17
    iput v0, p1, Lb8/j;->y:I

    .line 18
    .line 19
    iget v0, p1, Lb8/j;->z:I

    .line 20
    .line 21
    iget p0, p0, La8/g;->e:I

    .line 22
    .line 23
    add-int/2addr v0, p0

    .line 24
    iput v0, p1, Lb8/j;->z:I

    .line 25
    .line 26
    return-void

    .line 27
    :pswitch_1
    check-cast p0, Lt7/f0;

    .line 28
    .line 29
    check-cast p1, Lb8/j;

    .line 30
    .line 31
    iput-object p0, p1, Lb8/j;->o:Lt7/f0;

    .line 32
    .line 33
    return-void

    .line 34
    :pswitch_2
    check-cast p0, Lt7/c0;

    .line 35
    .line 36
    check-cast p1, Lt7/j0;

    .line 37
    .line 38
    invoke-interface {p1, p0}, Lt7/j0;->E(Lt7/c0;)V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    :pswitch_3
    check-cast p0, La8/f0;

    .line 43
    .line 44
    check-cast p1, Lt7/j0;

    .line 45
    .line 46
    iget-object p0, p0, La8/f0;->d:La8/i0;

    .line 47
    .line 48
    iget-object p0, p0, La8/i0;->W:Lt7/a0;

    .line 49
    .line 50
    invoke-interface {p1, p0}, Lt7/j0;->C(Lt7/a0;)V

    .line 51
    .line 52
    .line 53
    return-void

    .line 54
    :pswitch_4
    check-cast p0, Lv7/c;

    .line 55
    .line 56
    check-cast p1, Lt7/j0;

    .line 57
    .line 58
    invoke-interface {p1, p0}, Lt7/j0;->k(Lv7/c;)V

    .line 59
    .line 60
    .line 61
    return-void

    .line 62
    :pswitch_5
    check-cast p0, Lt7/u0;

    .line 63
    .line 64
    check-cast p1, Lt7/j0;

    .line 65
    .line 66
    invoke-interface {p1, p0}, Lt7/j0;->h(Lt7/u0;)V

    .line 67
    .line 68
    .line 69
    return-void

    .line 70
    :pswitch_6
    check-cast p0, Lt7/a0;

    .line 71
    .line 72
    check-cast p1, Lt7/j0;

    .line 73
    .line 74
    invoke-interface {p1, p0}, Lt7/j0;->C(Lt7/a0;)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    nop

    .line 79
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_0
        :pswitch_1
    .end packed-switch
.end method

.method public onComplete(Laq/j;)V
    .locals 0

    .line 1
    iget p1, p0, La8/t;->d:I

    .line 2
    .line 3
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    .line 4
    .line 5
    packed-switch p1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    check-cast p0, Ljava/util/concurrent/ScheduledFuture;

    .line 9
    .line 10
    const/4 p1, 0x0

    .line 11
    invoke-interface {p0, p1}, Ljava/util/concurrent/Future;->cancel(Z)Z

    .line 12
    .line 13
    .line 14
    return-void

    .line 15
    :pswitch_0
    check-cast p0, Lcom/google/firebase/messaging/i0;

    .line 16
    .line 17
    iget-object p0, p0, Lcom/google/firebase/messaging/i0;->b:Laq/k;

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    invoke-virtual {p0, p1}, Laq/k;->d(Ljava/lang/Object;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_1
    check-cast p0, Landroid/content/Intent;

    .line 25
    .line 26
    invoke-static {p0}, Lcom/google/firebase/messaging/g0;->b(Landroid/content/Intent;)V

    .line 27
    .line 28
    .line 29
    return-void

    .line 30
    nop

    :pswitch_data_0
    .packed-switch 0xd
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public ready(Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V
    .locals 0

    .line 1
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    check-cast p0, Lcom/salesforce/marketingcloud/events/Event;

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/events/Event;->a(Lcom/salesforce/marketingcloud/events/Event;Lcom/salesforce/marketingcloud/MarketingCloudSdk;)V

    return-void
.end method

.method public ready(Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V
    .locals 0

    .line 2
    iget-object p0, p0, La8/t;->e:Ljava/lang/Object;

    check-cast p0, [Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;

    invoke-static {p0, p1}, Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk$Companion;->b([Lcom/salesforce/marketingcloud/sfmcsdk/components/events/Event;Lcom/salesforce/marketingcloud/sfmcsdk/SFMCSdk;)V

    return-void
.end method

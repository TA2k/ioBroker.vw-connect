.class public La0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/t1;
.implements Laq/g;
.implements Lc1/c0;
.implements Lc1/q;
.implements Lc1/g2;
.implements Llo/e;
.implements Llo/l;
.implements Ld6/e;
.implements Laq/f;
.implements Laq/d;
.implements Lx4/v;
.implements Llo/n;
.implements Le6/m;
.implements Lh1/b;
.implements Ll4/p;
.implements Lia/c;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(FFLc1/p;)V
    .locals 1

    const/4 v0, 0x7

    iput v0, p0, La0/j;->d:I

    .line 39
    sget-object v0, Lc1/e2;->a:[I

    if-eqz p3, :cond_0

    .line 40
    new-instance v0, La0/j;

    invoke-direct {v0, p3, p1, p2}, La0/j;-><init>(Lc1/p;FF)V

    goto :goto_0

    .line 41
    :cond_0
    new-instance v0, Lbu/c;

    invoke-direct {v0, p1, p2}, Lbu/c;-><init>(FF)V

    .line 42
    :goto_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 43
    new-instance p1, Lcom/google/firebase/messaging/w;

    invoke-direct {p1, v0}, Lcom/google/firebase/messaging/w;-><init>(Lc1/q;)V

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(I)V
    .locals 1

    iput p1, p0, La0/j;->d:I

    packed-switch p1, :pswitch_data_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    new-instance p1, Laq/t;

    invoke-direct {p1}, Laq/t;-><init>()V

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    return-void

    .line 3
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    new-instance p1, Ljava/util/concurrent/CountDownLatch;

    const/4 v0, 0x1

    invoke-direct {p1, v0}, Ljava/util/concurrent/CountDownLatch;-><init>(I)V

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    return-void

    :pswitch_data_0
    .packed-switch 0x10
        :pswitch_0
    .end packed-switch
.end method

.method public synthetic constructor <init>(IZ)V
    .locals 0

    .line 5
    iput p1, p0, La0/j;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    const/16 v0, 0xa

    iput v0, p0, La0/j;->d:I

    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    const-string v0, "com.google.android.gms.appid"

    const/4 v1, 0x0

    invoke-virtual {p1, v0, v1}, Landroid/content/Context;->getSharedPreferences(Ljava/lang/String;I)Landroid/content/SharedPreferences;

    move-result-object v0

    iput-object v0, p0, La0/j;->e:Ljava/lang/Object;

    .line 18
    const-string v1, "com.google.android.gms.appid-no-backup"

    .line 19
    invoke-virtual {p1}, Landroid/content/Context;->getNoBackupFilesDir()Ljava/io/File;

    move-result-object p1

    .line 20
    new-instance v2, Ljava/io/File;

    invoke-direct {v2, p1, v1}, Ljava/io/File;-><init>(Ljava/io/File;Ljava/lang/String;)V

    .line 21
    invoke-virtual {v2}, Ljava/io/File;->exists()Z

    move-result p1

    if-eqz p1, :cond_0

    goto :goto_0

    .line 22
    :cond_0
    :try_start_0
    invoke-virtual {v2}, Ljava/io/File;->createNewFile()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 23
    monitor-enter p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 24
    :try_start_1
    invoke-interface {v0}, Landroid/content/SharedPreferences;->getAll()Ljava/util/Map;

    move-result-object p1

    invoke-interface {p1}, Ljava/util/Map;->isEmpty()Z

    move-result p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    :try_start_2
    monitor-exit p0

    if-nez p1, :cond_1

    .line 25
    const-string p1, "FirebaseMessaging"

    const-string v1, "App restored, clearing state"

    invoke-static {p1, v1}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;)I

    .line 26
    monitor-enter p0
    :try_end_2
    .catch Ljava/io/IOException; {:try_start_2 .. :try_end_2} :catch_0

    .line 27
    :try_start_3
    invoke-interface {v0}, Landroid/content/SharedPreferences;->edit()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->clear()Landroid/content/SharedPreferences$Editor;

    move-result-object p1

    invoke-interface {p1}, Landroid/content/SharedPreferences$Editor;->commit()Z
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 28
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    goto :goto_0

    :catchall_0
    move-exception p1

    :try_start_5
    monitor-exit p0
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    :try_start_6
    throw p1
    :try_end_6
    .catch Ljava/io/IOException; {:try_start_6 .. :try_end_6} :catch_0

    :catchall_1
    move-exception p1

    .line 29
    :try_start_7
    monitor-exit p0
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_1

    :try_start_8
    throw p1
    :try_end_8
    .catch Ljava/io/IOException; {:try_start_8 .. :try_end_8} :catch_0

    :catch_0
    move-exception p0

    .line 30
    const-string p1, "FirebaseMessaging"

    const/4 v0, 0x3

    invoke-static {p1, v0}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    move-result p1

    if-eqz p1, :cond_1

    .line 31
    const-string p1, "FirebaseMessaging"

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Error creating file in no backup dir: "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p0}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    move-result-object p0

    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p0

    invoke-static {p1, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    :cond_1
    :goto_0
    return-void
.end method

.method public constructor <init>(Landroid/view/ContentInfo;)V
    .locals 1

    const/16 v0, 0xe

    iput v0, p0, La0/j;->d:I

    .line 36
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 37
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 38
    invoke-static {p1}, Lc4/a;->n(Ljava/lang/Object;)Landroid/view/ContentInfo;

    move-result-object p1

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lc1/p;FF)V
    .locals 5

    const/4 v0, 0x6

    iput v0, p0, La0/j;->d:I

    .line 44
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 45
    invoke-virtual {p1}, Lc1/p;->b()I

    move-result v0

    new-array v1, v0, [Lc1/d0;

    const/4 v2, 0x0

    :goto_0
    if-ge v2, v0, :cond_0

    .line 46
    new-instance v3, Lc1/d0;

    invoke-virtual {p1, v2}, Lc1/p;->a(I)F

    move-result v4

    invoke-direct {v3, p2, p3, v4}, Lc1/d0;-><init>(FFF)V

    aput-object v3, v1, v2

    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    .line 47
    :cond_0
    iput-object v1, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    .line 6
    iput p2, p0, La0/j;->d:I

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 1

    const/16 v0, 0xf

    iput v0, p0, La0/j;->d:I

    const-string v0, "name"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 34
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 35
    invoke-static {p1}, Ljp/ne;->b(Ljava/lang/String;)Lq6/e;

    move-result-object p1

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 1

    const/16 v0, 0x12

    iput v0, p0, La0/j;->d:I

    .line 32
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 33
    invoke-static {p1}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    move-result-object p1

    iput-object p1, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lt4/c;)V
    .locals 2

    const/4 v0, 0x4

    iput v0, p0, La0/j;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    new-instance v0, Lb1/x0;

    .line 9
    sget v1, Lb1/h1;->a:F

    .line 10
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    iput v1, v0, Lb1/x0;->d:F

    .line 11
    invoke-interface {p1}, Lt4/c;->a()F

    move-result p1

    sget v1, Lb1/y0;->a:F

    const v1, 0x43c10b3d

    mul-float/2addr p1, v1

    const/high16 v1, 0x43200000    # 160.0f

    mul-float/2addr p1, v1

    const v1, 0x3f570a3d    # 0.84f

    mul-float/2addr p1, v1

    .line 12
    iput p1, v0, Lb1/x0;->e:F

    .line 13
    iput-object v0, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lu2/c;)V
    .locals 1

    const/4 v0, 0x5

    iput v0, p0, La0/j;->d:I

    .line 14
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    new-instance v0, Ljava/lang/ref/WeakReference;

    invoke-direct {v0, p1}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    iput-object v0, p0, La0/j;->e:Ljava/lang/Object;

    return-void
.end method

.method public static U(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    const-string v0, "|T|"

    .line 2
    .line 3
    const-string v1, "|*"

    .line 4
    .line 5
    invoke-static {p0, v0, p1, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method


# virtual methods
.method public A()Landroid/content/ClipData;
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo;

    .line 4
    .line 5
    invoke-static {p0}, Lc4/a;->e(Landroid/view/ContentInfo;)Landroid/content/ClipData;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public B(Landroid/view/View;)Z
    .locals 3

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/material/behavior/SwipeDismissBehavior;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lcom/google/android/material/behavior/SwipeDismissBehavior;->r(Landroid/view/View;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/4 v1, 0x0

    .line 10
    if-eqz v0, :cond_4

    .line 11
    .line 12
    invoke-virtual {p1}, Landroid/view/View;->getLayoutDirection()I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x1

    .line 17
    if-ne v0, v2, :cond_0

    .line 18
    .line 19
    move v1, v2

    .line 20
    :cond_0
    iget p0, p0, Lcom/google/android/material/behavior/SwipeDismissBehavior;->d:I

    .line 21
    .line 22
    if-nez p0, :cond_1

    .line 23
    .line 24
    if-nez v1, :cond_2

    .line 25
    .line 26
    :cond_1
    if-ne p0, v2, :cond_3

    .line 27
    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    :cond_2
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    neg-int p0, p0

    .line 35
    goto :goto_0

    .line 36
    :cond_3
    invoke-virtual {p1}, Landroid/view/View;->getWidth()I

    .line 37
    .line 38
    .line 39
    move-result p0

    .line 40
    :goto_0
    sget-object v0, Ld6/r0;->a:Ljava/util/WeakHashMap;

    .line 41
    .line 42
    invoke-virtual {p1, p0}, Landroid/view/View;->offsetLeftAndRight(I)V

    .line 43
    .line 44
    .line 45
    const/4 p0, 0x0

    .line 46
    invoke-virtual {p1, p0}, Landroid/view/View;->setAlpha(F)V

    .line 47
    .line 48
    .line 49
    return v2

    .line 50
    :cond_4
    return v1
.end method

.method public C()F
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 6

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    move-wide v1, p1

    .line 7
    move-object v3, p3

    .line 8
    move-object v4, p4

    .line 9
    move-object v5, p5

    .line 10
    invoke-virtual/range {v0 .. v5}, Lcom/google/firebase/messaging/w;->D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public E(I)I
    .locals 1

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh11/h;

    .line 4
    .line 5
    iget v0, p0, Lh11/h;->d:I

    .line 6
    .line 7
    add-int/lit8 v0, v0, -0x1

    .line 8
    .line 9
    if-gt p1, v0, :cond_0

    .line 10
    .line 11
    return p1

    .line 12
    :cond_0
    iget v0, p0, Lh11/h;->e:I

    .line 13
    .line 14
    add-int/lit8 v0, v0, -0x1

    .line 15
    .line 16
    if-gt p1, v0, :cond_1

    .line 17
    .line 18
    add-int/lit8 p1, p1, -0x1

    .line 19
    .line 20
    return p1

    .line 21
    :cond_1
    iget p0, p0, Lh11/h;->f:I

    .line 22
    .line 23
    add-int/lit8 v0, p0, 0x1

    .line 24
    .line 25
    if-gt p1, v0, :cond_2

    .line 26
    .line 27
    add-int/lit8 p1, p1, -0x2

    .line 28
    .line 29
    return p1

    .line 30
    :cond_2
    return p0
.end method

.method public F(Lt4/k;JLt4/m;J)J
    .locals 7

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lay0/a;

    .line 4
    .line 5
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lt4/j;

    .line 10
    .line 11
    iget-wide v0, p0, Lt4/j;->a:J

    .line 12
    .line 13
    iget p0, p1, Lt4/k;->a:I

    .line 14
    .line 15
    const/16 v2, 0x20

    .line 16
    .line 17
    shr-long v3, v0, v2

    .line 18
    .line 19
    long-to-int v3, v3

    .line 20
    add-int/2addr p0, v3

    .line 21
    shr-long v3, p5, v2

    .line 22
    .line 23
    long-to-int v3, v3

    .line 24
    shr-long v4, p2, v2

    .line 25
    .line 26
    long-to-int v4, v4

    .line 27
    sget-object v5, Lt4/m;->d:Lt4/m;

    .line 28
    .line 29
    const/4 v6, 0x1

    .line 30
    if-ne p4, v5, :cond_0

    .line 31
    .line 32
    move p4, v6

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    const/4 p4, 0x0

    .line 35
    :goto_0
    invoke-static {p0, v3, v4, p4}, Lkp/b7;->a(IIIZ)I

    .line 36
    .line 37
    .line 38
    move-result p0

    .line 39
    iget p1, p1, Lt4/k;->b:I

    .line 40
    .line 41
    const-wide v3, 0xffffffffL

    .line 42
    .line 43
    .line 44
    .line 45
    .line 46
    and-long/2addr v0, v3

    .line 47
    long-to-int p4, v0

    .line 48
    add-int/2addr p1, p4

    .line 49
    and-long p4, p5, v3

    .line 50
    .line 51
    long-to-int p4, p4

    .line 52
    and-long/2addr p2, v3

    .line 53
    long-to-int p2, p2

    .line 54
    invoke-static {p1, p4, p2, v6}, Lkp/b7;->a(IIIZ)I

    .line 55
    .line 56
    .line 57
    move-result p1

    .line 58
    int-to-long p2, p0

    .line 59
    shl-long/2addr p2, v2

    .line 60
    int-to-long p0, p1

    .line 61
    and-long/2addr p0, v3

    .line 62
    or-long/2addr p0, p2

    .line 63
    return-wide p0
.end method

.method public I(Lg1/e2;Ljava/lang/Float;Ljava/lang/Float;Lay0/k;Lh1/f;)Ljava/lang/Object;
    .locals 3

    .line 1
    invoke-virtual {p2}, Ljava/lang/Number;->floatValue()F

    .line 2
    .line 3
    .line 4
    move-result p2

    .line 5
    invoke-virtual {p3}, Ljava/lang/Number;->floatValue()F

    .line 6
    .line 7
    .line 8
    move-result p3

    .line 9
    const/4 v0, 0x0

    .line 10
    const/16 v1, 0x1c

    .line 11
    .line 12
    invoke-static {v0, p3, v1}, Lc1/d;->b(FFI)Lc1/k;

    .line 13
    .line 14
    .line 15
    move-result-object p3

    .line 16
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lc1/u;

    .line 19
    .line 20
    move-object v2, p3

    .line 21
    move-object p3, p0

    .line 22
    move-object p0, p1

    .line 23
    move p1, p2

    .line 24
    move-object p2, v2

    .line 25
    invoke-static/range {p0 .. p5}, Lh1/k;->a(Lg1/e2;FLc1/k;Lc1/u;Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    if-ne p0, p1, :cond_0

    .line 32
    .line 33
    return-object p0

    .line 34
    :cond_0
    check-cast p0, Lh1/a;

    .line 35
    .line 36
    return-object p0
.end method

.method public K(F)J
    .locals 4

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb1/x0;

    .line 4
    .line 5
    invoke-virtual {p0, p1}, Lb1/x0;->b(F)D

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    sget v0, Lb1/y0;->a:F

    .line 10
    .line 11
    float-to-double v0, v0

    .line 12
    const-wide/high16 v2, 0x3ff0000000000000L    # 1.0

    .line 13
    .line 14
    sub-double/2addr v0, v2

    .line 15
    div-double/2addr p0, v0

    .line 16
    invoke-static {p0, p1}, Ljava/lang/Math;->exp(D)D

    .line 17
    .line 18
    .line 19
    move-result-wide p0

    .line 20
    const-wide v0, 0x408f400000000000L    # 1000.0

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    mul-double/2addr p0, v0

    .line 26
    double-to-long p0, p0

    .line 27
    const-wide/32 v0, 0xf4240

    .line 28
    .line 29
    .line 30
    mul-long/2addr p0, v0

    .line 31
    return-wide p0
.end method

.method public M(FF)F
    .locals 8

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lb1/x0;

    .line 4
    .line 5
    invoke-virtual {p0, p2}, Lb1/x0;->b(F)D

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    sget v2, Lb1/y0;->a:F

    .line 10
    .line 11
    float-to-double v2, v2

    .line 12
    const-wide/high16 v4, 0x3ff0000000000000L    # 1.0

    .line 13
    .line 14
    sub-double v4, v2, v4

    .line 15
    .line 16
    iget v6, p0, Lb1/x0;->d:F

    .line 17
    .line 18
    iget p0, p0, Lb1/x0;->e:F

    .line 19
    .line 20
    mul-float/2addr v6, p0

    .line 21
    float-to-double v6, v6

    .line 22
    div-double/2addr v2, v4

    .line 23
    mul-double/2addr v2, v0

    .line 24
    invoke-static {v2, v3}, Ljava/lang/Math;->exp(D)D

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    mul-double/2addr v0, v6

    .line 29
    double-to-float p0, v0

    .line 30
    invoke-static {p2}, Ljava/lang/Math;->signum(F)F

    .line 31
    .line 32
    .line 33
    move-result p2

    .line 34
    mul-float/2addr p2, p0

    .line 35
    add-float/2addr p2, p1

    .line 36
    return p2
.end method

.method public N()I
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo;

    .line 4
    .line 5
    invoke-static {p0}, Lc4/a;->d(Landroid/view/ContentInfo;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public O(JF)F
    .locals 4

    .line 1
    const-wide/32 v0, 0xf4240

    .line 2
    .line 3
    .line 4
    div-long/2addr p1, v0

    .line 5
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lb1/x0;

    .line 8
    .line 9
    invoke-virtual {p0, p3}, Lb1/x0;->a(F)Lb1/w0;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-wide v0, p0, Lb1/w0;->c:J

    .line 14
    .line 15
    const-wide/16 v2, 0x0

    .line 16
    .line 17
    cmp-long p3, v0, v2

    .line 18
    .line 19
    if-lez p3, :cond_0

    .line 20
    .line 21
    long-to-float p1, p1

    .line 22
    long-to-float p2, v0

    .line 23
    div-float/2addr p1, p2

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/high16 p1, 0x3f800000    # 1.0f

    .line 26
    .line 27
    :goto_0
    invoke-static {p1}, Lb1/b;->a(F)Lb1/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    iget p1, p1, Lb1/a;->b:F

    .line 32
    .line 33
    iget p2, p0, Lb1/w0;->a:F

    .line 34
    .line 35
    invoke-static {p2}, Ljava/lang/Math;->signum(F)F

    .line 36
    .line 37
    .line 38
    move-result p2

    .line 39
    mul-float/2addr p2, p1

    .line 40
    iget p0, p0, Lb1/w0;->b:F

    .line 41
    .line 42
    mul-float/2addr p2, p0

    .line 43
    long-to-float p0, v0

    .line 44
    div-float/2addr p2, p0

    .line 45
    const/high16 p0, 0x447a0000    # 1000.0f

    .line 46
    .line 47
    mul-float/2addr p2, p0

    .line 48
    return p2
.end method

.method public P(Lc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/firebase/messaging/w;->P(Lc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public Q()V
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/common/data/DataHolder;

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public R(I)I
    .locals 1

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh11/h;

    .line 4
    .line 5
    iget v0, p0, Lh11/h;->d:I

    .line 6
    .line 7
    if-ge p1, v0, :cond_0

    .line 8
    .line 9
    return p1

    .line 10
    :cond_0
    iget v0, p0, Lh11/h;->e:I

    .line 11
    .line 12
    if-ge p1, v0, :cond_1

    .line 13
    .line 14
    add-int/lit8 p1, p1, 0x1

    .line 15
    .line 16
    return p1

    .line 17
    :cond_1
    iget p0, p0, Lh11/h;->f:I

    .line 18
    .line 19
    if-gt p1, p0, :cond_2

    .line 20
    .line 21
    add-int/lit8 p1, p1, 0x2

    .line 22
    .line 23
    return p1

    .line 24
    :cond_2
    add-int/lit8 p0, p0, 0x2

    .line 25
    .line 26
    return p0
.end method

.method public S(JFF)F
    .locals 4

    .line 1
    const-wide/32 v0, 0xf4240

    .line 2
    .line 3
    .line 4
    div-long/2addr p1, v0

    .line 5
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lb1/x0;

    .line 8
    .line 9
    invoke-virtual {p0, p4}, Lb1/x0;->a(F)Lb1/w0;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    iget-wide v0, p0, Lb1/w0;->c:J

    .line 14
    .line 15
    const-wide/16 v2, 0x0

    .line 16
    .line 17
    cmp-long p4, v0, v2

    .line 18
    .line 19
    if-lez p4, :cond_0

    .line 20
    .line 21
    long-to-float p1, p1

    .line 22
    long-to-float p2, v0

    .line 23
    div-float/2addr p1, p2

    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const/high16 p1, 0x3f800000    # 1.0f

    .line 26
    .line 27
    :goto_0
    iget p2, p0, Lb1/w0;->b:F

    .line 28
    .line 29
    iget p0, p0, Lb1/w0;->a:F

    .line 30
    .line 31
    invoke-static {p0}, Ljava/lang/Math;->signum(F)F

    .line 32
    .line 33
    .line 34
    move-result p0

    .line 35
    mul-float/2addr p0, p2

    .line 36
    invoke-static {p1}, Lb1/b;->a(F)Lb1/a;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget p1, p1, Lb1/a;->a:F

    .line 41
    .line 42
    mul-float/2addr p0, p1

    .line 43
    add-float/2addr p0, p3

    .line 44
    return p0
.end method

.method public T(IILo8/p;)V
    .locals 22

    .line 1
    move/from16 v0, p1

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p0

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    iget-object v2, v2, La0/j;->e:Ljava/lang/Object;

    .line 10
    .line 11
    move-object v4, v2

    .line 12
    check-cast v4, Lg9/d;

    .line 13
    .line 14
    iget-object v2, v4, Lg9/d;->b:Lg9/e;

    .line 15
    .line 16
    iget-object v5, v4, Lg9/d;->c:Landroid/util/SparseArray;

    .line 17
    .line 18
    iget-object v6, v4, Lg9/d;->k:Lw7/p;

    .line 19
    .line 20
    iget-object v7, v4, Lg9/d;->i:Lw7/p;

    .line 21
    .line 22
    const/16 v8, 0xa1

    .line 23
    .line 24
    const/16 v9, 0xa3

    .line 25
    .line 26
    const/4 v10, 0x0

    .line 27
    const/4 v11, 0x2

    .line 28
    const/4 v12, 0x4

    .line 29
    const/4 v13, 0x1

    .line 30
    const/4 v14, 0x0

    .line 31
    if-eq v0, v8, :cond_b

    .line 32
    .line 33
    if-eq v0, v9, :cond_b

    .line 34
    .line 35
    const/16 v2, 0xa5

    .line 36
    .line 37
    if-eq v0, v2, :cond_8

    .line 38
    .line 39
    const/16 v2, 0x41ed

    .line 40
    .line 41
    if-eq v0, v2, :cond_5

    .line 42
    .line 43
    const/16 v2, 0x4255

    .line 44
    .line 45
    if-eq v0, v2, :cond_4

    .line 46
    .line 47
    const/16 v2, 0x47e2

    .line 48
    .line 49
    if-eq v0, v2, :cond_3

    .line 50
    .line 51
    const/16 v2, 0x53ab

    .line 52
    .line 53
    if-eq v0, v2, :cond_2

    .line 54
    .line 55
    const/16 v2, 0x63a2

    .line 56
    .line 57
    if-eq v0, v2, :cond_1

    .line 58
    .line 59
    const/16 v2, 0x7672

    .line 60
    .line 61
    if-ne v0, v2, :cond_0

    .line 62
    .line 63
    invoke-virtual {v4, v0}, Lg9/d;->f(I)V

    .line 64
    .line 65
    .line 66
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 67
    .line 68
    new-array v2, v1, [B

    .line 69
    .line 70
    iput-object v2, v0, Lg9/c;->x:[B

    .line 71
    .line 72
    invoke-interface {v3, v2, v14, v1}, Lo8/p;->readFully([BII)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 77
    .line 78
    const-string v2, "Unexpected id: "

    .line 79
    .line 80
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 81
    .line 82
    .line 83
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    invoke-static {v10, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 91
    .line 92
    .line 93
    move-result-object v0

    .line 94
    throw v0

    .line 95
    :cond_1
    invoke-virtual {v4, v0}, Lg9/d;->f(I)V

    .line 96
    .line 97
    .line 98
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 99
    .line 100
    new-array v2, v1, [B

    .line 101
    .line 102
    iput-object v2, v0, Lg9/c;->l:[B

    .line 103
    .line 104
    invoke-interface {v3, v2, v14, v1}, Lo8/p;->readFully([BII)V

    .line 105
    .line 106
    .line 107
    return-void

    .line 108
    :cond_2
    iget-object v0, v6, Lw7/p;->a:[B

    .line 109
    .line 110
    invoke-static {v0, v14}, Ljava/util/Arrays;->fill([BB)V

    .line 111
    .line 112
    .line 113
    iget-object v0, v6, Lw7/p;->a:[B

    .line 114
    .line 115
    rsub-int/lit8 v2, v1, 0x4

    .line 116
    .line 117
    invoke-interface {v3, v0, v2, v1}, Lo8/p;->readFully([BII)V

    .line 118
    .line 119
    .line 120
    invoke-virtual {v6, v14}, Lw7/p;->I(I)V

    .line 121
    .line 122
    .line 123
    invoke-virtual {v6}, Lw7/p;->y()J

    .line 124
    .line 125
    .line 126
    move-result-wide v0

    .line 127
    long-to-int v0, v0

    .line 128
    iput v0, v4, Lg9/d;->z:I

    .line 129
    .line 130
    return-void

    .line 131
    :cond_3
    new-array v2, v1, [B

    .line 132
    .line 133
    invoke-interface {v3, v2, v14, v1}, Lo8/p;->readFully([BII)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v4, v0}, Lg9/d;->f(I)V

    .line 137
    .line 138
    .line 139
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 140
    .line 141
    new-instance v1, Lo8/h0;

    .line 142
    .line 143
    invoke-direct {v1, v13, v2, v14, v14}, Lo8/h0;-><init>(I[BII)V

    .line 144
    .line 145
    .line 146
    iput-object v1, v0, Lg9/c;->k:Lo8/h0;

    .line 147
    .line 148
    return-void

    .line 149
    :cond_4
    invoke-virtual {v4, v0}, Lg9/d;->f(I)V

    .line 150
    .line 151
    .line 152
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 153
    .line 154
    new-array v2, v1, [B

    .line 155
    .line 156
    iput-object v2, v0, Lg9/c;->j:[B

    .line 157
    .line 158
    invoke-interface {v3, v2, v14, v1}, Lo8/p;->readFully([BII)V

    .line 159
    .line 160
    .line 161
    return-void

    .line 162
    :cond_5
    invoke-virtual {v4, v0}, Lg9/d;->f(I)V

    .line 163
    .line 164
    .line 165
    iget-object v0, v4, Lg9/d;->x:Lg9/c;

    .line 166
    .line 167
    iget v2, v0, Lg9/c;->h:I

    .line 168
    .line 169
    const v4, 0x64767643

    .line 170
    .line 171
    .line 172
    if-eq v2, v4, :cond_7

    .line 173
    .line 174
    const v4, 0x64766343

    .line 175
    .line 176
    .line 177
    if-ne v2, v4, :cond_6

    .line 178
    .line 179
    goto :goto_0

    .line 180
    :cond_6
    invoke-interface {v3, v1}, Lo8/p;->n(I)V

    .line 181
    .line 182
    .line 183
    return-void

    .line 184
    :cond_7
    :goto_0
    new-array v2, v1, [B

    .line 185
    .line 186
    iput-object v2, v0, Lg9/c;->P:[B

    .line 187
    .line 188
    invoke-interface {v3, v2, v14, v1}, Lo8/p;->readFully([BII)V

    .line 189
    .line 190
    .line 191
    return-void

    .line 192
    :cond_8
    iget v0, v4, Lg9/d;->J:I

    .line 193
    .line 194
    if-eq v0, v11, :cond_9

    .line 195
    .line 196
    goto/16 :goto_12

    .line 197
    .line 198
    :cond_9
    iget v0, v4, Lg9/d;->P:I

    .line 199
    .line 200
    invoke-virtual {v5, v0}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object v0

    .line 204
    check-cast v0, Lg9/c;

    .line 205
    .line 206
    iget v2, v4, Lg9/d;->S:I

    .line 207
    .line 208
    iget-object v4, v4, Lg9/d;->p:Lw7/p;

    .line 209
    .line 210
    if-ne v2, v12, :cond_a

    .line 211
    .line 212
    const-string v2, "V_VP9"

    .line 213
    .line 214
    iget-object v0, v0, Lg9/c;->c:Ljava/lang/String;

    .line 215
    .line 216
    invoke-virtual {v2, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 217
    .line 218
    .line 219
    move-result v0

    .line 220
    if-eqz v0, :cond_a

    .line 221
    .line 222
    invoke-virtual {v4, v1}, Lw7/p;->F(I)V

    .line 223
    .line 224
    .line 225
    iget-object v0, v4, Lw7/p;->a:[B

    .line 226
    .line 227
    invoke-interface {v3, v0, v14, v1}, Lo8/p;->readFully([BII)V

    .line 228
    .line 229
    .line 230
    return-void

    .line 231
    :cond_a
    invoke-interface {v3, v1}, Lo8/p;->n(I)V

    .line 232
    .line 233
    .line 234
    return-void

    .line 235
    :cond_b
    iget v6, v4, Lg9/d;->J:I

    .line 236
    .line 237
    const/16 v8, 0x8

    .line 238
    .line 239
    if-nez v6, :cond_c

    .line 240
    .line 241
    invoke-virtual {v2, v3, v14, v13, v8}, Lg9/e;->b(Lo8/p;ZZI)J

    .line 242
    .line 243
    .line 244
    move-result-wide v9

    .line 245
    long-to-int v9, v9

    .line 246
    iput v9, v4, Lg9/d;->P:I

    .line 247
    .line 248
    iget v2, v2, Lg9/e;->c:I

    .line 249
    .line 250
    iput v2, v4, Lg9/d;->Q:I

    .line 251
    .line 252
    const-wide v9, -0x7fffffffffffffffL    # -4.9E-324

    .line 253
    .line 254
    .line 255
    .line 256
    .line 257
    iput-wide v9, v4, Lg9/d;->L:J

    .line 258
    .line 259
    iput v13, v4, Lg9/d;->J:I

    .line 260
    .line 261
    invoke-virtual {v7, v14}, Lw7/p;->F(I)V

    .line 262
    .line 263
    .line 264
    :cond_c
    iget v2, v4, Lg9/d;->P:I

    .line 265
    .line 266
    invoke-virtual {v5, v2}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 267
    .line 268
    .line 269
    move-result-object v2

    .line 270
    move-object v5, v2

    .line 271
    check-cast v5, Lg9/c;

    .line 272
    .line 273
    if-nez v5, :cond_d

    .line 274
    .line 275
    iget v0, v4, Lg9/d;->Q:I

    .line 276
    .line 277
    sub-int v0, v1, v0

    .line 278
    .line 279
    invoke-interface {v3, v0}, Lo8/p;->n(I)V

    .line 280
    .line 281
    .line 282
    iput v14, v4, Lg9/d;->J:I

    .line 283
    .line 284
    return-void

    .line 285
    :cond_d
    iget-object v2, v5, Lg9/c;->Z:Lo8/i0;

    .line 286
    .line 287
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 288
    .line 289
    .line 290
    iget v2, v4, Lg9/d;->J:I

    .line 291
    .line 292
    if-ne v2, v13, :cond_22

    .line 293
    .line 294
    const/4 v2, 0x3

    .line 295
    invoke-virtual {v4, v3, v2}, Lg9/d;->k(Lo8/p;I)V

    .line 296
    .line 297
    .line 298
    iget-object v9, v7, Lw7/p;->a:[B

    .line 299
    .line 300
    aget-byte v9, v9, v11

    .line 301
    .line 302
    and-int/lit8 v9, v9, 0x6

    .line 303
    .line 304
    shr-int/2addr v9, v13

    .line 305
    const/16 v10, 0xff

    .line 306
    .line 307
    if-nez v9, :cond_10

    .line 308
    .line 309
    iput v13, v4, Lg9/d;->N:I

    .line 310
    .line 311
    iget-object v6, v4, Lg9/d;->O:[I

    .line 312
    .line 313
    if-nez v6, :cond_e

    .line 314
    .line 315
    new-array v6, v13, [I

    .line 316
    .line 317
    goto :goto_1

    .line 318
    :cond_e
    array-length v9, v6

    .line 319
    if-lt v9, v13, :cond_f

    .line 320
    .line 321
    goto :goto_1

    .line 322
    :cond_f
    array-length v6, v6

    .line 323
    mul-int/2addr v6, v11

    .line 324
    invoke-static {v6, v13}, Ljava/lang/Math;->max(II)I

    .line 325
    .line 326
    .line 327
    move-result v6

    .line 328
    new-array v6, v6, [I

    .line 329
    .line 330
    :goto_1
    iput-object v6, v4, Lg9/d;->O:[I

    .line 331
    .line 332
    iget v9, v4, Lg9/d;->Q:I

    .line 333
    .line 334
    sub-int/2addr v1, v9

    .line 335
    sub-int/2addr v1, v2

    .line 336
    aput v1, v6, v14

    .line 337
    .line 338
    :goto_2
    move/from16 v18, v8

    .line 339
    .line 340
    move/from16 v17, v13

    .line 341
    .line 342
    move/from16 v19, v14

    .line 343
    .line 344
    goto/16 :goto_b

    .line 345
    .line 346
    :cond_10
    invoke-virtual {v4, v3, v12}, Lg9/d;->k(Lo8/p;I)V

    .line 347
    .line 348
    .line 349
    iget-object v15, v7, Lw7/p;->a:[B

    .line 350
    .line 351
    aget-byte v15, v15, v2

    .line 352
    .line 353
    and-int/2addr v15, v10

    .line 354
    add-int/2addr v15, v13

    .line 355
    iput v15, v4, Lg9/d;->N:I

    .line 356
    .line 357
    iget-object v6, v4, Lg9/d;->O:[I

    .line 358
    .line 359
    if-nez v6, :cond_11

    .line 360
    .line 361
    new-array v6, v15, [I

    .line 362
    .line 363
    move/from16 v17, v12

    .line 364
    .line 365
    goto :goto_3

    .line 366
    :cond_11
    move/from16 v17, v12

    .line 367
    .line 368
    array-length v12, v6

    .line 369
    if-lt v12, v15, :cond_12

    .line 370
    .line 371
    goto :goto_3

    .line 372
    :cond_12
    array-length v6, v6

    .line 373
    mul-int/2addr v6, v11

    .line 374
    invoke-static {v6, v15}, Ljava/lang/Math;->max(II)I

    .line 375
    .line 376
    .line 377
    move-result v6

    .line 378
    new-array v6, v6, [I

    .line 379
    .line 380
    :goto_3
    iput-object v6, v4, Lg9/d;->O:[I

    .line 381
    .line 382
    if-ne v9, v11, :cond_13

    .line 383
    .line 384
    iget v2, v4, Lg9/d;->Q:I

    .line 385
    .line 386
    sub-int/2addr v1, v2

    .line 387
    add-int/lit8 v1, v1, -0x4

    .line 388
    .line 389
    iget v2, v4, Lg9/d;->N:I

    .line 390
    .line 391
    div-int/2addr v1, v2

    .line 392
    invoke-static {v6, v14, v2, v1}, Ljava/util/Arrays;->fill([IIII)V

    .line 393
    .line 394
    .line 395
    goto :goto_2

    .line 396
    :cond_13
    if-ne v9, v13, :cond_16

    .line 397
    .line 398
    move v2, v14

    .line 399
    move v6, v2

    .line 400
    move/from16 v12, v17

    .line 401
    .line 402
    :goto_4
    iget v9, v4, Lg9/d;->N:I

    .line 403
    .line 404
    sub-int/2addr v9, v13

    .line 405
    if-ge v2, v9, :cond_15

    .line 406
    .line 407
    iget-object v9, v4, Lg9/d;->O:[I

    .line 408
    .line 409
    aput v14, v9, v2

    .line 410
    .line 411
    :goto_5
    add-int/lit8 v9, v12, 0x1

    .line 412
    .line 413
    invoke-virtual {v4, v3, v9}, Lg9/d;->k(Lo8/p;I)V

    .line 414
    .line 415
    .line 416
    iget-object v15, v7, Lw7/p;->a:[B

    .line 417
    .line 418
    aget-byte v12, v15, v12

    .line 419
    .line 420
    and-int/2addr v12, v10

    .line 421
    iget-object v15, v4, Lg9/d;->O:[I

    .line 422
    .line 423
    aget v16, v15, v2

    .line 424
    .line 425
    add-int v16, v16, v12

    .line 426
    .line 427
    aput v16, v15, v2

    .line 428
    .line 429
    if-eq v12, v10, :cond_14

    .line 430
    .line 431
    add-int v6, v6, v16

    .line 432
    .line 433
    add-int/lit8 v2, v2, 0x1

    .line 434
    .line 435
    move v12, v9

    .line 436
    goto :goto_4

    .line 437
    :cond_14
    move v12, v9

    .line 438
    goto :goto_5

    .line 439
    :cond_15
    iget-object v2, v4, Lg9/d;->O:[I

    .line 440
    .line 441
    iget v15, v4, Lg9/d;->Q:I

    .line 442
    .line 443
    sub-int/2addr v1, v15

    .line 444
    sub-int/2addr v1, v12

    .line 445
    sub-int/2addr v1, v6

    .line 446
    aput v1, v2, v9

    .line 447
    .line 448
    goto :goto_2

    .line 449
    :cond_16
    if-ne v9, v2, :cond_21

    .line 450
    .line 451
    move v2, v14

    .line 452
    move v6, v2

    .line 453
    move/from16 v12, v17

    .line 454
    .line 455
    :goto_6
    iget v9, v4, Lg9/d;->N:I

    .line 456
    .line 457
    sub-int/2addr v9, v13

    .line 458
    if-ge v2, v9, :cond_1e

    .line 459
    .line 460
    iget-object v9, v4, Lg9/d;->O:[I

    .line 461
    .line 462
    aput v14, v9, v2

    .line 463
    .line 464
    add-int/lit8 v9, v12, 0x1

    .line 465
    .line 466
    invoke-virtual {v4, v3, v9}, Lg9/d;->k(Lo8/p;I)V

    .line 467
    .line 468
    .line 469
    iget-object v15, v7, Lw7/p;->a:[B

    .line 470
    .line 471
    aget-byte v15, v15, v12

    .line 472
    .line 473
    if-eqz v15, :cond_1d

    .line 474
    .line 475
    move v15, v14

    .line 476
    :goto_7
    if-ge v15, v8, :cond_19

    .line 477
    .line 478
    rsub-int/lit8 v17, v15, 0x7

    .line 479
    .line 480
    move/from16 v18, v8

    .line 481
    .line 482
    shl-int v8, v13, v17

    .line 483
    .line 484
    move/from16 v17, v13

    .line 485
    .line 486
    iget-object v13, v7, Lw7/p;->a:[B

    .line 487
    .line 488
    aget-byte v13, v13, v12

    .line 489
    .line 490
    and-int/2addr v13, v8

    .line 491
    if-eqz v13, :cond_18

    .line 492
    .line 493
    add-int v13, v9, v15

    .line 494
    .line 495
    invoke-virtual {v4, v3, v13}, Lg9/d;->k(Lo8/p;I)V

    .line 496
    .line 497
    .line 498
    move/from16 v19, v14

    .line 499
    .line 500
    iget-object v14, v7, Lw7/p;->a:[B

    .line 501
    .line 502
    aget-byte v12, v14, v12

    .line 503
    .line 504
    and-int/2addr v12, v10

    .line 505
    not-int v8, v8

    .line 506
    and-int/2addr v8, v12

    .line 507
    int-to-long v11, v8

    .line 508
    :goto_8
    if-ge v9, v13, :cond_17

    .line 509
    .line 510
    shl-long v11, v11, v18

    .line 511
    .line 512
    iget-object v8, v7, Lw7/p;->a:[B

    .line 513
    .line 514
    add-int/lit8 v20, v9, 0x1

    .line 515
    .line 516
    aget-byte v8, v8, v9

    .line 517
    .line 518
    and-int/2addr v8, v10

    .line 519
    int-to-long v8, v8

    .line 520
    or-long/2addr v11, v8

    .line 521
    move/from16 v9, v20

    .line 522
    .line 523
    goto :goto_8

    .line 524
    :cond_17
    if-lez v2, :cond_1a

    .line 525
    .line 526
    mul-int/lit8 v15, v15, 0x7

    .line 527
    .line 528
    add-int/lit8 v15, v15, 0x6

    .line 529
    .line 530
    const-wide/16 v8, 0x1

    .line 531
    .line 532
    shl-long v20, v8, v15

    .line 533
    .line 534
    sub-long v20, v20, v8

    .line 535
    .line 536
    sub-long v11, v11, v20

    .line 537
    .line 538
    goto :goto_9

    .line 539
    :cond_18
    move/from16 v19, v14

    .line 540
    .line 541
    add-int/lit8 v15, v15, 0x1

    .line 542
    .line 543
    move/from16 v13, v17

    .line 544
    .line 545
    move/from16 v8, v18

    .line 546
    .line 547
    const/4 v11, 0x2

    .line 548
    goto :goto_7

    .line 549
    :cond_19
    move/from16 v18, v8

    .line 550
    .line 551
    move/from16 v17, v13

    .line 552
    .line 553
    move/from16 v19, v14

    .line 554
    .line 555
    const-wide/16 v11, 0x0

    .line 556
    .line 557
    move v13, v9

    .line 558
    :cond_1a
    :goto_9
    const-wide/32 v8, -0x80000000

    .line 559
    .line 560
    .line 561
    cmp-long v8, v11, v8

    .line 562
    .line 563
    if-ltz v8, :cond_1c

    .line 564
    .line 565
    const-wide/32 v8, 0x7fffffff

    .line 566
    .line 567
    .line 568
    cmp-long v8, v11, v8

    .line 569
    .line 570
    if-gtz v8, :cond_1c

    .line 571
    .line 572
    long-to-int v8, v11

    .line 573
    iget-object v9, v4, Lg9/d;->O:[I

    .line 574
    .line 575
    if-nez v2, :cond_1b

    .line 576
    .line 577
    goto :goto_a

    .line 578
    :cond_1b
    add-int/lit8 v11, v2, -0x1

    .line 579
    .line 580
    aget v11, v9, v11

    .line 581
    .line 582
    add-int/2addr v8, v11

    .line 583
    :goto_a
    aput v8, v9, v2

    .line 584
    .line 585
    add-int/2addr v6, v8

    .line 586
    add-int/lit8 v2, v2, 0x1

    .line 587
    .line 588
    move v12, v13

    .line 589
    move/from16 v13, v17

    .line 590
    .line 591
    move/from16 v8, v18

    .line 592
    .line 593
    move/from16 v14, v19

    .line 594
    .line 595
    const/4 v11, 0x2

    .line 596
    goto/16 :goto_6

    .line 597
    .line 598
    :cond_1c
    const-string v0, "EBML lacing sample size out of range."

    .line 599
    .line 600
    const/4 v6, 0x0

    .line 601
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 602
    .line 603
    .line 604
    move-result-object v0

    .line 605
    throw v0

    .line 606
    :cond_1d
    const/4 v6, 0x0

    .line 607
    const-string v0, "No valid varint length mask found"

    .line 608
    .line 609
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 610
    .line 611
    .line 612
    move-result-object v0

    .line 613
    throw v0

    .line 614
    :cond_1e
    move/from16 v18, v8

    .line 615
    .line 616
    move/from16 v17, v13

    .line 617
    .line 618
    move/from16 v19, v14

    .line 619
    .line 620
    iget-object v2, v4, Lg9/d;->O:[I

    .line 621
    .line 622
    iget v8, v4, Lg9/d;->Q:I

    .line 623
    .line 624
    sub-int/2addr v1, v8

    .line 625
    sub-int/2addr v1, v12

    .line 626
    sub-int/2addr v1, v6

    .line 627
    aput v1, v2, v9

    .line 628
    .line 629
    :goto_b
    iget-object v1, v7, Lw7/p;->a:[B

    .line 630
    .line 631
    aget-byte v2, v1, v19

    .line 632
    .line 633
    shl-int/lit8 v2, v2, 0x8

    .line 634
    .line 635
    aget-byte v1, v1, v17

    .line 636
    .line 637
    and-int/2addr v1, v10

    .line 638
    or-int/2addr v1, v2

    .line 639
    iget-wide v8, v4, Lg9/d;->E:J

    .line 640
    .line 641
    int-to-long v1, v1

    .line 642
    invoke-virtual {v4, v1, v2}, Lg9/d;->m(J)J

    .line 643
    .line 644
    .line 645
    move-result-wide v1

    .line 646
    add-long/2addr v1, v8

    .line 647
    iput-wide v1, v4, Lg9/d;->K:J

    .line 648
    .line 649
    iget v1, v5, Lg9/c;->e:I

    .line 650
    .line 651
    const/4 v14, 0x2

    .line 652
    if-eq v1, v14, :cond_20

    .line 653
    .line 654
    const/16 v1, 0xa3

    .line 655
    .line 656
    if-ne v0, v1, :cond_1f

    .line 657
    .line 658
    iget-object v1, v7, Lw7/p;->a:[B

    .line 659
    .line 660
    aget-byte v1, v1, v14

    .line 661
    .line 662
    const/16 v2, 0x80

    .line 663
    .line 664
    and-int/2addr v1, v2

    .line 665
    if-ne v1, v2, :cond_1f

    .line 666
    .line 667
    goto :goto_c

    .line 668
    :cond_1f
    move/from16 v1, v19

    .line 669
    .line 670
    goto :goto_d

    .line 671
    :cond_20
    :goto_c
    move/from16 v1, v17

    .line 672
    .line 673
    :goto_d
    iput v1, v4, Lg9/d;->R:I

    .line 674
    .line 675
    iput v14, v4, Lg9/d;->J:I

    .line 676
    .line 677
    move/from16 v1, v19

    .line 678
    .line 679
    iput v1, v4, Lg9/d;->M:I

    .line 680
    .line 681
    :goto_e
    const/16 v1, 0xa3

    .line 682
    .line 683
    goto :goto_f

    .line 684
    :cond_21
    new-instance v0, Ljava/lang/StringBuilder;

    .line 685
    .line 686
    const-string v1, "Unexpected lacing value: "

    .line 687
    .line 688
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 689
    .line 690
    .line 691
    invoke-virtual {v0, v9}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 692
    .line 693
    .line 694
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 695
    .line 696
    .line 697
    move-result-object v0

    .line 698
    const/4 v6, 0x0

    .line 699
    invoke-static {v6, v0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 700
    .line 701
    .line 702
    move-result-object v0

    .line 703
    throw v0

    .line 704
    :cond_22
    move/from16 v17, v13

    .line 705
    .line 706
    goto :goto_e

    .line 707
    :goto_f
    if-ne v0, v1, :cond_24

    .line 708
    .line 709
    :goto_10
    iget v0, v4, Lg9/d;->M:I

    .line 710
    .line 711
    iget v1, v4, Lg9/d;->N:I

    .line 712
    .line 713
    if-ge v0, v1, :cond_23

    .line 714
    .line 715
    iget-object v1, v4, Lg9/d;->O:[I

    .line 716
    .line 717
    aget v0, v1, v0

    .line 718
    .line 719
    const/4 v1, 0x0

    .line 720
    invoke-virtual {v4, v3, v5, v0, v1}, Lg9/d;->n(Lo8/p;Lg9/c;IZ)I

    .line 721
    .line 722
    .line 723
    move-result v9

    .line 724
    iget-wide v0, v4, Lg9/d;->K:J

    .line 725
    .line 726
    iget v2, v4, Lg9/d;->M:I

    .line 727
    .line 728
    iget v6, v5, Lg9/c;->f:I

    .line 729
    .line 730
    mul-int/2addr v2, v6

    .line 731
    div-int/lit16 v2, v2, 0x3e8

    .line 732
    .line 733
    int-to-long v6, v2

    .line 734
    add-long/2addr v6, v0

    .line 735
    iget v8, v4, Lg9/d;->R:I

    .line 736
    .line 737
    const/4 v10, 0x0

    .line 738
    invoke-virtual/range {v4 .. v10}, Lg9/d;->g(Lg9/c;JIII)V

    .line 739
    .line 740
    .line 741
    iget v0, v4, Lg9/d;->M:I

    .line 742
    .line 743
    add-int/lit8 v0, v0, 0x1

    .line 744
    .line 745
    iput v0, v4, Lg9/d;->M:I

    .line 746
    .line 747
    goto :goto_10

    .line 748
    :cond_23
    const/4 v1, 0x0

    .line 749
    iput v1, v4, Lg9/d;->J:I

    .line 750
    .line 751
    return-void

    .line 752
    :cond_24
    :goto_11
    iget v0, v4, Lg9/d;->M:I

    .line 753
    .line 754
    iget v1, v4, Lg9/d;->N:I

    .line 755
    .line 756
    if-ge v0, v1, :cond_25

    .line 757
    .line 758
    iget-object v1, v4, Lg9/d;->O:[I

    .line 759
    .line 760
    aget v2, v1, v0

    .line 761
    .line 762
    move/from16 v6, v17

    .line 763
    .line 764
    invoke-virtual {v4, v3, v5, v2, v6}, Lg9/d;->n(Lo8/p;Lg9/c;IZ)I

    .line 765
    .line 766
    .line 767
    move-result v2

    .line 768
    aput v2, v1, v0

    .line 769
    .line 770
    iget v0, v4, Lg9/d;->M:I

    .line 771
    .line 772
    add-int/2addr v0, v6

    .line 773
    iput v0, v4, Lg9/d;->M:I

    .line 774
    .line 775
    goto :goto_11

    .line 776
    :cond_25
    :goto_12
    return-void
.end method

.method public V(Lhx/a;)Lhx/b;
    .locals 10

    .line 1
    const-string v0, "Wultra-SSL-Pinning"

    .line 2
    .line 3
    const-string v1, "message"

    .line 4
    .line 5
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Ljava/net/URL;

    .line 8
    .line 9
    invoke-virtual {p0}, Ljava/net/URL;->openConnection()Ljava/net/URLConnection;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Lcom/google/firebase/perf/network/FirebasePerfUrlConnection;->instrument(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    check-cast p0, Ljava/net/URLConnection;

    .line 18
    .line 19
    const-string v2, "null cannot be cast to non-null type java.net.HttpURLConnection"

    .line 20
    .line 21
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    check-cast p0, Ljava/net/HttpURLConnection;

    .line 25
    .line 26
    const-string v2, "GET"

    .line 27
    .line 28
    invoke-virtual {p0, v2}, Ljava/net/HttpURLConnection;->setRequestMethod(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    const-string v2, "Accept"

    .line 32
    .line 33
    const-string v3, "application/json"

    .line 34
    .line 35
    invoke-virtual {p0, v2, v3}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object p1, p1, Lhx/a;->a:Ljava/util/Map;

    .line 39
    .line 40
    invoke-interface {p1}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 41
    .line 42
    .line 43
    move-result-object p1

    .line 44
    invoke-interface {p1}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 49
    .line 50
    .line 51
    move-result v2

    .line 52
    if-eqz v2, :cond_0

    .line 53
    .line 54
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v2

    .line 58
    check-cast v2, Ljava/util/Map$Entry;

    .line 59
    .line 60
    invoke-interface {v2}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v3

    .line 64
    check-cast v3, Ljava/lang/String;

    .line 65
    .line 66
    invoke-interface {v2}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    check-cast v2, Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {p0, v3, v2}, Ljava/net/URLConnection;->addRequestProperty(Ljava/lang/String;Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_0
    :try_start_0
    invoke-virtual {p0}, Ljava/net/URLConnection;->connect()V

    .line 77
    .line 78
    .line 79
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->getResponseCode()I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    div-int/lit8 v2, p1, 0x64

    .line 84
    .line 85
    const/4 v3, 0x2

    .line 86
    if-ne v2, v3, :cond_1

    .line 87
    .line 88
    const/4 v2, 0x1

    .line 89
    goto :goto_1

    .line 90
    :cond_1
    const/4 v2, 0x0

    .line 91
    :goto_1
    if-eqz v2, :cond_2

    .line 92
    .line 93
    invoke-virtual {p0}, Ljava/net/URLConnection;->getInputStream()Ljava/io/InputStream;

    .line 94
    .line 95
    .line 96
    move-result-object v3

    .line 97
    goto :goto_2

    .line 98
    :catchall_0
    move-exception p1

    .line 99
    goto :goto_4

    .line 100
    :catch_0
    move-exception p1

    .line 101
    goto/16 :goto_5

    .line 102
    .line 103
    :cond_2
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->getErrorStream()Ljava/io/InputStream;

    .line 104
    .line 105
    .line 106
    move-result-object v3
    :try_end_0
    .catch Lhx/c; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 107
    :goto_2
    :try_start_1
    const-string v4, "it"

    .line 108
    .line 109
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    invoke-static {v3}, Llp/ud;->c(Ljava/io/InputStream;)[B

    .line 113
    .line 114
    .line 115
    move-result-object v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 116
    :try_start_2
    invoke-interface {v3}, Ljava/io/Closeable;->close()V

    .line 117
    .line 118
    .line 119
    new-instance v3, Ljava/util/LinkedHashMap;

    .line 120
    .line 121
    invoke-direct {v3}, Ljava/util/LinkedHashMap;-><init>()V

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0}, Ljava/net/URLConnection;->getHeaderFields()Ljava/util/Map;

    .line 125
    .line 126
    .line 127
    move-result-object v5

    .line 128
    invoke-interface {v5}, Ljava/util/Map;->keySet()Ljava/util/Set;

    .line 129
    .line 130
    .line 131
    move-result-object v5

    .line 132
    check-cast v5, Ljava/lang/Iterable;

    .line 133
    .line 134
    invoke-interface {v5}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 135
    .line 136
    .line 137
    move-result-object v5

    .line 138
    :cond_3
    :goto_3
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 139
    .line 140
    .line 141
    move-result v6

    .line 142
    if-eqz v6, :cond_4

    .line 143
    .line 144
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v6

    .line 148
    check-cast v6, Ljava/lang/String;

    .line 149
    .line 150
    if-eqz v6, :cond_3

    .line 151
    .line 152
    invoke-virtual {p0, v6}, Ljava/net/URLConnection;->getHeaderField(Ljava/lang/String;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v7

    .line 156
    if-eqz v7, :cond_3

    .line 157
    .line 158
    invoke-static {}, Ljava/util/Locale;->getDefault()Ljava/util/Locale;

    .line 159
    .line 160
    .line 161
    move-result-object v8

    .line 162
    const-string v9, "getDefault()"

    .line 163
    .line 164
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {v6, v8}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 168
    .line 169
    .line 170
    move-result-object v6

    .line 171
    const-string v8, "this as java.lang.String).toLowerCase(locale)"

    .line 172
    .line 173
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 174
    .line 175
    .line 176
    invoke-interface {v3, v6, v7}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    goto :goto_3

    .line 180
    :cond_4
    new-instance v5, Lhx/b;

    .line 181
    .line 182
    invoke-direct {v5, p1, v3, v4}, Lhx/b;-><init>(ILjava/util/LinkedHashMap;[B)V
    :try_end_2
    .catch Lhx/c; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 183
    .line 184
    .line 185
    if-eqz v2, :cond_5

    .line 186
    .line 187
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 188
    .line 189
    .line 190
    return-object v5

    .line 191
    :cond_5
    :try_start_3
    new-instance p1, Lhx/c;

    .line 192
    .line 193
    invoke-direct {p1, v5}, Lhx/c;-><init>(Lhx/b;)V

    .line 194
    .line 195
    .line 196
    throw p1
    :try_end_3
    .catch Lhx/c; {:try_start_3 .. :try_end_3} :catch_0
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 197
    :catchall_1
    move-exception p1

    .line 198
    :try_start_4
    throw p1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 199
    :catchall_2
    move-exception v2

    .line 200
    :try_start_5
    invoke-static {v3, p1}, Llp/vd;->b(Ljava/io/Closeable;Ljava/lang/Throwable;)V

    .line 201
    .line 202
    .line 203
    throw v2
    :try_end_5
    .catch Lhx/c; {:try_start_5 .. :try_end_5} :catch_0
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 204
    :goto_4
    :try_start_6
    new-instance v2, Ljava/lang/StringBuilder;

    .line 205
    .line 206
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 207
    .line 208
    .line 209
    const-string v3, "RestAPI: HTTP request failed with error: "

    .line 210
    .line 211
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 212
    .line 213
    .line 214
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 215
    .line 216
    .line 217
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 218
    .line 219
    .line 220
    move-result-object v2

    .line 221
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    invoke-static {v0, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 225
    .line 226
    .line 227
    throw p1

    .line 228
    :catchall_3
    move-exception p1

    .line 229
    goto :goto_6

    .line 230
    :goto_5
    iget-object v2, p1, Lhx/c;->d:Lhx/b;

    .line 231
    .line 232
    iget-object v2, v2, Lhx/b;->c:[B

    .line 233
    .line 234
    new-instance v2, Ljava/lang/StringBuilder;

    .line 235
    .line 236
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 237
    .line 238
    .line 239
    const-string v3, "RestAPI: HTTP request failed with response code "

    .line 240
    .line 241
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    iget-object v3, p1, Lhx/c;->d:Lhx/b;

    .line 245
    .line 246
    iget v3, v3, Lhx/b;->a:I

    .line 247
    .line 248
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 249
    .line 250
    .line 251
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 252
    .line 253
    .line 254
    move-result-object v2

    .line 255
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 256
    .line 257
    .line 258
    invoke-static {v0, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 259
    .line 260
    .line 261
    throw p1
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 262
    :goto_6
    invoke-virtual {p0}, Ljava/net/HttpURLConnection;->disconnect()V

    .line 263
    .line 264
    .line 265
    throw p1
.end method

.method public W(IJ)V
    .locals 8

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lg9/d;

    .line 4
    .line 5
    const/16 v0, 0x5031

    .line 6
    .line 7
    const/4 v1, 0x0

    .line 8
    const-string v2, " not supported"

    .line 9
    .line 10
    if-eq p1, v0, :cond_13

    .line 11
    .line 12
    const/16 v0, 0x5032

    .line 13
    .line 14
    const-wide/16 v3, 0x1

    .line 15
    .line 16
    if-eq p1, v0, :cond_11

    .line 17
    .line 18
    const/4 v0, 0x0

    .line 19
    const/4 v5, 0x3

    .line 20
    const/4 v6, 0x2

    .line 21
    const/4 v7, 0x1

    .line 22
    sparse-switch p1, :sswitch_data_0

    .line 23
    .line 24
    .line 25
    const/4 v0, -0x1

    .line 26
    packed-switch p1, :pswitch_data_0

    .line 27
    .line 28
    .line 29
    goto/16 :goto_0

    .line 30
    .line 31
    :pswitch_0
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 32
    .line 33
    .line 34
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 35
    .line 36
    long-to-int p1, p2

    .line 37
    iput p1, p0, Lg9/c;->E:I

    .line 38
    .line 39
    return-void

    .line 40
    :pswitch_1
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 41
    .line 42
    .line 43
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 44
    .line 45
    long-to-int p1, p2

    .line 46
    iput p1, p0, Lg9/c;->D:I

    .line 47
    .line 48
    return-void

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 50
    .line 51
    .line 52
    iget-object p1, p0, Lg9/d;->x:Lg9/c;

    .line 53
    .line 54
    iput-boolean v7, p1, Lg9/c;->z:Z

    .line 55
    .line 56
    long-to-int p1, p2

    .line 57
    invoke-static {p1}, Lt7/f;->f(I)I

    .line 58
    .line 59
    .line 60
    move-result p1

    .line 61
    if-eq p1, v0, :cond_14

    .line 62
    .line 63
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 64
    .line 65
    iput p1, p0, Lg9/c;->A:I

    .line 66
    .line 67
    return-void

    .line 68
    :pswitch_3
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 69
    .line 70
    .line 71
    long-to-int p1, p2

    .line 72
    invoke-static {p1}, Lt7/f;->g(I)I

    .line 73
    .line 74
    .line 75
    move-result p1

    .line 76
    if-eq p1, v0, :cond_14

    .line 77
    .line 78
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 79
    .line 80
    iput p1, p0, Lg9/c;->B:I

    .line 81
    .line 82
    return-void

    .line 83
    :pswitch_4
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 84
    .line 85
    .line 86
    long-to-int p1, p2

    .line 87
    if-eq p1, v7, :cond_1

    .line 88
    .line 89
    if-eq p1, v6, :cond_0

    .line 90
    .line 91
    goto/16 :goto_0

    .line 92
    .line 93
    :cond_0
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 94
    .line 95
    iput v7, p0, Lg9/c;->C:I

    .line 96
    .line 97
    return-void

    .line 98
    :cond_1
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 99
    .line 100
    iput v6, p0, Lg9/c;->C:I

    .line 101
    .line 102
    return-void

    .line 103
    :sswitch_0
    iput-wide p2, p0, Lg9/d;->t:J

    .line 104
    .line 105
    return-void

    .line 106
    :sswitch_1
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 107
    .line 108
    .line 109
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 110
    .line 111
    long-to-int p1, p2

    .line 112
    iput p1, p0, Lg9/c;->f:I

    .line 113
    .line 114
    return-void

    .line 115
    :sswitch_2
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 116
    .line 117
    .line 118
    long-to-int p1, p2

    .line 119
    if-eqz p1, :cond_5

    .line 120
    .line 121
    if-eq p1, v7, :cond_4

    .line 122
    .line 123
    if-eq p1, v6, :cond_3

    .line 124
    .line 125
    if-eq p1, v5, :cond_2

    .line 126
    .line 127
    goto/16 :goto_0

    .line 128
    .line 129
    :cond_2
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 130
    .line 131
    iput v5, p0, Lg9/c;->t:I

    .line 132
    .line 133
    return-void

    .line 134
    :cond_3
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 135
    .line 136
    iput v6, p0, Lg9/c;->t:I

    .line 137
    .line 138
    return-void

    .line 139
    :cond_4
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 140
    .line 141
    iput v7, p0, Lg9/c;->t:I

    .line 142
    .line 143
    return-void

    .line 144
    :cond_5
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 145
    .line 146
    iput v0, p0, Lg9/c;->t:I

    .line 147
    .line 148
    return-void

    .line 149
    :sswitch_3
    iput-wide p2, p0, Lg9/d;->U:J

    .line 150
    .line 151
    return-void

    .line 152
    :sswitch_4
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 153
    .line 154
    .line 155
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 156
    .line 157
    long-to-int p1, p2

    .line 158
    iput p1, p0, Lg9/c;->R:I

    .line 159
    .line 160
    return-void

    .line 161
    :sswitch_5
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 162
    .line 163
    .line 164
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 165
    .line 166
    iput-wide p2, p0, Lg9/c;->U:J

    .line 167
    .line 168
    return-void

    .line 169
    :sswitch_6
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 170
    .line 171
    .line 172
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 173
    .line 174
    iput-wide p2, p0, Lg9/c;->T:J

    .line 175
    .line 176
    return-void

    .line 177
    :sswitch_7
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 178
    .line 179
    .line 180
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 181
    .line 182
    long-to-int p1, p2

    .line 183
    iput p1, p0, Lg9/c;->g:I

    .line 184
    .line 185
    return-void

    .line 186
    :sswitch_8
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 187
    .line 188
    .line 189
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 190
    .line 191
    iput-boolean v7, p0, Lg9/c;->z:Z

    .line 192
    .line 193
    long-to-int p1, p2

    .line 194
    iput p1, p0, Lg9/c;->p:I

    .line 195
    .line 196
    return-void

    .line 197
    :sswitch_9
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 198
    .line 199
    .line 200
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 201
    .line 202
    cmp-long p1, p2, v3

    .line 203
    .line 204
    if-nez p1, :cond_6

    .line 205
    .line 206
    move v0, v7

    .line 207
    :cond_6
    iput-boolean v0, p0, Lg9/c;->W:Z

    .line 208
    .line 209
    return-void

    .line 210
    :sswitch_a
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 211
    .line 212
    .line 213
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 214
    .line 215
    long-to-int p1, p2

    .line 216
    iput p1, p0, Lg9/c;->r:I

    .line 217
    .line 218
    return-void

    .line 219
    :sswitch_b
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 220
    .line 221
    .line 222
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 223
    .line 224
    long-to-int p1, p2

    .line 225
    iput p1, p0, Lg9/c;->s:I

    .line 226
    .line 227
    return-void

    .line 228
    :sswitch_c
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 229
    .line 230
    .line 231
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 232
    .line 233
    long-to-int p1, p2

    .line 234
    iput p1, p0, Lg9/c;->q:I

    .line 235
    .line 236
    return-void

    .line 237
    :sswitch_d
    long-to-int p2, p2

    .line 238
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 239
    .line 240
    .line 241
    if-eqz p2, :cond_a

    .line 242
    .line 243
    if-eq p2, v7, :cond_9

    .line 244
    .line 245
    if-eq p2, v5, :cond_8

    .line 246
    .line 247
    const/16 p1, 0xf

    .line 248
    .line 249
    if-eq p2, p1, :cond_7

    .line 250
    .line 251
    goto/16 :goto_0

    .line 252
    .line 253
    :cond_7
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 254
    .line 255
    iput v5, p0, Lg9/c;->y:I

    .line 256
    .line 257
    return-void

    .line 258
    :cond_8
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 259
    .line 260
    iput v7, p0, Lg9/c;->y:I

    .line 261
    .line 262
    return-void

    .line 263
    :cond_9
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 264
    .line 265
    iput v6, p0, Lg9/c;->y:I

    .line 266
    .line 267
    return-void

    .line 268
    :cond_a
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 269
    .line 270
    iput v0, p0, Lg9/c;->y:I

    .line 271
    .line 272
    return-void

    .line 273
    :sswitch_e
    iget-wide v0, p0, Lg9/d;->s:J

    .line 274
    .line 275
    add-long/2addr p2, v0

    .line 276
    iput-wide p2, p0, Lg9/d;->A:J

    .line 277
    .line 278
    return-void

    .line 279
    :sswitch_f
    cmp-long p0, p2, v3

    .line 280
    .line 281
    if-nez p0, :cond_b

    .line 282
    .line 283
    goto/16 :goto_0

    .line 284
    .line 285
    :cond_b
    new-instance p0, Ljava/lang/StringBuilder;

    .line 286
    .line 287
    const-string p1, "AESSettingsCipherMode "

    .line 288
    .line 289
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 290
    .line 291
    .line 292
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 296
    .line 297
    .line 298
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 303
    .line 304
    .line 305
    move-result-object p0

    .line 306
    throw p0

    .line 307
    :sswitch_10
    const-wide/16 p0, 0x5

    .line 308
    .line 309
    cmp-long p0, p2, p0

    .line 310
    .line 311
    if-nez p0, :cond_c

    .line 312
    .line 313
    goto/16 :goto_0

    .line 314
    .line 315
    :cond_c
    new-instance p0, Ljava/lang/StringBuilder;

    .line 316
    .line 317
    const-string p1, "ContentEncAlgo "

    .line 318
    .line 319
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 320
    .line 321
    .line 322
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 323
    .line 324
    .line 325
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 326
    .line 327
    .line 328
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 333
    .line 334
    .line 335
    move-result-object p0

    .line 336
    throw p0

    .line 337
    :sswitch_11
    cmp-long p0, p2, v3

    .line 338
    .line 339
    if-nez p0, :cond_d

    .line 340
    .line 341
    goto/16 :goto_0

    .line 342
    .line 343
    :cond_d
    new-instance p0, Ljava/lang/StringBuilder;

    .line 344
    .line 345
    const-string p1, "EBMLReadVersion "

    .line 346
    .line 347
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 348
    .line 349
    .line 350
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 351
    .line 352
    .line 353
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 354
    .line 355
    .line 356
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object p0

    .line 360
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 361
    .line 362
    .line 363
    move-result-object p0

    .line 364
    throw p0

    .line 365
    :sswitch_12
    cmp-long p0, p2, v3

    .line 366
    .line 367
    if-ltz p0, :cond_e

    .line 368
    .line 369
    const-wide/16 p0, 0x2

    .line 370
    .line 371
    cmp-long p0, p2, p0

    .line 372
    .line 373
    if-gtz p0, :cond_e

    .line 374
    .line 375
    goto/16 :goto_0

    .line 376
    .line 377
    :cond_e
    new-instance p0, Ljava/lang/StringBuilder;

    .line 378
    .line 379
    const-string p1, "DocTypeReadVersion "

    .line 380
    .line 381
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 382
    .line 383
    .line 384
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 385
    .line 386
    .line 387
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 388
    .line 389
    .line 390
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 391
    .line 392
    .line 393
    move-result-object p0

    .line 394
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 395
    .line 396
    .line 397
    move-result-object p0

    .line 398
    throw p0

    .line 399
    :sswitch_13
    const-wide/16 p0, 0x3

    .line 400
    .line 401
    cmp-long p0, p2, p0

    .line 402
    .line 403
    if-nez p0, :cond_f

    .line 404
    .line 405
    goto/16 :goto_0

    .line 406
    .line 407
    :cond_f
    new-instance p0, Ljava/lang/StringBuilder;

    .line 408
    .line 409
    const-string p1, "ContentCompAlgo "

    .line 410
    .line 411
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 412
    .line 413
    .line 414
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 415
    .line 416
    .line 417
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 418
    .line 419
    .line 420
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 421
    .line 422
    .line 423
    move-result-object p0

    .line 424
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 425
    .line 426
    .line 427
    move-result-object p0

    .line 428
    throw p0

    .line 429
    :sswitch_14
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 430
    .line 431
    .line 432
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 433
    .line 434
    long-to-int p1, p2

    .line 435
    iput p1, p0, Lg9/c;->h:I

    .line 436
    .line 437
    return-void

    .line 438
    :sswitch_15
    iput-boolean v7, p0, Lg9/d;->T:Z

    .line 439
    .line 440
    return-void

    .line 441
    :sswitch_16
    iget-boolean v0, p0, Lg9/d;->H:Z

    .line 442
    .line 443
    if-nez v0, :cond_14

    .line 444
    .line 445
    invoke-virtual {p0, p1}, Lg9/d;->e(I)V

    .line 446
    .line 447
    .line 448
    iget-object p1, p0, Lg9/d;->G:Lq3/b;

    .line 449
    .line 450
    invoke-virtual {p1, p2, p3}, Lq3/b;->a(J)V

    .line 451
    .line 452
    .line 453
    iput-boolean v7, p0, Lg9/d;->H:Z

    .line 454
    .line 455
    return-void

    .line 456
    :sswitch_17
    long-to-int p1, p2

    .line 457
    iput p1, p0, Lg9/d;->S:I

    .line 458
    .line 459
    return-void

    .line 460
    :sswitch_18
    invoke-virtual {p0, p2, p3}, Lg9/d;->m(J)J

    .line 461
    .line 462
    .line 463
    move-result-wide p1

    .line 464
    iput-wide p1, p0, Lg9/d;->E:J

    .line 465
    .line 466
    return-void

    .line 467
    :sswitch_19
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 468
    .line 469
    .line 470
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 471
    .line 472
    long-to-int p1, p2

    .line 473
    iput p1, p0, Lg9/c;->d:I

    .line 474
    .line 475
    return-void

    .line 476
    :sswitch_1a
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 477
    .line 478
    .line 479
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 480
    .line 481
    long-to-int p1, p2

    .line 482
    iput p1, p0, Lg9/c;->o:I

    .line 483
    .line 484
    return-void

    .line 485
    :sswitch_1b
    invoke-virtual {p0, p1}, Lg9/d;->e(I)V

    .line 486
    .line 487
    .line 488
    iget-object p1, p0, Lg9/d;->F:Lq3/b;

    .line 489
    .line 490
    invoke-virtual {p0, p2, p3}, Lg9/d;->m(J)J

    .line 491
    .line 492
    .line 493
    move-result-wide p2

    .line 494
    invoke-virtual {p1, p2, p3}, Lq3/b;->a(J)V

    .line 495
    .line 496
    .line 497
    return-void

    .line 498
    :sswitch_1c
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 499
    .line 500
    .line 501
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 502
    .line 503
    long-to-int p1, p2

    .line 504
    iput p1, p0, Lg9/c;->n:I

    .line 505
    .line 506
    return-void

    .line 507
    :sswitch_1d
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 508
    .line 509
    .line 510
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 511
    .line 512
    long-to-int p1, p2

    .line 513
    iput p1, p0, Lg9/c;->Q:I

    .line 514
    .line 515
    return-void

    .line 516
    :sswitch_1e
    invoke-virtual {p0, p2, p3}, Lg9/d;->m(J)J

    .line 517
    .line 518
    .line 519
    move-result-wide p1

    .line 520
    iput-wide p1, p0, Lg9/d;->L:J

    .line 521
    .line 522
    return-void

    .line 523
    :sswitch_1f
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 524
    .line 525
    .line 526
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 527
    .line 528
    cmp-long p1, p2, v3

    .line 529
    .line 530
    if-nez p1, :cond_10

    .line 531
    .line 532
    move v0, v7

    .line 533
    :cond_10
    iput-boolean v0, p0, Lg9/c;->X:Z

    .line 534
    .line 535
    return-void

    .line 536
    :sswitch_20
    invoke-virtual {p0, p1}, Lg9/d;->f(I)V

    .line 537
    .line 538
    .line 539
    iget-object p0, p0, Lg9/d;->x:Lg9/c;

    .line 540
    .line 541
    long-to-int p1, p2

    .line 542
    iput p1, p0, Lg9/c;->e:I

    .line 543
    .line 544
    return-void

    .line 545
    :cond_11
    cmp-long p0, p2, v3

    .line 546
    .line 547
    if-nez p0, :cond_12

    .line 548
    .line 549
    goto :goto_0

    .line 550
    :cond_12
    new-instance p0, Ljava/lang/StringBuilder;

    .line 551
    .line 552
    const-string p1, "ContentEncodingScope "

    .line 553
    .line 554
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 555
    .line 556
    .line 557
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 558
    .line 559
    .line 560
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 561
    .line 562
    .line 563
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 564
    .line 565
    .line 566
    move-result-object p0

    .line 567
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 568
    .line 569
    .line 570
    move-result-object p0

    .line 571
    throw p0

    .line 572
    :cond_13
    const-wide/16 p0, 0x0

    .line 573
    .line 574
    cmp-long p0, p2, p0

    .line 575
    .line 576
    if-nez p0, :cond_15

    .line 577
    .line 578
    :cond_14
    :goto_0
    return-void

    .line 579
    :cond_15
    new-instance p0, Ljava/lang/StringBuilder;

    .line 580
    .line 581
    const-string p1, "ContentEncodingOrder "

    .line 582
    .line 583
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 584
    .line 585
    .line 586
    invoke-virtual {p0, p2, p3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 587
    .line 588
    .line 589
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 590
    .line 591
    .line 592
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 593
    .line 594
    .line 595
    move-result-object p0

    .line 596
    invoke-static {v1, p0}, Lt7/e0;->a(Ljava/lang/RuntimeException;Ljava/lang/String;)Lt7/e0;

    .line 597
    .line 598
    .line 599
    move-result-object p0

    .line 600
    throw p0

    .line 601
    :sswitch_data_0
    .sparse-switch
        0x83 -> :sswitch_20
        0x88 -> :sswitch_1f
        0x9b -> :sswitch_1e
        0x9f -> :sswitch_1d
        0xb0 -> :sswitch_1c
        0xb3 -> :sswitch_1b
        0xba -> :sswitch_1a
        0xd7 -> :sswitch_19
        0xe7 -> :sswitch_18
        0xee -> :sswitch_17
        0xf1 -> :sswitch_16
        0xfb -> :sswitch_15
        0x41e7 -> :sswitch_14
        0x4254 -> :sswitch_13
        0x4285 -> :sswitch_12
        0x42f7 -> :sswitch_11
        0x47e1 -> :sswitch_10
        0x47e8 -> :sswitch_f
        0x53ac -> :sswitch_e
        0x53b8 -> :sswitch_d
        0x54b0 -> :sswitch_c
        0x54b2 -> :sswitch_b
        0x54ba -> :sswitch_a
        0x55aa -> :sswitch_9
        0x55b2 -> :sswitch_8
        0x55ee -> :sswitch_7
        0x56aa -> :sswitch_6
        0x56bb -> :sswitch_5
        0x6264 -> :sswitch_4
        0x75a2 -> :sswitch_3
        0x7671 -> :sswitch_2
        0x23e383 -> :sswitch_1
        0x2ad7b1 -> :sswitch_0
    .end sparse-switch

    .line 602
    .line 603
    .line 604
    .line 605
    .line 606
    .line 607
    .line 608
    .line 609
    .line 610
    .line 611
    .line 612
    .line 613
    .line 614
    .line 615
    .line 616
    .line 617
    .line 618
    .line 619
    .line 620
    .line 621
    .line 622
    .line 623
    .line 624
    .line 625
    .line 626
    .line 627
    .line 628
    .line 629
    .line 630
    .line 631
    .line 632
    .line 633
    .line 634
    .line 635
    .line 636
    .line 637
    .line 638
    .line 639
    .line 640
    .line 641
    .line 642
    .line 643
    .line 644
    .line 645
    .line 646
    .line 647
    .line 648
    .line 649
    .line 650
    .line 651
    .line 652
    .line 653
    .line 654
    .line 655
    .line 656
    .line 657
    .line 658
    .line 659
    .line 660
    .line 661
    .line 662
    .line 663
    .line 664
    .line 665
    .line 666
    .line 667
    .line 668
    .line 669
    .line 670
    .line 671
    .line 672
    .line 673
    .line 674
    .line 675
    .line 676
    .line 677
    .line 678
    .line 679
    .line 680
    .line 681
    .line 682
    .line 683
    .line 684
    .line 685
    .line 686
    .line 687
    .line 688
    .line 689
    .line 690
    .line 691
    .line 692
    .line 693
    .line 694
    .line 695
    .line 696
    .line 697
    .line 698
    .line 699
    .line 700
    .line 701
    .line 702
    .line 703
    .line 704
    .line 705
    .line 706
    .line 707
    .line 708
    .line 709
    .line 710
    .line 711
    .line 712
    .line 713
    .line 714
    .line 715
    .line 716
    .line 717
    .line 718
    .line 719
    .line 720
    .line 721
    .line 722
    .line 723
    .line 724
    .line 725
    .line 726
    .line 727
    .line 728
    .line 729
    .line 730
    .line 731
    .line 732
    .line 733
    .line 734
    .line 735
    :pswitch_data_0
    .packed-switch 0x55b9
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public a()Z
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    return p0
.end method

.method public accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p2, Laq/k;

    .line 2
    .line 3
    check-cast p1, Lgp/f;

    .line 4
    .line 5
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast p0, Lpp/e;

    .line 8
    .line 9
    invoke-virtual {p1}, Lno/e;->r()Landroid/os/IInterface;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lgp/v;

    .line 14
    .line 15
    new-instance v0, Lgp/d;

    .line 16
    .line 17
    const/4 v1, 0x0

    .line 18
    invoke-direct {v0, v1, p2}, Lgp/d;-><init>(ILaq/k;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p1}, Lbp/a;->S()Landroid/os/Parcel;

    .line 22
    .line 23
    .line 24
    move-result-object p2

    .line 25
    invoke-static {p2, p0}, Lgp/b;->b(Landroid/os/Parcel;Landroid/os/Parcelable;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p2, v0}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 29
    .line 30
    .line 31
    const/4 p0, 0x0

    .line 32
    invoke-virtual {p2, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    const/16 p0, 0x3f

    .line 36
    .line 37
    invoke-virtual {p1, p2, p0}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 38
    .line 39
    .line 40
    return-void
.end method

.method public c(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, La0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 11
    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    check-cast p1, Ljava/lang/Void;

    .line 15
    .line 16
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Laq/s;

    .line 19
    .line 20
    iget-object p0, p0, Laq/s;->d:Laq/k;

    .line 21
    .line 22
    iget-object p0, p0, Laq/k;->a:Laq/t;

    .line 23
    .line 24
    invoke-virtual {p0}, Laq/t;->p()V

    .line 25
    .line 26
    .line 27
    return-void

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public get(I)Lc1/b0;
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, [Lc1/d0;

    .line 4
    .line 5
    aget-object p0, p0, p1

    .line 6
    .line 7
    return-object p0
.end method

.method public getSource()I
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo;

    .line 4
    .line 5
    invoke-static {p0}, Lc4/a;->D(Landroid/view/ContentInfo;)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public h(Lc1/p;Lc1/p;Lc1/p;)J
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/firebase/messaging/w;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/firebase/messaging/w;->h(Lc1/p;Lc1/p;Lc1/p;)J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    return-wide p0
.end method

.method public m()V
    .locals 1

    .line 1
    const-string p0, "DIAGNOSTIC_PROFILE_IS_COMPRESSED"

    .line 2
    .line 3
    const-string v0, "ProfileInstaller"

    .line 4
    .line 5
    invoke-static {v0, p0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public n(ILjava/lang/Object;)V
    .locals 3

    .line 1
    packed-switch p1, :pswitch_data_0

    .line 2
    .line 3
    .line 4
    :pswitch_0
    const-string v0, ""

    .line 5
    .line 6
    goto :goto_0

    .line 7
    :pswitch_1
    const-string v0, "RESULT_DELETE_SKIP_FILE_SUCCESS"

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :pswitch_2
    const-string v0, "RESULT_INSTALL_SKIP_FILE_SUCCESS"

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :pswitch_3
    const-string v0, "RESULT_PARSE_EXCEPTION"

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :pswitch_4
    const-string v0, "RESULT_IO_EXCEPTION"

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :pswitch_5
    const-string v0, "RESULT_BASELINE_PROFILE_NOT_FOUND"

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :pswitch_6
    const-string v0, "RESULT_DESIRED_FORMAT_UNSUPPORTED"

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :pswitch_7
    const-string v0, "RESULT_NOT_WRITABLE"

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_8
    const-string v0, "RESULT_UNSUPPORTED_ART_VERSION"

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :pswitch_9
    const-string v0, "RESULT_ALREADY_INSTALLED"

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :pswitch_a
    const-string v0, "RESULT_INSTALL_SUCCESS"

    .line 35
    .line 36
    :goto_0
    const/4 v1, 0x6

    .line 37
    const-string v2, "ProfileInstaller"

    .line 38
    .line 39
    if-eq p1, v1, :cond_0

    .line 40
    .line 41
    const/4 v1, 0x7

    .line 42
    if-eq p1, v1, :cond_0

    .line 43
    .line 44
    const/16 v1, 0x8

    .line 45
    .line 46
    if-eq p1, v1, :cond_0

    .line 47
    .line 48
    invoke-static {v2, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    goto :goto_1

    .line 52
    :cond_0
    check-cast p2, Ljava/lang/Throwable;

    .line 53
    .line 54
    invoke-static {v2, v0, p2}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 55
    .line 56
    .line 57
    :goto_1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast p0, Landroidx/profileinstaller/ProfileInstallReceiver;

    .line 60
    .line 61
    invoke-virtual {p0, p1}, Landroid/content/BroadcastReceiver;->setResultCode(I)V

    .line 62
    .line 63
    .line 64
    return-void

    .line 65
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_0
        :pswitch_2
        :pswitch_1
    .end packed-switch
.end method

.method public onFailure(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public p()Lh0/q0;
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/q0;

    .line 4
    .line 5
    return-object p0
.end method

.method public bridge synthetic q(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lcom/google/android/gms/common/data/DataHolder;

    .line 4
    .line 5
    check-cast p1, Leu0/b;

    .line 6
    .line 7
    :try_start_0
    new-instance v0, Lbq/a;

    .line 8
    .line 9
    invoke-direct {v0, p0}, Lbq/a;-><init>(Lcom/google/android/gms/common/data/DataHolder;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p1, v0}, Leu0/b;->a(Lbq/a;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    .line 14
    .line 15
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p1

    .line 20
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 21
    .line 22
    .line 23
    throw p1
.end method

.method public s()V
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ljava/util/concurrent/CountDownLatch;

    .line 4
    .line 5
    invoke-virtual {p0}, Ljava/util/concurrent/CountDownLatch;->countDown()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 6

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v0, p0

    .line 4
    check-cast v0, Lcom/google/firebase/messaging/w;

    .line 5
    .line 6
    move-wide v1, p1

    .line 7
    move-object v3, p3

    .line 8
    move-object v4, p4

    .line 9
    move-object v5, p5

    .line 10
    invoke-virtual/range {v0 .. v5}, Lcom/google/firebase/messaging/w;->t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget v0, p0, La0/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v1, "ContentInfoCompat{"

    .line 14
    .line 15
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Landroid/view/ContentInfo;

    .line 21
    .line 22
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    const-string p0, "}"

    .line 26
    .line 27
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_data_0
    .packed-switch 0xe
        :pswitch_0
    .end packed-switch
.end method

.method public x()Landroid/view/ContentInfo;
    .locals 0

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Landroid/view/ContentInfo;

    .line 4
    .line 5
    return-object p0
.end method

.method public z(Ljava/lang/Object;)V
    .locals 2

    .line 1
    iget-object p0, p0, La0/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Laq/k;

    .line 4
    .line 5
    check-cast p1, Lcom/google/android/gms/common/api/Status;

    .line 6
    .line 7
    iget v0, p1, Lcom/google/android/gms/common/api/Status;->d:I

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    return-void

    .line 17
    :cond_0
    const/16 v1, 0xfa2

    .line 18
    .line 19
    if-ne v0, v1, :cond_1

    .line 20
    .line 21
    sget-object p1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Laq/k;->b(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    return-void

    .line 27
    :cond_1
    new-instance v0, Lko/e;

    .line 28
    .line 29
    invoke-direct {v0, p1}, Lko/e;-><init>(Lcom/google/android/gms/common/api/Status;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {p0, v0}, Laq/k;->a(Ljava/lang/Exception;)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

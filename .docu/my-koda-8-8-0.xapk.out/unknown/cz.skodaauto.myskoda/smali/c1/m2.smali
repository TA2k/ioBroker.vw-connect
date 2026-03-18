.class public final Lc1/m2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lc1/f2;
.implements Li9/c;
.implements Ll2/c;
.implements Ll4/p;
.implements Ly7/g;


# instance fields
.field public d:I

.field public e:I

.field public final f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(I)V
    .locals 1

    packed-switch p1, :pswitch_data_0

    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/16 p1, 0x100

    .line 11
    new-array p1, p1, [Lc1/m2;

    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    const/4 p1, 0x0

    .line 12
    iput p1, p0, Lc1/m2;->d:I

    .line 13
    iput p1, p0, Lc1/m2;->e:I

    return-void

    .line 14
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 15
    new-instance p1, Lb81/d;

    const/16 v0, 0x1c

    invoke-direct {p1, v0}, Lb81/d;-><init>(I)V

    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    const/16 p1, 0x1f40

    .line 16
    iput p1, p0, Lc1/m2;->d:I

    .line 17
    iput p1, p0, Lc1/m2;->e:I

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x9
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(II)V
    .locals 1

    .line 18
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 19
    iput-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 20
    iput p1, p0, Lc1/m2;->d:I

    and-int/lit8 p1, p2, 0x7

    if-nez p1, :cond_0

    const/16 p1, 0x8

    .line 21
    :cond_0
    iput p1, p0, Lc1/m2;->e:I

    return-void
.end method

.method public constructor <init>(IILc1/w;)V
    .locals 2

    .line 22
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 23
    iput p1, p0, Lc1/m2;->d:I

    .line 24
    iput p2, p0, Lc1/m2;->e:I

    .line 25
    new-instance v0, Lcom/google/firebase/messaging/w;

    new-instance v1, Lc1/e0;

    invoke-direct {v1, p1, p2, p3}, Lc1/e0;-><init>(IILc1/w;)V

    invoke-direct {v0, v1}, Lcom/google/firebase/messaging/w;-><init>(Lc1/b0;)V

    iput-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/Object;I)V
    .locals 0

    .line 1
    iput p1, p0, Lc1/m2;->d:I

    iput p3, p0, Lc1/m2;->e:I

    iput-object p2, p0, Lc1/m2;->f:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    iput v0, p0, Lc1/m2;->e:I

    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Landroid/view/View;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Ll2/c;I)V
    .locals 0

    .line 9
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    iput p2, p0, Lc1/m2;->d:I

    return-void
.end method

.method public constructor <init>(Ll4/p;II)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 7
    iput p2, p0, Lc1/m2;->d:I

    .line 8
    iput p3, p0, Lc1/m2;->e:I

    return-void
.end method

.method public constructor <init>(Lx7/d;Lt7/o;)V
    .locals 3

    .line 26
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 27
    iget-object p1, p1, Lx7/d;->f:Lw7/p;

    iput-object p1, p0, Lc1/m2;->f:Ljava/lang/Object;

    const/16 v0, 0xc

    .line 28
    invoke-virtual {p1, v0}, Lw7/p;->I(I)V

    .line 29
    invoke-virtual {p1}, Lw7/p;->A()I

    move-result v0

    .line 30
    const-string v1, "audio/raw"

    iget-object v2, p2, Lt7/o;->n:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_1

    .line 31
    iget v1, p2, Lt7/o;->H:I

    iget p2, p2, Lt7/o;->F:I

    .line 32
    invoke-static {v1}, Lw7/w;->n(I)I

    move-result v1

    mul-int/2addr v1, p2

    if-eqz v0, :cond_0

    .line 33
    rem-int p2, v0, v1

    if-eqz p2, :cond_1

    .line 34
    :cond_0
    new-instance p2, Ljava/lang/StringBuilder;

    const-string v2, "Audio sample size mismatch. stsd sample size: "

    invoke-direct {p2, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {p2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v2, ", stsz sample size: "

    invoke-virtual {p2, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {p2, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p2

    const-string v0, "BoxParsers"

    invoke-static {v0, p2}, Lw7/a;->y(Ljava/lang/String;Ljava/lang/String;)V

    move v0, v1

    :cond_1
    if-nez v0, :cond_2

    const/4 v0, -0x1

    .line 35
    :cond_2
    iput v0, p0, Lc1/m2;->d:I

    .line 36
    invoke-virtual {p1}, Lw7/p;->A()I

    move-result p1

    iput p1, p0, Lc1/m2;->e:I

    return-void
.end method


# virtual methods
.method public D(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 6

    .line 1
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

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
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll4/p;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ll4/p;->E(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-ltz p1, :cond_0

    .line 10
    .line 11
    iget v1, p0, Lc1/m2;->e:I

    .line 12
    .line 13
    if-gt p1, v1, :cond_0

    .line 14
    .line 15
    iget p0, p0, Lc1/m2;->d:I

    .line 16
    .line 17
    invoke-static {v0, p0, p1}, Lt1/o1;->c(III)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return v0
.end method

.method public R(I)I
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll4/p;

    .line 4
    .line 5
    invoke-interface {v0, p1}, Ll4/p;->R(I)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-ltz p1, :cond_0

    .line 10
    .line 11
    iget v1, p0, Lc1/m2;->d:I

    .line 12
    .line 13
    if-gt p1, v1, :cond_0

    .line 14
    .line 15
    iget p0, p0, Lc1/m2;->e:I

    .line 16
    .line 17
    invoke-static {v0, p0, p1}, Lt1/o1;->b(III)V

    .line 18
    .line 19
    .line 20
    :cond_0
    return v0
.end method

.method public b(III)V
    .locals 1

    .line 1
    iget v0, p0, Lc1/m2;->e:I

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    iget v0, p0, Lc1/m2;->d:I

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x0

    .line 9
    :goto_0
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast p0, Ll2/c;

    .line 12
    .line 13
    add-int/2addr p1, v0

    .line 14
    add-int/2addr p2, v0

    .line 15
    invoke-interface {p0, p1, p2, p3}, Ll2/c;->b(III)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public c(II)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll2/c;

    .line 4
    .line 5
    iget v1, p0, Lc1/m2;->e:I

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    iget p0, p0, Lc1/m2;->d:I

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    add-int/2addr p1, p0

    .line 14
    invoke-interface {v0, p1, p2}, Ll2/c;->c(II)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public d(Ljava/lang/Object;Lay0/n;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll2/c;

    .line 4
    .line 5
    invoke-interface {p0, p1, p2}, Ll2/c;->d(Ljava/lang/Object;Lay0/n;)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public e(ILjava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll2/c;

    .line 4
    .line 5
    iget v1, p0, Lc1/m2;->e:I

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    iget p0, p0, Lc1/m2;->d:I

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    add-int/2addr p1, p0

    .line 14
    invoke-interface {v0, p1, p2}, Ll2/c;->e(ILjava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public g()Ljava/lang/Object;
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll2/c;

    .line 4
    .line 5
    invoke-interface {p0}, Ll2/c;->g()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public i()Ly7/h;
    .locals 3

    .line 1
    new-instance v0, Ly7/o;

    .line 2
    .line 3
    iget v1, p0, Lc1/m2;->d:I

    .line 4
    .line 5
    iget v2, p0, Lc1/m2;->e:I

    .line 6
    .line 7
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lb81/d;

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, p0}, Ly7/o;-><init>(IILb81/d;)V

    .line 12
    .line 13
    .line 14
    return-object v0
.end method

.method public j()I
    .locals 2

    .line 1
    iget v0, p0, Lc1/m2;->d:I

    .line 2
    .line 3
    const/4 v1, -0x1

    .line 4
    if-ne v0, v1, :cond_0

    .line 5
    .line 6
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lw7/p;

    .line 9
    .line 10
    invoke-virtual {p0}, Lw7/p;->A()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0

    .line 15
    :cond_0
    return v0
.end method

.method public k(ILjava/lang/Object;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ll2/c;

    .line 4
    .line 5
    iget v1, p0, Lc1/m2;->e:I

    .line 6
    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    iget p0, p0, Lc1/m2;->d:I

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    :goto_0
    add-int/2addr p1, p0

    .line 14
    invoke-interface {v0, p1, p2}, Ll2/c;->k(ILjava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    return-void
.end method

.method public l(Ljava/lang/Object;)V
    .locals 1

    .line 1
    iget v0, p0, Lc1/m2;->e:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lc1/m2;->e:I

    .line 6
    .line 7
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Ll2/c;

    .line 10
    .line 11
    invoke-interface {p0, p1}, Ll2/c;->l(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

.method public m()V
    .locals 0

    .line 1
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Ll2/c;

    .line 4
    .line 5
    invoke-interface {p0}, Ll2/c;->m()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public n()I
    .locals 0

    .line 1
    iget p0, p0, Lc1/m2;->d:I

    .line 2
    .line 3
    return p0
.end method

.method public o()V
    .locals 1

    .line 1
    iget v0, p0, Lc1/m2;->e:I

    .line 2
    .line 3
    if-lez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x0

    .line 8
    :goto_0
    if-nez v0, :cond_1

    .line 9
    .line 10
    const-string v0, "OffsetApplier up called with no corresponding down"

    .line 11
    .line 12
    invoke-static {v0}, Ll2/v;->c(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_1
    iget v0, p0, Lc1/m2;->e:I

    .line 16
    .line 17
    add-int/lit8 v0, v0, -0x1

    .line 18
    .line 19
    iput v0, p0, Lc1/m2;->e:I

    .line 20
    .line 21
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Ll2/c;

    .line 24
    .line 25
    invoke-interface {p0}, Ll2/c;->o()V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public p()I
    .locals 0

    .line 1
    iget p0, p0, Lc1/m2;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public declared-synchronized q()I
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget v0, p0, Lc1/m2;->d:I

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const-string v0, "com.google.android.gms"
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 7
    .line 8
    :try_start_1
    iget-object v1, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v1, Landroid/content/Context;

    .line 11
    .line 12
    invoke-static {v1}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-virtual {v1, v2, v0}, Lcq/r1;->c(ILjava/lang/String;)Landroid/content/pm/PackageInfo;

    .line 18
    .line 19
    .line 20
    move-result-object v0
    :try_end_1
    .catch Landroid/content/pm/PackageManager$NameNotFoundException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception v0

    .line 23
    goto :goto_1

    .line 24
    :catch_0
    move-exception v0

    .line 25
    :try_start_2
    const-string v1, "Failed to find package "

    .line 26
    .line 27
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    invoke-virtual {v1, v0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    const-string v1, "Metadata"

    .line 36
    .line 37
    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 38
    .line 39
    .line 40
    const/4 v0, 0x0

    .line 41
    :goto_0
    if-eqz v0, :cond_0

    .line 42
    .line 43
    iget v0, v0, Landroid/content/pm/PackageInfo;->versionCode:I

    .line 44
    .line 45
    iput v0, p0, Lc1/m2;->d:I

    .line 46
    .line 47
    :cond_0
    iget v0, p0, Lc1/m2;->d:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 48
    .line 49
    monitor-exit p0

    .line 50
    return v0

    .line 51
    :goto_1
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 52
    throw v0
.end method

.method public declared-synchronized r()I
    .locals 4

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget v0, p0, Lc1/m2;->e:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 3
    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    monitor-exit p0

    .line 7
    return v0

    .line 8
    :cond_0
    :try_start_1
    iget-object v0, p0, Lc1/m2;->f:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast v0, Landroid/content/Context;

    .line 11
    .line 12
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    invoke-static {v0}, Lvo/b;->a(Landroid/content/Context;)Lcq/r1;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    const-string v2, "com.google.android.c2dm.permission.SEND"

    .line 21
    .line 22
    const-string v3, "com.google.android.gms"

    .line 23
    .line 24
    iget-object v0, v0, Lcq/r1;->d:Landroid/content/Context;

    .line 25
    .line 26
    invoke-virtual {v0}, Landroid/content/Context;->getPackageManager()Landroid/content/pm/PackageManager;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    invoke-virtual {v0, v2, v3}, Landroid/content/pm/PackageManager;->checkPermission(Ljava/lang/String;Ljava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    const/4 v2, -0x1

    .line 35
    const/4 v3, 0x0

    .line 36
    if-ne v0, v2, :cond_1

    .line 37
    .line 38
    const-string v0, "Metadata"

    .line 39
    .line 40
    const-string v1, "Google Play services missing or without correct permission."

    .line 41
    .line 42
    invoke-static {v0, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 43
    .line 44
    .line 45
    monitor-exit p0

    .line 46
    return v3

    .line 47
    :catchall_0
    move-exception v0

    .line 48
    goto :goto_0

    .line 49
    :cond_1
    :try_start_2
    new-instance v0, Landroid/content/Intent;

    .line 50
    .line 51
    const-string v2, "com.google.iid.TOKEN_REQUEST"

    .line 52
    .line 53
    invoke-direct {v0, v2}, Landroid/content/Intent;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    const-string v2, "com.google.android.gms"

    .line 57
    .line 58
    invoke-virtual {v0, v2}, Landroid/content/Intent;->setPackage(Ljava/lang/String;)Landroid/content/Intent;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v1, v0, v3}, Landroid/content/pm/PackageManager;->queryBroadcastReceivers(Landroid/content/Intent;I)Ljava/util/List;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    const/4 v1, 0x2

    .line 66
    if-eqz v0, :cond_2

    .line 67
    .line 68
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    if-nez v0, :cond_2

    .line 73
    .line 74
    iput v1, p0, Lc1/m2;->e:I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 75
    .line 76
    monitor-exit p0

    .line 77
    return v1

    .line 78
    :cond_2
    :try_start_3
    const-string v0, "Metadata"

    .line 79
    .line 80
    const-string v2, "Failed to resolve IID implementation package, falling back"

    .line 81
    .line 82
    invoke-static {v0, v2}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 83
    .line 84
    .line 85
    iput v1, p0, Lc1/m2;->e:I
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 86
    .line 87
    monitor-exit p0

    .line 88
    return v1

    .line 89
    :goto_0
    :try_start_4
    monitor-exit p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 90
    throw v0
.end method

.method public t(JLc1/p;Lc1/p;Lc1/p;)Lc1/p;
    .locals 6

    .line 1
    iget-object p0, p0, Lc1/m2;->f:Ljava/lang/Object;

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

.method public u()I
    .locals 0

    .line 1
    iget p0, p0, Lc1/m2;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public y()I
    .locals 0

    .line 1
    iget p0, p0, Lc1/m2;->d:I

    .line 2
    .line 3
    return p0
.end method

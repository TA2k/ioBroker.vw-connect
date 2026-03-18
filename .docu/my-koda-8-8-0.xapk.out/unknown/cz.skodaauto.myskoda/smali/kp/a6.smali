.class public abstract Lkp/a6;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Z)Ljava/util/concurrent/ExecutorService;
    .locals 2

    .line 1
    new-instance v0, Leb/c;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Leb/c;-><init>(Z)V

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/lang/Runtime;->getRuntime()Ljava/lang/Runtime;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-virtual {p0}, Ljava/lang/Runtime;->availableProcessors()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    add-int/lit8 p0, p0, -0x1

    .line 15
    .line 16
    const/4 v1, 0x4

    .line 17
    invoke-static {p0, v1}, Ljava/lang/Math;->min(II)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    const/4 v1, 0x2

    .line 22
    invoke-static {v1, p0}, Ljava/lang/Math;->max(II)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    invoke-static {p0, v0}, Ljava/util/concurrent/Executors;->newFixedThreadPool(ILjava/util/concurrent/ThreadFactory;)Ljava/util/concurrent/ExecutorService;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    const-string v0, "newFixedThreadPool(...)"

    .line 31
    .line 32
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    return-object p0
.end method

.method public static final b(Lqp0/o;Lqr0/s;Lij0/a;)Ljava/lang/String;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "unitsType"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "stringResource"

    .line 12
    .line 13
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-wide v0, p0, Lqp0/o;->c:D

    .line 17
    .line 18
    sget-object v2, Lqr0/e;->d:Lqr0/e;

    .line 19
    .line 20
    invoke-static {v0, v1, p1, v2}, Lkp/f6;->a(DLqr0/s;Lqr0/e;)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    iget-object p0, p0, Lqp0/o;->f:Lmy0/c;

    .line 25
    .line 26
    if-eqz p0, :cond_0

    .line 27
    .line 28
    iget-wide v0, p0, Lmy0/c;->d:J

    .line 29
    .line 30
    const/4 p0, 0x0

    .line 31
    const/4 v2, 0x6

    .line 32
    invoke-static {v0, v1, p2, p0, v2}, Ljp/d1;->c(JLij0/a;ZI)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/4 p0, 0x0

    .line 38
    :goto_0
    if-eqz p0, :cond_2

    .line 39
    .line 40
    const-string p2, " ("

    .line 41
    .line 42
    const-string v0, ")"

    .line 43
    .line 44
    invoke-static {p0, p2, p1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->l(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    if-nez p0, :cond_1

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    return-object p0

    .line 52
    :cond_2
    :goto_1
    return-object p1
.end method

.method public static final c(Lqp0/b;Ljava/lang/String;)Lqp0/o;
    .locals 14

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v1, Lqp0/o;

    .line 7
    .line 8
    iget-object v2, p0, Lqp0/b;->b:Ljava/util/ArrayList;

    .line 9
    .line 10
    iget-object v3, p0, Lqp0/b;->a:Ljava/lang/String;

    .line 11
    .line 12
    iget-wide v4, p0, Lqp0/b;->c:D

    .line 13
    .line 14
    iget-wide v6, p0, Lqp0/b;->d:J

    .line 15
    .line 16
    iget-object v8, p0, Lqp0/b;->f:Lmy0/c;

    .line 17
    .line 18
    iget-object v9, p0, Lqp0/b;->e:Lmy0/c;

    .line 19
    .line 20
    const/4 v11, 0x1

    .line 21
    const/16 v13, 0x200

    .line 22
    .line 23
    const/4 v10, 0x0

    .line 24
    move-object v12, p1

    .line 25
    invoke-direct/range {v1 .. v13}, Lqp0/o;-><init>(Ljava/util/ArrayList;Ljava/lang/String;DJLmy0/c;Lmy0/c;ZZLjava/lang/String;I)V

    .line 26
    .line 27
    .line 28
    return-object v1
.end method

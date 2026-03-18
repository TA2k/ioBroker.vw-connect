.class public abstract Lvz0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lqz0/j;


# static fields
.field public static final d:Lvz0/c;


# instance fields
.field public final a:Lvz0/k;

.field public final b:Lwq/f;

.field public final c:Lpv/g;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Lvz0/c;

    .line 2
    .line 3
    new-instance v1, Lvz0/k;

    .line 4
    .line 5
    const/4 v10, 0x1

    .line 6
    sget-object v11, Lvz0/a;->e:Lvz0/a;

    .line 7
    .line 8
    const/4 v2, 0x0

    .line 9
    const/4 v3, 0x0

    .line 10
    const/4 v4, 0x0

    .line 11
    const/4 v5, 0x0

    .line 12
    const/4 v6, 0x1

    .line 13
    const-string v7, "    "

    .line 14
    .line 15
    const-string v8, "type"

    .line 16
    .line 17
    const/4 v9, 0x0

    .line 18
    invoke-direct/range {v1 .. v11}, Lvz0/k;-><init>(ZZZZZLjava/lang/String;Ljava/lang/String;ZZLvz0/a;)V

    .line 19
    .line 20
    .line 21
    sget-object v2, Lxz0/a;->a:Lwq/f;

    .line 22
    .line 23
    invoke-direct {v0, v1, v2}, Lvz0/d;-><init>(Lvz0/k;Lwq/f;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lvz0/d;->d:Lvz0/c;

    .line 27
    .line 28
    return-void
.end method

.method public constructor <init>(Lvz0/k;Lwq/f;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lvz0/d;->a:Lvz0/k;

    .line 5
    .line 6
    iput-object p2, p0, Lvz0/d;->b:Lwq/f;

    .line 7
    .line 8
    new-instance p1, Lpv/g;

    .line 9
    .line 10
    const/16 p2, 0x16

    .line 11
    .line 12
    invoke-direct {p1, p2}, Lpv/g;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lvz0/d;->c:Lpv/g;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lqz0/a;Lvz0/n;)Ljava/lang/Object;
    .locals 3

    .line 1
    const-string v0, "deserializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "element"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    instance-of v0, p2, Lvz0/a0;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    new-instance v0, Lwz0/t;

    .line 17
    .line 18
    check-cast p2, Lvz0/a0;

    .line 19
    .line 20
    const/16 v2, 0xc

    .line 21
    .line 22
    invoke-direct {v0, p0, p2, v1, v2}, Lwz0/t;-><init>(Lvz0/d;Lvz0/a0;Ljava/lang/String;I)V

    .line 23
    .line 24
    .line 25
    goto :goto_1

    .line 26
    :cond_0
    instance-of v0, p2, Lvz0/f;

    .line 27
    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    new-instance v0, Lwz0/u;

    .line 31
    .line 32
    check-cast p2, Lvz0/f;

    .line 33
    .line 34
    invoke-direct {v0, p0, p2}, Lwz0/u;-><init>(Lvz0/d;Lvz0/f;)V

    .line 35
    .line 36
    .line 37
    goto :goto_1

    .line 38
    :cond_1
    instance-of v0, p2, Lvz0/u;

    .line 39
    .line 40
    if-nez v0, :cond_3

    .line 41
    .line 42
    sget-object v0, Lvz0/x;->INSTANCE:Lvz0/x;

    .line 43
    .line 44
    invoke-virtual {p2, v0}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    if-eqz v0, :cond_2

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_2
    new-instance p0, La8/r0;

    .line 52
    .line 53
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_3
    :goto_0
    new-instance v0, Lwz0/r;

    .line 58
    .line 59
    check-cast p2, Lvz0/e0;

    .line 60
    .line 61
    invoke-direct {v0, p0, p2, v1}, Lwz0/r;-><init>(Lvz0/d;Lvz0/n;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    :goto_1
    invoke-virtual {v0, p1}, Lwz0/a;->d(Lqz0/a;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    return-object p0
.end method

.method public final b(Ljava/lang/String;Lqz0/a;)Ljava/lang/Object;
    .locals 7

    .line 1
    const-string v0, "deserializer"

    .line 2
    .line 3
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "string"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance v4, Lwz0/d0;

    .line 12
    .line 13
    invoke-direct {v4, p1}, Lwz0/d0;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v1, Lwz0/a0;

    .line 17
    .line 18
    sget-object v3, Lwz0/f0;->f:Lwz0/f0;

    .line 19
    .line 20
    invoke-interface {p2}, Lqz0/a;->getDescriptor()Lsz0/g;

    .line 21
    .line 22
    .line 23
    move-result-object v5

    .line 24
    const/4 v6, 0x0

    .line 25
    move-object v2, p0

    .line 26
    invoke-direct/range {v1 .. v6}, Lwz0/a0;-><init>(Lvz0/d;Lwz0/f0;Lo8/j;Lsz0/g;Lgr/f;)V

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1, p2}, Lwz0/a0;->d(Lqz0/a;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    move-result-object p0

    .line 33
    invoke-virtual {v4}, Lo8/j;->p()V

    .line 34
    .line 35
    .line 36
    return-object p0
.end method

.method public final c(Lqz0/a;Ljava/lang/Object;)Lvz0/n;
    .locals 4

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 7
    .line 8
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    new-instance v1, Lwz0/s;

    .line 12
    .line 13
    new-instance v2, Lo1/w0;

    .line 14
    .line 15
    const/4 v3, 0x1

    .line 16
    invoke-direct {v2, v0, v3}, Lo1/w0;-><init>(Lkotlin/jvm/internal/f0;I)V

    .line 17
    .line 18
    .line 19
    invoke-direct {v1, p0, v2, v3}, Lwz0/s;-><init>(Lvz0/d;Lay0/k;I)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1, p1, p2}, Lwz0/s;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    iget-object p0, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    check-cast p0, Lvz0/n;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_0
    const-string p0, "result"

    .line 33
    .line 34
    invoke-static {p0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    const/4 p0, 0x0

    .line 38
    throw p0
.end method

.method public final d(Lqz0/a;Ljava/lang/Object;)Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, "serializer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance v0, Lb11/a;

    .line 7
    .line 8
    const/16 v1, 0xb

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    invoke-direct {v0, v2, v1}, Lb11/a;-><init>(CI)V

    .line 12
    .line 13
    .line 14
    sget-object v1, Lwz0/f;->f:Lwz0/f;

    .line 15
    .line 16
    monitor-enter v1

    .line 17
    :try_start_0
    iget-object v2, v1, Landroidx/datastore/preferences/protobuf/k;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v2, Lmx0/l;

    .line 20
    .line 21
    invoke-virtual {v2}, Lmx0/l;->isEmpty()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    const/4 v4, 0x0

    .line 26
    if-eqz v3, :cond_0

    .line 27
    .line 28
    move-object v2, v4

    .line 29
    goto :goto_0

    .line 30
    :cond_0
    invoke-virtual {v2}, Lmx0/l;->removeLast()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    :goto_0
    check-cast v2, [C

    .line 35
    .line 36
    if-eqz v2, :cond_1

    .line 37
    .line 38
    iget v3, v1, Landroidx/datastore/preferences/protobuf/k;->d:I

    .line 39
    .line 40
    array-length v4, v2

    .line 41
    sub-int/2addr v3, v4

    .line 42
    iput v3, v1, Landroidx/datastore/preferences/protobuf/k;->d:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    move-object v4, v2

    .line 45
    goto :goto_1

    .line 46
    :catchall_0
    move-exception p0

    .line 47
    goto :goto_2

    .line 48
    :cond_1
    :goto_1
    monitor-exit v1

    .line 49
    if-nez v4, :cond_2

    .line 50
    .line 51
    const/16 v1, 0x80

    .line 52
    .line 53
    new-array v4, v1, [C

    .line 54
    .line 55
    :cond_2
    iput-object v4, v0, Lb11/a;->f:Ljava/lang/Object;

    .line 56
    .line 57
    :try_start_1
    new-instance v1, Lwz0/b0;

    .line 58
    .line 59
    sget-object v2, Lwz0/f0;->f:Lwz0/f0;

    .line 60
    .line 61
    sget-object v3, Lwz0/f0;->k:Lsx0/b;

    .line 62
    .line 63
    invoke-virtual {v3}, Lsx0/b;->c()I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    new-array v3, v3, [Lvz0/r;

    .line 68
    .line 69
    new-instance v4, Lb6/f;

    .line 70
    .line 71
    invoke-direct {v4, v0}, Lb6/f;-><init>(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    invoke-direct {v1, v4, p0, v2, v3}, Lwz0/b0;-><init>(Lb6/f;Lvz0/d;Lwz0/f0;[Lvz0/r;)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1, p1, p2}, Lwz0/b0;->D(Lqz0/a;Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0}, Lb11/a;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 84
    invoke-virtual {v0}, Lb11/a;->j()V

    .line 85
    .line 86
    .line 87
    return-object p0

    .line 88
    :catchall_1
    move-exception p0

    .line 89
    invoke-virtual {v0}, Lb11/a;->j()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :goto_2
    monitor-exit v1

    .line 94
    throw p0
.end method

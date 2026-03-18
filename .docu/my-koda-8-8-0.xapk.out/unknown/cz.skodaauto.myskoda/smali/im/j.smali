.class public final Lim/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm/f;


# instance fields
.field public final a:Llx0/q;

.field public final b:Llx0/q;

.field public final c:Lvp/y1;


# direct methods
.method public constructor <init>(Lay0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lhz/a;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sget-object v1, Lim/i;->d:Lim/i;

    .line 9
    .line 10
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lim/j;->a:Llx0/q;

    .line 18
    .line 19
    invoke-static {v0}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lim/j;->b:Llx0/q;

    .line 24
    .line 25
    new-instance p1, Lvp/y1;

    .line 26
    .line 27
    const/16 v0, 0xb

    .line 28
    .line 29
    const/4 v2, 0x0

    .line 30
    invoke-direct {p1, v0, v2}, Lvp/y1;-><init>(IZ)V

    .line 31
    .line 32
    .line 33
    iput-object v1, p1, Lvp/y1;->e:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v0, Ljm/b;->a:Ljm/b;

    .line 36
    .line 37
    iput-object v0, p1, Lvp/y1;->f:Ljava/lang/Object;

    .line 38
    .line 39
    iput-object p1, p0, Lim/j;->c:Lvp/y1;

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/Object;Lmm/n;Lyl/r;)Ldm/g;
    .locals 9

    .line 1
    check-cast p1, Lyl/t;

    .line 2
    .line 3
    iget-object v0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 4
    .line 5
    const-string v1, "http"

    .line 6
    .line 7
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    const/4 v1, 0x0

    .line 12
    if-nez v0, :cond_1

    .line 13
    .line 14
    iget-object v0, p1, Lyl/t;->c:Ljava/lang/String;

    .line 15
    .line 16
    const-string v2, "https"

    .line 17
    .line 18
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    return-object v1

    .line 26
    :cond_1
    :goto_0
    new-instance v2, Lim/o;

    .line 27
    .line 28
    iget-object v3, p1, Lyl/t;->a:Ljava/lang/String;

    .line 29
    .line 30
    iget-object v5, p0, Lim/j;->a:Llx0/q;

    .line 31
    .line 32
    new-instance p1, Lh50/q0;

    .line 33
    .line 34
    const/16 v0, 0xc

    .line 35
    .line 36
    invoke-direct {p1, p3, v0}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 37
    .line 38
    .line 39
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 40
    .line 41
    .line 42
    move-result-object v6

    .line 43
    iget-object v7, p0, Lim/j;->b:Llx0/q;

    .line 44
    .line 45
    iget-object p0, p0, Lim/j;->c:Lvp/y1;

    .line 46
    .line 47
    iget-object p1, p2, Lmm/n;->a:Landroid/content/Context;

    .line 48
    .line 49
    iget-object p3, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 50
    .line 51
    sget-object v0, Ljm/b;->a:Ljm/b;

    .line 52
    .line 53
    if-eq p3, v0, :cond_2

    .line 54
    .line 55
    goto :goto_2

    .line 56
    :cond_2
    monitor-enter p0

    .line 57
    :try_start_0
    iget-object p3, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 58
    .line 59
    if-eq p3, v0, :cond_3

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    iget-object p3, p0, Lvp/y1;->e:Ljava/lang/Object;

    .line 63
    .line 64
    check-cast p3, Lay0/k;

    .line 65
    .line 66
    invoke-static {p3}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    invoke-interface {p3, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    iput-object p1, p0, Lvp/y1;->f:Ljava/lang/Object;

    .line 74
    .line 75
    iput-object v1, p0, Lvp/y1;->e:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 76
    .line 77
    move-object p3, p1

    .line 78
    :goto_1
    monitor-exit p0

    .line 79
    :goto_2
    move-object v8, p3

    .line 80
    check-cast v8, Lim/e;

    .line 81
    .line 82
    move-object v4, p2

    .line 83
    invoke-direct/range {v2 .. v8}, Lim/o;-><init>(Ljava/lang/String;Lmm/n;Llx0/q;Llx0/q;Llx0/q;Lim/e;)V

    .line 84
    .line 85
    .line 86
    return-object v2

    .line 87
    :catchall_0
    move-exception v0

    .line 88
    move-object p1, v0

    .line 89
    monitor-exit p0

    .line 90
    throw p1
.end method

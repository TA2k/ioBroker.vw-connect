.class public final Llo/d0;
.super Llo/v;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final b:Laq/k;

.field public final synthetic c:I

.field public final d:Ljava/lang/Object;


# direct methods
.method public constructor <init>(ILaq/k;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Llo/f0;-><init>(I)V

    .line 2
    iput-object p2, p0, Llo/d0;->b:Laq/k;

    return-void
.end method

.method public constructor <init>(Llo/k;Laq/k;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llo/d0;->c:I

    const/4 v0, 0x4

    .line 3
    invoke-direct {p0, v0, p2}, Llo/d0;-><init>(ILaq/k;)V

    iput-object p1, p0, Llo/d0;->d:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Llo/z;Laq/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llo/d0;->c:I

    const/4 v0, 0x3

    .line 4
    invoke-direct {p0, v0, p2}, Llo/d0;-><init>(ILaq/k;)V

    iput-object p1, p0, Llo/d0;->d:Ljava/lang/Object;

    return-void
.end method

.method private final bridge synthetic i(Lvp/y1;Z)V
    .locals 0

    .line 1
    return-void
.end method

.method private final bridge synthetic j(Lvp/y1;Z)V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a(Lcom/google/android/gms/common/api/Status;)V
    .locals 1

    .line 1
    new-instance v0, Lko/e;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lko/e;-><init>(Lcom/google/android/gms/common/api/Status;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Llo/d0;->b:Laq/k;

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public final b(Ljava/lang/Exception;)V
    .locals 0

    .line 1
    iget-object p0, p0, Llo/d0;->b:Laq/k;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final c(Llo/s;)V
    .locals 1

    .line 1
    :try_start_0
    invoke-virtual {p0, p1}, Llo/d0;->h(Llo/s;)V
    :try_end_0
    .catch Landroid/os/DeadObjectException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_1
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    .line 2
    .line 3
    .line 4
    return-void

    .line 5
    :catch_0
    move-exception p1

    .line 6
    iget-object p0, p0, Llo/d0;->b:Laq/k;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Laq/k;->c(Ljava/lang/Exception;)Z

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :catch_1
    move-exception p1

    .line 13
    invoke-static {p1}, Llo/f0;->e(Landroid/os/RemoteException;)Lcom/google/android/gms/common/api/Status;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    invoke-virtual {p0, p1}, Llo/d0;->a(Lcom/google/android/gms/common/api/Status;)V

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catch_2
    move-exception p1

    .line 22
    invoke-static {p1}, Llo/f0;->e(Landroid/os/RemoteException;)Lcom/google/android/gms/common/api/Status;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    invoke-virtual {p0, v0}, Llo/d0;->a(Lcom/google/android/gms/common/api/Status;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public final bridge synthetic d(Lvp/y1;Z)V
    .locals 0

    .line 1
    iget p0, p0, Llo/d0;->c:I

    .line 2
    .line 3
    return-void
.end method

.method public final f(Llo/s;)Z
    .locals 1

    .line 1
    iget v0, p0, Llo/d0;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p1, Llo/s;->h:Ljava/util/HashMap;

    .line 7
    .line 8
    iget-object p0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Llo/k;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Llo/z;

    .line 17
    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    iget-object p0, p0, Llo/z;->a:Lw7/o;

    .line 21
    .line 22
    iget-boolean p0, p0, Lw7/o;->a:Z

    .line 23
    .line 24
    if-eqz p0, :cond_0

    .line 25
    .line 26
    const/4 p0, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    :goto_0
    return p0

    .line 30
    :pswitch_0
    iget-object p0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p0, Llo/z;

    .line 33
    .line 34
    iget-object p0, p0, Llo/z;->a:Lw7/o;

    .line 35
    .line 36
    iget-boolean p0, p0, Lw7/o;->a:Z

    .line 37
    .line 38
    return p0

    .line 39
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final g(Llo/s;)[Ljo/d;
    .locals 1

    .line 1
    iget v0, p0, Llo/d0;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p1, p1, Llo/s;->h:Ljava/util/HashMap;

    .line 7
    .line 8
    iget-object p0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Llo/k;

    .line 11
    .line 12
    invoke-virtual {p1, p0}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Llo/z;

    .line 17
    .line 18
    if-nez p0, :cond_0

    .line 19
    .line 20
    const/4 p0, 0x0

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    iget-object p0, p0, Llo/z;->a:Lw7/o;

    .line 23
    .line 24
    iget-object p0, p0, Lw7/o;->d:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast p0, [Ljo/d;

    .line 27
    .line 28
    :goto_0
    return-object p0

    .line 29
    :pswitch_0
    iget-object p0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 30
    .line 31
    check-cast p0, Llo/z;

    .line 32
    .line 33
    iget-object p0, p0, Llo/z;->a:Lw7/o;

    .line 34
    .line 35
    iget-object p0, p0, Lw7/o;->d:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p0, [Ljo/d;

    .line 38
    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final h(Llo/s;)V
    .locals 3

    .line 1
    iget v0, p0, Llo/d0;->c:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Llo/d0;->b:Laq/k;

    .line 7
    .line 8
    iget-object v1, p1, Llo/s;->h:Ljava/util/HashMap;

    .line 9
    .line 10
    iget-object p0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Llo/k;

    .line 13
    .line 14
    invoke-virtual {v1, p0}, Ljava/util/HashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    check-cast p0, Llo/z;

    .line 19
    .line 20
    if-eqz p0, :cond_0

    .line 21
    .line 22
    iget-object p1, p1, Llo/s;->d:Lko/c;

    .line 23
    .line 24
    iget-object v1, p0, Llo/z;->b:Lb81/a;

    .line 25
    .line 26
    iget-object v1, v1, Lb81/a;->f:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v1, Lf8/d;

    .line 29
    .line 30
    iget-object v1, v1, Lf8/d;->g:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast v1, Llo/n;

    .line 33
    .line 34
    invoke-interface {v1, p1, v0}, Llo/n;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    iget-object p0, p0, Llo/z;->a:Lw7/o;

    .line 38
    .line 39
    iget-object p0, p0, Lw7/o;->c:Ljava/lang/Object;

    .line 40
    .line 41
    check-cast p0, Lis/b;

    .line 42
    .line 43
    const/4 p1, 0x0

    .line 44
    iput-object p1, p0, Lis/b;->b:Ljava/lang/Object;

    .line 45
    .line 46
    iput-object p1, p0, Lis/b;->c:Ljava/lang/Object;

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_0
    sget-object p0, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 50
    .line 51
    invoke-virtual {v0, p0}, Laq/k;->d(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    :goto_0
    return-void

    .line 55
    :pswitch_0
    iget-object v0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 56
    .line 57
    check-cast v0, Llo/z;

    .line 58
    .line 59
    iget-object v0, v0, Llo/z;->a:Lw7/o;

    .line 60
    .line 61
    iget-object v1, p1, Llo/s;->d:Lko/c;

    .line 62
    .line 63
    iget-object v2, p0, Llo/d0;->b:Laq/k;

    .line 64
    .line 65
    iget-object v0, v0, Lw7/o;->e:Ljava/lang/Object;

    .line 66
    .line 67
    check-cast v0, Lf8/d;

    .line 68
    .line 69
    iget-object v0, v0, Lf8/d;->f:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v0, Llo/n;

    .line 72
    .line 73
    invoke-interface {v0, v1, v2}, Llo/n;->accept(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object v0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v0, Llo/z;

    .line 79
    .line 80
    iget-object v0, v0, Llo/z;->a:Lw7/o;

    .line 81
    .line 82
    iget-object v0, v0, Lw7/o;->c:Ljava/lang/Object;

    .line 83
    .line 84
    check-cast v0, Lis/b;

    .line 85
    .line 86
    iget-object v0, v0, Lis/b;->c:Ljava/lang/Object;

    .line 87
    .line 88
    check-cast v0, Llo/k;

    .line 89
    .line 90
    if-eqz v0, :cond_1

    .line 91
    .line 92
    iget-object p1, p1, Llo/s;->h:Ljava/util/HashMap;

    .line 93
    .line 94
    iget-object p0, p0, Llo/d0;->d:Ljava/lang/Object;

    .line 95
    .line 96
    check-cast p0, Llo/z;

    .line 97
    .line 98
    invoke-virtual {p1, v0, p0}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    :cond_1
    return-void

    .line 102
    nop

    .line 103
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

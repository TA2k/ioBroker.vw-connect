.class public final synthetic Ldu/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Laq/b;
.implements Ly4/i;


# instance fields
.field public final synthetic d:Ljava/lang/Object;

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iput-object p1, p0, Ldu/g;->d:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object p2, p0, Ldu/g;->e:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Ldu/g;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iput-object p4, p0, Ldu/g;->g:Ljava/lang/Object;

    .line 8
    .line 9
    iput-object p5, p0, Ldu/g;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public h(Ly4/h;)Ljava/lang/Object;
    .locals 9

    .line 1
    iget-object v0, p0, Ldu/g;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    iget-object v1, p0, Ldu/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    move-object v3, v1

    .line 8
    check-cast v3, Leb/j;

    .line 9
    .line 10
    iget-object v1, p0, Ldu/g;->f:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v4, v1

    .line 13
    check-cast v4, Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p0, Ldu/g;->g:Ljava/lang/Object;

    .line 16
    .line 17
    move-object v5, v1

    .line 18
    check-cast v5, Lay0/a;

    .line 19
    .line 20
    iget-object p0, p0, Ldu/g;->h:Ljava/lang/Object;

    .line 21
    .line 22
    move-object v6, p0

    .line 23
    check-cast v6, Landroidx/lifecycle/i0;

    .line 24
    .line 25
    new-instance v2, Leb/d0;

    .line 26
    .line 27
    const/4 v8, 0x0

    .line 28
    move-object v7, p1

    .line 29
    invoke-direct/range {v2 .. v8}, Leb/d0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 30
    .line 31
    .line 32
    invoke-interface {v0, v2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0
.end method

.method public w(Laq/j;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object p1, p0, Ldu/g;->d:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p1, Ldu/i;

    .line 4
    .line 5
    iget-object v0, p0, Ldu/g;->e:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v0, Laq/j;

    .line 8
    .line 9
    iget-object v1, p0, Ldu/g;->f:Ljava/lang/Object;

    .line 10
    .line 11
    check-cast v1, Laq/j;

    .line 12
    .line 13
    iget-object v2, p0, Ldu/g;->g:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast v2, Ljava/util/Date;

    .line 16
    .line 17
    iget-object p0, p0, Ldu/g;->h:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Ljava/util/HashMap;

    .line 20
    .line 21
    invoke-virtual {v0}, Laq/j;->i()Z

    .line 22
    .line 23
    .line 24
    move-result v3

    .line 25
    if-nez v3, :cond_0

    .line 26
    .line 27
    new-instance p0, Lcu/c;

    .line 28
    .line 29
    const-string p1, "Firebase Installations failed to get installation ID for fetch."

    .line 30
    .line 31
    invoke-virtual {v0}, Laq/j;->f()Ljava/lang/Exception;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-direct {p0, p1, v0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 36
    .line 37
    .line 38
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    return-object p0

    .line 43
    :cond_0
    invoke-virtual {v1}, Laq/j;->i()Z

    .line 44
    .line 45
    .line 46
    move-result v3

    .line 47
    if-nez v3, :cond_1

    .line 48
    .line 49
    new-instance p0, Lcu/c;

    .line 50
    .line 51
    const-string p1, "Firebase Installations failed to get installation auth token for fetch."

    .line 52
    .line 53
    invoke-virtual {v1}, Laq/j;->f()Ljava/lang/Exception;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    invoke-direct {p0, p1, v0}, Lsr/h;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 58
    .line 59
    .line 60
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :cond_1
    invoke-virtual {v0}, Laq/j;->g()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object v0

    .line 69
    check-cast v0, Ljava/lang/String;

    .line 70
    .line 71
    invoke-virtual {v1}, Laq/j;->g()Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    check-cast v1, Lht/a;

    .line 76
    .line 77
    iget-object v1, v1, Lht/a;->a:Ljava/lang/String;

    .line 78
    .line 79
    :try_start_0
    invoke-virtual {p1, v0, v1, v2, p0}, Ldu/i;->b(Ljava/lang/String;Ljava/lang/String;Ljava/util/Date;Ljava/util/HashMap;)Ldu/h;

    .line 80
    .line 81
    .line 82
    move-result-object p0

    .line 83
    iget v0, p0, Ldu/h;->a:I

    .line 84
    .line 85
    if-eqz v0, :cond_2

    .line 86
    .line 87
    invoke-static {p0}, Ljp/l1;->e(Ljava/lang/Object;)Laq/t;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    goto :goto_0

    .line 92
    :cond_2
    iget-object v0, p1, Ldu/i;->e:Ldu/c;

    .line 93
    .line 94
    iget-object v1, p0, Ldu/h;->b:Ldu/e;

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ldu/c;->d(Ldu/e;)Laq/t;

    .line 97
    .line 98
    .line 99
    move-result-object v0

    .line 100
    iget-object p1, p1, Ldu/i;->c:Ljava/util/concurrent/Executor;

    .line 101
    .line 102
    new-instance v1, La8/t;

    .line 103
    .line 104
    const/16 v2, 0x15

    .line 105
    .line 106
    invoke-direct {v1, p0, v2}, La8/t;-><init>(Ljava/lang/Object;I)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v0, p1, v1}, Laq/t;->j(Ljava/util/concurrent/Executor;Laq/i;)Laq/t;

    .line 110
    .line 111
    .line 112
    move-result-object p0
    :try_end_0
    .catch Lcu/d; {:try_start_0 .. :try_end_0} :catch_0

    .line 113
    goto :goto_0

    .line 114
    :catch_0
    move-exception p0

    .line 115
    invoke-static {p0}, Ljp/l1;->d(Ljava/lang/Exception;)Laq/t;

    .line 116
    .line 117
    .line 118
    move-result-object p0

    .line 119
    :goto_0
    return-object p0
.end method

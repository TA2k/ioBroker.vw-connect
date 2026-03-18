.class public final Ljs/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lss/b;


# direct methods
.method public constructor <init>(Lss/b;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ljs/b;->a:Lss/b;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a(Lgu/d;)V
    .locals 9

    .line 1
    iget-object p0, p0, Ljs/b;->a:Lss/b;

    .line 2
    .line 3
    iget-object p1, p1, Lgu/d;->a:Ljava/util/HashSet;

    .line 4
    .line 5
    new-instance v0, Ljava/util/ArrayList;

    .line 6
    .line 7
    const/16 v1, 0xa

    .line 8
    .line 9
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 21
    .line 22
    .line 23
    move-result v1

    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    check-cast v1, Lgu/e;

    .line 31
    .line 32
    check-cast v1, Lgu/c;

    .line 33
    .line 34
    iget-object v3, v1, Lgu/c;->b:Ljava/lang/String;

    .line 35
    .line 36
    iget-object v4, v1, Lgu/c;->d:Ljava/lang/String;

    .line 37
    .line 38
    iget-object v2, v1, Lgu/c;->e:Ljava/lang/String;

    .line 39
    .line 40
    iget-object v6, v1, Lgu/c;->c:Ljava/lang/String;

    .line 41
    .line 42
    iget-wide v7, v1, Lgu/c;->f:J

    .line 43
    .line 44
    sget-object v1, Los/n;->a:Lbu/c;

    .line 45
    .line 46
    invoke-virtual {v2}, Ljava/lang/String;->length()I

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    const/16 v5, 0x100

    .line 51
    .line 52
    if-le v1, v5, :cond_0

    .line 53
    .line 54
    const/4 v1, 0x0

    .line 55
    invoke-virtual {v2, v1, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    :cond_0
    move-object v5, v2

    .line 60
    new-instance v2, Los/b;

    .line 61
    .line 62
    invoke-direct/range {v2 .. v8}, Los/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;J)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v0, v2}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    goto :goto_0

    .line 69
    :cond_1
    iget-object p1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast p1, Lh01/v;

    .line 72
    .line 73
    monitor-enter p1

    .line 74
    :try_start_0
    iget-object v1, p0, Lss/b;->j:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v1, Lh01/v;

    .line 77
    .line 78
    invoke-virtual {v1, v0}, Lh01/v;->b(Ljava/util/List;)Z

    .line 79
    .line 80
    .line 81
    move-result v0

    .line 82
    if-nez v0, :cond_2

    .line 83
    .line 84
    monitor-exit p1

    .line 85
    goto :goto_1

    .line 86
    :catchall_0
    move-exception v0

    .line 87
    move-object p0, v0

    .line 88
    goto :goto_2

    .line 89
    :cond_2
    iget-object v0, p0, Lss/b;->j:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Lh01/v;

    .line 92
    .line 93
    invoke-virtual {v0}, Lh01/v;->a()Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    iget-object v1, p0, Lss/b;->g:Ljava/lang/Object;

    .line 98
    .line 99
    check-cast v1, Lns/d;

    .line 100
    .line 101
    iget-object v1, v1, Lns/d;->b:Lns/b;

    .line 102
    .line 103
    new-instance v2, Lno/nordicsemi/android/ble/o0;

    .line 104
    .line 105
    const/4 v3, 0x2

    .line 106
    invoke-direct {v2, v3, p0, v0}, Lno/nordicsemi/android/ble/o0;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {v1, v2}, Lns/b;->a(Ljava/lang/Runnable;)Laq/t;

    .line 110
    .line 111
    .line 112
    monitor-exit p1
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 113
    :goto_1
    const-string p0, "Updated Crashlytics Rollout State"

    .line 114
    .line 115
    const/4 p1, 0x3

    .line 116
    const-string v0, "FirebaseCrashlytics"

    .line 117
    .line 118
    invoke-static {v0, p1}, Landroid/util/Log;->isLoggable(Ljava/lang/String;I)Z

    .line 119
    .line 120
    .line 121
    move-result p1

    .line 122
    if-eqz p1, :cond_3

    .line 123
    .line 124
    const-string p1, "FirebaseCrashlytics"

    .line 125
    .line 126
    const/4 v0, 0x0

    .line 127
    invoke-static {p1, p0, v0}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 128
    .line 129
    .line 130
    :cond_3
    return-void

    .line 131
    :goto_2
    :try_start_1
    monitor-exit p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 132
    throw p0
.end method

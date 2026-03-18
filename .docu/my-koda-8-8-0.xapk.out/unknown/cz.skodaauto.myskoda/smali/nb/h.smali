.class public final Lnb/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final d:Lfb/e;

.field public final e:Lfb/j;

.field public final f:Z

.field public final g:I


# direct methods
.method public constructor <init>(Lfb/e;Lfb/j;ZI)V
    .locals 1

    .line 1
    const-string v0, "processor"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "token"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p1, p0, Lnb/h;->d:Lfb/e;

    .line 15
    .line 16
    iput-object p2, p0, Lnb/h;->e:Lfb/j;

    .line 17
    .line 18
    iput-boolean p3, p0, Lnb/h;->f:Z

    .line 19
    .line 20
    iput p4, p0, Lnb/h;->g:I

    .line 21
    .line 22
    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    .line 1
    iget-boolean v0, p0, Lnb/h;->f:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, p0, Lnb/h;->d:Lfb/e;

    .line 6
    .line 7
    iget-object v1, p0, Lnb/h;->e:Lfb/j;

    .line 8
    .line 9
    iget v2, p0, Lnb/h;->g:I

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    iget-object v1, v1, Lfb/j;->a:Lmb/i;

    .line 15
    .line 16
    iget-object v1, v1, Lmb/i;->a:Ljava/lang/String;

    .line 17
    .line 18
    iget-object v3, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 19
    .line 20
    monitor-enter v3

    .line 21
    :try_start_0
    invoke-virtual {v0, v1}, Lfb/e;->b(Ljava/lang/String;)Lfb/f0;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    monitor-exit v3
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 26
    invoke-static {v1, v0, v2}, Lfb/e;->d(Ljava/lang/String;Lfb/f0;I)Z

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    goto :goto_2

    .line 31
    :catchall_0
    move-exception p0

    .line 32
    :try_start_1
    monitor-exit v3
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 33
    throw p0

    .line 34
    :cond_0
    iget-object v0, p0, Lnb/h;->d:Lfb/e;

    .line 35
    .line 36
    iget-object v1, p0, Lnb/h;->e:Lfb/j;

    .line 37
    .line 38
    iget v2, p0, Lnb/h;->g:I

    .line 39
    .line 40
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 41
    .line 42
    .line 43
    const-string v3, "Ignored stopWork. WorkerWrapper "

    .line 44
    .line 45
    iget-object v4, v1, Lfb/j;->a:Lmb/i;

    .line 46
    .line 47
    iget-object v4, v4, Lmb/i;->a:Ljava/lang/String;

    .line 48
    .line 49
    iget-object v5, v0, Lfb/e;->k:Ljava/lang/Object;

    .line 50
    .line 51
    monitor-enter v5

    .line 52
    :try_start_2
    iget-object v6, v0, Lfb/e;->f:Ljava/util/HashMap;

    .line 53
    .line 54
    invoke-virtual {v6, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object v6

    .line 58
    const/4 v7, 0x0

    .line 59
    if-eqz v6, :cond_1

    .line 60
    .line 61
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 62
    .line 63
    .line 64
    move-result-object v0

    .line 65
    sget-object v1, Lfb/e;->l:Ljava/lang/String;

    .line 66
    .line 67
    new-instance v2, Ljava/lang/StringBuilder;

    .line 68
    .line 69
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v3, " is in foreground"

    .line 76
    .line 77
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 81
    .line 82
    .line 83
    move-result-object v2

    .line 84
    invoke-virtual {v0, v1, v2}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    monitor-exit v5

    .line 88
    :goto_0
    move v0, v7

    .line 89
    goto :goto_2

    .line 90
    :catchall_1
    move-exception p0

    .line 91
    goto :goto_3

    .line 92
    :cond_1
    iget-object v3, v0, Lfb/e;->h:Ljava/util/HashMap;

    .line 93
    .line 94
    invoke-virtual {v3, v4}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object v3

    .line 98
    check-cast v3, Ljava/util/Set;

    .line 99
    .line 100
    if-eqz v3, :cond_3

    .line 101
    .line 102
    invoke-interface {v3, v1}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v1

    .line 106
    if-nez v1, :cond_2

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_2
    invoke-virtual {v0, v4}, Lfb/e;->b(Ljava/lang/String;)Lfb/f0;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    monitor-exit v5
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 114
    invoke-static {v4, v0, v2}, Lfb/e;->d(Ljava/lang/String;Lfb/f0;I)Z

    .line 115
    .line 116
    .line 117
    move-result v0

    .line 118
    goto :goto_2

    .line 119
    :cond_3
    :goto_1
    :try_start_3
    monitor-exit v5
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 120
    goto :goto_0

    .line 121
    :goto_2
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 122
    .line 123
    .line 124
    move-result-object v1

    .line 125
    const-string v2, "StopWorkRunnable"

    .line 126
    .line 127
    invoke-static {v2}, Leb/w;->f(Ljava/lang/String;)Ljava/lang/String;

    .line 128
    .line 129
    .line 130
    move-result-object v2

    .line 131
    new-instance v3, Ljava/lang/StringBuilder;

    .line 132
    .line 133
    const-string v4, "StopWorkRunnable for "

    .line 134
    .line 135
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 136
    .line 137
    .line 138
    iget-object p0, p0, Lnb/h;->e:Lfb/j;

    .line 139
    .line 140
    iget-object p0, p0, Lfb/j;->a:Lmb/i;

    .line 141
    .line 142
    iget-object p0, p0, Lmb/i;->a:Ljava/lang/String;

    .line 143
    .line 144
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    const-string p0, "; Processor.stopWork = "

    .line 148
    .line 149
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 150
    .line 151
    .line 152
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 156
    .line 157
    .line 158
    move-result-object p0

    .line 159
    invoke-virtual {v1, v2, p0}, Leb/w;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 160
    .line 161
    .line 162
    return-void

    .line 163
    :goto_3
    :try_start_4
    monitor-exit v5
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 164
    throw p0
.end method

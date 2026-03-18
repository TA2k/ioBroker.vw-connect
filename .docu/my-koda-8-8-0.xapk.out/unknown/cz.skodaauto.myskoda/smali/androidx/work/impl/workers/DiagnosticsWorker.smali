.class public final Landroidx/work/impl/workers/DiagnosticsWorker;
.super Landroidx/work/Worker;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0004\u0008\u0000\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u00a2\u0006\u0004\u0008\u0006\u0010\u0007\u00a8\u0006\u0008"
    }
    d2 = {
        "Landroidx/work/impl/workers/DiagnosticsWorker;",
        "Landroidx/work/Worker;",
        "Landroid/content/Context;",
        "context",
        "Landroidx/work/WorkerParameters;",
        "parameters",
        "<init>",
        "(Landroid/content/Context;Landroidx/work/WorkerParameters;)V",
        "work-runtime_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x1,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public constructor <init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V
    .locals 1

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "parameters"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    invoke-direct {p0, p1, p2}, Landroidx/work/Worker;-><init>(Landroid/content/Context;Landroidx/work/WorkerParameters;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final d()Leb/t;
    .locals 9

    .line 1
    iget-object p0, p0, Leb/v;->d:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {p0}, Lfb/u;->f(Landroid/content/Context;)Lfb/u;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    iget-object v0, p0, Lfb/u;->c:Landroidx/work/impl/WorkDatabase;

    .line 8
    .line 9
    const-string v1, "getWorkDatabase(...)"

    .line 10
    .line 11
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 15
    .line 16
    .line 17
    move-result-object v1

    .line 18
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->v()Lmb/k;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->y()Lmb/u;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    invoke-virtual {v0}, Landroidx/work/impl/WorkDatabase;->u()Lmb/h;

    .line 27
    .line 28
    .line 29
    move-result-object v0

    .line 30
    iget-object p0, p0, Lfb/u;->b:Leb/b;

    .line 31
    .line 32
    iget-object p0, p0, Leb/b;->d:Leb/j;

    .line 33
    .line 34
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 35
    .line 36
    .line 37
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 38
    .line 39
    .line 40
    move-result-wide v4

    .line 41
    sget-object p0, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 42
    .line 43
    const-wide/16 v6, 0x1

    .line 44
    .line 45
    invoke-virtual {p0, v6, v7}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 46
    .line 47
    .line 48
    move-result-wide v6

    .line 49
    sub-long/2addr v4, v6

    .line 50
    iget-object p0, v1, Lmb/s;->a:Lla/u;

    .line 51
    .line 52
    new-instance v6, Le81/e;

    .line 53
    .line 54
    const/4 v7, 0x5

    .line 55
    invoke-direct {v6, v4, v5, v7}, Le81/e;-><init>(JI)V

    .line 56
    .line 57
    .line 58
    const/4 v4, 0x1

    .line 59
    const/4 v5, 0x0

    .line 60
    invoke-static {p0, v4, v5, v6}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    check-cast p0, Ljava/util/List;

    .line 65
    .line 66
    iget-object v6, v1, Lmb/s;->a:Lla/u;

    .line 67
    .line 68
    new-instance v7, Lm40/e;

    .line 69
    .line 70
    const/16 v8, 0xd

    .line 71
    .line 72
    invoke-direct {v7, v8}, Lm40/e;-><init>(I)V

    .line 73
    .line 74
    .line 75
    invoke-static {v6, v4, v5, v7}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v6

    .line 79
    check-cast v6, Ljava/util/List;

    .line 80
    .line 81
    iget-object v1, v1, Lmb/s;->a:Lla/u;

    .line 82
    .line 83
    new-instance v7, Lm40/e;

    .line 84
    .line 85
    const/16 v8, 0x11

    .line 86
    .line 87
    invoke-direct {v7, v8}, Lm40/e;-><init>(I)V

    .line 88
    .line 89
    .line 90
    invoke-static {v1, v4, v5, v7}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    check-cast v1, Ljava/util/List;

    .line 95
    .line 96
    move-object v4, p0

    .line 97
    check-cast v4, Ljava/util/Collection;

    .line 98
    .line 99
    invoke-interface {v4}, Ljava/util/Collection;->isEmpty()Z

    .line 100
    .line 101
    .line 102
    move-result v4

    .line 103
    if-nez v4, :cond_0

    .line 104
    .line 105
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 106
    .line 107
    .line 108
    move-result-object v4

    .line 109
    sget-object v5, Lpb/a;->a:Ljava/lang/String;

    .line 110
    .line 111
    const-string v7, "Recently completed work:\n\n"

    .line 112
    .line 113
    invoke-virtual {v4, v5, v7}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 117
    .line 118
    .line 119
    move-result-object v4

    .line 120
    invoke-static {v2, v3, v0, p0}, Lpb/a;->a(Lmb/k;Lmb/u;Lmb/h;Ljava/util/List;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    invoke-virtual {v4, v5, p0}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 125
    .line 126
    .line 127
    :cond_0
    move-object p0, v6

    .line 128
    check-cast p0, Ljava/util/Collection;

    .line 129
    .line 130
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 131
    .line 132
    .line 133
    move-result p0

    .line 134
    if-nez p0, :cond_1

    .line 135
    .line 136
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    sget-object v4, Lpb/a;->a:Ljava/lang/String;

    .line 141
    .line 142
    const-string v5, "Running work:\n\n"

    .line 143
    .line 144
    invoke-virtual {p0, v4, v5}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 145
    .line 146
    .line 147
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    invoke-static {v2, v3, v0, v6}, Lpb/a;->a(Lmb/k;Lmb/u;Lmb/h;Ljava/util/List;)Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object v5

    .line 155
    invoke-virtual {p0, v4, v5}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    :cond_1
    move-object p0, v1

    .line 159
    check-cast p0, Ljava/util/Collection;

    .line 160
    .line 161
    invoke-interface {p0}, Ljava/util/Collection;->isEmpty()Z

    .line 162
    .line 163
    .line 164
    move-result p0

    .line 165
    if-nez p0, :cond_2

    .line 166
    .line 167
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 168
    .line 169
    .line 170
    move-result-object p0

    .line 171
    sget-object v4, Lpb/a;->a:Ljava/lang/String;

    .line 172
    .line 173
    const-string v5, "Enqueued work:\n\n"

    .line 174
    .line 175
    invoke-virtual {p0, v4, v5}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 179
    .line 180
    .line 181
    move-result-object p0

    .line 182
    invoke-static {v2, v3, v0, v1}, Lpb/a;->a(Lmb/k;Lmb/u;Lmb/h;Ljava/util/List;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    invoke-virtual {p0, v4, v0}, Leb/w;->e(Ljava/lang/String;Ljava/lang/String;)V

    .line 187
    .line 188
    .line 189
    :cond_2
    new-instance p0, Leb/t;

    .line 190
    .line 191
    sget-object v0, Leb/h;->b:Leb/h;

    .line 192
    .line 193
    invoke-direct {p0, v0}, Leb/t;-><init>(Leb/h;)V

    .line 194
    .line 195
    .line 196
    return-object p0
.end method

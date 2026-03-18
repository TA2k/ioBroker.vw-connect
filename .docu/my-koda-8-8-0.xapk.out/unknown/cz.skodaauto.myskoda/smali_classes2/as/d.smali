.class public final Las/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lcs/a;


# instance fields
.field public final a:Lsr/f;

.field public final b:Lgt/b;

.field public final c:Ljava/util/ArrayList;

.field public final d:Ljava/util/ArrayList;

.field public final e:Las/g;

.field public final f:Las/i;

.field public final g:Ljava/util/concurrent/Executor;

.field public final h:Ljava/util/concurrent/Executor;

.field public final i:Ljava/util/concurrent/Executor;

.field public final j:Laq/t;

.field public final k:Lrb0/a;

.field public l:Les/d;

.field public m:Las/b;

.field public n:Laq/t;


# direct methods
.method public constructor <init>(Lsr/f;Lgt/b;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Ljava/util/concurrent/ScheduledExecutorService;)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    invoke-static {p2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Las/d;->a:Lsr/f;

    .line 11
    .line 12
    iput-object p2, p0, Las/d;->b:Lgt/b;

    .line 13
    .line 14
    new-instance p2, Ljava/util/ArrayList;

    .line 15
    .line 16
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p2, p0, Las/d;->c:Ljava/util/ArrayList;

    .line 20
    .line 21
    new-instance p2, Ljava/util/ArrayList;

    .line 22
    .line 23
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p2, p0, Las/d;->d:Ljava/util/ArrayList;

    .line 27
    .line 28
    new-instance p2, Las/g;

    .line 29
    .line 30
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 31
    .line 32
    .line 33
    iget-object v0, p1, Lsr/f;->a:Landroid/content/Context;

    .line 34
    .line 35
    invoke-virtual {p1}, Lsr/f;->d()Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object v1

    .line 39
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 40
    .line 41
    .line 42
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    invoke-static {v1}, Lno/c0;->e(Ljava/lang/String;)V

    .line 46
    .line 47
    .line 48
    new-instance v2, Ljava/lang/StringBuilder;

    .line 49
    .line 50
    const-string v3, "com.google.firebase.appcheck.store."

    .line 51
    .line 52
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 59
    .line 60
    .line 61
    move-result-object v1

    .line 62
    new-instance v2, Lgs/o;

    .line 63
    .line 64
    new-instance v3, Las/f;

    .line 65
    .line 66
    const/4 v4, 0x0

    .line 67
    invoke-direct {v3, v0, v1, v4}, Las/f;-><init>(Landroid/content/Context;Ljava/lang/String;I)V

    .line 68
    .line 69
    .line 70
    invoke-direct {v2, v3}, Lgs/o;-><init>(Lgt/b;)V

    .line 71
    .line 72
    .line 73
    iput-object v2, p2, Las/g;->a:Lgs/o;

    .line 74
    .line 75
    iput-object p2, p0, Las/d;->e:Las/g;

    .line 76
    .line 77
    new-instance p2, Las/i;

    .line 78
    .line 79
    invoke-virtual {p1}, Lsr/f;->a()V

    .line 80
    .line 81
    .line 82
    new-instance p1, Laq/a;

    .line 83
    .line 84
    invoke-direct {p1, p0, p4, p6}, Laq/a;-><init>(Las/d;Ljava/util/concurrent/Executor;Ljava/util/concurrent/ScheduledExecutorService;)V

    .line 85
    .line 86
    .line 87
    new-instance p1, Lrb0/a;

    .line 88
    .line 89
    const/4 p6, 0x2

    .line 90
    invoke-direct {p1, p6}, Lrb0/a;-><init>(I)V

    .line 91
    .line 92
    .line 93
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 94
    .line 95
    .line 96
    const-wide/16 v1, -0x1

    .line 97
    .line 98
    iput-wide v1, p2, Las/i;->a:J

    .line 99
    .line 100
    invoke-virtual {v0}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    .line 101
    .line 102
    .line 103
    move-result-object p1

    .line 104
    check-cast p1, Landroid/app/Application;

    .line 105
    .line 106
    invoke-static {p1}, Llo/d;->b(Landroid/app/Application;)V

    .line 107
    .line 108
    .line 109
    sget-object p1, Llo/d;->h:Llo/d;

    .line 110
    .line 111
    new-instance p6, Las/h;

    .line 112
    .line 113
    invoke-direct {p6}, Ljava/lang/Object;-><init>()V

    .line 114
    .line 115
    .line 116
    invoke-virtual {p1, p6}, Llo/d;->a(Llo/c;)V

    .line 117
    .line 118
    .line 119
    iput-object p2, p0, Las/d;->f:Las/i;

    .line 120
    .line 121
    iput-object p3, p0, Las/d;->g:Ljava/util/concurrent/Executor;

    .line 122
    .line 123
    iput-object p4, p0, Las/d;->h:Ljava/util/concurrent/Executor;

    .line 124
    .line 125
    iput-object p5, p0, Las/d;->i:Ljava/util/concurrent/Executor;

    .line 126
    .line 127
    new-instance p1, Laq/k;

    .line 128
    .line 129
    invoke-direct {p1}, Laq/k;-><init>()V

    .line 130
    .line 131
    .line 132
    new-instance p2, La8/z;

    .line 133
    .line 134
    const/4 p3, 0x1

    .line 135
    invoke-direct {p2, p3, p0, p1}, La8/z;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 136
    .line 137
    .line 138
    invoke-interface {p5, p2}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 139
    .line 140
    .line 141
    iget-object p1, p1, Laq/k;->a:Laq/t;

    .line 142
    .line 143
    iput-object p1, p0, Las/d;->j:Laq/t;

    .line 144
    .line 145
    new-instance p1, Lrb0/a;

    .line 146
    .line 147
    const/4 p2, 0x2

    .line 148
    invoke-direct {p1, p2}, Lrb0/a;-><init>(I)V

    .line 149
    .line 150
    .line 151
    iput-object p1, p0, Las/d;->k:Lrb0/a;

    .line 152
    .line 153
    return-void
.end method

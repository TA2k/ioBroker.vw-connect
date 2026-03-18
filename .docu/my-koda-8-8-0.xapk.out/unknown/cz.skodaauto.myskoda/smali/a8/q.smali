.class public final La8/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lw7/r;

.field public final c:La8/d;

.field public final d:La8/d;

.field public final e:La8/d;

.field public final f:La8/d;

.field public final g:Landroid/os/Looper;

.field public final h:I

.field public final i:Lt7/c;

.field public final j:I

.field public final k:Z

.field public final l:La8/r1;

.field public final m:La8/q1;

.field public final n:J

.field public final o:J

.field public final p:J

.field public final q:La8/i;

.field public final r:J

.field public final s:J

.field public final t:Z

.field public u:Z

.field public final v:Ljava/lang/String;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 8

    .line 1
    new-instance v0, La8/d;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, p1, v1}, La8/d;-><init>(Ljava/lang/Object;I)V

    .line 5
    .line 6
    .line 7
    new-instance v2, La8/d;

    .line 8
    .line 9
    const/4 v3, 0x2

    .line 10
    invoke-direct {v2, p1, v3}, La8/d;-><init>(Ljava/lang/Object;I)V

    .line 11
    .line 12
    .line 13
    new-instance v3, La8/d;

    .line 14
    .line 15
    const/4 v4, 0x3

    .line 16
    invoke-direct {v3, p1, v4}, La8/d;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    new-instance v4, La8/d;

    .line 20
    .line 21
    const/4 v5, 0x4

    .line 22
    invoke-direct {v4, p1, v5}, La8/d;-><init>(Ljava/lang/Object;I)V

    .line 23
    .line 24
    .line 25
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    iput-object p1, p0, La8/q;->a:Landroid/content/Context;

    .line 32
    .line 33
    iput-object v0, p0, La8/q;->c:La8/d;

    .line 34
    .line 35
    iput-object v2, p0, La8/q;->d:La8/d;

    .line 36
    .line 37
    iput-object v3, p0, La8/q;->e:La8/d;

    .line 38
    .line 39
    iput-object v4, p0, La8/q;->f:La8/d;

    .line 40
    .line 41
    sget-object p1, Lw7/w;->a:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 44
    .line 45
    .line 46
    move-result-object p1

    .line 47
    if-eqz p1, :cond_0

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_0
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    :goto_0
    iput-object p1, p0, La8/q;->g:Landroid/os/Looper;

    .line 55
    .line 56
    sget-object p1, Lt7/c;->b:Lt7/c;

    .line 57
    .line 58
    iput-object p1, p0, La8/q;->i:Lt7/c;

    .line 59
    .line 60
    iput v1, p0, La8/q;->j:I

    .line 61
    .line 62
    iput-boolean v1, p0, La8/q;->k:Z

    .line 63
    .line 64
    sget-object p1, La8/r1;->c:La8/r1;

    .line 65
    .line 66
    iput-object p1, p0, La8/q;->l:La8/r1;

    .line 67
    .line 68
    const-wide/16 v2, 0x1388

    .line 69
    .line 70
    iput-wide v2, p0, La8/q;->n:J

    .line 71
    .line 72
    const-wide/16 v2, 0x3a98

    .line 73
    .line 74
    iput-wide v2, p0, La8/q;->o:J

    .line 75
    .line 76
    const-wide/16 v2, 0xbb8

    .line 77
    .line 78
    iput-wide v2, p0, La8/q;->p:J

    .line 79
    .line 80
    sget-object p1, La8/q1;->b:La8/q1;

    .line 81
    .line 82
    iput-object p1, p0, La8/q;->m:La8/q1;

    .line 83
    .line 84
    const-wide/16 v2, 0x14

    .line 85
    .line 86
    invoke-static {v2, v3}, Lw7/w;->D(J)J

    .line 87
    .line 88
    .line 89
    move-result-wide v2

    .line 90
    const-wide/16 v4, 0x1f4

    .line 91
    .line 92
    invoke-static {v4, v5}, Lw7/w;->D(J)J

    .line 93
    .line 94
    .line 95
    move-result-wide v6

    .line 96
    new-instance p1, La8/i;

    .line 97
    .line 98
    invoke-direct {p1, v2, v3, v6, v7}, La8/i;-><init>(JJ)V

    .line 99
    .line 100
    .line 101
    iput-object p1, p0, La8/q;->q:La8/i;

    .line 102
    .line 103
    sget-object p1, Lw7/r;->a:Lw7/r;

    .line 104
    .line 105
    iput-object p1, p0, La8/q;->b:Lw7/r;

    .line 106
    .line 107
    iput-wide v4, p0, La8/q;->r:J

    .line 108
    .line 109
    const-wide/16 v2, 0x7d0

    .line 110
    .line 111
    iput-wide v2, p0, La8/q;->s:J

    .line 112
    .line 113
    iput-boolean v1, p0, La8/q;->t:Z

    .line 114
    .line 115
    const-string p1, ""

    .line 116
    .line 117
    iput-object p1, p0, La8/q;->v:Ljava/lang/String;

    .line 118
    .line 119
    const/16 p1, -0x3e8

    .line 120
    .line 121
    iput p1, p0, La8/q;->h:I

    .line 122
    .line 123
    new-instance p0, Ldv/a;

    .line 124
    .line 125
    invoke-direct {p0}, Ldv/a;-><init>()V

    .line 126
    .line 127
    .line 128
    return-void
.end method

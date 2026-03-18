.class public final Lrn/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lrn/j;

.field public final b:Ljava/lang/String;

.field public final c:Lon/c;

.field public final d:Lon/e;

.field public final e:Lrn/r;


# direct methods
.method public constructor <init>(Lrn/j;Ljava/lang/String;Lon/c;Lon/e;Lrn/r;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrn/q;->a:Lrn/j;

    .line 5
    .line 6
    iput-object p2, p0, Lrn/q;->b:Ljava/lang/String;

    .line 7
    .line 8
    iput-object p3, p0, Lrn/q;->c:Lon/c;

    .line 9
    .line 10
    iput-object p4, p0, Lrn/q;->d:Lon/e;

    .line 11
    .line 12
    iput-object p5, p0, Lrn/q;->e:Lrn/r;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final a(Lon/a;Lon/g;)V
    .locals 12

    .line 1
    iget-object v0, p0, Lrn/q;->b:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object v1, p0, Lrn/q;->d:Lon/e;

    .line 6
    .line 7
    if-eqz v1, :cond_1

    .line 8
    .line 9
    iget-object v2, p0, Lrn/q;->e:Lrn/r;

    .line 10
    .line 11
    iget-object v3, v2, Lrn/r;->c:Lwn/b;

    .line 12
    .line 13
    iget-object v4, p1, Lon/a;->b:Lon/d;

    .line 14
    .line 15
    iget-object v5, p0, Lrn/q;->a:Lrn/j;

    .line 16
    .line 17
    invoke-virtual {v5, v4}, Lrn/j;->b(Lon/d;)Lrn/j;

    .line 18
    .line 19
    .line 20
    move-result-object v8

    .line 21
    new-instance v4, Lg1/q;

    .line 22
    .line 23
    invoke-direct {v4}, Lg1/q;-><init>()V

    .line 24
    .line 25
    .line 26
    new-instance v5, Ljava/util/HashMap;

    .line 27
    .line 28
    invoke-direct {v5}, Ljava/util/HashMap;-><init>()V

    .line 29
    .line 30
    .line 31
    iput-object v5, v4, Lg1/q;->g:Ljava/lang/Object;

    .line 32
    .line 33
    iget-object v5, v2, Lrn/r;->a:Lao/a;

    .line 34
    .line 35
    invoke-interface {v5}, Lao/a;->a()J

    .line 36
    .line 37
    .line 38
    move-result-wide v5

    .line 39
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 40
    .line 41
    .line 42
    move-result-object v5

    .line 43
    iput-object v5, v4, Lg1/q;->e:Ljava/lang/Object;

    .line 44
    .line 45
    iget-object v2, v2, Lrn/r;->b:Lao/a;

    .line 46
    .line 47
    invoke-interface {v2}, Lao/a;->a()J

    .line 48
    .line 49
    .line 50
    move-result-wide v5

    .line 51
    invoke-static {v5, v6}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 52
    .line 53
    .line 54
    move-result-object v2

    .line 55
    iput-object v2, v4, Lg1/q;->f:Ljava/lang/Object;

    .line 56
    .line 57
    iput-object v0, v4, Lg1/q;->b:Ljava/lang/Object;

    .line 58
    .line 59
    new-instance v0, Lrn/m;

    .line 60
    .line 61
    iget-object v2, p1, Lon/a;->a:Ljava/lang/Object;

    .line 62
    .line 63
    invoke-interface {v1, v2}, Lon/e;->apply(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v1

    .line 67
    check-cast v1, [B

    .line 68
    .line 69
    iget-object p0, p0, Lrn/q;->c:Lon/c;

    .line 70
    .line 71
    invoke-direct {v0, p0, v1}, Lrn/m;-><init>(Lon/c;[B)V

    .line 72
    .line 73
    .line 74
    iput-object v0, v4, Lg1/q;->d:Ljava/lang/Object;

    .line 75
    .line 76
    const/4 p0, 0x0

    .line 77
    iput-object p0, v4, Lg1/q;->c:Ljava/lang/Object;

    .line 78
    .line 79
    iget-object p0, p1, Lon/a;->c:Lon/b;

    .line 80
    .line 81
    if-eqz p0, :cond_0

    .line 82
    .line 83
    iget-object p0, p0, Lon/b;->a:Ljava/lang/Integer;

    .line 84
    .line 85
    iput-object p0, v4, Lg1/q;->h:Ljava/lang/Object;

    .line 86
    .line 87
    :cond_0
    invoke-virtual {v4}, Lg1/q;->d()Lrn/h;

    .line 88
    .line 89
    .line 90
    move-result-object v10

    .line 91
    move-object v7, v3

    .line 92
    check-cast v7, Lwn/a;

    .line 93
    .line 94
    iget-object p0, v7, Lwn/a;->b:Ljava/util/concurrent/Executor;

    .line 95
    .line 96
    new-instance v6, Lc8/r;

    .line 97
    .line 98
    const/4 v11, 0x7

    .line 99
    move-object v9, p2

    .line 100
    invoke-direct/range {v6 .. v11}, Lc8/r;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 101
    .line 102
    .line 103
    invoke-interface {p0, v6}, Ljava/util/concurrent/Executor;->execute(Ljava/lang/Runnable;)V

    .line 104
    .line 105
    .line 106
    return-void

    .line 107
    :cond_1
    new-instance p0, Ljava/lang/NullPointerException;

    .line 108
    .line 109
    const-string p1, "Null transformer"

    .line 110
    .line 111
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    throw p0

    .line 115
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 116
    .line 117
    const-string p1, "Null transportName"

    .line 118
    .line 119
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 120
    .line 121
    .line 122
    throw p0
.end method

.class public final Lrb/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lb0/d0;


# instance fields
.field public final d:Lj1/a;

.field public final e:Lay0/k;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lj1/a;Lay0/k;)V
    .locals 1

    .line 1
    sget-object v0, Lqb/a;->e:Lqb/a;

    .line 2
    .line 3
    const-string v0, "onResult"

    .line 4
    .line 5
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lrb/b;->d:Lj1/a;

    .line 12
    .line 13
    iput-object p2, p0, Lrb/b;->e:Lay0/k;

    .line 14
    .line 15
    sget-object p1, Lmx0/s;->d:Lmx0/s;

    .line 16
    .line 17
    iput-object p1, p0, Lrb/b;->f:Ljava/lang/Object;

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final d(Lb0/p1;)V
    .locals 7

    .line 1
    iget-object v0, p1, Lb0/b0;->e:Lb0/a1;

    .line 2
    .line 3
    invoke-interface {v0}, Lb0/a1;->r()Landroid/media/Image;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    return-void

    .line 10
    :cond_0
    iget-object v1, p1, Lb0/p1;->h:Lb0/v0;

    .line 11
    .line 12
    invoke-interface {v1}, Lb0/v0;->d()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    sget-object v2, Lqb/a;->e:Lqb/a;

    .line 17
    .line 18
    new-instance v3, Lrb/a;

    .line 19
    .line 20
    const/4 v4, 0x0

    .line 21
    invoke-direct {v3, p0, v4}, Lrb/a;-><init>(Lrb/b;I)V

    .line 22
    .line 23
    .line 24
    new-instance v4, Lrb/a;

    .line 25
    .line 26
    const/4 v5, 0x1

    .line 27
    invoke-direct {v4, p0, v5}, Lrb/a;-><init>(Lrb/b;I)V

    .line 28
    .line 29
    .line 30
    new-instance v5, Lr1/b;

    .line 31
    .line 32
    const/4 v6, 0x7

    .line 33
    invoke-direct {v5, p1, v6}, Lr1/b;-><init>(Ljava/lang/Object;I)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0, v1}, Lmv/a;->a(Landroid/media/Image;I)Lmv/a;

    .line 37
    .line 38
    .line 39
    move-result-object p1

    .line 40
    iget-object p0, p0, Lrb/b;->d:Lj1/a;

    .line 41
    .line 42
    iget-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v0, Llv/c;

    .line 45
    .line 46
    if-nez v0, :cond_1

    .line 47
    .line 48
    const/4 v0, 0x0

    .line 49
    iget-object v1, v2, Lqb/a;->d:[I

    .line 50
    .line 51
    aget v0, v1, v0

    .line 52
    .line 53
    new-instance v1, Lhv/b;

    .line 54
    .line 55
    invoke-direct {v1, v0}, Lhv/b;-><init>(I)V

    .line 56
    .line 57
    .line 58
    invoke-static {v1}, Llp/c1;->a(Lhv/b;)Llv/c;

    .line 59
    .line 60
    .line 61
    move-result-object v0

    .line 62
    iput-object v0, p0, Lj1/a;->e:Ljava/lang/Object;

    .line 63
    .line 64
    :cond_1
    invoke-virtual {v0, p1}, Lnv/b;->b(Lmv/a;)Laq/t;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    iget v1, p1, Lmv/a;->c:I

    .line 69
    .line 70
    iget p1, p1, Lmv/a;->d:I

    .line 71
    .line 72
    new-instance v2, Lgv/a;

    .line 73
    .line 74
    invoke-direct {v2, v0, v1, p1}, Lgv/a;-><init>(Llv/c;II)V

    .line 75
    .line 76
    .line 77
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 78
    .line 79
    .line 80
    sget-object p1, Laq/l;->a:Lj0/e;

    .line 81
    .line 82
    new-instance v0, Laq/t;

    .line 83
    .line 84
    invoke-direct {v0}, Laq/t;-><init>()V

    .line 85
    .line 86
    .line 87
    new-instance v1, Laq/q;

    .line 88
    .line 89
    invoke-direct {v1, p1, v2, v0}, Laq/q;-><init>(Ljava/util/concurrent/Executor;Laq/i;Laq/t;)V

    .line 90
    .line 91
    .line 92
    iget-object v2, p0, Laq/t;->b:Lcom/google/android/gms/internal/measurement/i4;

    .line 93
    .line 94
    invoke-virtual {v2, v1}, Lcom/google/android/gms/internal/measurement/i4;->A(Laq/r;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {p0}, Laq/t;->s()V

    .line 98
    .line 99
    .line 100
    new-instance p0, Lpg/m;

    .line 101
    .line 102
    const/16 v1, 0x9

    .line 103
    .line 104
    invoke-direct {p0, v3, v1}, Lpg/m;-><init>(Ljava/lang/Object;I)V

    .line 105
    .line 106
    .line 107
    new-instance v1, Lgr/k;

    .line 108
    .line 109
    const/16 v2, 0x1b

    .line 110
    .line 111
    invoke-direct {v1, p0, v2}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 112
    .line 113
    .line 114
    invoke-virtual {v0, p1, v1}, Laq/t;->d(Ljava/util/concurrent/Executor;Laq/g;)Laq/t;

    .line 115
    .line 116
    .line 117
    new-instance p0, Lgr/k;

    .line 118
    .line 119
    const/16 v1, 0x1c

    .line 120
    .line 121
    invoke-direct {p0, v4, v1}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0, p1, p0}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 125
    .line 126
    .line 127
    new-instance p0, Lgr/k;

    .line 128
    .line 129
    const/16 p1, 0x1d

    .line 130
    .line 131
    invoke-direct {p0, v5, p1}, Lgr/k;-><init>(Ljava/lang/Object;I)V

    .line 132
    .line 133
    .line 134
    invoke-virtual {v0, p0}, Laq/t;->k(Laq/e;)Laq/t;

    .line 135
    .line 136
    .line 137
    return-void
.end method

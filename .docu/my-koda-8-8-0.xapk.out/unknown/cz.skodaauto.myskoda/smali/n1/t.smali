.class public final Ln1/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I

.field public final b:Ljava/util/List;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 6
    iput v0, p0, Ln1/t;->a:I

    const/4 v0, 0x0

    .line 7
    invoke-static {v0}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    move-result-object v0

    iput-object v0, p0, Ln1/t;->b:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(ILjava/util/List;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Ln1/t;->a:I

    iput-object p2, p0, Ln1/t;->b:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(ILjava/util/List;ILw71/c;D)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput p1, p0, Ln1/t;->a:I

    .line 4
    iput-object p2, p0, Ln1/t;->b:Ljava/util/List;

    return-void
.end method

.method public constructor <init>(Ljava/util/ArrayList;)V
    .locals 1

    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 9
    iput v0, p0, Ln1/t;->a:I

    .line 10
    iput-object p1, p0, Ln1/t;->b:Ljava/util/List;

    return-void
.end method


# virtual methods
.method public a(ILw71/c;DI)Ljava/util/ArrayList;
    .locals 8

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    if-lez p5, :cond_0

    .line 7
    .line 8
    add-int/lit8 p1, p1, 0x1

    .line 9
    .line 10
    iget v1, p0, Ln1/t;->a:I

    .line 11
    .line 12
    add-int/lit8 v1, v1, -0x1

    .line 13
    .line 14
    invoke-static {p1, v1}, Lkp/r9;->m(II)Lgy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    add-int/lit8 p1, p1, -0x1

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-static {p1, v1}, Lkp/r9;->k(II)Lgy0/h;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    :goto_0
    iget v1, p1, Lgy0/h;->d:I

    .line 27
    .line 28
    iget v2, p1, Lgy0/h;->e:I

    .line 29
    .line 30
    iget p1, p1, Lgy0/h;->f:I

    .line 31
    .line 32
    if-lez p1, :cond_1

    .line 33
    .line 34
    if-le v1, v2, :cond_2

    .line 35
    .line 36
    :cond_1
    if-gez p1, :cond_b

    .line 37
    .line 38
    if-gt v2, v1, :cond_b

    .line 39
    .line 40
    :cond_2
    :goto_1
    iget-object v3, p0, Ln1/t;->b:Ljava/util/List;

    .line 41
    .line 42
    invoke-static {v1, v3}, Llp/bd;->d(ILjava/util/List;)Llx0/l;

    .line 43
    .line 44
    .line 45
    move-result-object v3

    .line 46
    if-eqz v3, :cond_a

    .line 47
    .line 48
    iget-object v4, v3, Llx0/l;->e:Ljava/lang/Object;

    .line 49
    .line 50
    iget-object v3, v3, Llx0/l;->d:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v3, Lw71/c;

    .line 53
    .line 54
    check-cast v4, Lw71/c;

    .line 55
    .line 56
    invoke-static {v3, v4}, Lw71/d;->d(Lw71/c;Lw71/c;)Z

    .line 57
    .line 58
    .line 59
    move-result v5

    .line 60
    if-eqz v5, :cond_3

    .line 61
    .line 62
    goto :goto_3

    .line 63
    :cond_3
    sget-object v5, Lw71/a;->c:Lmb/e;

    .line 64
    .line 65
    invoke-static {v5, v3, v4}, Lmb/e;->p(Lmb/e;Lw71/c;Lw71/c;)Lw71/a;

    .line 66
    .line 67
    .line 68
    move-result-object v6

    .line 69
    if-nez v6, :cond_4

    .line 70
    .line 71
    goto :goto_3

    .line 72
    :cond_4
    invoke-virtual {v5, v3, v4}, Lmb/e;->m(Lw71/c;Lw71/c;)Lw71/a;

    .line 73
    .line 74
    .line 75
    move-result-object v7

    .line 76
    if-nez v7, :cond_5

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_5
    if-lez p5, :cond_6

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_6
    move-object v3, v4

    .line 83
    :goto_2
    if-eqz p2, :cond_7

    .line 84
    .line 85
    invoke-static {v5, p2, v3}, Lmb/e;->p(Lmb/e;Lw71/c;Lw71/c;)Lw71/a;

    .line 86
    .line 87
    .line 88
    move-result-object v4

    .line 89
    if-nez v4, :cond_8

    .line 90
    .line 91
    :cond_7
    const-wide v4, 0x3ff921fb54442d18L    # 1.5707963267948966

    .line 92
    .line 93
    .line 94
    .line 95
    .line 96
    add-double/2addr v4, p3

    .line 97
    invoke-static {v3, v4, v5}, Lmb/e;->n(Lw71/c;D)Lw71/a;

    .line 98
    .line 99
    .line 100
    move-result-object v4

    .line 101
    if-nez v4, :cond_8

    .line 102
    .line 103
    goto :goto_3

    .line 104
    :cond_8
    invoke-virtual {v7, v4}, Lw71/a;->b(Lw71/a;)Lw71/c;

    .line 105
    .line 106
    .line 107
    move-result-object p2

    .line 108
    if-eqz p2, :cond_9

    .line 109
    .line 110
    const/4 p3, 0x5

    .line 111
    invoke-static {p2, p3}, Lw71/d;->i(Lw71/c;I)Lw71/c;

    .line 112
    .line 113
    .line 114
    move-result-object p3

    .line 115
    invoke-virtual {v0, p3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    :cond_9
    invoke-virtual {v6}, Lw71/a;->a()D

    .line 119
    .line 120
    .line 121
    move-result-wide p3

    .line 122
    :cond_a
    :goto_3
    if-eq v1, v2, :cond_b

    .line 123
    .line 124
    add-int/2addr v1, p1

    .line 125
    goto :goto_1

    .line 126
    :cond_b
    return-object v0
.end method

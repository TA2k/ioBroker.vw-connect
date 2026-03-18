.class public final Lr11/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lr11/w;


# instance fields
.field public final d:[Lr11/w;

.field public final e:I


# direct methods
.method public constructor <init>([Lr11/w;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lr11/g;->d:[Lr11/w;

    .line 5
    .line 6
    array-length v0, p1

    .line 7
    const/4 v1, 0x0

    .line 8
    :cond_0
    :goto_0
    add-int/lit8 v0, v0, -0x1

    .line 9
    .line 10
    if-ltz v0, :cond_1

    .line 11
    .line 12
    aget-object v2, p1, v0

    .line 13
    .line 14
    if-eqz v2, :cond_0

    .line 15
    .line 16
    invoke-interface {v2}, Lr11/w;->a()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    if-le v2, v1, :cond_0

    .line 21
    .line 22
    move v1, v2

    .line 23
    goto :goto_0

    .line 24
    :cond_1
    iput v1, p0, Lr11/g;->e:I

    .line 25
    .line 26
    return-void
.end method


# virtual methods
.method public final a()I
    .locals 0

    .line 1
    iget p0, p0, Lr11/g;->e:I

    .line 2
    .line 3
    return p0
.end method

.method public final d(Lr11/s;Ljava/lang/CharSequence;I)I
    .locals 8

    .line 1
    iget-object p0, p0, Lr11/g;->d:[Lr11/w;

    .line 2
    .line 3
    array-length v0, p0

    .line 4
    iget-object v1, p1, Lr11/s;->i:Lr11/r;

    .line 5
    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    new-instance v1, Lr11/r;

    .line 9
    .line 10
    invoke-direct {v1, p1}, Lr11/r;-><init>(Lr11/s;)V

    .line 11
    .line 12
    .line 13
    iput-object v1, p1, Lr11/s;->i:Lr11/r;

    .line 14
    .line 15
    :cond_0
    iget-object v1, p1, Lr11/s;->i:Lr11/r;

    .line 16
    .line 17
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x0

    .line 19
    move v5, p3

    .line 20
    move v6, v5

    .line 21
    move v4, v2

    .line 22
    :goto_0
    if-ge v4, v0, :cond_8

    .line 23
    .line 24
    aget-object v7, p0, v4

    .line 25
    .line 26
    if-nez v7, :cond_2

    .line 27
    .line 28
    if-gt v5, p3, :cond_1

    .line 29
    .line 30
    return p3

    .line 31
    :cond_1
    const/4 v2, 0x1

    .line 32
    goto :goto_3

    .line 33
    :cond_2
    invoke-interface {v7, p1, p2, p3}, Lr11/w;->d(Lr11/s;Ljava/lang/CharSequence;I)I

    .line 34
    .line 35
    .line 36
    move-result v7

    .line 37
    if-lt v7, p3, :cond_6

    .line 38
    .line 39
    if-le v7, v5, :cond_7

    .line 40
    .line 41
    invoke-interface {p2}, Ljava/lang/CharSequence;->length()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    if-ge v7, v3, :cond_5

    .line 46
    .line 47
    add-int/lit8 v3, v4, 0x1

    .line 48
    .line 49
    if-ge v3, v0, :cond_5

    .line 50
    .line 51
    aget-object v3, p0, v3

    .line 52
    .line 53
    if-nez v3, :cond_3

    .line 54
    .line 55
    goto :goto_1

    .line 56
    :cond_3
    iget-object v3, p1, Lr11/s;->i:Lr11/r;

    .line 57
    .line 58
    if-nez v3, :cond_4

    .line 59
    .line 60
    new-instance v3, Lr11/r;

    .line 61
    .line 62
    invoke-direct {v3, p1}, Lr11/r;-><init>(Lr11/s;)V

    .line 63
    .line 64
    .line 65
    iput-object v3, p1, Lr11/s;->i:Lr11/r;

    .line 66
    .line 67
    :cond_4
    iget-object v3, p1, Lr11/s;->i:Lr11/r;

    .line 68
    .line 69
    move v5, v7

    .line 70
    goto :goto_2

    .line 71
    :cond_5
    :goto_1
    return v7

    .line 72
    :cond_6
    if-gez v7, :cond_7

    .line 73
    .line 74
    not-int v7, v7

    .line 75
    if-le v7, v6, :cond_7

    .line 76
    .line 77
    move v6, v7

    .line 78
    :cond_7
    :goto_2
    invoke-virtual {p1, v1}, Lr11/s;->d(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    add-int/lit8 v4, v4, 0x1

    .line 82
    .line 83
    goto :goto_0

    .line 84
    :cond_8
    :goto_3
    if-gt v5, p3, :cond_a

    .line 85
    .line 86
    if-ne v5, p3, :cond_9

    .line 87
    .line 88
    if-eqz v2, :cond_9

    .line 89
    .line 90
    goto :goto_4

    .line 91
    :cond_9
    not-int p0, v6

    .line 92
    return p0

    .line 93
    :cond_a
    :goto_4
    if-eqz v3, :cond_b

    .line 94
    .line 95
    invoke-virtual {p1, v3}, Lr11/s;->d(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    :cond_b
    return v5
.end method

.class public final Ll2/o1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/util/ArrayList;

.field public final b:I

.field public c:I

.field public final d:Ljava/util/ArrayList;

.field public final e:Landroidx/collection/b0;

.field public final f:Llx0/q;


# direct methods
.method public constructor <init>(Ljava/util/ArrayList;I)V
    .locals 5

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ll2/o1;->a:Ljava/util/ArrayList;

    .line 5
    .line 6
    iput p2, p0, Ll2/o1;->b:I

    .line 7
    .line 8
    if-ltz p2, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-string p2, "Invalid start index"

    .line 12
    .line 13
    invoke-static {p2}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    new-instance p2, Ljava/util/ArrayList;

    .line 17
    .line 18
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 19
    .line 20
    .line 21
    iput-object p2, p0, Ll2/o1;->d:Ljava/util/ArrayList;

    .line 22
    .line 23
    new-instance p2, Landroidx/collection/b0;

    .line 24
    .line 25
    invoke-direct {p2}, Landroidx/collection/b0;-><init>()V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p1}, Ljava/util/ArrayList;->size()I

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    const/4 v0, 0x0

    .line 33
    move v1, v0

    .line 34
    :goto_1
    if-ge v0, p1, :cond_1

    .line 35
    .line 36
    iget-object v2, p0, Ll2/o1;->a:Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-virtual {v2, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v2

    .line 42
    check-cast v2, Ll2/u0;

    .line 43
    .line 44
    iget v3, v2, Ll2/u0;->c:I

    .line 45
    .line 46
    iget v2, v2, Ll2/u0;->d:I

    .line 47
    .line 48
    new-instance v4, Ll2/n0;

    .line 49
    .line 50
    invoke-direct {v4, v0, v1, v2}, Ll2/n0;-><init>(III)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p2, v3, v4}, Landroidx/collection/b0;->h(ILjava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    add-int/2addr v1, v2

    .line 57
    add-int/lit8 v0, v0, 0x1

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    iput-object p2, p0, Ll2/o1;->e:Landroidx/collection/b0;

    .line 61
    .line 62
    new-instance p1, Lep0/f;

    .line 63
    .line 64
    const/4 p2, 0x5

    .line 65
    invoke-direct {p1, p0, p2}, Lep0/f;-><init>(Ljava/lang/Object;I)V

    .line 66
    .line 67
    .line 68
    invoke-static {p1}, Lpm/a;->d(Lay0/a;)Llx0/q;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    iput-object p1, p0, Ll2/o1;->f:Llx0/q;

    .line 73
    .line 74
    return-void
.end method


# virtual methods
.method public final a(II)Z
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move/from16 v1, p2

    .line 4
    .line 5
    iget-object v0, v0, Ll2/o1;->e:Landroidx/collection/b0;

    .line 6
    .line 7
    move/from16 v2, p1

    .line 8
    .line 9
    invoke-virtual {v0, v2}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    check-cast v2, Ll2/n0;

    .line 14
    .line 15
    const/4 v3, 0x0

    .line 16
    if-eqz v2, :cond_4

    .line 17
    .line 18
    iget v4, v2, Ll2/n0;->b:I

    .line 19
    .line 20
    iget v5, v2, Ll2/n0;->c:I

    .line 21
    .line 22
    sub-int v5, v1, v5

    .line 23
    .line 24
    iput v1, v2, Ll2/n0;->c:I

    .line 25
    .line 26
    if-eqz v5, :cond_3

    .line 27
    .line 28
    iget-object v1, v0, Landroidx/collection/p;->c:[Ljava/lang/Object;

    .line 29
    .line 30
    iget-object v0, v0, Landroidx/collection/p;->a:[J

    .line 31
    .line 32
    array-length v6, v0

    .line 33
    add-int/lit8 v6, v6, -0x2

    .line 34
    .line 35
    if-ltz v6, :cond_3

    .line 36
    .line 37
    move v7, v3

    .line 38
    :goto_0
    aget-wide v8, v0, v7

    .line 39
    .line 40
    not-long v10, v8

    .line 41
    const/4 v12, 0x7

    .line 42
    shl-long/2addr v10, v12

    .line 43
    and-long/2addr v10, v8

    .line 44
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 45
    .line 46
    .line 47
    .line 48
    .line 49
    and-long/2addr v10, v12

    .line 50
    cmp-long v10, v10, v12

    .line 51
    .line 52
    if-eqz v10, :cond_2

    .line 53
    .line 54
    sub-int v10, v7, v6

    .line 55
    .line 56
    not-int v10, v10

    .line 57
    ushr-int/lit8 v10, v10, 0x1f

    .line 58
    .line 59
    const/16 v11, 0x8

    .line 60
    .line 61
    rsub-int/lit8 v10, v10, 0x8

    .line 62
    .line 63
    move v12, v3

    .line 64
    :goto_1
    if-ge v12, v10, :cond_1

    .line 65
    .line 66
    const-wide/16 v13, 0xff

    .line 67
    .line 68
    and-long/2addr v13, v8

    .line 69
    const-wide/16 v15, 0x80

    .line 70
    .line 71
    cmp-long v13, v13, v15

    .line 72
    .line 73
    if-gez v13, :cond_0

    .line 74
    .line 75
    shl-int/lit8 v13, v7, 0x3

    .line 76
    .line 77
    add-int/2addr v13, v12

    .line 78
    aget-object v13, v1, v13

    .line 79
    .line 80
    check-cast v13, Ll2/n0;

    .line 81
    .line 82
    iget v14, v13, Ll2/n0;->b:I

    .line 83
    .line 84
    if-lt v14, v4, :cond_0

    .line 85
    .line 86
    invoke-virtual {v13, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v14

    .line 90
    if-nez v14, :cond_0

    .line 91
    .line 92
    iget v14, v13, Ll2/n0;->b:I

    .line 93
    .line 94
    add-int/2addr v14, v5

    .line 95
    if-ltz v14, :cond_0

    .line 96
    .line 97
    iput v14, v13, Ll2/n0;->b:I

    .line 98
    .line 99
    :cond_0
    shr-long/2addr v8, v11

    .line 100
    add-int/lit8 v12, v12, 0x1

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_1
    if-ne v10, v11, :cond_3

    .line 104
    .line 105
    :cond_2
    if-eq v7, v6, :cond_3

    .line 106
    .line 107
    add-int/lit8 v7, v7, 0x1

    .line 108
    .line 109
    goto :goto_0

    .line 110
    :cond_3
    const/4 v0, 0x1

    .line 111
    return v0

    .line 112
    :cond_4
    return v3
.end method

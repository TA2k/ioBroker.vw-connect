.class public final Lv9/x;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final b:Lw7/u;

.field public final c:Lw7/p;

.field public d:Z

.field public e:Z

.field public f:Z

.field public g:J

.field public h:J

.field public i:J


# direct methods
.method public constructor <init>(I)V
    .locals 2

    .line 1
    iput p1, p0, Lv9/x;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance p1, Lw7/u;

    .line 10
    .line 11
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    invoke-direct {p1, v0, v1}, Lw7/u;-><init>(J)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lv9/x;->b:Lw7/u;

    .line 17
    .line 18
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 19
    .line 20
    .line 21
    .line 22
    .line 23
    iput-wide v0, p0, Lv9/x;->g:J

    .line 24
    .line 25
    iput-wide v0, p0, Lv9/x;->h:J

    .line 26
    .line 27
    iput-wide v0, p0, Lv9/x;->i:J

    .line 28
    .line 29
    new-instance p1, Lw7/p;

    .line 30
    .line 31
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 32
    .line 33
    .line 34
    iput-object p1, p0, Lv9/x;->c:Lw7/p;

    .line 35
    .line 36
    return-void

    .line 37
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 38
    .line 39
    .line 40
    new-instance p1, Lw7/u;

    .line 41
    .line 42
    const-wide/16 v0, 0x0

    .line 43
    .line 44
    invoke-direct {p1, v0, v1}, Lw7/u;-><init>(J)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lv9/x;->b:Lw7/u;

    .line 48
    .line 49
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    iput-wide v0, p0, Lv9/x;->g:J

    .line 55
    .line 56
    iput-wide v0, p0, Lv9/x;->h:J

    .line 57
    .line 58
    iput-wide v0, p0, Lv9/x;->i:J

    .line 59
    .line 60
    new-instance p1, Lw7/p;

    .line 61
    .line 62
    invoke-direct {p1}, Lw7/p;-><init>()V

    .line 63
    .line 64
    .line 65
    iput-object p1, p0, Lv9/x;->c:Lw7/p;

    .line 66
    .line 67
    return-void

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public static b(I[B)I
    .locals 2

    .line 1
    aget-byte v0, p1, p0

    .line 2
    .line 3
    and-int/lit16 v0, v0, 0xff

    .line 4
    .line 5
    shl-int/lit8 v0, v0, 0x18

    .line 6
    .line 7
    add-int/lit8 v1, p0, 0x1

    .line 8
    .line 9
    aget-byte v1, p1, v1

    .line 10
    .line 11
    and-int/lit16 v1, v1, 0xff

    .line 12
    .line 13
    shl-int/lit8 v1, v1, 0x10

    .line 14
    .line 15
    or-int/2addr v0, v1

    .line 16
    add-int/lit8 v1, p0, 0x2

    .line 17
    .line 18
    aget-byte v1, p1, v1

    .line 19
    .line 20
    and-int/lit16 v1, v1, 0xff

    .line 21
    .line 22
    shl-int/lit8 v1, v1, 0x8

    .line 23
    .line 24
    or-int/2addr v0, v1

    .line 25
    add-int/lit8 p0, p0, 0x3

    .line 26
    .line 27
    aget-byte p0, p1, p0

    .line 28
    .line 29
    and-int/lit16 p0, p0, 0xff

    .line 30
    .line 31
    or-int/2addr p0, v0

    .line 32
    return p0
.end method

.method public static c(Lw7/p;)J
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lw7/p;->b:I

    .line 4
    .line 5
    invoke-virtual {v0}, Lw7/p;->a()I

    .line 6
    .line 7
    .line 8
    move-result v2

    .line 9
    const-wide v3, -0x7fffffffffffffffL    # -4.9E-324

    .line 10
    .line 11
    .line 12
    .line 13
    .line 14
    const/16 v5, 0x9

    .line 15
    .line 16
    if-ge v2, v5, :cond_0

    .line 17
    .line 18
    return-wide v3

    .line 19
    :cond_0
    new-array v2, v5, [B

    .line 20
    .line 21
    const/4 v6, 0x0

    .line 22
    invoke-virtual {v0, v2, v6, v5}, Lw7/p;->h([BII)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, v1}, Lw7/p;->I(I)V

    .line 26
    .line 27
    .line 28
    aget-byte v0, v2, v6

    .line 29
    .line 30
    and-int/lit16 v1, v0, 0xc4

    .line 31
    .line 32
    const/16 v5, 0x44

    .line 33
    .line 34
    if-eq v1, v5, :cond_1

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_1
    const/4 v1, 0x2

    .line 38
    aget-byte v1, v2, v1

    .line 39
    .line 40
    and-int/lit8 v5, v1, 0x4

    .line 41
    .line 42
    const/4 v6, 0x4

    .line 43
    if-eq v5, v6, :cond_2

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_2
    aget-byte v5, v2, v6

    .line 47
    .line 48
    and-int/lit8 v7, v5, 0x4

    .line 49
    .line 50
    if-eq v7, v6, :cond_3

    .line 51
    .line 52
    goto :goto_0

    .line 53
    :cond_3
    const/4 v6, 0x5

    .line 54
    aget-byte v7, v2, v6

    .line 55
    .line 56
    const/4 v8, 0x1

    .line 57
    and-int/2addr v7, v8

    .line 58
    if-eq v7, v8, :cond_4

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_4
    const/16 v7, 0x8

    .line 62
    .line 63
    aget-byte v7, v2, v7

    .line 64
    .line 65
    const/4 v9, 0x3

    .line 66
    and-int/2addr v7, v9

    .line 67
    if-ne v7, v9, :cond_5

    .line 68
    .line 69
    int-to-long v3, v0

    .line 70
    const-wide/16 v10, 0x38

    .line 71
    .line 72
    and-long/2addr v10, v3

    .line 73
    shr-long/2addr v10, v9

    .line 74
    const/16 v0, 0x1e

    .line 75
    .line 76
    shl-long/2addr v10, v0

    .line 77
    const-wide/16 v12, 0x3

    .line 78
    .line 79
    and-long/2addr v3, v12

    .line 80
    const/16 v0, 0x1c

    .line 81
    .line 82
    shl-long/2addr v3, v0

    .line 83
    or-long/2addr v3, v10

    .line 84
    aget-byte v0, v2, v8

    .line 85
    .line 86
    int-to-long v7, v0

    .line 87
    const-wide/16 v10, 0xff

    .line 88
    .line 89
    and-long/2addr v7, v10

    .line 90
    const/16 v0, 0x14

    .line 91
    .line 92
    shl-long/2addr v7, v0

    .line 93
    or-long/2addr v3, v7

    .line 94
    int-to-long v0, v1

    .line 95
    const-wide/16 v7, 0xf8

    .line 96
    .line 97
    and-long v14, v0, v7

    .line 98
    .line 99
    shr-long/2addr v14, v9

    .line 100
    const/16 v16, 0xf

    .line 101
    .line 102
    shl-long v14, v14, v16

    .line 103
    .line 104
    or-long/2addr v3, v14

    .line 105
    and-long/2addr v0, v12

    .line 106
    const/16 v12, 0xd

    .line 107
    .line 108
    shl-long/2addr v0, v12

    .line 109
    or-long/2addr v0, v3

    .line 110
    aget-byte v2, v2, v9

    .line 111
    .line 112
    int-to-long v2, v2

    .line 113
    and-long/2addr v2, v10

    .line 114
    shl-long/2addr v2, v6

    .line 115
    or-long/2addr v0, v2

    .line 116
    int-to-long v2, v5

    .line 117
    and-long/2addr v2, v7

    .line 118
    shr-long/2addr v2, v9

    .line 119
    or-long/2addr v0, v2

    .line 120
    return-wide v0

    .line 121
    :cond_5
    :goto_0
    return-wide v3
.end method


# virtual methods
.method public final a(Lo8/p;)V
    .locals 3

    .line 1
    iget v0, p0, Lv9/x;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lw7/w;->b:[B

    .line 7
    .line 8
    iget-object v1, p0, Lv9/x;->c:Lw7/p;

    .line 9
    .line 10
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 11
    .line 12
    .line 13
    array-length v2, v0

    .line 14
    invoke-virtual {v1, v2, v0}, Lw7/p;->G(I[B)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x1

    .line 18
    iput-boolean v0, p0, Lv9/x;->d:Z

    .line 19
    .line 20
    invoke-interface {p1}, Lo8/p;->e()V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    :pswitch_0
    sget-object v0, Lw7/w;->b:[B

    .line 25
    .line 26
    iget-object v1, p0, Lv9/x;->c:Lw7/p;

    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 29
    .line 30
    .line 31
    array-length v2, v0

    .line 32
    invoke-virtual {v1, v2, v0}, Lw7/p;->G(I[B)V

    .line 33
    .line 34
    .line 35
    const/4 v0, 0x1

    .line 36
    iput-boolean v0, p0, Lv9/x;->d:Z

    .line 37
    .line 38
    invoke-interface {p1}, Lo8/p;->e()V

    .line 39
    .line 40
    .line 41
    return-void

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

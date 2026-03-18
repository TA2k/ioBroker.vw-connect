.class public final Lr8/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final synthetic a:I

.field public final b:Lw7/p;

.field public final c:Lo8/e0;


# direct methods
.method public constructor <init>(I)V
    .locals 2

    .line 1
    iput p1, p0, Lr8/a;->a:I

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
    new-instance p1, Lw7/p;

    .line 10
    .line 11
    const/4 v0, 0x4

    .line 12
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lr8/a;->b:Lw7/p;

    .line 16
    .line 17
    new-instance p1, Lo8/e0;

    .line 18
    .line 19
    const/4 v0, -0x1

    .line 20
    const-string v1, "image/avif"

    .line 21
    .line 22
    invoke-direct {p1, v0, v0, v1}, Lo8/e0;-><init>(IILjava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, p0, Lr8/a;->c:Lo8/e0;

    .line 26
    .line 27
    return-void

    .line 28
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 29
    .line 30
    .line 31
    new-instance p1, Lw7/p;

    .line 32
    .line 33
    const/4 v0, 0x4

    .line 34
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 35
    .line 36
    .line 37
    iput-object p1, p0, Lr8/a;->b:Lw7/p;

    .line 38
    .line 39
    new-instance p1, Lo8/e0;

    .line 40
    .line 41
    const/4 v0, -0x1

    .line 42
    const-string v1, "image/webp"

    .line 43
    .line 44
    invoke-direct {p1, v0, v0, v1}, Lo8/e0;-><init>(IILjava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iput-object p1, p0, Lr8/a;->c:Lo8/e0;

    .line 48
    .line 49
    return-void

    .line 50
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 51
    .line 52
    .line 53
    new-instance p1, Lw7/p;

    .line 54
    .line 55
    const/4 v0, 0x4

    .line 56
    invoke-direct {p1, v0}, Lw7/p;-><init>(I)V

    .line 57
    .line 58
    .line 59
    iput-object p1, p0, Lr8/a;->b:Lw7/p;

    .line 60
    .line 61
    new-instance p1, Lo8/e0;

    .line 62
    .line 63
    const/4 v0, -0x1

    .line 64
    const-string v1, "image/heif"

    .line 65
    .line 66
    invoke-direct {p1, v0, v0, v1}, Lo8/e0;-><init>(IILjava/lang/String;)V

    .line 67
    .line 68
    .line 69
    iput-object p1, p0, Lr8/a;->c:Lo8/e0;

    .line 70
    .line 71
    return-void

    .line 72
    nop

    .line 73
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method private final e()V
    .locals 0

    .line 1
    return-void
.end method

.method private final f()V
    .locals 0

    .line 1
    return-void
.end method

.method private final g()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 7

    .line 1
    iget v0, p0, Lr8/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lr8/a;->b:Lw7/p;

    .line 7
    .line 8
    const/4 v0, 0x4

    .line 9
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 10
    .line 11
    .line 12
    iget-object v1, p0, Lw7/p;->a:[B

    .line 13
    .line 14
    check-cast p1, Lo8/l;

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    invoke-virtual {p1, v1, v2, v0, v2}, Lo8/l;->b([BIIZ)Z

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 21
    .line 22
    .line 23
    move-result-wide v3

    .line 24
    const-wide/32 v5, 0x52494646

    .line 25
    .line 26
    .line 27
    cmp-long v1, v3, v5

    .line 28
    .line 29
    if-eqz v1, :cond_0

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    invoke-virtual {p1, v0, v2}, Lo8/l;->c(IZ)Z

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lw7/p;->a:[B

    .line 39
    .line 40
    invoke-virtual {p1, v1, v2, v0, v2}, Lo8/l;->b([BIIZ)Z

    .line 41
    .line 42
    .line 43
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 44
    .line 45
    .line 46
    move-result-wide p0

    .line 47
    const-wide/32 v0, 0x57454250

    .line 48
    .line 49
    .line 50
    cmp-long p0, p0, v0

    .line 51
    .line 52
    if-nez p0, :cond_1

    .line 53
    .line 54
    const/4 v2, 0x1

    .line 55
    :cond_1
    :goto_0
    return v2

    .line 56
    :pswitch_0
    check-cast p1, Lo8/l;

    .line 57
    .line 58
    const/4 v0, 0x4

    .line 59
    const/4 v1, 0x0

    .line 60
    invoke-virtual {p1, v0, v1}, Lo8/l;->c(IZ)Z

    .line 61
    .line 62
    .line 63
    iget-object p0, p0, Lr8/a;->b:Lw7/p;

    .line 64
    .line 65
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 66
    .line 67
    .line 68
    iget-object v2, p0, Lw7/p;->a:[B

    .line 69
    .line 70
    invoke-virtual {p1, v2, v1, v0, v1}, Lo8/l;->b([BIIZ)Z

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 74
    .line 75
    .line 76
    move-result-wide v2

    .line 77
    const v4, 0x66747970

    .line 78
    .line 79
    .line 80
    int-to-long v4, v4

    .line 81
    cmp-long v2, v2, v4

    .line 82
    .line 83
    if-nez v2, :cond_2

    .line 84
    .line 85
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 86
    .line 87
    .line 88
    iget-object v2, p0, Lw7/p;->a:[B

    .line 89
    .line 90
    invoke-virtual {p1, v2, v1, v0, v1}, Lo8/l;->b([BIIZ)Z

    .line 91
    .line 92
    .line 93
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 94
    .line 95
    .line 96
    move-result-wide p0

    .line 97
    const v0, 0x68656963

    .line 98
    .line 99
    .line 100
    int-to-long v2, v0

    .line 101
    cmp-long p0, p0, v2

    .line 102
    .line 103
    if-nez p0, :cond_2

    .line 104
    .line 105
    const/4 v1, 0x1

    .line 106
    :cond_2
    return v1

    .line 107
    :pswitch_1
    check-cast p1, Lo8/l;

    .line 108
    .line 109
    const/4 v0, 0x4

    .line 110
    const/4 v1, 0x0

    .line 111
    invoke-virtual {p1, v0, v1}, Lo8/l;->c(IZ)Z

    .line 112
    .line 113
    .line 114
    iget-object p0, p0, Lr8/a;->b:Lw7/p;

    .line 115
    .line 116
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 117
    .line 118
    .line 119
    iget-object v2, p0, Lw7/p;->a:[B

    .line 120
    .line 121
    invoke-virtual {p1, v2, v1, v0, v1}, Lo8/l;->b([BIIZ)Z

    .line 122
    .line 123
    .line 124
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 125
    .line 126
    .line 127
    move-result-wide v2

    .line 128
    const v4, 0x66747970

    .line 129
    .line 130
    .line 131
    int-to-long v4, v4

    .line 132
    cmp-long v2, v2, v4

    .line 133
    .line 134
    if-nez v2, :cond_3

    .line 135
    .line 136
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 137
    .line 138
    .line 139
    iget-object v2, p0, Lw7/p;->a:[B

    .line 140
    .line 141
    invoke-virtual {p1, v2, v1, v0, v1}, Lo8/l;->b([BIIZ)Z

    .line 142
    .line 143
    .line 144
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 145
    .line 146
    .line 147
    move-result-wide p0

    .line 148
    const v0, 0x61766966

    .line 149
    .line 150
    .line 151
    int-to-long v2, v0

    .line 152
    cmp-long p0, p0, v2

    .line 153
    .line 154
    if-nez p0, :cond_3

    .line 155
    .line 156
    const/4 v1, 0x1

    .line 157
    :cond_3
    return v1

    .line 158
    nop

    .line 159
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final b()V
    .locals 0

    .line 1
    iget p0, p0, Lr8/a;->a:I

    .line 2
    .line 3
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 1

    .line 1
    iget v0, p0, Lr8/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 7
    .line 8
    invoke-virtual {p0, p1}, Lo8/e0;->c(Lo8/q;)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 13
    .line 14
    invoke-virtual {p0, p1}, Lo8/e0;->c(Lo8/q;)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_1
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 19
    .line 20
    invoke-virtual {p0, p1}, Lo8/e0;->c(Lo8/q;)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final d(JJ)V
    .locals 1

    .line 1
    iget v0, p0, Lr8/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2, p3, p4}, Lo8/e0;->d(JJ)V

    .line 9
    .line 10
    .line 11
    return-void

    .line 12
    :pswitch_0
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 13
    .line 14
    invoke-virtual {p0, p1, p2, p3, p4}, Lo8/e0;->d(JJ)V

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :pswitch_1
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 19
    .line 20
    invoke-virtual {p0, p1, p2, p3, p4}, Lo8/e0;->d(JJ)V

    .line 21
    .line 22
    .line 23
    return-void

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 1

    .line 1
    iget v0, p0, Lr8/a;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lo8/e0;->h(Lo8/p;Lo8/s;)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lo8/e0;->h(Lo8/p;Lo8/s;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :pswitch_1
    iget-object p0, p0, Lr8/a;->c:Lo8/e0;

    .line 21
    .line 22
    invoke-virtual {p0, p1, p2}, Lo8/e0;->h(Lo8/p;Lo8/s;)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

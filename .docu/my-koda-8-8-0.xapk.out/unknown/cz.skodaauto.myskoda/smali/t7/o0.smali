.class public final Lt7/o0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final p:Ljava/lang/Object;

.field public static final q:Lt7/x;


# instance fields
.field public a:Ljava/lang/Object;

.field public b:Ljava/lang/Object;

.field public c:Lt7/x;

.field public d:J

.field public e:J

.field public f:J

.field public g:Z

.field public h:Z

.field public i:Lt7/t;

.field public j:Z

.field public k:J

.field public l:J

.field public m:I

.field public n:I

.field public o:J


# direct methods
.method static constructor <clinit>()V
    .locals 15

    .line 1
    new-instance v0, Ljava/lang/Object;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lt7/o0;->p:Ljava/lang/Object;

    .line 7
    .line 8
    new-instance v0, Lo8/s;

    .line 9
    .line 10
    invoke-direct {v0}, Lo8/s;-><init>()V

    .line 11
    .line 12
    .line 13
    sget-object v1, Lhr/h0;->e:Lhr/f0;

    .line 14
    .line 15
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 16
    .line 17
    sget-object v6, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 18
    .line 19
    sget-object v7, Lhr/x0;->h:Lhr/x0;

    .line 20
    .line 21
    new-instance v1, Lt7/s;

    .line 22
    .line 23
    invoke-direct {v1}, Lt7/s;-><init>()V

    .line 24
    .line 25
    .line 26
    sget-object v14, Lt7/v;->a:Lt7/v;

    .line 27
    .line 28
    sget-object v3, Landroid/net/Uri;->EMPTY:Landroid/net/Uri;

    .line 29
    .line 30
    const/4 v5, 0x0

    .line 31
    if-eqz v3, :cond_0

    .line 32
    .line 33
    new-instance v2, Lt7/u;

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    const-wide v8, -0x7fffffffffffffffL    # -4.9E-324

    .line 37
    .line 38
    .line 39
    .line 40
    .line 41
    invoke-direct/range {v2 .. v9}, Lt7/u;-><init>(Landroid/net/Uri;Ljava/lang/String;Lkp/o9;Ljava/util/List;Lhr/h0;J)V

    .line 42
    .line 43
    .line 44
    move-object v11, v2

    .line 45
    goto :goto_0

    .line 46
    :cond_0
    move-object v11, v5

    .line 47
    :goto_0
    new-instance v8, Lt7/x;

    .line 48
    .line 49
    new-instance v10, Lt7/r;

    .line 50
    .line 51
    invoke-direct {v10, v0}, Lt7/q;-><init>(Lo8/s;)V

    .line 52
    .line 53
    .line 54
    new-instance v12, Lt7/t;

    .line 55
    .line 56
    invoke-direct {v12, v1}, Lt7/t;-><init>(Lt7/s;)V

    .line 57
    .line 58
    .line 59
    sget-object v13, Lt7/a0;->B:Lt7/a0;

    .line 60
    .line 61
    const-string v9, "androidx.media3.common.Timeline"

    .line 62
    .line 63
    invoke-direct/range {v8 .. v14}, Lt7/x;-><init>(Ljava/lang/String;Lt7/r;Lt7/u;Lt7/t;Lt7/a0;Lt7/v;)V

    .line 64
    .line 65
    .line 66
    sput-object v8, Lt7/o0;->q:Lt7/x;

    .line 67
    .line 68
    const/4 v0, 0x4

    .line 69
    const/4 v1, 0x5

    .line 70
    const/4 v2, 0x1

    .line 71
    const/4 v3, 0x2

    .line 72
    const/4 v4, 0x3

    .line 73
    invoke-static {v2, v3, v4, v0, v1}, Lp3/m;->w(IIIII)V

    .line 74
    .line 75
    .line 76
    const/16 v0, 0x9

    .line 77
    .line 78
    const/16 v1, 0xa

    .line 79
    .line 80
    const/4 v2, 0x6

    .line 81
    const/4 v3, 0x7

    .line 82
    const/16 v4, 0x8

    .line 83
    .line 84
    invoke-static {v2, v3, v4, v0, v1}, Lp3/m;->w(IIIII)V

    .line 85
    .line 86
    .line 87
    const/16 v0, 0xb

    .line 88
    .line 89
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 90
    .line 91
    .line 92
    const/16 v0, 0xc

    .line 93
    .line 94
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 95
    .line 96
    .line 97
    const/16 v0, 0xd

    .line 98
    .line 99
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 100
    .line 101
    .line 102
    return-void
.end method

.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lt7/o0;->p:Ljava/lang/Object;

    .line 5
    .line 6
    iput-object v0, p0, Lt7/o0;->a:Ljava/lang/Object;

    .line 7
    .line 8
    sget-object v0, Lt7/o0;->q:Lt7/x;

    .line 9
    .line 10
    iput-object v0, p0, Lt7/o0;->c:Lt7/x;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a()Z
    .locals 0

    .line 1
    iget-object p0, p0, Lt7/o0;->i:Lt7/t;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    const/4 p0, 0x1

    .line 6
    return p0

    .line 7
    :cond_0
    const/4 p0, 0x0

    .line 8
    return p0
.end method

.method public final b(Lt7/x;ZZLt7/t;JJ)V
    .locals 2

    .line 1
    sget-object v0, Lt7/o0;->p:Ljava/lang/Object;

    .line 2
    .line 3
    iput-object v0, p0, Lt7/o0;->a:Ljava/lang/Object;

    .line 4
    .line 5
    if-eqz p1, :cond_0

    .line 6
    .line 7
    move-object v0, p1

    .line 8
    goto :goto_0

    .line 9
    :cond_0
    sget-object v0, Lt7/o0;->q:Lt7/x;

    .line 10
    .line 11
    :goto_0
    iput-object v0, p0, Lt7/o0;->c:Lt7/x;

    .line 12
    .line 13
    if-eqz p1, :cond_1

    .line 14
    .line 15
    iget-object p1, p1, Lt7/x;->b:Lt7/u;

    .line 16
    .line 17
    :cond_1
    const/4 p1, 0x0

    .line 18
    iput-object p1, p0, Lt7/o0;->b:Ljava/lang/Object;

    .line 19
    .line 20
    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 21
    .line 22
    .line 23
    .line 24
    .line 25
    iput-wide v0, p0, Lt7/o0;->d:J

    .line 26
    .line 27
    iput-wide v0, p0, Lt7/o0;->e:J

    .line 28
    .line 29
    iput-wide v0, p0, Lt7/o0;->f:J

    .line 30
    .line 31
    iput-boolean p2, p0, Lt7/o0;->g:Z

    .line 32
    .line 33
    iput-boolean p3, p0, Lt7/o0;->h:Z

    .line 34
    .line 35
    iput-object p4, p0, Lt7/o0;->i:Lt7/t;

    .line 36
    .line 37
    iput-wide p5, p0, Lt7/o0;->k:J

    .line 38
    .line 39
    iput-wide p7, p0, Lt7/o0;->l:J

    .line 40
    .line 41
    const/4 p1, 0x0

    .line 42
    iput p1, p0, Lt7/o0;->m:I

    .line 43
    .line 44
    iput p1, p0, Lt7/o0;->n:I

    .line 45
    .line 46
    const-wide/16 p2, 0x0

    .line 47
    .line 48
    iput-wide p2, p0, Lt7/o0;->o:J

    .line 49
    .line 50
    iput-boolean p1, p0, Lt7/o0;->j:Z

    .line 51
    .line 52
    return-void
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_0

    .line 4
    .line 5
    :cond_0
    if-eqz p1, :cond_2

    .line 6
    .line 7
    const-class v0, Lt7/o0;

    .line 8
    .line 9
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 10
    .line 11
    .line 12
    move-result-object v1

    .line 13
    invoke-virtual {v0, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    if-nez v0, :cond_1

    .line 18
    .line 19
    goto/16 :goto_1

    .line 20
    .line 21
    :cond_1
    check-cast p1, Lt7/o0;

    .line 22
    .line 23
    iget-object v0, p0, Lt7/o0;->a:Ljava/lang/Object;

    .line 24
    .line 25
    iget-object v1, p1, Lt7/o0;->a:Ljava/lang/Object;

    .line 26
    .line 27
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_2

    .line 32
    .line 33
    iget-object v0, p0, Lt7/o0;->c:Lt7/x;

    .line 34
    .line 35
    iget-object v1, p1, Lt7/o0;->c:Lt7/x;

    .line 36
    .line 37
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v0

    .line 41
    if-eqz v0, :cond_2

    .line 42
    .line 43
    iget-object v0, p0, Lt7/o0;->i:Lt7/t;

    .line 44
    .line 45
    iget-object v1, p1, Lt7/o0;->i:Lt7/t;

    .line 46
    .line 47
    invoke-static {v0, v1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eqz v0, :cond_2

    .line 52
    .line 53
    iget-wide v0, p0, Lt7/o0;->d:J

    .line 54
    .line 55
    iget-wide v2, p1, Lt7/o0;->d:J

    .line 56
    .line 57
    cmp-long v0, v0, v2

    .line 58
    .line 59
    if-nez v0, :cond_2

    .line 60
    .line 61
    iget-wide v0, p0, Lt7/o0;->e:J

    .line 62
    .line 63
    iget-wide v2, p1, Lt7/o0;->e:J

    .line 64
    .line 65
    cmp-long v0, v0, v2

    .line 66
    .line 67
    if-nez v0, :cond_2

    .line 68
    .line 69
    iget-wide v0, p0, Lt7/o0;->f:J

    .line 70
    .line 71
    iget-wide v2, p1, Lt7/o0;->f:J

    .line 72
    .line 73
    cmp-long v0, v0, v2

    .line 74
    .line 75
    if-nez v0, :cond_2

    .line 76
    .line 77
    iget-boolean v0, p0, Lt7/o0;->g:Z

    .line 78
    .line 79
    iget-boolean v1, p1, Lt7/o0;->g:Z

    .line 80
    .line 81
    if-ne v0, v1, :cond_2

    .line 82
    .line 83
    iget-boolean v0, p0, Lt7/o0;->h:Z

    .line 84
    .line 85
    iget-boolean v1, p1, Lt7/o0;->h:Z

    .line 86
    .line 87
    if-ne v0, v1, :cond_2

    .line 88
    .line 89
    iget-boolean v0, p0, Lt7/o0;->j:Z

    .line 90
    .line 91
    iget-boolean v1, p1, Lt7/o0;->j:Z

    .line 92
    .line 93
    if-ne v0, v1, :cond_2

    .line 94
    .line 95
    iget-wide v0, p0, Lt7/o0;->k:J

    .line 96
    .line 97
    iget-wide v2, p1, Lt7/o0;->k:J

    .line 98
    .line 99
    cmp-long v0, v0, v2

    .line 100
    .line 101
    if-nez v0, :cond_2

    .line 102
    .line 103
    iget-wide v0, p0, Lt7/o0;->l:J

    .line 104
    .line 105
    iget-wide v2, p1, Lt7/o0;->l:J

    .line 106
    .line 107
    cmp-long v0, v0, v2

    .line 108
    .line 109
    if-nez v0, :cond_2

    .line 110
    .line 111
    iget v0, p0, Lt7/o0;->m:I

    .line 112
    .line 113
    iget v1, p1, Lt7/o0;->m:I

    .line 114
    .line 115
    if-ne v0, v1, :cond_2

    .line 116
    .line 117
    iget v0, p0, Lt7/o0;->n:I

    .line 118
    .line 119
    iget v1, p1, Lt7/o0;->n:I

    .line 120
    .line 121
    if-ne v0, v1, :cond_2

    .line 122
    .line 123
    iget-wide v0, p0, Lt7/o0;->o:J

    .line 124
    .line 125
    iget-wide p0, p1, Lt7/o0;->o:J

    .line 126
    .line 127
    cmp-long p0, v0, p0

    .line 128
    .line 129
    if-nez p0, :cond_2

    .line 130
    .line 131
    :goto_0
    const/4 p0, 0x1

    .line 132
    return p0

    .line 133
    :cond_2
    :goto_1
    const/4 p0, 0x0

    .line 134
    return p0
.end method

.method public final hashCode()I
    .locals 7

    .line 1
    iget-object v0, p0, Lt7/o0;->a:Ljava/lang/Object;

    .line 2
    .line 3
    const/16 v1, 0xd9

    .line 4
    .line 5
    const/16 v2, 0x1f

    .line 6
    .line 7
    invoke-static {v1, v0, v2}, Lp3/m;->b(ILjava/lang/Object;I)I

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    iget-object v1, p0, Lt7/o0;->c:Lt7/x;

    .line 12
    .line 13
    invoke-virtual {v1}, Lt7/x;->hashCode()I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    add-int/2addr v1, v0

    .line 18
    mul-int/lit16 v1, v1, 0x3c1

    .line 19
    .line 20
    iget-object v0, p0, Lt7/o0;->i:Lt7/t;

    .line 21
    .line 22
    if-nez v0, :cond_0

    .line 23
    .line 24
    const/4 v0, 0x0

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    invoke-virtual {v0}, Lt7/t;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    :goto_0
    add-int/2addr v1, v0

    .line 31
    mul-int/2addr v1, v2

    .line 32
    iget-wide v3, p0, Lt7/o0;->d:J

    .line 33
    .line 34
    const/16 v0, 0x20

    .line 35
    .line 36
    ushr-long v5, v3, v0

    .line 37
    .line 38
    xor-long/2addr v3, v5

    .line 39
    long-to-int v3, v3

    .line 40
    add-int/2addr v1, v3

    .line 41
    mul-int/2addr v1, v2

    .line 42
    iget-wide v3, p0, Lt7/o0;->e:J

    .line 43
    .line 44
    ushr-long v5, v3, v0

    .line 45
    .line 46
    xor-long/2addr v3, v5

    .line 47
    long-to-int v3, v3

    .line 48
    add-int/2addr v1, v3

    .line 49
    mul-int/2addr v1, v2

    .line 50
    iget-wide v3, p0, Lt7/o0;->f:J

    .line 51
    .line 52
    ushr-long v5, v3, v0

    .line 53
    .line 54
    xor-long/2addr v3, v5

    .line 55
    long-to-int v3, v3

    .line 56
    add-int/2addr v1, v3

    .line 57
    mul-int/2addr v1, v2

    .line 58
    iget-boolean v3, p0, Lt7/o0;->g:Z

    .line 59
    .line 60
    add-int/2addr v1, v3

    .line 61
    mul-int/2addr v1, v2

    .line 62
    iget-boolean v3, p0, Lt7/o0;->h:Z

    .line 63
    .line 64
    add-int/2addr v1, v3

    .line 65
    mul-int/2addr v1, v2

    .line 66
    iget-boolean v3, p0, Lt7/o0;->j:Z

    .line 67
    .line 68
    add-int/2addr v1, v3

    .line 69
    mul-int/2addr v1, v2

    .line 70
    iget-wide v3, p0, Lt7/o0;->k:J

    .line 71
    .line 72
    ushr-long v5, v3, v0

    .line 73
    .line 74
    xor-long/2addr v3, v5

    .line 75
    long-to-int v3, v3

    .line 76
    add-int/2addr v1, v3

    .line 77
    mul-int/2addr v1, v2

    .line 78
    iget-wide v3, p0, Lt7/o0;->l:J

    .line 79
    .line 80
    ushr-long v5, v3, v0

    .line 81
    .line 82
    xor-long/2addr v3, v5

    .line 83
    long-to-int v3, v3

    .line 84
    add-int/2addr v1, v3

    .line 85
    mul-int/2addr v1, v2

    .line 86
    iget v3, p0, Lt7/o0;->m:I

    .line 87
    .line 88
    add-int/2addr v1, v3

    .line 89
    mul-int/2addr v1, v2

    .line 90
    iget v3, p0, Lt7/o0;->n:I

    .line 91
    .line 92
    add-int/2addr v1, v3

    .line 93
    mul-int/2addr v1, v2

    .line 94
    iget-wide v2, p0, Lt7/o0;->o:J

    .line 95
    .line 96
    ushr-long v4, v2, v0

    .line 97
    .line 98
    xor-long/2addr v2, v4

    .line 99
    long-to-int p0, v2

    .line 100
    add-int/2addr v1, p0

    .line 101
    return v1
.end method

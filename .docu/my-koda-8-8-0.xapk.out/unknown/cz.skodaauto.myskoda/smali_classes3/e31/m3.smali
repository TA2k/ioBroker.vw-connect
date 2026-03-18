.class public final Le31/m3;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Le31/w2;

.field public static final l:[Llx0/i;


# instance fields
.field public final a:Le31/f3;

.field public final b:Le31/v2;

.field public final c:Ljava/util/List;

.field public final d:Ljava/util/List;

.field public final e:Le31/z2;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/util/List;

.field public final h:Ljava/util/List;

.field public final i:Ljava/lang/String;

.field public final j:Ljava/lang/Double;

.field public final k:Ljava/lang/Boolean;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Le31/w2;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Le31/m3;->Companion:Le31/w2;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Le31/t0;

    .line 11
    .line 12
    const/16 v2, 0xc

    .line 13
    .line 14
    invoke-direct {v1, v2}, Le31/t0;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Le31/t0;

    .line 22
    .line 23
    const/16 v3, 0xd

    .line 24
    .line 25
    invoke-direct {v2, v3}, Le31/t0;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    new-instance v3, Le31/t0;

    .line 33
    .line 34
    const/16 v4, 0xe

    .line 35
    .line 36
    invoke-direct {v3, v4}, Le31/t0;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    new-instance v4, Le31/t0;

    .line 44
    .line 45
    const/16 v5, 0xf

    .line 46
    .line 47
    invoke-direct {v4, v5}, Le31/t0;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0, v4}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    const/16 v4, 0xb

    .line 55
    .line 56
    new-array v4, v4, [Llx0/i;

    .line 57
    .line 58
    const/4 v5, 0x0

    .line 59
    const/4 v6, 0x0

    .line 60
    aput-object v6, v4, v5

    .line 61
    .line 62
    const/4 v5, 0x1

    .line 63
    aput-object v6, v4, v5

    .line 64
    .line 65
    const/4 v5, 0x2

    .line 66
    aput-object v1, v4, v5

    .line 67
    .line 68
    const/4 v1, 0x3

    .line 69
    aput-object v2, v4, v1

    .line 70
    .line 71
    const/4 v1, 0x4

    .line 72
    aput-object v6, v4, v1

    .line 73
    .line 74
    const/4 v1, 0x5

    .line 75
    aput-object v6, v4, v1

    .line 76
    .line 77
    const/4 v1, 0x6

    .line 78
    aput-object v3, v4, v1

    .line 79
    .line 80
    const/4 v1, 0x7

    .line 81
    aput-object v0, v4, v1

    .line 82
    .line 83
    const/16 v0, 0x8

    .line 84
    .line 85
    aput-object v6, v4, v0

    .line 86
    .line 87
    const/16 v0, 0x9

    .line 88
    .line 89
    aput-object v6, v4, v0

    .line 90
    .line 91
    const/16 v0, 0xa

    .line 92
    .line 93
    aput-object v6, v4, v0

    .line 94
    .line 95
    sput-object v4, Le31/m3;->l:[Llx0/i;

    .line 96
    .line 97
    return-void
.end method

.method public synthetic constructor <init>(ILe31/f3;Le31/v2;Ljava/util/List;Ljava/util/List;Le31/z2;Ljava/lang/String;Ljava/util/List;Ljava/util/List;Ljava/lang/String;Ljava/lang/Double;Ljava/lang/Boolean;)V
    .locals 3

    .line 1
    and-int/lit16 v0, p1, 0x401

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x401

    .line 5
    .line 6
    if-ne v2, v0, :cond_9

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-object p2, p0, Le31/m3;->a:Le31/f3;

    .line 12
    .line 13
    and-int/lit8 p2, p1, 0x2

    .line 14
    .line 15
    if-nez p2, :cond_0

    .line 16
    .line 17
    iput-object v1, p0, Le31/m3;->b:Le31/v2;

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    iput-object p3, p0, Le31/m3;->b:Le31/v2;

    .line 21
    .line 22
    :goto_0
    and-int/lit8 p2, p1, 0x4

    .line 23
    .line 24
    if-nez p2, :cond_1

    .line 25
    .line 26
    iput-object v1, p0, Le31/m3;->c:Ljava/util/List;

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_1
    iput-object p4, p0, Le31/m3;->c:Ljava/util/List;

    .line 30
    .line 31
    :goto_1
    and-int/lit8 p2, p1, 0x8

    .line 32
    .line 33
    if-nez p2, :cond_2

    .line 34
    .line 35
    iput-object v1, p0, Le31/m3;->d:Ljava/util/List;

    .line 36
    .line 37
    goto :goto_2

    .line 38
    :cond_2
    iput-object p5, p0, Le31/m3;->d:Ljava/util/List;

    .line 39
    .line 40
    :goto_2
    and-int/lit8 p2, p1, 0x10

    .line 41
    .line 42
    if-nez p2, :cond_3

    .line 43
    .line 44
    iput-object v1, p0, Le31/m3;->e:Le31/z2;

    .line 45
    .line 46
    goto :goto_3

    .line 47
    :cond_3
    iput-object p6, p0, Le31/m3;->e:Le31/z2;

    .line 48
    .line 49
    :goto_3
    and-int/lit8 p2, p1, 0x20

    .line 50
    .line 51
    if-nez p2, :cond_4

    .line 52
    .line 53
    iput-object v1, p0, Le31/m3;->f:Ljava/lang/String;

    .line 54
    .line 55
    goto :goto_4

    .line 56
    :cond_4
    iput-object p7, p0, Le31/m3;->f:Ljava/lang/String;

    .line 57
    .line 58
    :goto_4
    and-int/lit8 p2, p1, 0x40

    .line 59
    .line 60
    if-nez p2, :cond_5

    .line 61
    .line 62
    iput-object v1, p0, Le31/m3;->g:Ljava/util/List;

    .line 63
    .line 64
    goto :goto_5

    .line 65
    :cond_5
    iput-object p8, p0, Le31/m3;->g:Ljava/util/List;

    .line 66
    .line 67
    :goto_5
    and-int/lit16 p2, p1, 0x80

    .line 68
    .line 69
    if-nez p2, :cond_6

    .line 70
    .line 71
    iput-object v1, p0, Le31/m3;->h:Ljava/util/List;

    .line 72
    .line 73
    goto :goto_6

    .line 74
    :cond_6
    iput-object p9, p0, Le31/m3;->h:Ljava/util/List;

    .line 75
    .line 76
    :goto_6
    and-int/lit16 p2, p1, 0x100

    .line 77
    .line 78
    if-nez p2, :cond_7

    .line 79
    .line 80
    iput-object v1, p0, Le31/m3;->i:Ljava/lang/String;

    .line 81
    .line 82
    goto :goto_7

    .line 83
    :cond_7
    iput-object p10, p0, Le31/m3;->i:Ljava/lang/String;

    .line 84
    .line 85
    :goto_7
    and-int/lit16 p1, p1, 0x200

    .line 86
    .line 87
    if-nez p1, :cond_8

    .line 88
    .line 89
    iput-object v1, p0, Le31/m3;->j:Ljava/lang/Double;

    .line 90
    .line 91
    goto :goto_8

    .line 92
    :cond_8
    iput-object p11, p0, Le31/m3;->j:Ljava/lang/Double;

    .line 93
    .line 94
    :goto_8
    iput-object p12, p0, Le31/m3;->k:Ljava/lang/Boolean;

    .line 95
    .line 96
    return-void

    .line 97
    :cond_9
    sget-object p0, Le31/s2;->a:Le31/s2;

    .line 98
    .line 99
    invoke-virtual {p0}, Le31/s2;->getDescriptor()Lsz0/g;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    .line 104
    .line 105
    .line 106
    throw v1
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Le31/m3;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Le31/m3;

    .line 12
    .line 13
    iget-object v1, p0, Le31/m3;->a:Le31/f3;

    .line 14
    .line 15
    iget-object v3, p1, Le31/m3;->a:Le31/f3;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object v1, p0, Le31/m3;->b:Le31/v2;

    .line 25
    .line 26
    iget-object v3, p1, Le31/m3;->b:Le31/v2;

    .line 27
    .line 28
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v1

    .line 32
    if-nez v1, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    iget-object v1, p0, Le31/m3;->c:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Le31/m3;->c:Ljava/util/List;

    .line 38
    .line 39
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    if-nez v1, :cond_4

    .line 44
    .line 45
    return v2

    .line 46
    :cond_4
    iget-object v1, p0, Le31/m3;->d:Ljava/util/List;

    .line 47
    .line 48
    iget-object v3, p1, Le31/m3;->d:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v1

    .line 54
    if-nez v1, :cond_5

    .line 55
    .line 56
    return v2

    .line 57
    :cond_5
    iget-object v1, p0, Le31/m3;->e:Le31/z2;

    .line 58
    .line 59
    iget-object v3, p1, Le31/m3;->e:Le31/z2;

    .line 60
    .line 61
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v1

    .line 65
    if-nez v1, :cond_6

    .line 66
    .line 67
    return v2

    .line 68
    :cond_6
    iget-object v1, p0, Le31/m3;->f:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v3, p1, Le31/m3;->f:Ljava/lang/String;

    .line 71
    .line 72
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v1

    .line 76
    if-nez v1, :cond_7

    .line 77
    .line 78
    return v2

    .line 79
    :cond_7
    iget-object v1, p0, Le31/m3;->g:Ljava/util/List;

    .line 80
    .line 81
    iget-object v3, p1, Le31/m3;->g:Ljava/util/List;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    if-nez v1, :cond_8

    .line 88
    .line 89
    return v2

    .line 90
    :cond_8
    iget-object v1, p0, Le31/m3;->h:Ljava/util/List;

    .line 91
    .line 92
    iget-object v3, p1, Le31/m3;->h:Ljava/util/List;

    .line 93
    .line 94
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 95
    .line 96
    .line 97
    move-result v1

    .line 98
    if-nez v1, :cond_9

    .line 99
    .line 100
    return v2

    .line 101
    :cond_9
    iget-object v1, p0, Le31/m3;->i:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v3, p1, Le31/m3;->i:Ljava/lang/String;

    .line 104
    .line 105
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 106
    .line 107
    .line 108
    move-result v1

    .line 109
    if-nez v1, :cond_a

    .line 110
    .line 111
    return v2

    .line 112
    :cond_a
    iget-object v1, p0, Le31/m3;->j:Ljava/lang/Double;

    .line 113
    .line 114
    iget-object v3, p1, Le31/m3;->j:Ljava/lang/Double;

    .line 115
    .line 116
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 117
    .line 118
    .line 119
    move-result v1

    .line 120
    if-nez v1, :cond_b

    .line 121
    .line 122
    return v2

    .line 123
    :cond_b
    iget-object p0, p0, Le31/m3;->k:Ljava/lang/Boolean;

    .line 124
    .line 125
    iget-object p1, p1, Le31/m3;->k:Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-nez p0, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Le31/m3;->a:Le31/f3;

    .line 2
    .line 3
    invoke-virtual {v0}, Le31/f3;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    const/4 v1, 0x0

    .line 10
    iget-object v2, p0, Le31/m3;->b:Le31/v2;

    .line 11
    .line 12
    if-nez v2, :cond_0

    .line 13
    .line 14
    move v2, v1

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    invoke-virtual {v2}, Le31/v2;->hashCode()I

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    :goto_0
    add-int/2addr v0, v2

    .line 21
    mul-int/lit8 v0, v0, 0x1f

    .line 22
    .line 23
    iget-object v2, p0, Le31/m3;->c:Ljava/util/List;

    .line 24
    .line 25
    if-nez v2, :cond_1

    .line 26
    .line 27
    move v2, v1

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    :goto_1
    add-int/2addr v0, v2

    .line 34
    mul-int/lit8 v0, v0, 0x1f

    .line 35
    .line 36
    iget-object v2, p0, Le31/m3;->d:Ljava/util/List;

    .line 37
    .line 38
    if-nez v2, :cond_2

    .line 39
    .line 40
    move v2, v1

    .line 41
    goto :goto_2

    .line 42
    :cond_2
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    :goto_2
    add-int/2addr v0, v2

    .line 47
    mul-int/lit8 v0, v0, 0x1f

    .line 48
    .line 49
    iget-object v2, p0, Le31/m3;->e:Le31/z2;

    .line 50
    .line 51
    if-nez v2, :cond_3

    .line 52
    .line 53
    move v2, v1

    .line 54
    goto :goto_3

    .line 55
    :cond_3
    invoke-virtual {v2}, Le31/z2;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    :goto_3
    add-int/2addr v0, v2

    .line 60
    mul-int/lit8 v0, v0, 0x1f

    .line 61
    .line 62
    iget-object v2, p0, Le31/m3;->f:Ljava/lang/String;

    .line 63
    .line 64
    if-nez v2, :cond_4

    .line 65
    .line 66
    move v2, v1

    .line 67
    goto :goto_4

    .line 68
    :cond_4
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 69
    .line 70
    .line 71
    move-result v2

    .line 72
    :goto_4
    add-int/2addr v0, v2

    .line 73
    mul-int/lit8 v0, v0, 0x1f

    .line 74
    .line 75
    iget-object v2, p0, Le31/m3;->g:Ljava/util/List;

    .line 76
    .line 77
    if-nez v2, :cond_5

    .line 78
    .line 79
    move v2, v1

    .line 80
    goto :goto_5

    .line 81
    :cond_5
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    :goto_5
    add-int/2addr v0, v2

    .line 86
    mul-int/lit8 v0, v0, 0x1f

    .line 87
    .line 88
    iget-object v2, p0, Le31/m3;->h:Ljava/util/List;

    .line 89
    .line 90
    if-nez v2, :cond_6

    .line 91
    .line 92
    move v2, v1

    .line 93
    goto :goto_6

    .line 94
    :cond_6
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 95
    .line 96
    .line 97
    move-result v2

    .line 98
    :goto_6
    add-int/2addr v0, v2

    .line 99
    mul-int/lit8 v0, v0, 0x1f

    .line 100
    .line 101
    iget-object v2, p0, Le31/m3;->i:Ljava/lang/String;

    .line 102
    .line 103
    if-nez v2, :cond_7

    .line 104
    .line 105
    move v2, v1

    .line 106
    goto :goto_7

    .line 107
    :cond_7
    invoke-virtual {v2}, Ljava/lang/String;->hashCode()I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    :goto_7
    add-int/2addr v0, v2

    .line 112
    mul-int/lit8 v0, v0, 0x1f

    .line 113
    .line 114
    iget-object v2, p0, Le31/m3;->j:Ljava/lang/Double;

    .line 115
    .line 116
    if-nez v2, :cond_8

    .line 117
    .line 118
    move v2, v1

    .line 119
    goto :goto_8

    .line 120
    :cond_8
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    :goto_8
    add-int/2addr v0, v2

    .line 125
    mul-int/lit8 v0, v0, 0x1f

    .line 126
    .line 127
    iget-object p0, p0, Le31/m3;->k:Ljava/lang/Boolean;

    .line 128
    .line 129
    if-nez p0, :cond_9

    .line 130
    .line 131
    goto :goto_9

    .line 132
    :cond_9
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 133
    .line 134
    .line 135
    move-result v1

    .line 136
    :goto_9
    add-int/2addr v0, v1

    .line 137
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "ServicePartnerResponse(id="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Le31/m3;->a:Le31/f3;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", address="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Le31/m3;->b:Le31/v2;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", openingHours="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    const-string v1, ", emails="

    .line 29
    .line 30
    const-string v2, ", coordinates="

    .line 31
    .line 32
    iget-object v3, p0, Le31/m3;->c:Ljava/util/List;

    .line 33
    .line 34
    iget-object v4, p0, Le31/m3;->d:Ljava/util/List;

    .line 35
    .line 36
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    iget-object v1, p0, Le31/m3;->e:Le31/z2;

    .line 40
    .line 41
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v1, ", name="

    .line 45
    .line 46
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget-object v1, p0, Le31/m3;->f:Ljava/lang/String;

    .line 50
    .line 51
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    const-string v1, ", phones="

    .line 55
    .line 56
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v1, ", services="

    .line 60
    .line 61
    const-string v2, ", url="

    .line 62
    .line 63
    iget-object v3, p0, Le31/m3;->g:Ljava/util/List;

    .line 64
    .line 65
    iget-object v4, p0, Le31/m3;->h:Ljava/util/List;

    .line 66
    .line 67
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object v1, p0, Le31/m3;->i:Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    const-string v1, ", distance="

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    iget-object v1, p0, Le31/m3;->j:Ljava/lang/Double;

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string v1, ", sboSupport="

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Le31/m3;->k:Ljava/lang/Boolean;

    .line 91
    .line 92
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    const-string p0, ")"

    .line 96
    .line 97
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 101
    .line 102
    .line 103
    move-result-object p0

    .line 104
    return-object p0
.end method

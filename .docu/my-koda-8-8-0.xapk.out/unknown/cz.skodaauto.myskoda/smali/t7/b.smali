.class public final Lt7/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final c:Lt7/b;

.field public static final d:Lt7/a;


# instance fields
.field public final a:I

.field public final b:[Lt7/a;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Lt7/b;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    new-array v2, v1, [Lt7/a;

    .line 5
    .line 6
    invoke-direct {v0, v2}, Lt7/b;-><init>([Lt7/a;)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lt7/b;->c:Lt7/b;

    .line 10
    .line 11
    new-instance v3, Lt7/a;

    .line 12
    .line 13
    new-array v6, v1, [I

    .line 14
    .line 15
    new-array v7, v1, [Lt7/x;

    .line 16
    .line 17
    new-array v8, v1, [J

    .line 18
    .line 19
    new-array v9, v1, [Ljava/lang/String;

    .line 20
    .line 21
    const/4 v4, -0x1

    .line 22
    const/4 v5, -0x1

    .line 23
    invoke-direct/range {v3 .. v9}, Lt7/a;-><init>(II[I[Lt7/x;[J[Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v0, v3, Lt7/a;->e:[I

    .line 27
    .line 28
    array-length v2, v0

    .line 29
    const/4 v5, 0x0

    .line 30
    invoke-static {v5, v2}, Ljava/lang/Math;->max(II)I

    .line 31
    .line 32
    .line 33
    move-result v4

    .line 34
    invoke-static {v0, v4}, Ljava/util/Arrays;->copyOf([II)[I

    .line 35
    .line 36
    .line 37
    move-result-object v7

    .line 38
    invoke-static {v7, v2, v4, v1}, Ljava/util/Arrays;->fill([IIII)V

    .line 39
    .line 40
    .line 41
    iget-object v0, v3, Lt7/a;->f:[J

    .line 42
    .line 43
    array-length v1, v0

    .line 44
    invoke-static {v5, v1}, Ljava/lang/Math;->max(II)I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    invoke-static {v0, v2}, Ljava/util/Arrays;->copyOf([JI)[J

    .line 49
    .line 50
    .line 51
    move-result-object v9

    .line 52
    const-wide v10, -0x7fffffffffffffffL    # -4.9E-324

    .line 53
    .line 54
    .line 55
    .line 56
    .line 57
    invoke-static {v9, v1, v2, v10, v11}, Ljava/util/Arrays;->fill([JIIJ)V

    .line 58
    .line 59
    .line 60
    iget-object v0, v3, Lt7/a;->d:[Lt7/x;

    .line 61
    .line 62
    invoke-static {v0, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    move-object v8, v0

    .line 67
    check-cast v8, [Lt7/x;

    .line 68
    .line 69
    iget-object v0, v3, Lt7/a;->g:[Ljava/lang/String;

    .line 70
    .line 71
    invoke-static {v0, v5}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object v0

    .line 75
    move-object v10, v0

    .line 76
    check-cast v10, [Ljava/lang/String;

    .line 77
    .line 78
    new-instance v4, Lt7/a;

    .line 79
    .line 80
    iget v6, v3, Lt7/a;->b:I

    .line 81
    .line 82
    invoke-direct/range {v4 .. v10}, Lt7/a;-><init>(II[I[Lt7/x;[J[Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    sput-object v4, Lt7/b;->d:Lt7/a;

    .line 86
    .line 87
    const/4 v0, 0x1

    .line 88
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 89
    .line 90
    .line 91
    const/4 v0, 0x2

    .line 92
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 93
    .line 94
    .line 95
    const/4 v0, 0x3

    .line 96
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 97
    .line 98
    .line 99
    const/4 v0, 0x4

    .line 100
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 101
    .line 102
    .line 103
    return-void
.end method

.method public constructor <init>([Lt7/a;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    array-length v0, p1

    .line 5
    iput v0, p0, Lt7/b;->a:I

    .line 6
    .line 7
    iput-object p1, p0, Lt7/b;->b:[Lt7/a;

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final a(I)Lt7/a;
    .locals 0

    .line 1
    if-gez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lt7/b;->d:Lt7/a;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    iget-object p0, p0, Lt7/b;->b:[Lt7/a;

    .line 7
    .line 8
    aget-object p0, p0, p1

    .line 9
    .line 10
    return-object p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto :goto_0

    .line 4
    :cond_0
    if-eqz p1, :cond_2

    .line 5
    .line 6
    const-class v0, Lt7/b;

    .line 7
    .line 8
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eq v0, v1, :cond_1

    .line 13
    .line 14
    goto :goto_1

    .line 15
    :cond_1
    check-cast p1, Lt7/b;

    .line 16
    .line 17
    iget v0, p0, Lt7/b;->a:I

    .line 18
    .line 19
    iget v1, p1, Lt7/b;->a:I

    .line 20
    .line 21
    if-ne v0, v1, :cond_2

    .line 22
    .line 23
    iget-object p0, p0, Lt7/b;->b:[Lt7/a;

    .line 24
    .line 25
    iget-object p1, p1, Lt7/b;->b:[Lt7/a;

    .line 26
    .line 27
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    if-eqz p0, :cond_2

    .line 32
    .line 33
    :goto_0
    const/4 p0, 0x1

    .line 34
    return p0

    .line 35
    :cond_2
    :goto_1
    const/4 p0, 0x0

    .line 36
    return p0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget v0, p0, Lt7/b;->a:I

    .line 2
    .line 3
    mul-int/lit16 v0, v0, 0x3c1

    .line 4
    .line 5
    const-wide/16 v1, 0x0

    .line 6
    .line 7
    long-to-int v1, v1

    .line 8
    add-int/2addr v0, v1

    .line 9
    mul-int/lit8 v0, v0, 0x1f

    .line 10
    .line 11
    const-wide v1, -0x7fffffffffffffffL    # -4.9E-324

    .line 12
    .line 13
    .line 14
    .line 15
    .line 16
    long-to-int v1, v1

    .line 17
    add-int/2addr v0, v1

    .line 18
    mul-int/lit16 v0, v0, 0x3c1

    .line 19
    .line 20
    iget-object p0, p0, Lt7/b;->b:[Lt7/a;

    .line 21
    .line 22
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    add-int/2addr p0, v0

    .line 27
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 11

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "AdPlaybackState(adsId=null, adResumePositionUs=0, adGroups=["

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    move v2, v1

    .line 10
    :goto_0
    iget-object v3, p0, Lt7/b;->b:[Lt7/a;

    .line 11
    .line 12
    array-length v4, v3

    .line 13
    const-string v5, "])"

    .line 14
    .line 15
    if-ge v2, v4, :cond_8

    .line 16
    .line 17
    const-string v4, "adGroup(timeUs=0, ads=["

    .line 18
    .line 19
    invoke-virtual {v0, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    aget-object v4, v3, v2

    .line 23
    .line 24
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 25
    .line 26
    .line 27
    move v4, v1

    .line 28
    :goto_1
    aget-object v6, v3, v2

    .line 29
    .line 30
    iget-object v6, v6, Lt7/a;->e:[I

    .line 31
    .line 32
    array-length v6, v6

    .line 33
    const-string v7, ", "

    .line 34
    .line 35
    const/4 v8, 0x1

    .line 36
    if-ge v4, v6, :cond_6

    .line 37
    .line 38
    const-string v6, "ad(state="

    .line 39
    .line 40
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    aget-object v6, v3, v2

    .line 44
    .line 45
    iget-object v6, v6, Lt7/a;->e:[I

    .line 46
    .line 47
    aget v6, v6, v4

    .line 48
    .line 49
    if-eqz v6, :cond_4

    .line 50
    .line 51
    if-eq v6, v8, :cond_3

    .line 52
    .line 53
    const/4 v9, 0x2

    .line 54
    if-eq v6, v9, :cond_2

    .line 55
    .line 56
    const/4 v9, 0x3

    .line 57
    if-eq v6, v9, :cond_1

    .line 58
    .line 59
    const/4 v9, 0x4

    .line 60
    if-eq v6, v9, :cond_0

    .line 61
    .line 62
    const/16 v6, 0x3f

    .line 63
    .line 64
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 65
    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_0
    const/16 v6, 0x21

    .line 69
    .line 70
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    goto :goto_2

    .line 74
    :cond_1
    const/16 v6, 0x50

    .line 75
    .line 76
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 77
    .line 78
    .line 79
    goto :goto_2

    .line 80
    :cond_2
    const/16 v6, 0x53

    .line 81
    .line 82
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    goto :goto_2

    .line 86
    :cond_3
    const/16 v6, 0x52

    .line 87
    .line 88
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    const/16 v6, 0x5f

    .line 93
    .line 94
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    :goto_2
    const-string v6, ", durationUs="

    .line 98
    .line 99
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 100
    .line 101
    .line 102
    aget-object v6, v3, v2

    .line 103
    .line 104
    iget-object v6, v6, Lt7/a;->f:[J

    .line 105
    .line 106
    aget-wide v9, v6, v4

    .line 107
    .line 108
    invoke-virtual {v0, v9, v10}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 109
    .line 110
    .line 111
    const/16 v6, 0x29

    .line 112
    .line 113
    invoke-virtual {v0, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    aget-object v6, v3, v2

    .line 117
    .line 118
    iget-object v6, v6, Lt7/a;->e:[I

    .line 119
    .line 120
    array-length v6, v6

    .line 121
    sub-int/2addr v6, v8

    .line 122
    if-ge v4, v6, :cond_5

    .line 123
    .line 124
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    :cond_5
    add-int/lit8 v4, v4, 0x1

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :cond_6
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    array-length v3, v3

    .line 134
    sub-int/2addr v3, v8

    .line 135
    if-ge v2, v3, :cond_7

    .line 136
    .line 137
    invoke-virtual {v0, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    :cond_7
    add-int/lit8 v2, v2, 0x1

    .line 141
    .line 142
    goto/16 :goto_0

    .line 143
    .line 144
    :cond_8
    invoke-virtual {v0, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 145
    .line 146
    .line 147
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0
.end method

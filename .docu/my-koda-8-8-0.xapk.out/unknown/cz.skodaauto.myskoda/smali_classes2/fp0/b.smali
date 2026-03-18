.class public final Lfp0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:Lgy0/j;

.field public static final h:Lgy0/j;

.field public static final i:Lgy0/j;

.field public static final j:Lgy0/j;

.field public static final k:Lgy0/j;

.field public static final l:Lgy0/j;


# instance fields
.field public final a:Lfp0/c;

.field public final b:Ljava/lang/Integer;

.field public final c:Ljava/lang/Integer;

.field public final d:Lqr0/d;

.field public final e:Lfp0/f;

.field public final f:Lfp0/f;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lgy0/j;

    .line 2
    .line 3
    const/16 v1, 0x1a

    .line 4
    .line 5
    const/16 v2, 0x64

    .line 6
    .line 7
    const/4 v3, 0x1

    .line 8
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lfp0/b;->g:Lgy0/j;

    .line 12
    .line 13
    new-instance v0, Lgy0/j;

    .line 14
    .line 15
    const/16 v1, 0xd

    .line 16
    .line 17
    const/16 v4, 0x19

    .line 18
    .line 19
    invoke-direct {v0, v1, v4, v3}, Lgy0/h;-><init>(III)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lfp0/b;->h:Lgy0/j;

    .line 23
    .line 24
    new-instance v0, Lgy0/j;

    .line 25
    .line 26
    const/16 v1, 0xc

    .line 27
    .line 28
    invoke-direct {v0, v3, v1, v3}, Lgy0/h;-><init>(III)V

    .line 29
    .line 30
    .line 31
    sput-object v0, Lfp0/b;->i:Lgy0/j;

    .line 32
    .line 33
    new-instance v0, Lgy0/j;

    .line 34
    .line 35
    const/16 v1, 0x15

    .line 36
    .line 37
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 38
    .line 39
    .line 40
    sput-object v0, Lfp0/b;->j:Lgy0/j;

    .line 41
    .line 42
    new-instance v0, Lgy0/j;

    .line 43
    .line 44
    const/16 v1, 0xb

    .line 45
    .line 46
    const/16 v2, 0x14

    .line 47
    .line 48
    invoke-direct {v0, v1, v2, v3}, Lgy0/h;-><init>(III)V

    .line 49
    .line 50
    .line 51
    sput-object v0, Lfp0/b;->k:Lgy0/j;

    .line 52
    .line 53
    new-instance v0, Lgy0/j;

    .line 54
    .line 55
    const/16 v1, 0xa

    .line 56
    .line 57
    invoke-direct {v0, v3, v1, v3}, Lgy0/h;-><init>(III)V

    .line 58
    .line 59
    .line 60
    sput-object v0, Lfp0/b;->l:Lgy0/j;

    .line 61
    .line 62
    return-void
.end method

.method public constructor <init>(Lfp0/c;Ljava/lang/Integer;Ljava/lang/Integer;Lqr0/d;)V
    .locals 1

    .line 1
    const-string v0, "engineType"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lfp0/b;->a:Lfp0/c;

    .line 10
    .line 11
    iput-object p2, p0, Lfp0/b;->b:Ljava/lang/Integer;

    .line 12
    .line 13
    iput-object p3, p0, Lfp0/b;->c:Ljava/lang/Integer;

    .line 14
    .line 15
    iput-object p4, p0, Lfp0/b;->d:Lqr0/d;

    .line 16
    .line 17
    if-eqz p3, :cond_0

    .line 18
    .line 19
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    sget-object p4, Lfp0/b;->g:Lgy0/j;

    .line 24
    .line 25
    invoke-virtual {p4, p1}, Lgy0/j;->i(I)Z

    .line 26
    .line 27
    .line 28
    move-result p1

    .line 29
    if-eqz p1, :cond_0

    .line 30
    .line 31
    sget-object p1, Lfp0/f;->d:Lfp0/f;

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    if-eqz p3, :cond_1

    .line 35
    .line 36
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 37
    .line 38
    .line 39
    move-result p1

    .line 40
    sget-object p4, Lfp0/b;->h:Lgy0/j;

    .line 41
    .line 42
    invoke-virtual {p4, p1}, Lgy0/j;->i(I)Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_1

    .line 47
    .line 48
    sget-object p1, Lfp0/f;->e:Lfp0/f;

    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_1
    if-eqz p3, :cond_2

    .line 52
    .line 53
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    sget-object p4, Lfp0/b;->i:Lgy0/j;

    .line 58
    .line 59
    invoke-virtual {p4, p1}, Lgy0/j;->i(I)Z

    .line 60
    .line 61
    .line 62
    move-result p1

    .line 63
    if-eqz p1, :cond_2

    .line 64
    .line 65
    sget-object p1, Lfp0/f;->f:Lfp0/f;

    .line 66
    .line 67
    goto :goto_0

    .line 68
    :cond_2
    if-nez p3, :cond_3

    .line 69
    .line 70
    sget-object p1, Lfp0/f;->g:Lfp0/f;

    .line 71
    .line 72
    goto :goto_0

    .line 73
    :cond_3
    sget-object p1, Lfp0/f;->h:Lfp0/f;

    .line 74
    .line 75
    :goto_0
    iput-object p1, p0, Lfp0/b;->e:Lfp0/f;

    .line 76
    .line 77
    if-eqz p2, :cond_4

    .line 78
    .line 79
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 80
    .line 81
    .line 82
    move-result p1

    .line 83
    sget-object p3, Lfp0/b;->j:Lgy0/j;

    .line 84
    .line 85
    invoke-virtual {p3, p1}, Lgy0/j;->i(I)Z

    .line 86
    .line 87
    .line 88
    move-result p1

    .line 89
    if-eqz p1, :cond_4

    .line 90
    .line 91
    sget-object p1, Lfp0/f;->d:Lfp0/f;

    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_4
    if-eqz p2, :cond_5

    .line 95
    .line 96
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 97
    .line 98
    .line 99
    move-result p1

    .line 100
    sget-object p3, Lfp0/b;->k:Lgy0/j;

    .line 101
    .line 102
    invoke-virtual {p3, p1}, Lgy0/j;->i(I)Z

    .line 103
    .line 104
    .line 105
    move-result p1

    .line 106
    if-eqz p1, :cond_5

    .line 107
    .line 108
    sget-object p1, Lfp0/f;->e:Lfp0/f;

    .line 109
    .line 110
    goto :goto_1

    .line 111
    :cond_5
    if-eqz p2, :cond_6

    .line 112
    .line 113
    invoke-virtual {p2}, Ljava/lang/Integer;->intValue()I

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    sget-object p3, Lfp0/b;->l:Lgy0/j;

    .line 118
    .line 119
    invoke-virtual {p3, p1}, Lgy0/j;->i(I)Z

    .line 120
    .line 121
    .line 122
    move-result p1

    .line 123
    if-eqz p1, :cond_6

    .line 124
    .line 125
    sget-object p1, Lfp0/f;->f:Lfp0/f;

    .line 126
    .line 127
    goto :goto_1

    .line 128
    :cond_6
    if-nez p2, :cond_7

    .line 129
    .line 130
    sget-object p1, Lfp0/f;->g:Lfp0/f;

    .line 131
    .line 132
    goto :goto_1

    .line 133
    :cond_7
    sget-object p1, Lfp0/f;->h:Lfp0/f;

    .line 134
    .line 135
    :goto_1
    iput-object p1, p0, Lfp0/b;->f:Lfp0/f;

    .line 136
    .line 137
    return-void
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
    instance-of v1, p1, Lfp0/b;

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
    check-cast p1, Lfp0/b;

    .line 12
    .line 13
    iget-object v1, p0, Lfp0/b;->a:Lfp0/c;

    .line 14
    .line 15
    iget-object v3, p1, Lfp0/b;->a:Lfp0/c;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Lfp0/b;->b:Ljava/lang/Integer;

    .line 21
    .line 22
    iget-object v3, p1, Lfp0/b;->b:Ljava/lang/Integer;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lfp0/b;->c:Ljava/lang/Integer;

    .line 32
    .line 33
    iget-object v3, p1, Lfp0/b;->c:Ljava/lang/Integer;

    .line 34
    .line 35
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    move-result v1

    .line 39
    if-nez v1, :cond_4

    .line 40
    .line 41
    return v2

    .line 42
    :cond_4
    iget-object p0, p0, Lfp0/b;->d:Lqr0/d;

    .line 43
    .line 44
    iget-object p1, p1, Lfp0/b;->d:Lqr0/d;

    .line 45
    .line 46
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result p0

    .line 50
    if-nez p0, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    return v0
.end method

.method public final hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Lfp0/b;->a:Lfp0/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lfp0/b;->b:Ljava/lang/Integer;

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
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

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
    iget-object v2, p0, Lfp0/b;->c:Ljava/lang/Integer;

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
    iget-object p0, p0, Lfp0/b;->d:Lqr0/d;

    .line 37
    .line 38
    if-nez p0, :cond_2

    .line 39
    .line 40
    goto :goto_2

    .line 41
    :cond_2
    iget-wide v1, p0, Lqr0/d;->a:D

    .line 42
    .line 43
    invoke-static {v1, v2}, Ljava/lang/Double;->hashCode(D)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    :goto_2
    add-int/2addr v0, v1

    .line 48
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "EngineRange(engineType="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lfp0/b;->a:Lfp0/c;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", currentSoCInPct="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lfp0/b;->b:Ljava/lang/Integer;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", currentFuelLevelPct="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lfp0/b;->c:Ljava/lang/Integer;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", remainingRange="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lfp0/b;->d:Lqr0/d;

    .line 39
    .line 40
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string p0, ")"

    .line 44
    .line 45
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object p0

    .line 52
    return-object p0
.end method

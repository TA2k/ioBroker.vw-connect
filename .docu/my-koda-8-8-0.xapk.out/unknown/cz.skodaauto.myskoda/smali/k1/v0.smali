.class public final Lk1/v0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/q1;


# instance fields
.field public final a:Lk1/q1;

.field public final b:I


# direct methods
.method public constructor <init>(Lk1/q1;I)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lk1/v0;->a:Lk1/q1;

    .line 5
    .line 6
    iput p2, p0, Lk1/v0;->b:I

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lt4/c;Lt4/m;)I
    .locals 2

    .line 1
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 2
    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x4

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 v0, 0x1

    .line 8
    :goto_0
    iget v1, p0, Lk1/v0;->b:I

    .line 9
    .line 10
    and-int/2addr v0, v1

    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Lk1/v0;->a:Lk1/q1;

    .line 14
    .line 15
    invoke-interface {p0, p1, p2}, Lk1/q1;->a(Lt4/c;Lt4/m;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_1
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final b(Lt4/c;)I
    .locals 1

    .line 1
    iget v0, p0, Lk1/v0;->b:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x10

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lk1/v0;->a:Lk1/q1;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Lk1/q1;->b(Lt4/c;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public final c(Lt4/c;)I
    .locals 1

    .line 1
    iget v0, p0, Lk1/v0;->b:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x20

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Lk1/v0;->a:Lk1/q1;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Lk1/q1;->c(Lt4/c;)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0
.end method

.method public final d(Lt4/c;Lt4/m;)I
    .locals 2

    .line 1
    sget-object v0, Lt4/m;->d:Lt4/m;

    .line 2
    .line 3
    if-ne p2, v0, :cond_0

    .line 4
    .line 5
    const/16 v0, 0x8

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const/4 v0, 0x2

    .line 9
    :goto_0
    iget v1, p0, Lk1/v0;->b:I

    .line 10
    .line 11
    and-int/2addr v0, v1

    .line 12
    if-eqz v0, :cond_1

    .line 13
    .line 14
    iget-object p0, p0, Lk1/v0;->a:Lk1/q1;

    .line 15
    .line 16
    invoke-interface {p0, p1, p2}, Lk1/q1;->d(Lt4/c;Lt4/m;)I

    .line 17
    .line 18
    .line 19
    move-result p0

    .line 20
    return p0

    .line 21
    :cond_1
    const/4 p0, 0x0

    .line 22
    return p0
.end method

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
    instance-of v1, p1, Lk1/v0;

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
    check-cast p1, Lk1/v0;

    .line 12
    .line 13
    iget-object v1, p1, Lk1/v0;->a:Lk1/q1;

    .line 14
    .line 15
    iget-object v3, p0, Lk1/v0;->a:Lk1/q1;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget p0, p0, Lk1/v0;->b:I

    .line 24
    .line 25
    iget p1, p1, Lk1/v0;->b:I

    .line 26
    .line 27
    if-ne p0, p1, :cond_2

    .line 28
    .line 29
    return v0

    .line 30
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Lk1/v0;->a:Lk1/q1;

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
    iget p0, p0, Lk1/v0;->b:I

    .line 10
    .line 11
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "("

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lk1/v0;->a:Lk1/q1;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, " only "

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    new-instance v1, Ljava/lang/StringBuilder;

    .line 19
    .line 20
    const-string v2, "WindowInsetsSides("

    .line 21
    .line 22
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    new-instance v2, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    .line 28
    .line 29
    .line 30
    sget v3, Lk1/d;->d:I

    .line 31
    .line 32
    iget p0, p0, Lk1/v0;->b:I

    .line 33
    .line 34
    and-int v4, p0, v3

    .line 35
    .line 36
    if-ne v4, v3, :cond_0

    .line 37
    .line 38
    const-string v3, "Start"

    .line 39
    .line 40
    invoke-static {v3, v2}, Lk1/d;->q(Ljava/lang/String;Ljava/lang/StringBuilder;)V

    .line 41
    .line 42
    .line 43
    :cond_0
    sget v3, Lk1/d;->f:I

    .line 44
    .line 45
    and-int v4, p0, v3

    .line 46
    .line 47
    if-ne v4, v3, :cond_1

    .line 48
    .line 49
    const-string v3, "Left"

    .line 50
    .line 51
    invoke-static {v3, v2}, Lk1/d;->q(Ljava/lang/String;Ljava/lang/StringBuilder;)V

    .line 52
    .line 53
    .line 54
    :cond_1
    and-int/lit8 v3, p0, 0x10

    .line 55
    .line 56
    const/16 v4, 0x10

    .line 57
    .line 58
    if-ne v3, v4, :cond_2

    .line 59
    .line 60
    const-string v3, "Top"

    .line 61
    .line 62
    invoke-static {v3, v2}, Lk1/d;->q(Ljava/lang/String;Ljava/lang/StringBuilder;)V

    .line 63
    .line 64
    .line 65
    :cond_2
    sget v3, Lk1/d;->e:I

    .line 66
    .line 67
    and-int v4, p0, v3

    .line 68
    .line 69
    if-ne v4, v3, :cond_3

    .line 70
    .line 71
    const-string v3, "End"

    .line 72
    .line 73
    invoke-static {v3, v2}, Lk1/d;->q(Ljava/lang/String;Ljava/lang/StringBuilder;)V

    .line 74
    .line 75
    .line 76
    :cond_3
    sget v3, Lk1/d;->g:I

    .line 77
    .line 78
    and-int v4, p0, v3

    .line 79
    .line 80
    if-ne v4, v3, :cond_4

    .line 81
    .line 82
    const-string v3, "Right"

    .line 83
    .line 84
    invoke-static {v3, v2}, Lk1/d;->q(Ljava/lang/String;Ljava/lang/StringBuilder;)V

    .line 85
    .line 86
    .line 87
    :cond_4
    const/16 v3, 0x20

    .line 88
    .line 89
    and-int/2addr p0, v3

    .line 90
    if-ne p0, v3, :cond_5

    .line 91
    .line 92
    const-string p0, "Bottom"

    .line 93
    .line 94
    invoke-static {p0, v2}, Lk1/d;->q(Ljava/lang/String;Ljava/lang/StringBuilder;)V

    .line 95
    .line 96
    .line 97
    :cond_5
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    const-string v2, "toString(...)"

    .line 102
    .line 103
    invoke-static {p0, v2}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 104
    .line 105
    .line 106
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    const/16 p0, 0x29

    .line 110
    .line 111
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 115
    .line 116
    .line 117
    move-result-object v1

    .line 118
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 119
    .line 120
    .line 121
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    return-object p0
.end method

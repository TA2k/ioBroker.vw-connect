.class public final Lh11/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh11/g;


# virtual methods
.method public final a(Lg11/l;)Lvp/y1;
    .locals 6

    .line 1
    iget-object p0, p1, Lg11/l;->e:Lh11/h;

    .line 2
    .line 3
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    const/16 v0, 0x60

    .line 8
    .line 9
    invoke-virtual {p0, v0}, Lh11/h;->h(C)I

    .line 10
    .line 11
    .line 12
    move-result v1

    .line 13
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    :cond_0
    invoke-virtual {p0, v0}, Lh11/h;->c(C)I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    if-lez v3, :cond_4

    .line 22
    .line 23
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    invoke-virtual {p0, v0}, Lh11/h;->h(C)I

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-ne v4, v1, :cond_0

    .line 32
    .line 33
    new-instance p1, Lj11/d;

    .line 34
    .line 35
    invoke-direct {p1}, Lj11/s;-><init>()V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p0, v2, v3}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 39
    .line 40
    .line 41
    move-result-object v0

    .line 42
    invoke-virtual {v0}, Lbn/c;->i()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v0

    .line 46
    const/16 v1, 0xa

    .line 47
    .line 48
    const/16 v2, 0x20

    .line 49
    .line 50
    invoke-virtual {v0, v1, v2}, Ljava/lang/String;->replace(CC)Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    const/4 v3, 0x3

    .line 59
    if-lt v1, v3, :cond_3

    .line 60
    .line 61
    const/4 v1, 0x0

    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 63
    .line 64
    .line 65
    move-result v3

    .line 66
    if-ne v3, v2, :cond_3

    .line 67
    .line 68
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 69
    .line 70
    .line 71
    move-result v3

    .line 72
    const/4 v4, 0x1

    .line 73
    sub-int/2addr v3, v4

    .line 74
    invoke-virtual {v0, v3}, Ljava/lang/String;->charAt(I)C

    .line 75
    .line 76
    .line 77
    move-result v3

    .line 78
    if-ne v3, v2, :cond_3

    .line 79
    .line 80
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 81
    .line 82
    .line 83
    move-result v3

    .line 84
    :goto_0
    if-ge v1, v3, :cond_2

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/String;->charAt(I)C

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    if-eq v5, v2, :cond_1

    .line 91
    .line 92
    goto :goto_1

    .line 93
    :cond_1
    add-int/lit8 v1, v1, 0x1

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_2
    move v1, v3

    .line 97
    :goto_1
    if-eq v1, v3, :cond_3

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 100
    .line 101
    .line 102
    move-result v1

    .line 103
    sub-int/2addr v1, v4

    .line 104
    invoke-virtual {v0, v4, v1}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    :cond_3
    iput-object v0, p1, Lj11/d;->g:Ljava/lang/String;

    .line 109
    .line 110
    invoke-virtual {p0}, Lh11/h;->n()Lb8/i;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    new-instance v0, Lvp/y1;

    .line 115
    .line 116
    const/16 v1, 0x8

    .line 117
    .line 118
    const/4 v2, 0x0

    .line 119
    invoke-direct {v0, p1, p0, v2, v1}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 120
    .line 121
    .line 122
    return-object v0

    .line 123
    :cond_4
    invoke-virtual {p0, p1, v2}, Lh11/h;->e(Lb8/i;Lb8/i;)Lbn/c;

    .line 124
    .line 125
    .line 126
    move-result-object p0

    .line 127
    new-instance p1, Lj11/y;

    .line 128
    .line 129
    invoke-virtual {p0}, Lbn/c;->i()Ljava/lang/String;

    .line 130
    .line 131
    .line 132
    move-result-object p0

    .line 133
    invoke-direct {p1, p0}, Lj11/y;-><init>(Ljava/lang/String;)V

    .line 134
    .line 135
    .line 136
    new-instance p0, Lvp/y1;

    .line 137
    .line 138
    const/16 v0, 0x8

    .line 139
    .line 140
    const/4 v1, 0x0

    .line 141
    invoke-direct {p0, p1, v2, v1, v0}, Lvp/y1;-><init>(Ljava/lang/Object;Ljava/lang/Object;ZI)V

    .line 142
    .line 143
    .line 144
    return-object p0
.end method

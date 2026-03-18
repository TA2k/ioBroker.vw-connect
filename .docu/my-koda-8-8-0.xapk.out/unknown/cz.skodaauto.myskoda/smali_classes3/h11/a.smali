.class public final Lh11/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm11/a;


# instance fields
.field public final a:C


# direct methods
.method public constructor <init>(C)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-char p1, p0, Lh11/a;->a:C

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final a()C
    .locals 0

    .line 1
    iget-char p0, p0, Lh11/a;->a:C

    .line 2
    .line 3
    return p0
.end method

.method public final b()I
    .locals 0

    .line 1
    const/4 p0, 0x1

    .line 2
    return p0
.end method

.method public final c(Lg11/d;Lg11/d;)I
    .locals 8

    .line 1
    iget-object v0, p1, Lg11/d;->a:Ljava/util/ArrayList;

    .line 2
    .line 3
    iget-object v1, p2, Lg11/d;->a:Ljava/util/ArrayList;

    .line 4
    .line 5
    iget-boolean v2, p1, Lg11/d;->e:Z

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    if-nez v2, :cond_0

    .line 9
    .line 10
    iget-boolean v2, p2, Lg11/d;->d:Z

    .line 11
    .line 12
    if-eqz v2, :cond_1

    .line 13
    .line 14
    :cond_0
    iget v2, p2, Lg11/d;->c:I

    .line 15
    .line 16
    rem-int/lit8 v4, v2, 0x3

    .line 17
    .line 18
    if-eqz v4, :cond_1

    .line 19
    .line 20
    iget v4, p1, Lg11/d;->c:I

    .line 21
    .line 22
    add-int/2addr v4, v2

    .line 23
    rem-int/lit8 v4, v4, 0x3

    .line 24
    .line 25
    if-nez v4, :cond_1

    .line 26
    .line 27
    return v3

    .line 28
    :cond_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    const/4 v4, 0x1

    .line 33
    iget-char p0, p0, Lh11/a;->a:C

    .line 34
    .line 35
    const/4 v5, 0x2

    .line 36
    if-lt v2, v5, :cond_2

    .line 37
    .line 38
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    .line 39
    .line 40
    .line 41
    move-result v2

    .line 42
    if-lt v2, v5, :cond_2

    .line 43
    .line 44
    new-instance v2, Lj11/x;

    .line 45
    .line 46
    new-instance v6, Ljava/lang/StringBuilder;

    .line 47
    .line 48
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 49
    .line 50
    .line 51
    invoke-static {p0}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    invoke-virtual {v6, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    invoke-direct {v2}, Lj11/s;-><init>()V

    .line 66
    .line 67
    .line 68
    iput-object p0, v2, Lj11/x;->g:Ljava/lang/String;

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :cond_2
    new-instance v2, Lj11/g;

    .line 72
    .line 73
    invoke-static {p0}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-direct {v2}, Lj11/s;-><init>()V

    .line 78
    .line 79
    .line 80
    iput-object p0, v2, Lj11/g;->g:Ljava/lang/String;

    .line 81
    .line 82
    move v5, v4

    .line 83
    :goto_0
    new-instance p0, Lbn/c;

    .line 84
    .line 85
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p1, v5}, Lg11/d;->b(I)Ljava/util/List;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    check-cast p1, Ljava/util/List;

    .line 93
    .line 94
    invoke-virtual {p0, p1}, Lbn/c;->h(Ljava/util/List;)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v0}, Ljava/util/ArrayList;->size()I

    .line 98
    .line 99
    .line 100
    move-result p1

    .line 101
    sub-int/2addr p1, v4

    .line 102
    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p1

    .line 106
    check-cast p1, Lj11/y;

    .line 107
    .line 108
    invoke-virtual {v1, v3}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    check-cast v0, Lj11/y;

    .line 113
    .line 114
    iget-object v1, p1, Lj11/s;->e:Lj11/s;

    .line 115
    .line 116
    new-instance v3, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;

    .line 117
    .line 118
    invoke-direct {v3, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;-><init>(Lj11/s;Lj11/s;)V

    .line 119
    .line 120
    .line 121
    :goto_1
    invoke-virtual {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->hasNext()Z

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    if-eqz v0, :cond_3

    .line 126
    .line 127
    invoke-virtual {v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/j2;->next()Ljava/lang/Object;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    check-cast v0, Lj11/s;

    .line 132
    .line 133
    invoke-virtual {v2, v0}, Lj11/s;->c(Lj11/s;)V

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0}, Lj11/s;->d()Ljava/util/List;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    invoke-virtual {p0, v0}, Lbn/c;->g(Ljava/util/List;)V

    .line 141
    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_3
    invoke-virtual {p2, v5}, Lg11/d;->a(I)Ljava/util/List;

    .line 145
    .line 146
    .line 147
    move-result-object p2

    .line 148
    check-cast p2, Ljava/util/List;

    .line 149
    .line 150
    invoke-virtual {p0, p2}, Lbn/c;->h(Ljava/util/List;)V

    .line 151
    .line 152
    .line 153
    iget-object p0, p0, Lbn/c;->d:Ljava/util/ArrayList;

    .line 154
    .line 155
    if-eqz p0, :cond_4

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_4
    sget-object p0, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 159
    .line 160
    :goto_2
    invoke-virtual {v2, p0}, Lj11/s;->g(Ljava/util/List;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p1, v2}, Lj11/s;->e(Lj11/s;)V

    .line 164
    .line 165
    .line 166
    return v5
.end method

.method public final d()C
    .locals 0

    .line 1
    iget-char p0, p0, Lh11/a;->a:C

    .line 2
    .line 3
    return p0
.end method

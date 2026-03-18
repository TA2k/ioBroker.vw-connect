.class public final Lcq0/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/util/List;

.field public final d:Lcq0/b;

.field public final e:Lcq0/l;

.field public final f:Lcq0/n;

.field public final g:Ljava/time/OffsetDateTime;

.field public final h:Ljava/time/OffsetDateTime;

.field public final i:Ljava/time/OffsetDateTime;

.field public final j:Ljava/time/OffsetDateTime;

.field public final k:Ljava/time/OffsetDateTime;

.field public final l:Ljava/time/OffsetDateTime;

.field public final m:Ljava/time/OffsetDateTime;

.field public final n:Ljava/util/List;

.field public final o:Ljava/lang/Integer;

.field public final p:Z

.field public final q:Lcq0/a;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Lcq0/b;Lcq0/l;Lcq0/n;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/time/OffsetDateTime;Ljava/util/ArrayList;Ljava/lang/Integer;ZLcq0/a;)V
    .locals 1

    .line 1
    const-string v0, "id"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "serviceName"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "submitDateTime"

    .line 12
    .line 13
    invoke-static {p7, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcq0/j;->a:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p2, p0, Lcq0/j;->b:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p3, p0, Lcq0/j;->c:Ljava/util/List;

    .line 24
    .line 25
    iput-object p4, p0, Lcq0/j;->d:Lcq0/b;

    .line 26
    .line 27
    iput-object p5, p0, Lcq0/j;->e:Lcq0/l;

    .line 28
    .line 29
    iput-object p6, p0, Lcq0/j;->f:Lcq0/n;

    .line 30
    .line 31
    iput-object p7, p0, Lcq0/j;->g:Ljava/time/OffsetDateTime;

    .line 32
    .line 33
    iput-object p8, p0, Lcq0/j;->h:Ljava/time/OffsetDateTime;

    .line 34
    .line 35
    iput-object p9, p0, Lcq0/j;->i:Ljava/time/OffsetDateTime;

    .line 36
    .line 37
    iput-object p10, p0, Lcq0/j;->j:Ljava/time/OffsetDateTime;

    .line 38
    .line 39
    iput-object p11, p0, Lcq0/j;->k:Ljava/time/OffsetDateTime;

    .line 40
    .line 41
    iput-object p12, p0, Lcq0/j;->l:Ljava/time/OffsetDateTime;

    .line 42
    .line 43
    iput-object p13, p0, Lcq0/j;->m:Ljava/time/OffsetDateTime;

    .line 44
    .line 45
    iput-object p14, p0, Lcq0/j;->n:Ljava/util/List;

    .line 46
    .line 47
    move-object/from16 p1, p15

    .line 48
    .line 49
    iput-object p1, p0, Lcq0/j;->o:Ljava/lang/Integer;

    .line 50
    .line 51
    move/from16 p1, p16

    .line 52
    .line 53
    iput-boolean p1, p0, Lcq0/j;->p:Z

    .line 54
    .line 55
    move-object/from16 p1, p17

    .line 56
    .line 57
    iput-object p1, p0, Lcq0/j;->q:Lcq0/a;

    .line 58
    .line 59
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_1

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Lcq0/j;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_0

    .line 10
    .line 11
    :cond_1
    check-cast p1, Lcq0/j;

    .line 12
    .line 13
    iget-object v0, p0, Lcq0/j;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v1, p1, Lcq0/j;->a:Ljava/lang/String;

    .line 16
    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_0

    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Lcq0/j;->b:Ljava/lang/String;

    .line 26
    .line 27
    iget-object v1, p1, Lcq0/j;->b:Ljava/lang/String;

    .line 28
    .line 29
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    if-nez v0, :cond_3

    .line 34
    .line 35
    goto/16 :goto_0

    .line 36
    .line 37
    :cond_3
    iget-object v0, p0, Lcq0/j;->c:Ljava/util/List;

    .line 38
    .line 39
    iget-object v1, p1, Lcq0/j;->c:Ljava/util/List;

    .line 40
    .line 41
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result v0

    .line 45
    if-nez v0, :cond_4

    .line 46
    .line 47
    goto/16 :goto_0

    .line 48
    .line 49
    :cond_4
    iget-object v0, p0, Lcq0/j;->d:Lcq0/b;

    .line 50
    .line 51
    iget-object v1, p1, Lcq0/j;->d:Lcq0/b;

    .line 52
    .line 53
    if-eq v0, v1, :cond_5

    .line 54
    .line 55
    goto/16 :goto_0

    .line 56
    .line 57
    :cond_5
    iget-object v0, p0, Lcq0/j;->e:Lcq0/l;

    .line 58
    .line 59
    iget-object v1, p1, Lcq0/j;->e:Lcq0/l;

    .line 60
    .line 61
    if-eq v0, v1, :cond_6

    .line 62
    .line 63
    goto/16 :goto_0

    .line 64
    .line 65
    :cond_6
    iget-object v0, p0, Lcq0/j;->f:Lcq0/n;

    .line 66
    .line 67
    iget-object v1, p1, Lcq0/j;->f:Lcq0/n;

    .line 68
    .line 69
    invoke-virtual {v0, v1}, Lcq0/n;->equals(Ljava/lang/Object;)Z

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    if-nez v0, :cond_7

    .line 74
    .line 75
    goto/16 :goto_0

    .line 76
    .line 77
    :cond_7
    iget-object v0, p0, Lcq0/j;->g:Ljava/time/OffsetDateTime;

    .line 78
    .line 79
    iget-object v1, p1, Lcq0/j;->g:Ljava/time/OffsetDateTime;

    .line 80
    .line 81
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 82
    .line 83
    .line 84
    move-result v0

    .line 85
    if-nez v0, :cond_8

    .line 86
    .line 87
    goto/16 :goto_0

    .line 88
    .line 89
    :cond_8
    iget-object v0, p0, Lcq0/j;->h:Ljava/time/OffsetDateTime;

    .line 90
    .line 91
    iget-object v1, p1, Lcq0/j;->h:Ljava/time/OffsetDateTime;

    .line 92
    .line 93
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-nez v0, :cond_9

    .line 98
    .line 99
    goto :goto_0

    .line 100
    :cond_9
    iget-object v0, p0, Lcq0/j;->i:Ljava/time/OffsetDateTime;

    .line 101
    .line 102
    iget-object v1, p1, Lcq0/j;->i:Ljava/time/OffsetDateTime;

    .line 103
    .line 104
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 105
    .line 106
    .line 107
    move-result v0

    .line 108
    if-nez v0, :cond_a

    .line 109
    .line 110
    goto :goto_0

    .line 111
    :cond_a
    iget-object v0, p0, Lcq0/j;->j:Ljava/time/OffsetDateTime;

    .line 112
    .line 113
    iget-object v1, p1, Lcq0/j;->j:Ljava/time/OffsetDateTime;

    .line 114
    .line 115
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 116
    .line 117
    .line 118
    move-result v0

    .line 119
    if-nez v0, :cond_b

    .line 120
    .line 121
    goto :goto_0

    .line 122
    :cond_b
    iget-object v0, p0, Lcq0/j;->k:Ljava/time/OffsetDateTime;

    .line 123
    .line 124
    iget-object v1, p1, Lcq0/j;->k:Ljava/time/OffsetDateTime;

    .line 125
    .line 126
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 127
    .line 128
    .line 129
    move-result v0

    .line 130
    if-nez v0, :cond_c

    .line 131
    .line 132
    goto :goto_0

    .line 133
    :cond_c
    iget-object v0, p0, Lcq0/j;->l:Ljava/time/OffsetDateTime;

    .line 134
    .line 135
    iget-object v1, p1, Lcq0/j;->l:Ljava/time/OffsetDateTime;

    .line 136
    .line 137
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    if-nez v0, :cond_d

    .line 142
    .line 143
    goto :goto_0

    .line 144
    :cond_d
    iget-object v0, p0, Lcq0/j;->m:Ljava/time/OffsetDateTime;

    .line 145
    .line 146
    iget-object v1, p1, Lcq0/j;->m:Ljava/time/OffsetDateTime;

    .line 147
    .line 148
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result v0

    .line 152
    if-nez v0, :cond_e

    .line 153
    .line 154
    goto :goto_0

    .line 155
    :cond_e
    iget-object v0, p0, Lcq0/j;->n:Ljava/util/List;

    .line 156
    .line 157
    iget-object v1, p1, Lcq0/j;->n:Ljava/util/List;

    .line 158
    .line 159
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 160
    .line 161
    .line 162
    move-result v0

    .line 163
    if-nez v0, :cond_f

    .line 164
    .line 165
    goto :goto_0

    .line 166
    :cond_f
    iget-object v0, p0, Lcq0/j;->o:Ljava/lang/Integer;

    .line 167
    .line 168
    iget-object v1, p1, Lcq0/j;->o:Ljava/lang/Integer;

    .line 169
    .line 170
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-nez v0, :cond_10

    .line 175
    .line 176
    goto :goto_0

    .line 177
    :cond_10
    iget-boolean v0, p0, Lcq0/j;->p:Z

    .line 178
    .line 179
    iget-boolean v1, p1, Lcq0/j;->p:Z

    .line 180
    .line 181
    if-eq v0, v1, :cond_11

    .line 182
    .line 183
    goto :goto_0

    .line 184
    :cond_11
    iget-object p0, p0, Lcq0/j;->q:Lcq0/a;

    .line 185
    .line 186
    iget-object p1, p1, Lcq0/j;->q:Lcq0/a;

    .line 187
    .line 188
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 189
    .line 190
    .line 191
    move-result p0

    .line 192
    if-nez p0, :cond_12

    .line 193
    .line 194
    :goto_0
    const/4 p0, 0x0

    .line 195
    return p0

    .line 196
    :cond_12
    :goto_1
    const/4 p0, 0x1

    .line 197
    return p0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcq0/j;->a:Ljava/lang/String;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/String;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Lcq0/j;->b:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    const/4 v2, 0x0

    .line 17
    iget-object v3, p0, Lcq0/j;->c:Ljava/util/List;

    .line 18
    .line 19
    if-nez v3, :cond_0

    .line 20
    .line 21
    move v3, v2

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 24
    .line 25
    .line 26
    move-result v3

    .line 27
    :goto_0
    add-int/2addr v0, v3

    .line 28
    mul-int/2addr v0, v1

    .line 29
    iget-object v3, p0, Lcq0/j;->d:Lcq0/b;

    .line 30
    .line 31
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 32
    .line 33
    .line 34
    move-result v3

    .line 35
    add-int/2addr v3, v0

    .line 36
    mul-int/2addr v3, v1

    .line 37
    iget-object v0, p0, Lcq0/j;->e:Lcq0/l;

    .line 38
    .line 39
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 40
    .line 41
    .line 42
    move-result v0

    .line 43
    add-int/2addr v0, v3

    .line 44
    mul-int/2addr v0, v1

    .line 45
    iget-object v3, p0, Lcq0/j;->f:Lcq0/n;

    .line 46
    .line 47
    invoke-virtual {v3}, Lcq0/n;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    add-int/2addr v3, v0

    .line 52
    mul-int/2addr v3, v1

    .line 53
    iget-object v0, p0, Lcq0/j;->g:Ljava/time/OffsetDateTime;

    .line 54
    .line 55
    invoke-static {v0, v3, v1}, Lia/b;->b(Ljava/time/OffsetDateTime;II)I

    .line 56
    .line 57
    .line 58
    move-result v0

    .line 59
    iget-object v3, p0, Lcq0/j;->h:Ljava/time/OffsetDateTime;

    .line 60
    .line 61
    if-nez v3, :cond_1

    .line 62
    .line 63
    move v3, v2

    .line 64
    goto :goto_1

    .line 65
    :cond_1
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 66
    .line 67
    .line 68
    move-result v3

    .line 69
    :goto_1
    add-int/2addr v0, v3

    .line 70
    mul-int/2addr v0, v1

    .line 71
    iget-object v3, p0, Lcq0/j;->i:Ljava/time/OffsetDateTime;

    .line 72
    .line 73
    if-nez v3, :cond_2

    .line 74
    .line 75
    move v3, v2

    .line 76
    goto :goto_2

    .line 77
    :cond_2
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 78
    .line 79
    .line 80
    move-result v3

    .line 81
    :goto_2
    add-int/2addr v0, v3

    .line 82
    mul-int/2addr v0, v1

    .line 83
    iget-object v3, p0, Lcq0/j;->j:Ljava/time/OffsetDateTime;

    .line 84
    .line 85
    if-nez v3, :cond_3

    .line 86
    .line 87
    move v3, v2

    .line 88
    goto :goto_3

    .line 89
    :cond_3
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    :goto_3
    add-int/2addr v0, v3

    .line 94
    mul-int/2addr v0, v1

    .line 95
    iget-object v3, p0, Lcq0/j;->k:Ljava/time/OffsetDateTime;

    .line 96
    .line 97
    if-nez v3, :cond_4

    .line 98
    .line 99
    move v3, v2

    .line 100
    goto :goto_4

    .line 101
    :cond_4
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 102
    .line 103
    .line 104
    move-result v3

    .line 105
    :goto_4
    add-int/2addr v0, v3

    .line 106
    mul-int/2addr v0, v1

    .line 107
    iget-object v3, p0, Lcq0/j;->l:Ljava/time/OffsetDateTime;

    .line 108
    .line 109
    if-nez v3, :cond_5

    .line 110
    .line 111
    move v3, v2

    .line 112
    goto :goto_5

    .line 113
    :cond_5
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 114
    .line 115
    .line 116
    move-result v3

    .line 117
    :goto_5
    add-int/2addr v0, v3

    .line 118
    mul-int/2addr v0, v1

    .line 119
    iget-object v3, p0, Lcq0/j;->m:Ljava/time/OffsetDateTime;

    .line 120
    .line 121
    if-nez v3, :cond_6

    .line 122
    .line 123
    move v3, v2

    .line 124
    goto :goto_6

    .line 125
    :cond_6
    invoke-virtual {v3}, Ljava/time/OffsetDateTime;->hashCode()I

    .line 126
    .line 127
    .line 128
    move-result v3

    .line 129
    :goto_6
    add-int/2addr v0, v3

    .line 130
    mul-int/2addr v0, v1

    .line 131
    iget-object v3, p0, Lcq0/j;->n:Ljava/util/List;

    .line 132
    .line 133
    if-nez v3, :cond_7

    .line 134
    .line 135
    move v3, v2

    .line 136
    goto :goto_7

    .line 137
    :cond_7
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 138
    .line 139
    .line 140
    move-result v3

    .line 141
    :goto_7
    add-int/2addr v0, v3

    .line 142
    mul-int/2addr v0, v1

    .line 143
    iget-object v3, p0, Lcq0/j;->o:Ljava/lang/Integer;

    .line 144
    .line 145
    if-nez v3, :cond_8

    .line 146
    .line 147
    move v3, v2

    .line 148
    goto :goto_8

    .line 149
    :cond_8
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 150
    .line 151
    .line 152
    move-result v3

    .line 153
    :goto_8
    add-int/2addr v0, v3

    .line 154
    mul-int/2addr v0, v1

    .line 155
    iget-boolean v3, p0, Lcq0/j;->p:Z

    .line 156
    .line 157
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 158
    .line 159
    .line 160
    move-result v0

    .line 161
    iget-object p0, p0, Lcq0/j;->q:Lcq0/a;

    .line 162
    .line 163
    if-nez p0, :cond_9

    .line 164
    .line 165
    goto :goto_9

    .line 166
    :cond_9
    invoke-virtual {p0}, Lcq0/a;->hashCode()I

    .line 167
    .line 168
    .line 169
    move-result v2

    .line 170
    :goto_9
    add-int/2addr v0, v2

    .line 171
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", serviceName="

    .line 2
    .line 3
    const-string v1, ", serviceIcons="

    .line 4
    .line 5
    const-string v2, "ServiceBookingItem(id="

    .line 6
    .line 7
    iget-object v3, p0, Lcq0/j;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcq0/j;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lcq0/j;->c:Ljava/util/List;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", type="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lcq0/j;->d:Lcq0/b;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", serviceBookingStatus="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    iget-object v1, p0, Lcq0/j;->e:Lcq0/l;

    .line 36
    .line 37
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    const-string v1, ", servicePartner="

    .line 41
    .line 42
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 43
    .line 44
    .line 45
    iget-object v1, p0, Lcq0/j;->f:Lcq0/n;

    .line 46
    .line 47
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 48
    .line 49
    .line 50
    const-string v1, ", submitDateTime="

    .line 51
    .line 52
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    iget-object v1, p0, Lcq0/j;->g:Ljava/time/OffsetDateTime;

    .line 56
    .line 57
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    const-string v1, ", bookingDateTime="

    .line 61
    .line 62
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 63
    .line 64
    .line 65
    iget-object v1, p0, Lcq0/j;->h:Ljava/time/OffsetDateTime;

    .line 66
    .line 67
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 68
    .line 69
    .line 70
    const-string v1, ", contactedDateTime="

    .line 71
    .line 72
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 73
    .line 74
    .line 75
    iget-object v1, p0, Lcq0/j;->i:Ljava/time/OffsetDateTime;

    .line 76
    .line 77
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 78
    .line 79
    .line 80
    const-string v1, ", updateDateTime="

    .line 81
    .line 82
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    iget-object v1, p0, Lcq0/j;->j:Ljava/time/OffsetDateTime;

    .line 86
    .line 87
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    const-string v1, ", acceptedDateTime="

    .line 91
    .line 92
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    iget-object v1, p0, Lcq0/j;->k:Ljava/time/OffsetDateTime;

    .line 96
    .line 97
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 98
    .line 99
    .line 100
    const-string v1, ", confirmationDateTime="

    .line 101
    .line 102
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    iget-object v1, p0, Lcq0/j;->l:Ljava/time/OffsetDateTime;

    .line 106
    .line 107
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 108
    .line 109
    .line 110
    const-string v1, ", closedDateTime="

    .line 111
    .line 112
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    iget-object v1, p0, Lcq0/j;->m:Ljava/time/OffsetDateTime;

    .line 116
    .line 117
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 118
    .line 119
    .line 120
    const-string v1, ", serviceOperation="

    .line 121
    .line 122
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 123
    .line 124
    .line 125
    iget-object v1, p0, Lcq0/j;->n:Ljava/util/List;

    .line 126
    .line 127
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    const-string v1, ", mileageInKm="

    .line 131
    .line 132
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 133
    .line 134
    .line 135
    iget-object v1, p0, Lcq0/j;->o:Ljava/lang/Integer;

    .line 136
    .line 137
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 138
    .line 139
    .line 140
    const-string v1, ", isActive="

    .line 141
    .line 142
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    iget-boolean v1, p0, Lcq0/j;->p:Z

    .line 146
    .line 147
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 148
    .line 149
    .line 150
    const-string v1, ", bookingAddons="

    .line 151
    .line 152
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 153
    .line 154
    .line 155
    iget-object p0, p0, Lcq0/j;->q:Lcq0/a;

    .line 156
    .line 157
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 158
    .line 159
    .line 160
    const-string p0, ")"

    .line 161
    .line 162
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    return-object p0
.end method

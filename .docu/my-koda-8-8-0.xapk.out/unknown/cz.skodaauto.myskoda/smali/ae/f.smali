.class public final Lae/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lae/e;

.field public static final q:[Llx0/i;


# instance fields
.field public final a:Z

.field public final b:Z

.field public final c:Z

.field public final d:Z

.field public final e:Ljava/lang/String;

.field public final f:Lae/e0;

.field public final g:Lae/s;

.field public final h:Lae/v;

.field public final i:Ljava/lang/String;

.field public final j:Z

.field public final k:Ljava/util/List;

.field public final l:Ljava/util/List;

.field public final m:Lae/y;

.field public final n:Ljava/lang/String;

.field public final o:Lae/h0;

.field public final p:Lae/b0;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lae/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lae/f;->Companion:Lae/e;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, La2/m;

    .line 11
    .line 12
    const/16 v2, 0xd

    .line 13
    .line 14
    invoke-direct {v1, v2}, La2/m;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v3, La2/m;

    .line 22
    .line 23
    const/16 v4, 0xe

    .line 24
    .line 25
    invoke-direct {v3, v4}, La2/m;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    const/16 v3, 0x10

    .line 33
    .line 34
    new-array v3, v3, [Llx0/i;

    .line 35
    .line 36
    const/4 v5, 0x0

    .line 37
    const/4 v6, 0x0

    .line 38
    aput-object v6, v3, v5

    .line 39
    .line 40
    const/4 v5, 0x1

    .line 41
    aput-object v6, v3, v5

    .line 42
    .line 43
    const/4 v5, 0x2

    .line 44
    aput-object v6, v3, v5

    .line 45
    .line 46
    const/4 v5, 0x3

    .line 47
    aput-object v6, v3, v5

    .line 48
    .line 49
    const/4 v5, 0x4

    .line 50
    aput-object v6, v3, v5

    .line 51
    .line 52
    const/4 v5, 0x5

    .line 53
    aput-object v6, v3, v5

    .line 54
    .line 55
    const/4 v5, 0x6

    .line 56
    aput-object v6, v3, v5

    .line 57
    .line 58
    const/4 v5, 0x7

    .line 59
    aput-object v6, v3, v5

    .line 60
    .line 61
    const/16 v5, 0x8

    .line 62
    .line 63
    aput-object v6, v3, v5

    .line 64
    .line 65
    const/16 v5, 0x9

    .line 66
    .line 67
    aput-object v6, v3, v5

    .line 68
    .line 69
    const/16 v5, 0xa

    .line 70
    .line 71
    aput-object v1, v3, v5

    .line 72
    .line 73
    const/16 v1, 0xb

    .line 74
    .line 75
    aput-object v0, v3, v1

    .line 76
    .line 77
    const/16 v0, 0xc

    .line 78
    .line 79
    aput-object v6, v3, v0

    .line 80
    .line 81
    aput-object v6, v3, v2

    .line 82
    .line 83
    aput-object v6, v3, v4

    .line 84
    .line 85
    const/16 v0, 0xf

    .line 86
    .line 87
    aput-object v6, v3, v0

    .line 88
    .line 89
    sput-object v3, Lae/f;->q:[Llx0/i;

    .line 90
    .line 91
    return-void
.end method

.method public synthetic constructor <init>(IZZZZLjava/lang/String;Lae/e0;Lae/s;Lae/v;Ljava/lang/String;ZLjava/util/List;Ljava/util/List;Lae/y;Ljava/lang/String;Lae/h0;Lae/b0;)V
    .locals 3

    .line 1
    and-int/lit16 v0, p1, 0xf7f

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0xf7f

    .line 5
    .line 6
    if-ne v2, v0, :cond_5

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 9
    .line 10
    .line 11
    iput-boolean p2, p0, Lae/f;->a:Z

    .line 12
    .line 13
    iput-boolean p3, p0, Lae/f;->b:Z

    .line 14
    .line 15
    iput-boolean p4, p0, Lae/f;->c:Z

    .line 16
    .line 17
    iput-boolean p5, p0, Lae/f;->d:Z

    .line 18
    .line 19
    iput-object p6, p0, Lae/f;->e:Ljava/lang/String;

    .line 20
    .line 21
    iput-object p7, p0, Lae/f;->f:Lae/e0;

    .line 22
    .line 23
    iput-object p8, p0, Lae/f;->g:Lae/s;

    .line 24
    .line 25
    and-int/lit16 p2, p1, 0x80

    .line 26
    .line 27
    if-nez p2, :cond_0

    .line 28
    .line 29
    iput-object v1, p0, Lae/f;->h:Lae/v;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    iput-object p9, p0, Lae/f;->h:Lae/v;

    .line 33
    .line 34
    :goto_0
    iput-object p10, p0, Lae/f;->i:Ljava/lang/String;

    .line 35
    .line 36
    iput-boolean p11, p0, Lae/f;->j:Z

    .line 37
    .line 38
    iput-object p12, p0, Lae/f;->k:Ljava/util/List;

    .line 39
    .line 40
    move-object/from16 p2, p13

    .line 41
    .line 42
    iput-object p2, p0, Lae/f;->l:Ljava/util/List;

    .line 43
    .line 44
    and-int/lit16 p2, p1, 0x1000

    .line 45
    .line 46
    if-nez p2, :cond_1

    .line 47
    .line 48
    iput-object v1, p0, Lae/f;->m:Lae/y;

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_1
    move-object/from16 p2, p14

    .line 52
    .line 53
    iput-object p2, p0, Lae/f;->m:Lae/y;

    .line 54
    .line 55
    :goto_1
    and-int/lit16 p2, p1, 0x2000

    .line 56
    .line 57
    if-nez p2, :cond_2

    .line 58
    .line 59
    iput-object v1, p0, Lae/f;->n:Ljava/lang/String;

    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_2
    move-object/from16 p2, p15

    .line 63
    .line 64
    iput-object p2, p0, Lae/f;->n:Ljava/lang/String;

    .line 65
    .line 66
    :goto_2
    and-int/lit16 p2, p1, 0x4000

    .line 67
    .line 68
    if-nez p2, :cond_3

    .line 69
    .line 70
    iput-object v1, p0, Lae/f;->o:Lae/h0;

    .line 71
    .line 72
    goto :goto_3

    .line 73
    :cond_3
    move-object/from16 p2, p16

    .line 74
    .line 75
    iput-object p2, p0, Lae/f;->o:Lae/h0;

    .line 76
    .line 77
    :goto_3
    const p2, 0x8000

    .line 78
    .line 79
    .line 80
    and-int/2addr p1, p2

    .line 81
    if-nez p1, :cond_4

    .line 82
    .line 83
    iput-object v1, p0, Lae/f;->p:Lae/b0;

    .line 84
    .line 85
    return-void

    .line 86
    :cond_4
    move-object/from16 p1, p17

    .line 87
    .line 88
    iput-object p1, p0, Lae/f;->p:Lae/b0;

    .line 89
    .line 90
    return-void

    .line 91
    :cond_5
    sget-object p0, Lae/d;->a:Lae/d;

    .line 92
    .line 93
    invoke-virtual {p0}, Lae/d;->getDescriptor()Lsz0/g;

    .line 94
    .line 95
    .line 96
    move-result-object p0

    .line 97
    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    .line 98
    .line 99
    .line 100
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
    instance-of v1, p1, Lae/f;

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
    check-cast p1, Lae/f;

    .line 12
    .line 13
    iget-boolean v1, p0, Lae/f;->a:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Lae/f;->a:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Lae/f;->b:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Lae/f;->b:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Lae/f;->c:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Lae/f;->c:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean v1, p0, Lae/f;->d:Z

    .line 35
    .line 36
    iget-boolean v3, p1, Lae/f;->d:Z

    .line 37
    .line 38
    if-eq v1, v3, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    iget-object v1, p0, Lae/f;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object v3, p1, Lae/f;->e:Ljava/lang/String;

    .line 44
    .line 45
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-nez v1, :cond_6

    .line 50
    .line 51
    return v2

    .line 52
    :cond_6
    iget-object v1, p0, Lae/f;->f:Lae/e0;

    .line 53
    .line 54
    iget-object v3, p1, Lae/f;->f:Lae/e0;

    .line 55
    .line 56
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 57
    .line 58
    .line 59
    move-result v1

    .line 60
    if-nez v1, :cond_7

    .line 61
    .line 62
    return v2

    .line 63
    :cond_7
    iget-object v1, p0, Lae/f;->g:Lae/s;

    .line 64
    .line 65
    iget-object v3, p1, Lae/f;->g:Lae/s;

    .line 66
    .line 67
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-nez v1, :cond_8

    .line 72
    .line 73
    return v2

    .line 74
    :cond_8
    iget-object v1, p0, Lae/f;->h:Lae/v;

    .line 75
    .line 76
    iget-object v3, p1, Lae/f;->h:Lae/v;

    .line 77
    .line 78
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 79
    .line 80
    .line 81
    move-result v1

    .line 82
    if-nez v1, :cond_9

    .line 83
    .line 84
    return v2

    .line 85
    :cond_9
    iget-object v1, p0, Lae/f;->i:Ljava/lang/String;

    .line 86
    .line 87
    iget-object v3, p1, Lae/f;->i:Ljava/lang/String;

    .line 88
    .line 89
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    if-nez v1, :cond_a

    .line 94
    .line 95
    return v2

    .line 96
    :cond_a
    iget-boolean v1, p0, Lae/f;->j:Z

    .line 97
    .line 98
    iget-boolean v3, p1, Lae/f;->j:Z

    .line 99
    .line 100
    if-eq v1, v3, :cond_b

    .line 101
    .line 102
    return v2

    .line 103
    :cond_b
    iget-object v1, p0, Lae/f;->k:Ljava/util/List;

    .line 104
    .line 105
    iget-object v3, p1, Lae/f;->k:Ljava/util/List;

    .line 106
    .line 107
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 108
    .line 109
    .line 110
    move-result v1

    .line 111
    if-nez v1, :cond_c

    .line 112
    .line 113
    return v2

    .line 114
    :cond_c
    iget-object v1, p0, Lae/f;->l:Ljava/util/List;

    .line 115
    .line 116
    iget-object v3, p1, Lae/f;->l:Ljava/util/List;

    .line 117
    .line 118
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 119
    .line 120
    .line 121
    move-result v1

    .line 122
    if-nez v1, :cond_d

    .line 123
    .line 124
    return v2

    .line 125
    :cond_d
    iget-object v1, p0, Lae/f;->m:Lae/y;

    .line 126
    .line 127
    iget-object v3, p1, Lae/f;->m:Lae/y;

    .line 128
    .line 129
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result v1

    .line 133
    if-nez v1, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget-object v1, p0, Lae/f;->n:Ljava/lang/String;

    .line 137
    .line 138
    iget-object v3, p1, Lae/f;->n:Ljava/lang/String;

    .line 139
    .line 140
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 141
    .line 142
    .line 143
    move-result v1

    .line 144
    if-nez v1, :cond_f

    .line 145
    .line 146
    return v2

    .line 147
    :cond_f
    iget-object v1, p0, Lae/f;->o:Lae/h0;

    .line 148
    .line 149
    iget-object v3, p1, Lae/f;->o:Lae/h0;

    .line 150
    .line 151
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v1

    .line 155
    if-nez v1, :cond_10

    .line 156
    .line 157
    return v2

    .line 158
    :cond_10
    iget-object p0, p0, Lae/f;->p:Lae/b0;

    .line 159
    .line 160
    iget-object p1, p1, Lae/f;->p:Lae/b0;

    .line 161
    .line 162
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    move-result p0

    .line 166
    if-nez p0, :cond_11

    .line 167
    .line 168
    return v2

    .line 169
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-boolean v0, p0, Lae/f;->a:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

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
    iget-boolean v2, p0, Lae/f;->b:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Lae/f;->c:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean v2, p0, Lae/f;->d:Z

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Lae/f;->e:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Lae/f;->f:Lae/e0;

    .line 35
    .line 36
    invoke-virtual {v2}, Lae/e0;->hashCode()I

    .line 37
    .line 38
    .line 39
    move-result v2

    .line 40
    add-int/2addr v2, v0

    .line 41
    mul-int/2addr v2, v1

    .line 42
    iget-object v0, p0, Lae/f;->g:Lae/s;

    .line 43
    .line 44
    invoke-virtual {v0}, Lae/s;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    add-int/2addr v0, v2

    .line 49
    mul-int/2addr v0, v1

    .line 50
    const/4 v2, 0x0

    .line 51
    iget-object v3, p0, Lae/f;->h:Lae/v;

    .line 52
    .line 53
    if-nez v3, :cond_0

    .line 54
    .line 55
    move v3, v2

    .line 56
    goto :goto_0

    .line 57
    :cond_0
    invoke-virtual {v3}, Lae/v;->hashCode()I

    .line 58
    .line 59
    .line 60
    move-result v3

    .line 61
    :goto_0
    add-int/2addr v0, v3

    .line 62
    mul-int/2addr v0, v1

    .line 63
    iget-object v3, p0, Lae/f;->i:Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    iget-boolean v3, p0, Lae/f;->j:Z

    .line 70
    .line 71
    invoke-static {v0, v1, v3}, La7/g0;->e(IIZ)I

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    iget-object v3, p0, Lae/f;->k:Ljava/util/List;

    .line 76
    .line 77
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    iget-object v3, p0, Lae/f;->l:Ljava/util/List;

    .line 82
    .line 83
    invoke-static {v0, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 84
    .line 85
    .line 86
    move-result v0

    .line 87
    iget-object v3, p0, Lae/f;->m:Lae/y;

    .line 88
    .line 89
    if-nez v3, :cond_1

    .line 90
    .line 91
    move v3, v2

    .line 92
    goto :goto_1

    .line 93
    :cond_1
    invoke-virtual {v3}, Lae/y;->hashCode()I

    .line 94
    .line 95
    .line 96
    move-result v3

    .line 97
    :goto_1
    add-int/2addr v0, v3

    .line 98
    mul-int/2addr v0, v1

    .line 99
    iget-object v3, p0, Lae/f;->n:Ljava/lang/String;

    .line 100
    .line 101
    if-nez v3, :cond_2

    .line 102
    .line 103
    move v3, v2

    .line 104
    goto :goto_2

    .line 105
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 106
    .line 107
    .line 108
    move-result v3

    .line 109
    :goto_2
    add-int/2addr v0, v3

    .line 110
    mul-int/2addr v0, v1

    .line 111
    iget-object v3, p0, Lae/f;->o:Lae/h0;

    .line 112
    .line 113
    if-nez v3, :cond_3

    .line 114
    .line 115
    move v3, v2

    .line 116
    goto :goto_3

    .line 117
    :cond_3
    invoke-virtual {v3}, Lae/h0;->hashCode()I

    .line 118
    .line 119
    .line 120
    move-result v3

    .line 121
    :goto_3
    add-int/2addr v0, v3

    .line 122
    mul-int/2addr v0, v1

    .line 123
    iget-object p0, p0, Lae/f;->p:Lae/b0;

    .line 124
    .line 125
    if-nez p0, :cond_4

    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_4
    invoke-virtual {p0}, Lae/b0;->hashCode()I

    .line 129
    .line 130
    .line 131
    move-result v2

    .line 132
    :goto_4
    add-int/2addr v0, v2

    .line 133
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", showBadge="

    .line 2
    .line 3
    const-string v1, ", showIonity="

    .line 4
    .line 5
    const-string v2, "CPOIResponse(showSubscriptionButton="

    .line 6
    .line 7
    iget-boolean v3, p0, Lae/f;->a:Z

    .line 8
    .line 9
    iget-boolean v4, p0, Lae/f;->b:Z

    .line 10
    .line 11
    invoke-static {v2, v0, v1, v3, v4}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", showSelectedPartner="

    .line 16
    .line 17
    const-string v2, ", name="

    .line 18
    .line 19
    iget-boolean v3, p0, Lae/f;->c:Z

    .line 20
    .line 21
    iget-boolean v4, p0, Lae/f;->d:Z

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lae/f;->e:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", opening="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lae/f;->f:Lae/e0;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", availability="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lae/f;->g:Lae/s;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", rating="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lae/f;->h:Lae/v;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", maxPowerBadgeLabel="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    const-string v1, ", consentRequired="

    .line 67
    .line 68
    const-string v2, ", chargingConnectorGroups="

    .line 69
    .line 70
    iget-object v3, p0, Lae/f;->i:Ljava/lang/String;

    .line 71
    .line 72
    iget-boolean v4, p0, Lae/f;->j:Z

    .line 73
    .line 74
    invoke-static {v3, v1, v2, v0, v4}, La7/g0;->t(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 75
    .line 76
    .line 77
    const-string v1, ", authenticationOptions="

    .line 78
    .line 79
    const-string v2, ", address="

    .line 80
    .line 81
    iget-object v3, p0, Lae/f;->k:Ljava/util/List;

    .line 82
    .line 83
    iget-object v4, p0, Lae/f;->l:Ljava/util/List;

    .line 84
    .line 85
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lae/f;->m:Lae/y;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", audiChargingHubAccessPin="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lae/f;->n:Ljava/lang/String;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", openingHoursByWeekday="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-object v1, p0, Lae/f;->o:Lae/h0;

    .line 109
    .line 110
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", loyaltyProgram="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-object p0, p0, Lae/f;->p:Lae/b0;

    .line 119
    .line 120
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string p0, ")"

    .line 124
    .line 125
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 129
    .line 130
    .line 131
    move-result-object p0

    .line 132
    return-object p0
.end method

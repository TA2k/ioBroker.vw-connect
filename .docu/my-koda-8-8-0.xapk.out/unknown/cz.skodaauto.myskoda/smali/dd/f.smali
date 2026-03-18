.class public final Ldd/f;
.super Ldd/k;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ldd/f;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Ldd/e;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/lang/String;

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Lgz0/p;

.field public final k:Ljava/lang/String;

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;

.field public final o:Ljava/lang/String;

.field public final p:Ljava/lang/String;

.field public final q:Ljava/lang/String;

.field public final r:Ljava/lang/String;

.field public final s:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ldd/e;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ldd/f;->Companion:Ldd/e;

    .line 7
    .line 8
    new-instance v0, Lcq/x0;

    .line 9
    .line 10
    const/16 v1, 0x19

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lcq/x0;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Ldd/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 16
    .line 17
    return-void
.end method

.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lgz0/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    const v0, 0xcfff

    and-int v1, p1, v0

    const/4 v2, 0x0

    if-ne v0, v1, :cond_2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p2, p0, Ldd/f;->d:Ljava/lang/String;

    iput-object p3, p0, Ldd/f;->e:Ljava/lang/String;

    iput-object p4, p0, Ldd/f;->f:Ljava/lang/String;

    iput-object p5, p0, Ldd/f;->g:Ljava/lang/String;

    iput-object p6, p0, Ldd/f;->h:Ljava/lang/String;

    iput-object p7, p0, Ldd/f;->i:Ljava/lang/String;

    iput-object p8, p0, Ldd/f;->j:Lgz0/p;

    iput-object p9, p0, Ldd/f;->k:Ljava/lang/String;

    iput-object p10, p0, Ldd/f;->l:Ljava/lang/String;

    iput-object p11, p0, Ldd/f;->m:Ljava/lang/String;

    iput-object p12, p0, Ldd/f;->n:Ljava/lang/String;

    move-object/from16 p2, p13

    iput-object p2, p0, Ldd/f;->o:Ljava/lang/String;

    and-int/lit16 p2, p1, 0x1000

    if-nez p2, :cond_0

    iput-object v2, p0, Ldd/f;->p:Ljava/lang/String;

    goto :goto_0

    :cond_0
    move-object/from16 p2, p14

    iput-object p2, p0, Ldd/f;->p:Ljava/lang/String;

    :goto_0
    and-int/lit16 p1, p1, 0x2000

    if-nez p1, :cond_1

    iput-object v2, p0, Ldd/f;->q:Ljava/lang/String;

    :goto_1
    move-object/from16 p1, p16

    goto :goto_2

    :cond_1
    move-object/from16 p1, p15

    iput-object p1, p0, Ldd/f;->q:Ljava/lang/String;

    goto :goto_1

    :goto_2
    iput-object p1, p0, Ldd/f;->r:Ljava/lang/String;

    move-object/from16 p1, p17

    iput-object p1, p0, Ldd/f;->s:Ljava/lang/String;

    return-void

    :cond_2
    sget-object p0, Ldd/d;->a:Ldd/d;

    invoke-virtual {p0}, Ldd/d;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v0, p0}, Luz0/b1;->l(IILsz0/g;)V

    throw v2
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lgz0/p;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 12

    move-object v0, p3

    move-object/from16 v1, p4

    move-object/from16 v2, p5

    move-object/from16 v3, p6

    move-object/from16 v4, p8

    move-object/from16 v5, p9

    move-object/from16 v6, p10

    move-object/from16 v7, p11

    move-object/from16 v8, p12

    move-object/from16 v9, p15

    move-object/from16 v10, p16

    const-string v11, "id"

    invoke-static {p1, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "address"

    invoke-static {p2, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "chargingStationName"

    invoke-static {p3, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "formattedStartDateTime"

    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "formattedEnergy"

    invoke-static {v2, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "formattedTotalPrice"

    invoke-static {v3, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "chargingStartTime"

    invoke-static {v4, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "chargingEndTime"

    invoke-static {v5, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "totalChargingTime"

    invoke-static {v6, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "chargingPowerType"

    invoke-static {v7, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "evseId"

    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "discount"

    invoke-static {v9, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v11, "contractName"

    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Ldd/f;->d:Ljava/lang/String;

    .line 5
    iput-object p2, p0, Ldd/f;->e:Ljava/lang/String;

    .line 6
    iput-object v0, p0, Ldd/f;->f:Ljava/lang/String;

    .line 7
    iput-object v1, p0, Ldd/f;->g:Ljava/lang/String;

    .line 8
    iput-object v2, p0, Ldd/f;->h:Ljava/lang/String;

    .line 9
    iput-object v3, p0, Ldd/f;->i:Ljava/lang/String;

    move-object/from16 p1, p7

    .line 10
    iput-object p1, p0, Ldd/f;->j:Lgz0/p;

    .line 11
    iput-object v4, p0, Ldd/f;->k:Ljava/lang/String;

    .line 12
    iput-object v5, p0, Ldd/f;->l:Ljava/lang/String;

    .line 13
    iput-object v6, p0, Ldd/f;->m:Ljava/lang/String;

    .line 14
    iput-object v7, p0, Ldd/f;->n:Ljava/lang/String;

    .line 15
    iput-object v8, p0, Ldd/f;->o:Ljava/lang/String;

    move-object/from16 p1, p13

    .line 16
    iput-object p1, p0, Ldd/f;->p:Ljava/lang/String;

    move-object/from16 p1, p14

    .line 17
    iput-object p1, p0, Ldd/f;->q:Ljava/lang/String;

    .line 18
    iput-object v9, p0, Ldd/f;->r:Ljava/lang/String;

    .line 19
    iput-object v10, p0, Ldd/f;->s:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
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
    instance-of v1, p1, Ldd/f;

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
    check-cast p1, Ldd/f;

    .line 12
    .line 13
    iget-object v1, p0, Ldd/f;->d:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Ldd/f;->d:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->e:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Ldd/f;->e:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->f:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Ldd/f;->f:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->g:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Ldd/f;->g:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->h:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Ldd/f;->h:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->i:Ljava/lang/String;

    .line 69
    .line 70
    iget-object v3, p1, Ldd/f;->i:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->j:Lgz0/p;

    .line 80
    .line 81
    iget-object v3, p1, Ldd/f;->j:Lgz0/p;

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
    iget-object v1, p0, Ldd/f;->k:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v3, p1, Ldd/f;->k:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->l:Ljava/lang/String;

    .line 102
    .line 103
    iget-object v3, p1, Ldd/f;->l:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->m:Ljava/lang/String;

    .line 113
    .line 114
    iget-object v3, p1, Ldd/f;->m:Ljava/lang/String;

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
    iget-object v1, p0, Ldd/f;->n:Ljava/lang/String;

    .line 124
    .line 125
    iget-object v3, p1, Ldd/f;->n:Ljava/lang/String;

    .line 126
    .line 127
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result v1

    .line 131
    if-nez v1, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    iget-object v1, p0, Ldd/f;->o:Ljava/lang/String;

    .line 135
    .line 136
    iget-object v3, p1, Ldd/f;->o:Ljava/lang/String;

    .line 137
    .line 138
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 139
    .line 140
    .line 141
    move-result v1

    .line 142
    if-nez v1, :cond_d

    .line 143
    .line 144
    return v2

    .line 145
    :cond_d
    iget-object v1, p0, Ldd/f;->p:Ljava/lang/String;

    .line 146
    .line 147
    iget-object v3, p1, Ldd/f;->p:Ljava/lang/String;

    .line 148
    .line 149
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 150
    .line 151
    .line 152
    move-result v1

    .line 153
    if-nez v1, :cond_e

    .line 154
    .line 155
    return v2

    .line 156
    :cond_e
    iget-object v1, p0, Ldd/f;->q:Ljava/lang/String;

    .line 157
    .line 158
    iget-object v3, p1, Ldd/f;->q:Ljava/lang/String;

    .line 159
    .line 160
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 161
    .line 162
    .line 163
    move-result v1

    .line 164
    if-nez v1, :cond_f

    .line 165
    .line 166
    return v2

    .line 167
    :cond_f
    iget-object v1, p0, Ldd/f;->r:Ljava/lang/String;

    .line 168
    .line 169
    iget-object v3, p1, Ldd/f;->r:Ljava/lang/String;

    .line 170
    .line 171
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 172
    .line 173
    .line 174
    move-result v1

    .line 175
    if-nez v1, :cond_10

    .line 176
    .line 177
    return v2

    .line 178
    :cond_10
    iget-object p0, p0, Ldd/f;->s:Ljava/lang/String;

    .line 179
    .line 180
    iget-object p1, p1, Ldd/f;->s:Ljava/lang/String;

    .line 181
    .line 182
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    move-result p0

    .line 186
    if-nez p0, :cond_11

    .line 187
    .line 188
    return v2

    .line 189
    :cond_11
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Ldd/f;->d:Ljava/lang/String;

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
    iget-object v2, p0, Ldd/f;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Ldd/f;->f:Ljava/lang/String;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Ldd/f;->g:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    iget-object v2, p0, Ldd/f;->h:Ljava/lang/String;

    .line 29
    .line 30
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    iget-object v2, p0, Ldd/f;->i:Ljava/lang/String;

    .line 35
    .line 36
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 37
    .line 38
    .line 39
    move-result v0

    .line 40
    iget-object v2, p0, Ldd/f;->j:Lgz0/p;

    .line 41
    .line 42
    iget-object v2, v2, Lgz0/p;->d:Ljava/time/Instant;

    .line 43
    .line 44
    invoke-virtual {v2}, Ljava/time/Instant;->hashCode()I

    .line 45
    .line 46
    .line 47
    move-result v2

    .line 48
    add-int/2addr v2, v0

    .line 49
    mul-int/2addr v2, v1

    .line 50
    iget-object v0, p0, Ldd/f;->k:Ljava/lang/String;

    .line 51
    .line 52
    invoke-static {v2, v1, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 53
    .line 54
    .line 55
    move-result v0

    .line 56
    iget-object v2, p0, Ldd/f;->l:Ljava/lang/String;

    .line 57
    .line 58
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 59
    .line 60
    .line 61
    move-result v0

    .line 62
    iget-object v2, p0, Ldd/f;->m:Ljava/lang/String;

    .line 63
    .line 64
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    iget-object v2, p0, Ldd/f;->n:Ljava/lang/String;

    .line 69
    .line 70
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    iget-object v2, p0, Ldd/f;->o:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    const/4 v2, 0x0

    .line 81
    iget-object v3, p0, Ldd/f;->p:Ljava/lang/String;

    .line 82
    .line 83
    if-nez v3, :cond_0

    .line 84
    .line 85
    move v3, v2

    .line 86
    goto :goto_0

    .line 87
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v3

    .line 91
    :goto_0
    add-int/2addr v0, v3

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-object v3, p0, Ldd/f;->q:Ljava/lang/String;

    .line 94
    .line 95
    if-nez v3, :cond_1

    .line 96
    .line 97
    goto :goto_1

    .line 98
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result v2

    .line 102
    :goto_1
    add-int/2addr v0, v2

    .line 103
    mul-int/2addr v0, v1

    .line 104
    iget-object v2, p0, Ldd/f;->r:Ljava/lang/String;

    .line 105
    .line 106
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 107
    .line 108
    .line 109
    move-result v0

    .line 110
    iget-object p0, p0, Ldd/f;->s:Ljava/lang/String;

    .line 111
    .line 112
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 113
    .line 114
    .line 115
    move-result p0

    .line 116
    add-int/2addr p0, v0

    .line 117
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", address="

    .line 2
    .line 3
    const-string v1, ", chargingStationName="

    .line 4
    .line 5
    const-string v2, "ChargingRecordItem(id="

    .line 6
    .line 7
    iget-object v3, p0, Ldd/f;->d:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Ldd/f;->e:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", formattedStartDateTime="

    .line 16
    .line 17
    const-string v2, ", formattedEnergy="

    .line 18
    .line 19
    iget-object v3, p0, Ldd/f;->f:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Ldd/f;->g:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    const-string v1, ", formattedTotalPrice="

    .line 27
    .line 28
    const-string v2, ", createdAt="

    .line 29
    .line 30
    iget-object v3, p0, Ldd/f;->h:Ljava/lang/String;

    .line 31
    .line 32
    iget-object v4, p0, Ldd/f;->i:Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    iget-object v1, p0, Ldd/f;->j:Lgz0/p;

    .line 38
    .line 39
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    const-string v1, ", chargingStartTime="

    .line 43
    .line 44
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    iget-object v1, p0, Ldd/f;->k:Ljava/lang/String;

    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v1, ", chargingEndTime="

    .line 53
    .line 54
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v1, ", totalChargingTime="

    .line 58
    .line 59
    const-string v2, ", chargingPowerType="

    .line 60
    .line 61
    iget-object v3, p0, Ldd/f;->l:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v4, p0, Ldd/f;->m:Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v1, ", evseId="

    .line 69
    .line 70
    const-string v2, ", latitude="

    .line 71
    .line 72
    iget-object v3, p0, Ldd/f;->n:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v4, p0, Ldd/f;->o:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-string v1, ", longitude="

    .line 80
    .line 81
    const-string v2, ", discount="

    .line 82
    .line 83
    iget-object v3, p0, Ldd/f;->p:Ljava/lang/String;

    .line 84
    .line 85
    iget-object v4, p0, Ldd/f;->q:Ljava/lang/String;

    .line 86
    .line 87
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    const-string v1, ", contractName="

    .line 91
    .line 92
    const-string v2, ")"

    .line 93
    .line 94
    iget-object v3, p0, Ldd/f;->r:Ljava/lang/String;

    .line 95
    .line 96
    iget-object p0, p0, Ldd/f;->s:Ljava/lang/String;

    .line 97
    .line 98
    invoke-static {v0, v3, v1, p0, v2}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const-string p2, "dest"

    .line 2
    .line 3
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p2, p0, Ldd/f;->d:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p2, p0, Ldd/f;->e:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object p2, p0, Ldd/f;->f:Ljava/lang/String;

    .line 17
    .line 18
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object p2, p0, Ldd/f;->g:Ljava/lang/String;

    .line 22
    .line 23
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object p2, p0, Ldd/f;->h:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    iget-object p2, p0, Ldd/f;->i:Ljava/lang/String;

    .line 32
    .line 33
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    const-string p2, "<this>"

    .line 37
    .line 38
    iget-object v0, p0, Ldd/f;->j:Lgz0/p;

    .line 39
    .line 40
    invoke-static {v0, p2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0}, Lgz0/p;->a()J

    .line 44
    .line 45
    .line 46
    move-result-wide v0

    .line 47
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 48
    .line 49
    .line 50
    iget-object p2, p0, Ldd/f;->k:Ljava/lang/String;

    .line 51
    .line 52
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    iget-object p2, p0, Ldd/f;->l:Ljava/lang/String;

    .line 56
    .line 57
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    iget-object p2, p0, Ldd/f;->m:Ljava/lang/String;

    .line 61
    .line 62
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 63
    .line 64
    .line 65
    iget-object p2, p0, Ldd/f;->n:Ljava/lang/String;

    .line 66
    .line 67
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    iget-object p2, p0, Ldd/f;->o:Ljava/lang/String;

    .line 71
    .line 72
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 73
    .line 74
    .line 75
    iget-object p2, p0, Ldd/f;->p:Ljava/lang/String;

    .line 76
    .line 77
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    iget-object p2, p0, Ldd/f;->q:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    iget-object p2, p0, Ldd/f;->r:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Ldd/f;->s:Ljava/lang/String;

    .line 91
    .line 92
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-void
.end method

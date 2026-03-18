.class public final Lc91/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lc91/r;

.field public static final o:[Llx0/i;


# instance fields
.field public final a:Lio/opentelemetry/api/trace/SpanContext;

.field public final b:Lio/opentelemetry/api/logs/Severity;

.field public final c:Ljava/lang/String;

.field public final d:Lio/opentelemetry/sdk/logs/data/Body;

.field public final e:Lio/opentelemetry/api/common/Attributes;

.field public final f:I

.field public final g:Ljava/lang/String;

.field public final h:Ljava/lang/String;

.field public final i:Ljava/lang/String;

.field public final j:Lio/opentelemetry/api/common/Attributes;

.field public final k:J

.field public final l:J

.field public final m:Lio/opentelemetry/api/common/Attributes;

.field public final n:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    new-instance v0, Lc91/r;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc91/s;->Companion:Lc91/r;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lc00/f1;

    .line 11
    .line 12
    const/16 v2, 0x18

    .line 13
    .line 14
    invoke-direct {v1, v2}, Lc00/f1;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Lc00/f1;

    .line 22
    .line 23
    const/16 v3, 0x19

    .line 24
    .line 25
    invoke-direct {v2, v3}, Lc00/f1;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    new-instance v3, Lc00/f1;

    .line 33
    .line 34
    const/16 v4, 0x1a

    .line 35
    .line 36
    invoke-direct {v3, v4}, Lc00/f1;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 40
    .line 41
    .line 42
    move-result-object v3

    .line 43
    new-instance v4, Lc00/f1;

    .line 44
    .line 45
    const/16 v5, 0x1b

    .line 46
    .line 47
    invoke-direct {v4, v5}, Lc00/f1;-><init>(I)V

    .line 48
    .line 49
    .line 50
    invoke-static {v0, v4}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 51
    .line 52
    .line 53
    move-result-object v4

    .line 54
    new-instance v5, Lc00/f1;

    .line 55
    .line 56
    const/16 v6, 0x1c

    .line 57
    .line 58
    invoke-direct {v5, v6}, Lc00/f1;-><init>(I)V

    .line 59
    .line 60
    .line 61
    invoke-static {v0, v5}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    new-instance v6, Lc00/f1;

    .line 66
    .line 67
    const/16 v7, 0x1d

    .line 68
    .line 69
    invoke-direct {v6, v7}, Lc00/f1;-><init>(I)V

    .line 70
    .line 71
    .line 72
    invoke-static {v0, v6}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 73
    .line 74
    .line 75
    move-result-object v0

    .line 76
    const/16 v6, 0xe

    .line 77
    .line 78
    new-array v6, v6, [Llx0/i;

    .line 79
    .line 80
    const/4 v7, 0x0

    .line 81
    aput-object v1, v6, v7

    .line 82
    .line 83
    const/4 v1, 0x1

    .line 84
    aput-object v2, v6, v1

    .line 85
    .line 86
    const/4 v1, 0x2

    .line 87
    const/4 v2, 0x0

    .line 88
    aput-object v2, v6, v1

    .line 89
    .line 90
    const/4 v1, 0x3

    .line 91
    aput-object v3, v6, v1

    .line 92
    .line 93
    const/4 v1, 0x4

    .line 94
    aput-object v4, v6, v1

    .line 95
    .line 96
    const/4 v1, 0x5

    .line 97
    aput-object v2, v6, v1

    .line 98
    .line 99
    const/4 v1, 0x6

    .line 100
    aput-object v2, v6, v1

    .line 101
    .line 102
    const/4 v1, 0x7

    .line 103
    aput-object v2, v6, v1

    .line 104
    .line 105
    const/16 v1, 0x8

    .line 106
    .line 107
    aput-object v2, v6, v1

    .line 108
    .line 109
    const/16 v1, 0x9

    .line 110
    .line 111
    aput-object v5, v6, v1

    .line 112
    .line 113
    const/16 v1, 0xa

    .line 114
    .line 115
    aput-object v2, v6, v1

    .line 116
    .line 117
    const/16 v1, 0xb

    .line 118
    .line 119
    aput-object v2, v6, v1

    .line 120
    .line 121
    const/16 v1, 0xc

    .line 122
    .line 123
    aput-object v0, v6, v1

    .line 124
    .line 125
    const/16 v0, 0xd

    .line 126
    .line 127
    aput-object v2, v6, v0

    .line 128
    .line 129
    sput-object v6, Lc91/s;->o:[Llx0/i;

    .line 130
    .line 131
    return-void
.end method

.method public synthetic constructor <init>(ILio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/sdk/logs/data/Body;Lio/opentelemetry/api/common/Attributes;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JJLio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V
    .locals 2

    and-int/lit16 v0, p1, 0x3fff

    const/16 v1, 0x3fff

    if-ne v1, v0, :cond_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    iput-object p3, p0, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    iput-object p4, p0, Lc91/s;->c:Ljava/lang/String;

    iput-object p5, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    iput-object p6, p0, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    iput p7, p0, Lc91/s;->f:I

    iput-object p8, p0, Lc91/s;->g:Ljava/lang/String;

    iput-object p9, p0, Lc91/s;->h:Ljava/lang/String;

    iput-object p10, p0, Lc91/s;->i:Ljava/lang/String;

    iput-object p11, p0, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    iput-wide p12, p0, Lc91/s;->k:J

    move-wide/from16 p1, p14

    iput-wide p1, p0, Lc91/s;->l:J

    move-object/from16 p1, p16

    iput-object p1, p0, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    move-object/from16 p1, p17

    iput-object p1, p0, Lc91/s;->n:Ljava/lang/String;

    return-void

    :cond_0
    sget-object p0, Lc91/q;->a:Lc91/q;

    invoke-virtual {p0}, Lc91/q;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v1, p0}, Luz0/b1;->l(IILsz0/g;)V

    const/4 p0, 0x0

    throw p0
.end method

.method public constructor <init>(Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/logs/Severity;Ljava/lang/String;Lio/opentelemetry/sdk/logs/data/Body;Lio/opentelemetry/api/common/Attributes;ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;JJLio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 4
    iput-object p2, p0, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 5
    iput-object p3, p0, Lc91/s;->c:Ljava/lang/String;

    .line 6
    iput-object p4, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 7
    iput-object p5, p0, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 8
    iput p6, p0, Lc91/s;->f:I

    .line 9
    iput-object p7, p0, Lc91/s;->g:Ljava/lang/String;

    .line 10
    iput-object p8, p0, Lc91/s;->h:Ljava/lang/String;

    .line 11
    iput-object p9, p0, Lc91/s;->i:Ljava/lang/String;

    .line 12
    iput-object p10, p0, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 13
    iput-wide p11, p0, Lc91/s;->k:J

    .line 14
    iput-wide p13, p0, Lc91/s;->l:J

    .line 15
    iput-object p15, p0, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    move-object/from16 p1, p16

    .line 16
    iput-object p1, p0, Lc91/s;->n:Ljava/lang/String;

    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 7

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lc91/s;

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
    check-cast p1, Lc91/s;

    .line 12
    .line 13
    iget-object v1, p0, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 14
    .line 15
    iget-object v3, p1, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

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
    iget-object v1, p0, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 25
    .line 26
    iget-object v3, p1, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lc91/s;->c:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v3, p1, Lc91/s;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 43
    .line 44
    iget-object v3, p1, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 45
    .line 46
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 47
    .line 48
    .line 49
    move-result v1

    .line 50
    if-nez v1, :cond_5

    .line 51
    .line 52
    return v2

    .line 53
    :cond_5
    iget-object v1, p0, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 54
    .line 55
    iget-object v3, p1, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 56
    .line 57
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 58
    .line 59
    .line 60
    move-result v1

    .line 61
    if-nez v1, :cond_6

    .line 62
    .line 63
    return v2

    .line 64
    :cond_6
    iget v1, p0, Lc91/s;->f:I

    .line 65
    .line 66
    iget v3, p1, Lc91/s;->f:I

    .line 67
    .line 68
    if-eq v1, v3, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-object v1, p0, Lc91/s;->g:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v3, p1, Lc91/s;->g:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-nez v1, :cond_8

    .line 80
    .line 81
    return v2

    .line 82
    :cond_8
    iget-object v1, p0, Lc91/s;->h:Ljava/lang/String;

    .line 83
    .line 84
    iget-object v3, p1, Lc91/s;->h:Ljava/lang/String;

    .line 85
    .line 86
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 87
    .line 88
    .line 89
    move-result v1

    .line 90
    if-nez v1, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-object v1, p0, Lc91/s;->i:Ljava/lang/String;

    .line 94
    .line 95
    iget-object v3, p1, Lc91/s;->i:Ljava/lang/String;

    .line 96
    .line 97
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v1

    .line 101
    if-nez v1, :cond_a

    .line 102
    .line 103
    return v2

    .line 104
    :cond_a
    iget-object v1, p0, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 105
    .line 106
    iget-object v3, p1, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 107
    .line 108
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-nez v1, :cond_b

    .line 113
    .line 114
    return v2

    .line 115
    :cond_b
    iget-wide v3, p0, Lc91/s;->k:J

    .line 116
    .line 117
    iget-wide v5, p1, Lc91/s;->k:J

    .line 118
    .line 119
    cmp-long v1, v3, v5

    .line 120
    .line 121
    if-eqz v1, :cond_c

    .line 122
    .line 123
    return v2

    .line 124
    :cond_c
    iget-wide v3, p0, Lc91/s;->l:J

    .line 125
    .line 126
    iget-wide v5, p1, Lc91/s;->l:J

    .line 127
    .line 128
    cmp-long v1, v3, v5

    .line 129
    .line 130
    if-eqz v1, :cond_d

    .line 131
    .line 132
    return v2

    .line 133
    :cond_d
    iget-object v1, p0, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    .line 134
    .line 135
    iget-object v3, p1, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    .line 136
    .line 137
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-nez v1, :cond_e

    .line 142
    .line 143
    return v2

    .line 144
    :cond_e
    iget-object p0, p0, Lc91/s;->n:Ljava/lang/String;

    .line 145
    .line 146
    iget-object p1, p1, Lc91/s;->n:Ljava/lang/String;

    .line 147
    .line 148
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    move-result p0

    .line 152
    if-nez p0, :cond_f

    .line 153
    .line 154
    return v2

    .line 155
    :cond_f
    return v0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 12
    .line 13
    if-nez v3, :cond_0

    .line 14
    .line 15
    move v3, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    :goto_0
    add-int/2addr v0, v3

    .line 22
    mul-int/2addr v0, v1

    .line 23
    iget-object v3, p0, Lc91/s;->c:Ljava/lang/String;

    .line 24
    .line 25
    if-nez v3, :cond_1

    .line 26
    .line 27
    move v3, v2

    .line 28
    goto :goto_1

    .line 29
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    :goto_1
    add-int/2addr v0, v3

    .line 34
    mul-int/2addr v0, v1

    .line 35
    iget-object v3, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 36
    .line 37
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 38
    .line 39
    .line 40
    move-result v3

    .line 41
    add-int/2addr v3, v0

    .line 42
    mul-int/2addr v3, v1

    .line 43
    iget-object v0, p0, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 44
    .line 45
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 46
    .line 47
    .line 48
    move-result v0

    .line 49
    add-int/2addr v0, v3

    .line 50
    mul-int/2addr v0, v1

    .line 51
    iget v3, p0, Lc91/s;->f:I

    .line 52
    .line 53
    invoke-static {v3, v0, v1}, Lc1/j0;->g(III)I

    .line 54
    .line 55
    .line 56
    move-result v0

    .line 57
    iget-object v3, p0, Lc91/s;->g:Ljava/lang/String;

    .line 58
    .line 59
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    iget-object v3, p0, Lc91/s;->h:Ljava/lang/String;

    .line 64
    .line 65
    if-nez v3, :cond_2

    .line 66
    .line 67
    move v3, v2

    .line 68
    goto :goto_2

    .line 69
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 70
    .line 71
    .line 72
    move-result v3

    .line 73
    :goto_2
    add-int/2addr v0, v3

    .line 74
    mul-int/2addr v0, v1

    .line 75
    iget-object v3, p0, Lc91/s;->i:Ljava/lang/String;

    .line 76
    .line 77
    if-nez v3, :cond_3

    .line 78
    .line 79
    move v3, v2

    .line 80
    goto :goto_3

    .line 81
    :cond_3
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 82
    .line 83
    .line 84
    move-result v3

    .line 85
    :goto_3
    add-int/2addr v0, v3

    .line 86
    mul-int/2addr v0, v1

    .line 87
    iget-object v3, p0, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 88
    .line 89
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    add-int/2addr v3, v0

    .line 94
    mul-int/2addr v3, v1

    .line 95
    iget-wide v4, p0, Lc91/s;->k:J

    .line 96
    .line 97
    invoke-static {v4, v5, v3, v1}, La7/g0;->f(JII)I

    .line 98
    .line 99
    .line 100
    move-result v0

    .line 101
    iget-wide v3, p0, Lc91/s;->l:J

    .line 102
    .line 103
    invoke-static {v3, v4, v0, v1}, La7/g0;->f(JII)I

    .line 104
    .line 105
    .line 106
    move-result v0

    .line 107
    iget-object v3, p0, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    .line 108
    .line 109
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 110
    .line 111
    .line 112
    move-result v3

    .line 113
    add-int/2addr v3, v0

    .line 114
    mul-int/2addr v3, v1

    .line 115
    iget-object p0, p0, Lc91/s;->n:Ljava/lang/String;

    .line 116
    .line 117
    if-nez p0, :cond_4

    .line 118
    .line 119
    goto :goto_4

    .line 120
    :cond_4
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 121
    .line 122
    .line 123
    move-result v2

    .line 124
    :goto_4
    add-int/2addr v3, v2

    .line 125
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "InternalSerializableLogRecordData(spanContext="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc91/s;->a:Lio/opentelemetry/api/trace/SpanContext;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", severity="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lc91/s;->b:Lio/opentelemetry/api/logs/Severity;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", severityText="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lc91/s;->c:Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", body="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lc91/s;->d:Lio/opentelemetry/sdk/logs/data/Body;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", attributes="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lc91/s;->e:Lio/opentelemetry/api/common/Attributes;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", totalAttributeCount="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget v1, p0, Lc91/s;->f:I

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", instrumentationScopeInfoName="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    const-string v1, ", instrumentationScopeInfoVersion="

    .line 69
    .line 70
    const-string v2, ", instrumentationScopeInfoSchemaUrl="

    .line 71
    .line 72
    iget-object v3, p0, Lc91/s;->g:Ljava/lang/String;

    .line 73
    .line 74
    iget-object v4, p0, Lc91/s;->h:Ljava/lang/String;

    .line 75
    .line 76
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    iget-object v1, p0, Lc91/s;->i:Ljava/lang/String;

    .line 80
    .line 81
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 82
    .line 83
    .line 84
    const-string v1, ", instrumentationScopeInfoAttributes="

    .line 85
    .line 86
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 87
    .line 88
    .line 89
    iget-object v1, p0, Lc91/s;->j:Lio/opentelemetry/api/common/Attributes;

    .line 90
    .line 91
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 92
    .line 93
    .line 94
    const-string v1, ", timestampEpochNanos="

    .line 95
    .line 96
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 97
    .line 98
    .line 99
    iget-wide v1, p0, Lc91/s;->k:J

    .line 100
    .line 101
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 102
    .line 103
    .line 104
    const-string v1, ", observedTimestampEpochNanos="

    .line 105
    .line 106
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    iget-wide v1, p0, Lc91/s;->l:J

    .line 110
    .line 111
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 112
    .line 113
    .line 114
    const-string v1, ", resourceAttributes="

    .line 115
    .line 116
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 117
    .line 118
    .line 119
    iget-object v1, p0, Lc91/s;->m:Lio/opentelemetry/api/common/Attributes;

    .line 120
    .line 121
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    const-string v1, ", resourceSchemaUrl="

    .line 125
    .line 126
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 127
    .line 128
    .line 129
    iget-object p0, p0, Lc91/s;->n:Ljava/lang/String;

    .line 130
    .line 131
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 132
    .line 133
    .line 134
    const-string p0, ")"

    .line 135
    .line 136
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 137
    .line 138
    .line 139
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object p0

    .line 143
    return-object p0
.end method

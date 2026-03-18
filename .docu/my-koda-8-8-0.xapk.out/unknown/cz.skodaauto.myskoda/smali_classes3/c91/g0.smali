.class public final Lc91/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lc91/f0;

.field public static final v:[Llx0/i;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lio/opentelemetry/api/trace/SpanKind;

.field public final c:Lio/opentelemetry/api/trace/SpanContext;

.field public final d:Lio/opentelemetry/api/trace/SpanContext;

.field public final e:Ljava/lang/String;

.field public final f:Lio/opentelemetry/api/trace/StatusCode;

.field public final g:J

.field public final h:Lio/opentelemetry/api/common/Attributes;

.field public final i:Ljava/util/List;

.field public final j:Ljava/util/List;

.field public final k:J

.field public final l:Z

.field public final m:I

.field public final n:I

.field public final o:I

.field public final p:Ljava/lang/String;

.field public final q:Ljava/lang/String;

.field public final r:Ljava/lang/String;

.field public final s:Lio/opentelemetry/api/common/Attributes;

.field public final t:Lio/opentelemetry/api/common/Attributes;

.field public final u:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 21

    .line 1
    new-instance v0, Lc91/f0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lc91/g0;->Companion:Lc91/f0;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lc91/u;

    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-direct {v1, v2}, Lc91/u;-><init>(I)V

    .line 14
    .line 15
    .line 16
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 17
    .line 18
    .line 19
    move-result-object v1

    .line 20
    new-instance v3, Lc91/u;

    .line 21
    .line 22
    const/4 v4, 0x4

    .line 23
    invoke-direct {v3, v4}, Lc91/u;-><init>(I)V

    .line 24
    .line 25
    .line 26
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 27
    .line 28
    .line 29
    move-result-object v3

    .line 30
    new-instance v5, Lc91/u;

    .line 31
    .line 32
    const/4 v6, 0x5

    .line 33
    invoke-direct {v5, v6}, Lc91/u;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0, v5}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 37
    .line 38
    .line 39
    move-result-object v5

    .line 40
    new-instance v7, Lc91/u;

    .line 41
    .line 42
    const/4 v8, 0x6

    .line 43
    invoke-direct {v7, v8}, Lc91/u;-><init>(I)V

    .line 44
    .line 45
    .line 46
    invoke-static {v0, v7}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 47
    .line 48
    .line 49
    move-result-object v7

    .line 50
    new-instance v9, Lc91/u;

    .line 51
    .line 52
    const/4 v10, 0x7

    .line 53
    invoke-direct {v9, v10}, Lc91/u;-><init>(I)V

    .line 54
    .line 55
    .line 56
    invoke-static {v0, v9}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 57
    .line 58
    .line 59
    move-result-object v9

    .line 60
    new-instance v11, Lc91/u;

    .line 61
    .line 62
    const/16 v12, 0x8

    .line 63
    .line 64
    invoke-direct {v11, v12}, Lc91/u;-><init>(I)V

    .line 65
    .line 66
    .line 67
    invoke-static {v0, v11}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 68
    .line 69
    .line 70
    move-result-object v11

    .line 71
    new-instance v13, Lc91/u;

    .line 72
    .line 73
    const/16 v14, 0x9

    .line 74
    .line 75
    invoke-direct {v13, v14}, Lc91/u;-><init>(I)V

    .line 76
    .line 77
    .line 78
    invoke-static {v0, v13}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 79
    .line 80
    .line 81
    move-result-object v13

    .line 82
    new-instance v15, Lc91/u;

    .line 83
    .line 84
    move/from16 v16, v2

    .line 85
    .line 86
    const/16 v2, 0xa

    .line 87
    .line 88
    invoke-direct {v15, v2}, Lc91/u;-><init>(I)V

    .line 89
    .line 90
    .line 91
    invoke-static {v0, v15}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 92
    .line 93
    .line 94
    move-result-object v15

    .line 95
    move/from16 v17, v2

    .line 96
    .line 97
    new-instance v2, Lc91/u;

    .line 98
    .line 99
    move/from16 v18, v4

    .line 100
    .line 101
    const/16 v4, 0xb

    .line 102
    .line 103
    invoke-direct {v2, v4}, Lc91/u;-><init>(I)V

    .line 104
    .line 105
    .line 106
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 107
    .line 108
    .line 109
    move-result-object v0

    .line 110
    const/16 v2, 0x15

    .line 111
    .line 112
    new-array v2, v2, [Llx0/i;

    .line 113
    .line 114
    const/16 v19, 0x0

    .line 115
    .line 116
    const/16 v20, 0x0

    .line 117
    .line 118
    aput-object v20, v2, v19

    .line 119
    .line 120
    const/16 v19, 0x1

    .line 121
    .line 122
    aput-object v1, v2, v19

    .line 123
    .line 124
    const/4 v1, 0x2

    .line 125
    aput-object v3, v2, v1

    .line 126
    .line 127
    aput-object v5, v2, v16

    .line 128
    .line 129
    aput-object v20, v2, v18

    .line 130
    .line 131
    aput-object v7, v2, v6

    .line 132
    .line 133
    aput-object v20, v2, v8

    .line 134
    .line 135
    aput-object v9, v2, v10

    .line 136
    .line 137
    aput-object v11, v2, v12

    .line 138
    .line 139
    aput-object v13, v2, v14

    .line 140
    .line 141
    aput-object v20, v2, v17

    .line 142
    .line 143
    aput-object v20, v2, v4

    .line 144
    .line 145
    const/16 v1, 0xc

    .line 146
    .line 147
    aput-object v20, v2, v1

    .line 148
    .line 149
    const/16 v1, 0xd

    .line 150
    .line 151
    aput-object v20, v2, v1

    .line 152
    .line 153
    const/16 v1, 0xe

    .line 154
    .line 155
    aput-object v20, v2, v1

    .line 156
    .line 157
    const/16 v1, 0xf

    .line 158
    .line 159
    aput-object v20, v2, v1

    .line 160
    .line 161
    const/16 v1, 0x10

    .line 162
    .line 163
    aput-object v20, v2, v1

    .line 164
    .line 165
    const/16 v1, 0x11

    .line 166
    .line 167
    aput-object v20, v2, v1

    .line 168
    .line 169
    const/16 v1, 0x12

    .line 170
    .line 171
    aput-object v15, v2, v1

    .line 172
    .line 173
    const/16 v1, 0x13

    .line 174
    .line 175
    aput-object v0, v2, v1

    .line 176
    .line 177
    const/16 v0, 0x14

    .line 178
    .line 179
    aput-object v20, v2, v0

    .line 180
    .line 181
    sput-object v2, Lc91/g0;->v:[Llx0/i;

    .line 182
    .line 183
    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/api/trace/StatusCode;JLio/opentelemetry/api/common/Attributes;Ljava/util/List;Ljava/util/List;JZIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V
    .locals 2

    const v0, 0x1fffff

    and-int v1, p1, v0

    if-ne v0, v1, :cond_0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lc91/g0;->a:Ljava/lang/String;

    iput-object p3, p0, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    iput-object p4, p0, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    iput-object p5, p0, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    iput-object p6, p0, Lc91/g0;->e:Ljava/lang/String;

    iput-object p7, p0, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    iput-wide p8, p0, Lc91/g0;->g:J

    iput-object p10, p0, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    iput-object p11, p0, Lc91/g0;->i:Ljava/util/List;

    iput-object p12, p0, Lc91/g0;->j:Ljava/util/List;

    move-wide p1, p13

    iput-wide p1, p0, Lc91/g0;->k:J

    move/from16 p1, p15

    iput-boolean p1, p0, Lc91/g0;->l:Z

    move/from16 p1, p16

    iput p1, p0, Lc91/g0;->m:I

    move/from16 p1, p17

    iput p1, p0, Lc91/g0;->n:I

    move/from16 p1, p18

    iput p1, p0, Lc91/g0;->o:I

    move-object/from16 p1, p19

    iput-object p1, p0, Lc91/g0;->p:Ljava/lang/String;

    move-object/from16 p1, p20

    iput-object p1, p0, Lc91/g0;->q:Ljava/lang/String;

    move-object/from16 p1, p21

    iput-object p1, p0, Lc91/g0;->r:Ljava/lang/String;

    move-object/from16 p1, p22

    iput-object p1, p0, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    move-object/from16 p1, p23

    iput-object p1, p0, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    move-object/from16 p1, p24

    iput-object p1, p0, Lc91/g0;->u:Ljava/lang/String;

    return-void

    :cond_0
    sget-object p0, Lc91/e0;->a:Lc91/e0;

    invoke-virtual {p0}, Lc91/e0;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v0, p0}, Luz0/b1;->l(IILsz0/g;)V

    const/4 p0, 0x0

    throw p0
.end method

.method public constructor <init>(Ljava/lang/String;Lio/opentelemetry/api/trace/SpanKind;Lio/opentelemetry/api/trace/SpanContext;Lio/opentelemetry/api/trace/SpanContext;Ljava/lang/String;Lio/opentelemetry/api/trace/StatusCode;JLio/opentelemetry/api/common/Attributes;Ljava/util/List;Ljava/util/List;JZIIILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;Lio/opentelemetry/api/common/Attributes;Ljava/lang/String;)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lc91/g0;->a:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 5
    iput-object p3, p0, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    .line 6
    iput-object p4, p0, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    .line 7
    iput-object p5, p0, Lc91/g0;->e:Ljava/lang/String;

    .line 8
    iput-object p6, p0, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 9
    iput-wide p7, p0, Lc91/g0;->g:J

    .line 10
    iput-object p9, p0, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 11
    iput-object p10, p0, Lc91/g0;->i:Ljava/util/List;

    .line 12
    iput-object p11, p0, Lc91/g0;->j:Ljava/util/List;

    .line 13
    iput-wide p12, p0, Lc91/g0;->k:J

    .line 14
    iput-boolean p14, p0, Lc91/g0;->l:Z

    .line 15
    iput p15, p0, Lc91/g0;->m:I

    move/from16 p1, p16

    .line 16
    iput p1, p0, Lc91/g0;->n:I

    move/from16 p1, p17

    .line 17
    iput p1, p0, Lc91/g0;->o:I

    move-object/from16 p1, p18

    .line 18
    iput-object p1, p0, Lc91/g0;->p:Ljava/lang/String;

    move-object/from16 p1, p19

    .line 19
    iput-object p1, p0, Lc91/g0;->q:Ljava/lang/String;

    move-object/from16 p1, p20

    .line 20
    iput-object p1, p0, Lc91/g0;->r:Ljava/lang/String;

    move-object/from16 p1, p21

    .line 21
    iput-object p1, p0, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    move-object/from16 p1, p22

    .line 22
    iput-object p1, p0, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    move-object/from16 p1, p23

    .line 23
    iput-object p1, p0, Lc91/g0;->u:Ljava/lang/String;

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
    instance-of v1, p1, Lc91/g0;

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
    check-cast p1, Lc91/g0;

    .line 12
    .line 13
    iget-object v1, p0, Lc91/g0;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lc91/g0;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 25
    .line 26
    iget-object v3, p1, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 27
    .line 28
    if-eq v1, v3, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-object v1, p0, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    .line 32
    .line 33
    iget-object v3, p1, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

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
    iget-object v1, p0, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    .line 43
    .line 44
    iget-object v3, p1, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

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
    iget-object v1, p0, Lc91/g0;->e:Ljava/lang/String;

    .line 54
    .line 55
    iget-object v3, p1, Lc91/g0;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 65
    .line 66
    iget-object v3, p1, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 67
    .line 68
    if-eq v1, v3, :cond_7

    .line 69
    .line 70
    return v2

    .line 71
    :cond_7
    iget-wide v3, p0, Lc91/g0;->g:J

    .line 72
    .line 73
    iget-wide v5, p1, Lc91/g0;->g:J

    .line 74
    .line 75
    cmp-long v1, v3, v5

    .line 76
    .line 77
    if-eqz v1, :cond_8

    .line 78
    .line 79
    return v2

    .line 80
    :cond_8
    iget-object v1, p0, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 81
    .line 82
    iget-object v3, p1, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 83
    .line 84
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 85
    .line 86
    .line 87
    move-result v1

    .line 88
    if-nez v1, :cond_9

    .line 89
    .line 90
    return v2

    .line 91
    :cond_9
    iget-object v1, p0, Lc91/g0;->i:Ljava/util/List;

    .line 92
    .line 93
    iget-object v3, p1, Lc91/g0;->i:Ljava/util/List;

    .line 94
    .line 95
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 96
    .line 97
    .line 98
    move-result v1

    .line 99
    if-nez v1, :cond_a

    .line 100
    .line 101
    return v2

    .line 102
    :cond_a
    iget-object v1, p0, Lc91/g0;->j:Ljava/util/List;

    .line 103
    .line 104
    iget-object v3, p1, Lc91/g0;->j:Ljava/util/List;

    .line 105
    .line 106
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v1

    .line 110
    if-nez v1, :cond_b

    .line 111
    .line 112
    return v2

    .line 113
    :cond_b
    iget-wide v3, p0, Lc91/g0;->k:J

    .line 114
    .line 115
    iget-wide v5, p1, Lc91/g0;->k:J

    .line 116
    .line 117
    cmp-long v1, v3, v5

    .line 118
    .line 119
    if-eqz v1, :cond_c

    .line 120
    .line 121
    return v2

    .line 122
    :cond_c
    iget-boolean v1, p0, Lc91/g0;->l:Z

    .line 123
    .line 124
    iget-boolean v3, p1, Lc91/g0;->l:Z

    .line 125
    .line 126
    if-eq v1, v3, :cond_d

    .line 127
    .line 128
    return v2

    .line 129
    :cond_d
    iget v1, p0, Lc91/g0;->m:I

    .line 130
    .line 131
    iget v3, p1, Lc91/g0;->m:I

    .line 132
    .line 133
    if-eq v1, v3, :cond_e

    .line 134
    .line 135
    return v2

    .line 136
    :cond_e
    iget v1, p0, Lc91/g0;->n:I

    .line 137
    .line 138
    iget v3, p1, Lc91/g0;->n:I

    .line 139
    .line 140
    if-eq v1, v3, :cond_f

    .line 141
    .line 142
    return v2

    .line 143
    :cond_f
    iget v1, p0, Lc91/g0;->o:I

    .line 144
    .line 145
    iget v3, p1, Lc91/g0;->o:I

    .line 146
    .line 147
    if-eq v1, v3, :cond_10

    .line 148
    .line 149
    return v2

    .line 150
    :cond_10
    iget-object v1, p0, Lc91/g0;->p:Ljava/lang/String;

    .line 151
    .line 152
    iget-object v3, p1, Lc91/g0;->p:Ljava/lang/String;

    .line 153
    .line 154
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 155
    .line 156
    .line 157
    move-result v1

    .line 158
    if-nez v1, :cond_11

    .line 159
    .line 160
    return v2

    .line 161
    :cond_11
    iget-object v1, p0, Lc91/g0;->q:Ljava/lang/String;

    .line 162
    .line 163
    iget-object v3, p1, Lc91/g0;->q:Ljava/lang/String;

    .line 164
    .line 165
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 166
    .line 167
    .line 168
    move-result v1

    .line 169
    if-nez v1, :cond_12

    .line 170
    .line 171
    return v2

    .line 172
    :cond_12
    iget-object v1, p0, Lc91/g0;->r:Ljava/lang/String;

    .line 173
    .line 174
    iget-object v3, p1, Lc91/g0;->r:Ljava/lang/String;

    .line 175
    .line 176
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v1

    .line 180
    if-nez v1, :cond_13

    .line 181
    .line 182
    return v2

    .line 183
    :cond_13
    iget-object v1, p0, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    .line 184
    .line 185
    iget-object v3, p1, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    .line 186
    .line 187
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 188
    .line 189
    .line 190
    move-result v1

    .line 191
    if-nez v1, :cond_14

    .line 192
    .line 193
    return v2

    .line 194
    :cond_14
    iget-object v1, p0, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    .line 195
    .line 196
    iget-object v3, p1, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    .line 197
    .line 198
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result v1

    .line 202
    if-nez v1, :cond_15

    .line 203
    .line 204
    return v2

    .line 205
    :cond_15
    iget-object p0, p0, Lc91/g0;->u:Ljava/lang/String;

    .line 206
    .line 207
    iget-object p1, p1, Lc91/g0;->u:Ljava/lang/String;

    .line 208
    .line 209
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 210
    .line 211
    .line 212
    move-result p0

    .line 213
    if-nez p0, :cond_16

    .line 214
    .line 215
    return v2

    .line 216
    :cond_16
    return v0
.end method

.method public final hashCode()I
    .locals 6

    .line 1
    iget-object v0, p0, Lc91/g0;->a:Ljava/lang/String;

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
    iget-object v2, p0, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-object v0, p0, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    .line 19
    .line 20
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    add-int/2addr v0, v2

    .line 25
    mul-int/2addr v0, v1

    .line 26
    iget-object v2, p0, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    .line 27
    .line 28
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 29
    .line 30
    .line 31
    move-result v2

    .line 32
    add-int/2addr v2, v0

    .line 33
    mul-int/2addr v2, v1

    .line 34
    const/4 v0, 0x0

    .line 35
    iget-object v3, p0, Lc91/g0;->e:Ljava/lang/String;

    .line 36
    .line 37
    if-nez v3, :cond_0

    .line 38
    .line 39
    move v3, v0

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 42
    .line 43
    .line 44
    move-result v3

    .line 45
    :goto_0
    add-int/2addr v2, v3

    .line 46
    mul-int/2addr v2, v1

    .line 47
    iget-object v3, p0, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 48
    .line 49
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    add-int/2addr v3, v2

    .line 54
    mul-int/2addr v3, v1

    .line 55
    iget-wide v4, p0, Lc91/g0;->g:J

    .line 56
    .line 57
    invoke-static {v4, v5, v3, v1}, La7/g0;->f(JII)I

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    iget-object v3, p0, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 62
    .line 63
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 64
    .line 65
    .line 66
    move-result v3

    .line 67
    add-int/2addr v3, v2

    .line 68
    mul-int/2addr v3, v1

    .line 69
    iget-object v2, p0, Lc91/g0;->i:Ljava/util/List;

    .line 70
    .line 71
    invoke-static {v3, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 72
    .line 73
    .line 74
    move-result v2

    .line 75
    iget-object v3, p0, Lc91/g0;->j:Ljava/util/List;

    .line 76
    .line 77
    invoke-static {v2, v1, v3}, Lia/b;->a(IILjava/util/List;)I

    .line 78
    .line 79
    .line 80
    move-result v2

    .line 81
    iget-wide v3, p0, Lc91/g0;->k:J

    .line 82
    .line 83
    invoke-static {v3, v4, v2, v1}, La7/g0;->f(JII)I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    iget-boolean v3, p0, Lc91/g0;->l:Z

    .line 88
    .line 89
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 90
    .line 91
    .line 92
    move-result v2

    .line 93
    iget v3, p0, Lc91/g0;->m:I

    .line 94
    .line 95
    invoke-static {v3, v2, v1}, Lc1/j0;->g(III)I

    .line 96
    .line 97
    .line 98
    move-result v2

    .line 99
    iget v3, p0, Lc91/g0;->n:I

    .line 100
    .line 101
    invoke-static {v3, v2, v1}, Lc1/j0;->g(III)I

    .line 102
    .line 103
    .line 104
    move-result v2

    .line 105
    iget v3, p0, Lc91/g0;->o:I

    .line 106
    .line 107
    invoke-static {v3, v2, v1}, Lc1/j0;->g(III)I

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    iget-object v3, p0, Lc91/g0;->p:Ljava/lang/String;

    .line 112
    .line 113
    invoke-static {v2, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 114
    .line 115
    .line 116
    move-result v2

    .line 117
    iget-object v3, p0, Lc91/g0;->q:Ljava/lang/String;

    .line 118
    .line 119
    if-nez v3, :cond_1

    .line 120
    .line 121
    move v3, v0

    .line 122
    goto :goto_1

    .line 123
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 124
    .line 125
    .line 126
    move-result v3

    .line 127
    :goto_1
    add-int/2addr v2, v3

    .line 128
    mul-int/2addr v2, v1

    .line 129
    iget-object v3, p0, Lc91/g0;->r:Ljava/lang/String;

    .line 130
    .line 131
    if-nez v3, :cond_2

    .line 132
    .line 133
    move v3, v0

    .line 134
    goto :goto_2

    .line 135
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 136
    .line 137
    .line 138
    move-result v3

    .line 139
    :goto_2
    add-int/2addr v2, v3

    .line 140
    mul-int/2addr v2, v1

    .line 141
    iget-object v3, p0, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    .line 142
    .line 143
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 144
    .line 145
    .line 146
    move-result v3

    .line 147
    add-int/2addr v3, v2

    .line 148
    mul-int/2addr v3, v1

    .line 149
    iget-object v2, p0, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    .line 150
    .line 151
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 152
    .line 153
    .line 154
    move-result v2

    .line 155
    add-int/2addr v2, v3

    .line 156
    mul-int/2addr v2, v1

    .line 157
    iget-object p0, p0, Lc91/g0;->u:Ljava/lang/String;

    .line 158
    .line 159
    if-nez p0, :cond_3

    .line 160
    .line 161
    goto :goto_3

    .line 162
    :cond_3
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 163
    .line 164
    .line 165
    move-result v0

    .line 166
    :goto_3
    add-int/2addr v2, v0

    .line 167
    return v2
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "InternalSerializableSpanData(name="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v1, p0, Lc91/g0;->a:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v1, ", kind="

    .line 14
    .line 15
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    iget-object v1, p0, Lc91/g0;->b:Lio/opentelemetry/api/trace/SpanKind;

    .line 19
    .line 20
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v1, ", spanContext="

    .line 24
    .line 25
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    iget-object v1, p0, Lc91/g0;->c:Lio/opentelemetry/api/trace/SpanContext;

    .line 29
    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    const-string v1, ", parentSpanContext="

    .line 34
    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    iget-object v1, p0, Lc91/g0;->d:Lio/opentelemetry/api/trace/SpanContext;

    .line 39
    .line 40
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 41
    .line 42
    .line 43
    const-string v1, ", statusDescription="

    .line 44
    .line 45
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 46
    .line 47
    .line 48
    iget-object v1, p0, Lc91/g0;->e:Ljava/lang/String;

    .line 49
    .line 50
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 51
    .line 52
    .line 53
    const-string v1, ", statusCode="

    .line 54
    .line 55
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 56
    .line 57
    .line 58
    iget-object v1, p0, Lc91/g0;->f:Lio/opentelemetry/api/trace/StatusCode;

    .line 59
    .line 60
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 61
    .line 62
    .line 63
    const-string v1, ", startEpochNanos="

    .line 64
    .line 65
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    iget-wide v1, p0, Lc91/g0;->g:J

    .line 69
    .line 70
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 71
    .line 72
    .line 73
    const-string v1, ", attributes="

    .line 74
    .line 75
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 76
    .line 77
    .line 78
    iget-object v1, p0, Lc91/g0;->h:Lio/opentelemetry/api/common/Attributes;

    .line 79
    .line 80
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    const-string v1, ", events="

    .line 84
    .line 85
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 86
    .line 87
    .line 88
    iget-object v1, p0, Lc91/g0;->i:Ljava/util/List;

    .line 89
    .line 90
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    const-string v1, ", links="

    .line 94
    .line 95
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 96
    .line 97
    .line 98
    iget-object v1, p0, Lc91/g0;->j:Ljava/util/List;

    .line 99
    .line 100
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    const-string v1, ", endEpochNanos="

    .line 104
    .line 105
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 106
    .line 107
    .line 108
    iget-wide v1, p0, Lc91/g0;->k:J

    .line 109
    .line 110
    invoke-virtual {v0, v1, v2}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 111
    .line 112
    .line 113
    const-string v1, ", hasEnded="

    .line 114
    .line 115
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 116
    .line 117
    .line 118
    iget-boolean v1, p0, Lc91/g0;->l:Z

    .line 119
    .line 120
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 121
    .line 122
    .line 123
    const-string v1, ", totalRecordedEvents="

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 126
    .line 127
    .line 128
    iget v1, p0, Lc91/g0;->m:I

    .line 129
    .line 130
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 131
    .line 132
    .line 133
    const-string v1, ", totalRecordedLinks="

    .line 134
    .line 135
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 136
    .line 137
    .line 138
    const-string v1, ", totalAttributeCount="

    .line 139
    .line 140
    const-string v2, ", instrumentationScopeInfoName="

    .line 141
    .line 142
    iget v3, p0, Lc91/g0;->n:I

    .line 143
    .line 144
    iget v4, p0, Lc91/g0;->o:I

    .line 145
    .line 146
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->u(Ljava/lang/StringBuilder;ILjava/lang/String;ILjava/lang/String;)V

    .line 147
    .line 148
    .line 149
    const-string v1, ", instrumentationScopeInfoVersion="

    .line 150
    .line 151
    const-string v2, ", instrumentationScopeInfoSchemaUrl="

    .line 152
    .line 153
    iget-object v3, p0, Lc91/g0;->p:Ljava/lang/String;

    .line 154
    .line 155
    iget-object v4, p0, Lc91/g0;->q:Ljava/lang/String;

    .line 156
    .line 157
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    iget-object v1, p0, Lc91/g0;->r:Ljava/lang/String;

    .line 161
    .line 162
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    const-string v1, ", instrumentationScopeInfoAttributes="

    .line 166
    .line 167
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 168
    .line 169
    .line 170
    iget-object v1, p0, Lc91/g0;->s:Lio/opentelemetry/api/common/Attributes;

    .line 171
    .line 172
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 173
    .line 174
    .line 175
    const-string v1, ", resourceAttributes="

    .line 176
    .line 177
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 178
    .line 179
    .line 180
    iget-object v1, p0, Lc91/g0;->t:Lio/opentelemetry/api/common/Attributes;

    .line 181
    .line 182
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 183
    .line 184
    .line 185
    const-string v1, ", resourceSchemaUrl="

    .line 186
    .line 187
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 188
    .line 189
    .line 190
    iget-object p0, p0, Lc91/g0;->u:Ljava/lang/String;

    .line 191
    .line 192
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 193
    .line 194
    .line 195
    const-string p0, ")"

    .line 196
    .line 197
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 198
    .line 199
    .line 200
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    return-object p0
.end method

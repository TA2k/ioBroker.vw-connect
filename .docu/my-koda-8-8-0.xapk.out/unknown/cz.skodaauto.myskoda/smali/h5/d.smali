.class public Lh5/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public A:F

.field public B:I

.field public C:F

.field public final D:[I

.field public E:F

.field public F:Z

.field public G:Z

.field public H:I

.field public I:I

.field public final J:Lh5/c;

.field public final K:Lh5/c;

.field public final L:Lh5/c;

.field public final M:Lh5/c;

.field public final N:Lh5/c;

.field public final O:Lh5/c;

.field public final P:Lh5/c;

.field public final Q:Lh5/c;

.field public final R:[Lh5/c;

.field public final S:Ljava/util/ArrayList;

.field public final T:[Z

.field public U:Lh5/e;

.field public V:I

.field public W:I

.field public X:F

.field public Y:I

.field public Z:I

.field public a:Z

.field public a0:I

.field public b:Li5/d;

.field public b0:I

.field public c:Li5/d;

.field public c0:I

.field public d:Li5/l;

.field public d0:I

.field public e:Li5/n;

.field public e0:F

.field public final f:[Z

.field public f0:F

.field public g:Z

.field public g0:Ljava/lang/Object;

.field public h:I

.field public h0:I

.field public i:I

.field public i0:Ljava/lang/String;

.field public final j:Le5/l;

.field public j0:I

.field public k:Ljava/lang/String;

.field public k0:I

.field public l:Z

.field public final l0:[F

.field public m:Z

.field public final m0:[Lh5/d;

.field public n:Z

.field public final n0:[Lh5/d;

.field public o:Z

.field public o0:I

.field public p:I

.field public p0:I

.field public q:I

.field public final q0:[I

.field public r:I

.field public s:I

.field public t:I

.field public final u:[I

.field public v:I

.field public w:I

.field public x:F

.field public y:I

.field public z:I


# direct methods
.method public constructor <init>()V
    .locals 12

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lh5/d;->a:Z

    const/4 v1, 0x0

    .line 3
    iput-object v1, p0, Lh5/d;->d:Li5/l;

    .line 4
    iput-object v1, p0, Lh5/d;->e:Li5/n;

    const/4 v2, 0x2

    .line 5
    new-array v3, v2, [Z

    fill-array-data v3, :array_0

    iput-object v3, p0, Lh5/d;->f:[Z

    const/4 v3, 0x1

    .line 6
    iput-boolean v3, p0, Lh5/d;->g:Z

    const/4 v4, -0x1

    .line 7
    iput v4, p0, Lh5/d;->h:I

    .line 8
    iput v4, p0, Lh5/d;->i:I

    .line 9
    new-instance v5, Le5/l;

    invoke-direct {v5, p0}, Le5/l;-><init>(Lh5/d;)V

    iput-object v5, p0, Lh5/d;->j:Le5/l;

    .line 10
    iput-boolean v0, p0, Lh5/d;->l:Z

    .line 11
    iput-boolean v0, p0, Lh5/d;->m:Z

    .line 12
    iput-boolean v0, p0, Lh5/d;->n:Z

    .line 13
    iput-boolean v0, p0, Lh5/d;->o:Z

    .line 14
    iput v4, p0, Lh5/d;->p:I

    .line 15
    iput v4, p0, Lh5/d;->q:I

    .line 16
    iput v0, p0, Lh5/d;->r:I

    .line 17
    iput v0, p0, Lh5/d;->s:I

    .line 18
    iput v0, p0, Lh5/d;->t:I

    .line 19
    new-array v5, v2, [I

    iput-object v5, p0, Lh5/d;->u:[I

    .line 20
    iput v0, p0, Lh5/d;->v:I

    .line 21
    iput v0, p0, Lh5/d;->w:I

    const/high16 v5, 0x3f800000    # 1.0f

    .line 22
    iput v5, p0, Lh5/d;->x:F

    .line 23
    iput v0, p0, Lh5/d;->y:I

    .line 24
    iput v0, p0, Lh5/d;->z:I

    .line 25
    iput v5, p0, Lh5/d;->A:F

    .line 26
    iput v4, p0, Lh5/d;->B:I

    .line 27
    iput v5, p0, Lh5/d;->C:F

    const v5, 0x7fffffff

    .line 28
    filled-new-array {v5, v5}, [I

    move-result-object v5

    iput-object v5, p0, Lh5/d;->D:[I

    const/high16 v5, 0x7fc00000    # Float.NaN

    .line 29
    iput v5, p0, Lh5/d;->E:F

    .line 30
    iput-boolean v0, p0, Lh5/d;->F:Z

    .line 31
    iput-boolean v0, p0, Lh5/d;->G:Z

    .line 32
    iput v0, p0, Lh5/d;->H:I

    .line 33
    iput v0, p0, Lh5/d;->I:I

    .line 34
    new-instance v6, Lh5/c;

    invoke-direct {v6, p0, v2}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v6, p0, Lh5/d;->J:Lh5/c;

    .line 35
    new-instance v8, Lh5/c;

    const/4 v5, 0x3

    invoke-direct {v8, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v8, p0, Lh5/d;->K:Lh5/c;

    .line 36
    new-instance v7, Lh5/c;

    const/4 v5, 0x4

    invoke-direct {v7, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v7, p0, Lh5/d;->L:Lh5/c;

    .line 37
    new-instance v9, Lh5/c;

    const/4 v5, 0x5

    invoke-direct {v9, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v9, p0, Lh5/d;->M:Lh5/c;

    .line 38
    new-instance v10, Lh5/c;

    const/4 v5, 0x6

    invoke-direct {v10, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v10, p0, Lh5/d;->N:Lh5/c;

    .line 39
    new-instance v5, Lh5/c;

    const/16 v11, 0x8

    invoke-direct {v5, p0, v11}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v5, p0, Lh5/d;->O:Lh5/c;

    .line 40
    new-instance v5, Lh5/c;

    const/16 v11, 0x9

    invoke-direct {v5, p0, v11}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v5, p0, Lh5/d;->P:Lh5/c;

    .line 41
    new-instance v11, Lh5/c;

    const/4 v5, 0x7

    invoke-direct {v11, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v11, p0, Lh5/d;->Q:Lh5/c;

    .line 42
    filled-new-array/range {v6 .. v11}, [Lh5/c;

    move-result-object v5

    iput-object v5, p0, Lh5/d;->R:[Lh5/c;

    .line 43
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    iput-object v5, p0, Lh5/d;->S:Ljava/util/ArrayList;

    .line 44
    new-array v5, v2, [Z

    iput-object v5, p0, Lh5/d;->T:[Z

    .line 45
    filled-new-array {v3, v3}, [I

    move-result-object v3

    iput-object v3, p0, Lh5/d;->q0:[I

    .line 46
    iput-object v1, p0, Lh5/d;->U:Lh5/e;

    .line 47
    iput v0, p0, Lh5/d;->V:I

    .line 48
    iput v0, p0, Lh5/d;->W:I

    const/4 v3, 0x0

    .line 49
    iput v3, p0, Lh5/d;->X:F

    .line 50
    iput v4, p0, Lh5/d;->Y:I

    .line 51
    iput v0, p0, Lh5/d;->Z:I

    .line 52
    iput v0, p0, Lh5/d;->a0:I

    .line 53
    iput v0, p0, Lh5/d;->b0:I

    const/high16 v3, 0x3f000000    # 0.5f

    .line 54
    iput v3, p0, Lh5/d;->e0:F

    .line 55
    iput v3, p0, Lh5/d;->f0:F

    .line 56
    iput v0, p0, Lh5/d;->h0:I

    .line 57
    iput-object v1, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 58
    iput v0, p0, Lh5/d;->j0:I

    .line 59
    iput v0, p0, Lh5/d;->k0:I

    .line 60
    new-array v0, v2, [F

    fill-array-data v0, :array_1

    iput-object v0, p0, Lh5/d;->l0:[F

    .line 61
    filled-new-array {v1, v1}, [Lh5/d;

    move-result-object v0

    iput-object v0, p0, Lh5/d;->m0:[Lh5/d;

    .line 62
    filled-new-array {v1, v1}, [Lh5/d;

    move-result-object v0

    iput-object v0, p0, Lh5/d;->n0:[Lh5/d;

    .line 63
    iput v4, p0, Lh5/d;->o0:I

    .line 64
    iput v4, p0, Lh5/d;->p0:I

    .line 65
    invoke-virtual {p0}, Lh5/d;->a()V

    return-void

    nop

    :array_0
    .array-data 1
        0x1t
        0x1t
    .end array-data

    nop

    :array_1
    .array-data 4
        -0x40800000    # -1.0f
        -0x40800000    # -1.0f
    .end array-data
.end method

.method public constructor <init>(II)V
    .locals 12

    .line 66
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 67
    iput-boolean v0, p0, Lh5/d;->a:Z

    const/4 v1, 0x0

    .line 68
    iput-object v1, p0, Lh5/d;->d:Li5/l;

    .line 69
    iput-object v1, p0, Lh5/d;->e:Li5/n;

    const/4 v2, 0x2

    .line 70
    new-array v3, v2, [Z

    fill-array-data v3, :array_0

    iput-object v3, p0, Lh5/d;->f:[Z

    const/4 v3, 0x1

    .line 71
    iput-boolean v3, p0, Lh5/d;->g:Z

    const/4 v4, -0x1

    .line 72
    iput v4, p0, Lh5/d;->h:I

    .line 73
    iput v4, p0, Lh5/d;->i:I

    .line 74
    new-instance v5, Le5/l;

    invoke-direct {v5, p0}, Le5/l;-><init>(Lh5/d;)V

    iput-object v5, p0, Lh5/d;->j:Le5/l;

    .line 75
    iput-boolean v0, p0, Lh5/d;->l:Z

    .line 76
    iput-boolean v0, p0, Lh5/d;->m:Z

    .line 77
    iput-boolean v0, p0, Lh5/d;->n:Z

    .line 78
    iput-boolean v0, p0, Lh5/d;->o:Z

    .line 79
    iput v4, p0, Lh5/d;->p:I

    .line 80
    iput v4, p0, Lh5/d;->q:I

    .line 81
    iput v0, p0, Lh5/d;->r:I

    .line 82
    iput v0, p0, Lh5/d;->s:I

    .line 83
    iput v0, p0, Lh5/d;->t:I

    .line 84
    new-array v5, v2, [I

    iput-object v5, p0, Lh5/d;->u:[I

    .line 85
    iput v0, p0, Lh5/d;->v:I

    .line 86
    iput v0, p0, Lh5/d;->w:I

    const/high16 v5, 0x3f800000    # 1.0f

    .line 87
    iput v5, p0, Lh5/d;->x:F

    .line 88
    iput v0, p0, Lh5/d;->y:I

    .line 89
    iput v0, p0, Lh5/d;->z:I

    .line 90
    iput v5, p0, Lh5/d;->A:F

    .line 91
    iput v4, p0, Lh5/d;->B:I

    .line 92
    iput v5, p0, Lh5/d;->C:F

    const v5, 0x7fffffff

    .line 93
    filled-new-array {v5, v5}, [I

    move-result-object v5

    iput-object v5, p0, Lh5/d;->D:[I

    const/high16 v5, 0x7fc00000    # Float.NaN

    .line 94
    iput v5, p0, Lh5/d;->E:F

    .line 95
    iput-boolean v0, p0, Lh5/d;->F:Z

    .line 96
    iput-boolean v0, p0, Lh5/d;->G:Z

    .line 97
    iput v0, p0, Lh5/d;->H:I

    .line 98
    iput v0, p0, Lh5/d;->I:I

    .line 99
    new-instance v6, Lh5/c;

    invoke-direct {v6, p0, v2}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v6, p0, Lh5/d;->J:Lh5/c;

    .line 100
    new-instance v8, Lh5/c;

    const/4 v5, 0x3

    invoke-direct {v8, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v8, p0, Lh5/d;->K:Lh5/c;

    .line 101
    new-instance v7, Lh5/c;

    const/4 v5, 0x4

    invoke-direct {v7, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v7, p0, Lh5/d;->L:Lh5/c;

    .line 102
    new-instance v9, Lh5/c;

    const/4 v5, 0x5

    invoke-direct {v9, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v9, p0, Lh5/d;->M:Lh5/c;

    .line 103
    new-instance v10, Lh5/c;

    const/4 v5, 0x6

    invoke-direct {v10, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v10, p0, Lh5/d;->N:Lh5/c;

    .line 104
    new-instance v5, Lh5/c;

    const/16 v11, 0x8

    invoke-direct {v5, p0, v11}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v5, p0, Lh5/d;->O:Lh5/c;

    .line 105
    new-instance v5, Lh5/c;

    const/16 v11, 0x9

    invoke-direct {v5, p0, v11}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v5, p0, Lh5/d;->P:Lh5/c;

    .line 106
    new-instance v11, Lh5/c;

    const/4 v5, 0x7

    invoke-direct {v11, p0, v5}, Lh5/c;-><init>(Lh5/d;I)V

    iput-object v11, p0, Lh5/d;->Q:Lh5/c;

    .line 107
    filled-new-array/range {v6 .. v11}, [Lh5/c;

    move-result-object v5

    iput-object v5, p0, Lh5/d;->R:[Lh5/c;

    .line 108
    new-instance v5, Ljava/util/ArrayList;

    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    iput-object v5, p0, Lh5/d;->S:Ljava/util/ArrayList;

    .line 109
    new-array v5, v2, [Z

    iput-object v5, p0, Lh5/d;->T:[Z

    .line 110
    filled-new-array {v3, v3}, [I

    move-result-object v3

    iput-object v3, p0, Lh5/d;->q0:[I

    .line 111
    iput-object v1, p0, Lh5/d;->U:Lh5/e;

    const/4 v3, 0x0

    .line 112
    iput v3, p0, Lh5/d;->X:F

    .line 113
    iput v4, p0, Lh5/d;->Y:I

    .line 114
    iput v0, p0, Lh5/d;->b0:I

    const/high16 v3, 0x3f000000    # 0.5f

    .line 115
    iput v3, p0, Lh5/d;->e0:F

    .line 116
    iput v3, p0, Lh5/d;->f0:F

    .line 117
    iput v0, p0, Lh5/d;->h0:I

    .line 118
    iput-object v1, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 119
    iput v0, p0, Lh5/d;->j0:I

    .line 120
    iput v0, p0, Lh5/d;->k0:I

    .line 121
    new-array v2, v2, [F

    fill-array-data v2, :array_1

    iput-object v2, p0, Lh5/d;->l0:[F

    .line 122
    filled-new-array {v1, v1}, [Lh5/d;

    move-result-object v2

    iput-object v2, p0, Lh5/d;->m0:[Lh5/d;

    .line 123
    filled-new-array {v1, v1}, [Lh5/d;

    move-result-object v1

    iput-object v1, p0, Lh5/d;->n0:[Lh5/d;

    .line 124
    iput v4, p0, Lh5/d;->o0:I

    .line 125
    iput v4, p0, Lh5/d;->p0:I

    .line 126
    iput v0, p0, Lh5/d;->Z:I

    .line 127
    iput v0, p0, Lh5/d;->a0:I

    .line 128
    iput p1, p0, Lh5/d;->V:I

    .line 129
    iput p2, p0, Lh5/d;->W:I

    .line 130
    invoke-virtual {p0}, Lh5/d;->a()V

    return-void

    nop

    :array_0
    .array-data 1
        0x1t
        0x1t
    .end array-data

    nop

    :array_1
    .array-data 4
        -0x40800000    # -1.0f
        -0x40800000    # -1.0f
    .end array-data
.end method

.method public static H(IILjava/lang/String;Ljava/lang/StringBuilder;)V
    .locals 1

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    return-void

    .line 4
    :cond_0
    const-string p1, " :   "

    .line 5
    .line 6
    const-string v0, ",\n"

    .line 7
    .line 8
    invoke-static {p3, p2, p1, p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->z(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public static I(Ljava/lang/StringBuilder;Ljava/lang/String;FF)V
    .locals 0

    .line 1
    cmpl-float p3, p2, p3

    .line 2
    .line 3
    if-nez p3, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    const-string p1, " :   "

    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 15
    .line 16
    .line 17
    const-string p1, ",\n"

    .line 18
    .line 19
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public static p(Ljava/lang/StringBuilder;Ljava/lang/String;IIIIIFI)V
    .locals 2

    .line 1
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 2
    .line 3
    .line 4
    const-string p1, " :  {\n"

    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 7
    .line 8
    .line 9
    const/4 p1, 0x1

    .line 10
    if-eq p8, p1, :cond_3

    .line 11
    .line 12
    const/4 p1, 0x2

    .line 13
    if-eq p8, p1, :cond_2

    .line 14
    .line 15
    const/4 p1, 0x3

    .line 16
    if-eq p8, p1, :cond_1

    .line 17
    .line 18
    const/4 p1, 0x4

    .line 19
    if-ne p8, p1, :cond_0

    .line 20
    .line 21
    const-string p1, "MATCH_PARENT"

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    const/4 p0, 0x0

    .line 25
    throw p0

    .line 26
    :cond_1
    const-string p1, "MATCH_CONSTRAINT"

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_2
    const-string p1, "WRAP_CONTENT"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_3
    const-string p1, "FIXED"

    .line 33
    .line 34
    :goto_0
    const-string p8, "FIXED"

    .line 35
    .line 36
    invoke-virtual {p8, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 37
    .line 38
    .line 39
    move-result p8

    .line 40
    if-eqz p8, :cond_4

    .line 41
    .line 42
    goto :goto_1

    .line 43
    :cond_4
    const-string p8, " :   "

    .line 44
    .line 45
    const-string v0, ",\n"

    .line 46
    .line 47
    const-string v1, "      behavior"

    .line 48
    .line 49
    invoke-static {p0, v1, p8, p1, v0}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    :goto_1
    const-string p1, "      size"

    .line 53
    .line 54
    const/4 p8, 0x0

    .line 55
    invoke-static {p2, p8, p1, p0}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 56
    .line 57
    .line 58
    const-string p1, "      min"

    .line 59
    .line 60
    invoke-static {p3, p8, p1, p0}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 61
    .line 62
    .line 63
    const-string p1, "      max"

    .line 64
    .line 65
    const p2, 0x7fffffff

    .line 66
    .line 67
    .line 68
    invoke-static {p4, p2, p1, p0}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 69
    .line 70
    .line 71
    const-string p1, "      matchMin"

    .line 72
    .line 73
    invoke-static {p5, p8, p1, p0}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 74
    .line 75
    .line 76
    const-string p1, "      matchDef"

    .line 77
    .line 78
    invoke-static {p6, p8, p1, p0}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 79
    .line 80
    .line 81
    const-string p1, "      matchPercent"

    .line 82
    .line 83
    const/high16 p2, 0x3f800000    # 1.0f

    .line 84
    .line 85
    invoke-static {p0, p1, p7, p2}, Lh5/d;->I(Ljava/lang/StringBuilder;Ljava/lang/String;FF)V

    .line 86
    .line 87
    .line 88
    const-string p1, "    },\n"

    .line 89
    .line 90
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    return-void
.end method

.method public static q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V
    .locals 2

    .line 1
    iget-object v0, p2, Lh5/c;->f:Lh5/c;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    const-string v0, "    "

    .line 7
    .line 8
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 9
    .line 10
    .line 11
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    const-string p1, " : [ \'"

    .line 15
    .line 16
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    iget-object p1, p2, Lh5/c;->f:Lh5/c;

    .line 20
    .line 21
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string p1, "\'"

    .line 25
    .line 26
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    iget p1, p2, Lh5/c;->h:I

    .line 30
    .line 31
    const/high16 v0, -0x80000000

    .line 32
    .line 33
    if-ne p1, v0, :cond_1

    .line 34
    .line 35
    iget p1, p2, Lh5/c;->g:I

    .line 36
    .line 37
    if-eqz p1, :cond_2

    .line 38
    .line 39
    :cond_1
    const-string p1, ","

    .line 40
    .line 41
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget v1, p2, Lh5/c;->g:I

    .line 45
    .line 46
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    iget v1, p2, Lh5/c;->h:I

    .line 50
    .line 51
    if-eq v1, v0, :cond_2

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget p2, p2, Lh5/c;->h:I

    .line 57
    .line 58
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    :cond_2
    const-string p1, " ] ,\n"

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    return-void
.end method


# virtual methods
.method public final A()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh5/d;->g:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget p0, p0, Lh5/d;->h0:I

    .line 6
    .line 7
    const/16 v0, 0x8

    .line 8
    .line 9
    if-eq p0, v0, :cond_0

    .line 10
    .line 11
    const/4 p0, 0x1

    .line 12
    return p0

    .line 13
    :cond_0
    const/4 p0, 0x0

    .line 14
    return p0
.end method

.method public B()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh5/d;->l:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lh5/d;->J:Lh5/c;

    .line 6
    .line 7
    iget-boolean v0, v0, Lh5/c;->c:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    iget-boolean p0, p0, Lh5/c;->c:Z

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public C()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh5/d;->m:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 6
    .line 7
    iget-boolean v0, v0, Lh5/c;->c:Z

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 12
    .line 13
    iget-boolean p0, p0, Lh5/c;->c:Z

    .line 14
    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    return p0

    .line 20
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 21
    return p0
.end method

.method public D()V
    .locals 5

    .line 1
    iget-object v0, p0, Lh5/d;->J:Lh5/c;

    .line 2
    .line 3
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 7
    .line 8
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lh5/d;->M:Lh5/c;

    .line 17
    .line 18
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lh5/d;->N:Lh5/c;

    .line 22
    .line 23
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lh5/d;->O:Lh5/c;

    .line 27
    .line 28
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 29
    .line 30
    .line 31
    iget-object v0, p0, Lh5/d;->P:Lh5/c;

    .line 32
    .line 33
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 34
    .line 35
    .line 36
    iget-object v0, p0, Lh5/d;->Q:Lh5/c;

    .line 37
    .line 38
    invoke-virtual {v0}, Lh5/c;->j()V

    .line 39
    .line 40
    .line 41
    const/4 v0, 0x0

    .line 42
    iput-object v0, p0, Lh5/d;->U:Lh5/e;

    .line 43
    .line 44
    const/high16 v1, 0x7fc00000    # Float.NaN

    .line 45
    .line 46
    iput v1, p0, Lh5/d;->E:F

    .line 47
    .line 48
    const/4 v1, 0x0

    .line 49
    iput v1, p0, Lh5/d;->V:I

    .line 50
    .line 51
    iput v1, p0, Lh5/d;->W:I

    .line 52
    .line 53
    const/4 v2, 0x0

    .line 54
    iput v2, p0, Lh5/d;->X:F

    .line 55
    .line 56
    const/4 v2, -0x1

    .line 57
    iput v2, p0, Lh5/d;->Y:I

    .line 58
    .line 59
    iput v1, p0, Lh5/d;->Z:I

    .line 60
    .line 61
    iput v1, p0, Lh5/d;->a0:I

    .line 62
    .line 63
    iput v1, p0, Lh5/d;->b0:I

    .line 64
    .line 65
    iput v1, p0, Lh5/d;->c0:I

    .line 66
    .line 67
    iput v1, p0, Lh5/d;->d0:I

    .line 68
    .line 69
    const/high16 v3, 0x3f000000    # 0.5f

    .line 70
    .line 71
    iput v3, p0, Lh5/d;->e0:F

    .line 72
    .line 73
    iput v3, p0, Lh5/d;->f0:F

    .line 74
    .line 75
    iget-object v3, p0, Lh5/d;->q0:[I

    .line 76
    .line 77
    const/4 v4, 0x1

    .line 78
    aput v4, v3, v1

    .line 79
    .line 80
    aput v4, v3, v4

    .line 81
    .line 82
    iput-object v0, p0, Lh5/d;->g0:Ljava/lang/Object;

    .line 83
    .line 84
    iput v1, p0, Lh5/d;->h0:I

    .line 85
    .line 86
    iput v1, p0, Lh5/d;->j0:I

    .line 87
    .line 88
    iput v1, p0, Lh5/d;->k0:I

    .line 89
    .line 90
    iget-object v0, p0, Lh5/d;->l0:[F

    .line 91
    .line 92
    const/high16 v3, -0x40800000    # -1.0f

    .line 93
    .line 94
    aput v3, v0, v1

    .line 95
    .line 96
    aput v3, v0, v4

    .line 97
    .line 98
    iput v2, p0, Lh5/d;->p:I

    .line 99
    .line 100
    iput v2, p0, Lh5/d;->q:I

    .line 101
    .line 102
    iget-object v0, p0, Lh5/d;->D:[I

    .line 103
    .line 104
    const v3, 0x7fffffff

    .line 105
    .line 106
    .line 107
    aput v3, v0, v1

    .line 108
    .line 109
    aput v3, v0, v4

    .line 110
    .line 111
    iput v1, p0, Lh5/d;->s:I

    .line 112
    .line 113
    iput v1, p0, Lh5/d;->t:I

    .line 114
    .line 115
    const/high16 v0, 0x3f800000    # 1.0f

    .line 116
    .line 117
    iput v0, p0, Lh5/d;->x:F

    .line 118
    .line 119
    iput v0, p0, Lh5/d;->A:F

    .line 120
    .line 121
    iput v3, p0, Lh5/d;->w:I

    .line 122
    .line 123
    iput v3, p0, Lh5/d;->z:I

    .line 124
    .line 125
    iput v1, p0, Lh5/d;->v:I

    .line 126
    .line 127
    iput v1, p0, Lh5/d;->y:I

    .line 128
    .line 129
    iput v2, p0, Lh5/d;->B:I

    .line 130
    .line 131
    iput v0, p0, Lh5/d;->C:F

    .line 132
    .line 133
    iget-object v0, p0, Lh5/d;->f:[Z

    .line 134
    .line 135
    aput-boolean v4, v0, v1

    .line 136
    .line 137
    aput-boolean v4, v0, v4

    .line 138
    .line 139
    iput-boolean v1, p0, Lh5/d;->G:Z

    .line 140
    .line 141
    iget-object v0, p0, Lh5/d;->T:[Z

    .line 142
    .line 143
    aput-boolean v1, v0, v1

    .line 144
    .line 145
    aput-boolean v1, v0, v4

    .line 146
    .line 147
    iput-boolean v4, p0, Lh5/d;->g:Z

    .line 148
    .line 149
    iget-object v0, p0, Lh5/d;->u:[I

    .line 150
    .line 151
    aput v1, v0, v1

    .line 152
    .line 153
    aput v1, v0, v4

    .line 154
    .line 155
    iput v2, p0, Lh5/d;->h:I

    .line 156
    .line 157
    iput v2, p0, Lh5/d;->i:I

    .line 158
    .line 159
    return-void
.end method

.method public final E()V
    .locals 3

    .line 1
    iget-object p0, p0, Lh5/d;->S:Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x0

    .line 8
    :goto_0
    if-ge v1, v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    check-cast v2, Lh5/c;

    .line 15
    .line 16
    invoke-virtual {v2}, Lh5/c;->j()V

    .line 17
    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    return-void
.end method

.method public final F()V
    .locals 4

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lh5/d;->l:Z

    .line 3
    .line 4
    iput-boolean v0, p0, Lh5/d;->m:Z

    .line 5
    .line 6
    iput-boolean v0, p0, Lh5/d;->n:Z

    .line 7
    .line 8
    iput-boolean v0, p0, Lh5/d;->o:Z

    .line 9
    .line 10
    iget-object p0, p0, Lh5/d;->S:Ljava/util/ArrayList;

    .line 11
    .line 12
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    move v2, v0

    .line 17
    :goto_0
    if-ge v2, v1, :cond_0

    .line 18
    .line 19
    invoke-virtual {p0, v2}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v3

    .line 23
    check-cast v3, Lh5/c;

    .line 24
    .line 25
    iput-boolean v0, v3, Lh5/c;->c:Z

    .line 26
    .line 27
    iput v0, v3, Lh5/c;->b:I

    .line 28
    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    return-void
.end method

.method public G(Lgw0/c;)V
    .locals 0

    .line 1
    iget-object p1, p0, Lh5/d;->J:Lh5/c;

    .line 2
    .line 3
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 4
    .line 5
    .line 6
    iget-object p1, p0, Lh5/d;->K:Lh5/c;

    .line 7
    .line 8
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 9
    .line 10
    .line 11
    iget-object p1, p0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 14
    .line 15
    .line 16
    iget-object p1, p0, Lh5/d;->M:Lh5/c;

    .line 17
    .line 18
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 19
    .line 20
    .line 21
    iget-object p1, p0, Lh5/d;->N:Lh5/c;

    .line 22
    .line 23
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 24
    .line 25
    .line 26
    iget-object p1, p0, Lh5/d;->Q:Lh5/c;

    .line 27
    .line 28
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 29
    .line 30
    .line 31
    iget-object p1, p0, Lh5/d;->O:Lh5/c;

    .line 32
    .line 33
    invoke-virtual {p1}, Lh5/c;->k()V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lh5/d;->P:Lh5/c;

    .line 37
    .line 38
    invoke-virtual {p0}, Lh5/c;->k()V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public final J(I)V
    .locals 0

    .line 1
    iput p1, p0, Lh5/d;->b0:I

    .line 2
    .line 3
    if-lez p1, :cond_0

    .line 4
    .line 5
    const/4 p1, 0x1

    .line 6
    goto :goto_0

    .line 7
    :cond_0
    const/4 p1, 0x0

    .line 8
    :goto_0
    iput-boolean p1, p0, Lh5/d;->F:Z

    .line 9
    .line 10
    return-void
.end method

.method public final K(Ljava/lang/String;)V
    .locals 8

    .line 1
    const/4 v0, 0x0

    .line 2
    if-eqz p1, :cond_8

    .line 3
    .line 4
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 5
    .line 6
    .line 7
    move-result v1

    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    goto/16 :goto_2

    .line 11
    .line 12
    :cond_0
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    const/16 v2, 0x2c

    .line 17
    .line 18
    invoke-virtual {p1, v2}, Ljava/lang/String;->indexOf(I)I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    const/4 v3, 0x0

    .line 23
    const/4 v4, 0x1

    .line 24
    const/4 v5, -0x1

    .line 25
    if-lez v2, :cond_3

    .line 26
    .line 27
    add-int/lit8 v6, v1, -0x1

    .line 28
    .line 29
    if-ge v2, v6, :cond_3

    .line 30
    .line 31
    invoke-virtual {p1, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v6

    .line 35
    const-string v7, "W"

    .line 36
    .line 37
    invoke-virtual {v6, v7}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 38
    .line 39
    .line 40
    move-result v7

    .line 41
    if-eqz v7, :cond_1

    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_1
    const-string v3, "H"

    .line 45
    .line 46
    invoke-virtual {v6, v3}, Ljava/lang/String;->equalsIgnoreCase(Ljava/lang/String;)Z

    .line 47
    .line 48
    .line 49
    move-result v3

    .line 50
    if-eqz v3, :cond_2

    .line 51
    .line 52
    move v3, v4

    .line 53
    goto :goto_0

    .line 54
    :cond_2
    move v3, v5

    .line 55
    :goto_0
    add-int/2addr v2, v4

    .line 56
    move v5, v3

    .line 57
    move v3, v2

    .line 58
    :cond_3
    const/16 v2, 0x3a

    .line 59
    .line 60
    invoke-virtual {p1, v2}, Ljava/lang/String;->indexOf(I)I

    .line 61
    .line 62
    .line 63
    move-result v2

    .line 64
    if-ltz v2, :cond_5

    .line 65
    .line 66
    sub-int/2addr v1, v4

    .line 67
    if-ge v2, v1, :cond_5

    .line 68
    .line 69
    invoke-virtual {p1, v3, v2}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v1

    .line 73
    add-int/2addr v2, v4

    .line 74
    invoke-virtual {p1, v2}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 75
    .line 76
    .line 77
    move-result-object p1

    .line 78
    invoke-virtual {v1}, Ljava/lang/String;->length()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    if-lez v2, :cond_6

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-lez v2, :cond_6

    .line 89
    .line 90
    :try_start_0
    invoke-static {v1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 91
    .line 92
    .line 93
    move-result v1

    .line 94
    invoke-static {p1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 95
    .line 96
    .line 97
    move-result p1

    .line 98
    cmpl-float v2, v1, v0

    .line 99
    .line 100
    if-lez v2, :cond_6

    .line 101
    .line 102
    cmpl-float v2, p1, v0

    .line 103
    .line 104
    if-lez v2, :cond_6

    .line 105
    .line 106
    if-ne v5, v4, :cond_4

    .line 107
    .line 108
    div-float/2addr p1, v1

    .line 109
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 110
    .line 111
    .line 112
    move-result p1

    .line 113
    goto :goto_1

    .line 114
    :cond_4
    div-float/2addr v1, p1

    .line 115
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 116
    .line 117
    .line 118
    move-result p1
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 119
    goto :goto_1

    .line 120
    :cond_5
    invoke-virtual {p1, v3}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 125
    .line 126
    .line 127
    move-result v1

    .line 128
    if-lez v1, :cond_6

    .line 129
    .line 130
    :try_start_1
    invoke-static {p1}, Ljava/lang/Float;->parseFloat(Ljava/lang/String;)F

    .line 131
    .line 132
    .line 133
    move-result p1
    :try_end_1
    .catch Ljava/lang/NumberFormatException; {:try_start_1 .. :try_end_1} :catch_0

    .line 134
    goto :goto_1

    .line 135
    :catch_0
    :cond_6
    move p1, v0

    .line 136
    :goto_1
    cmpl-float v0, p1, v0

    .line 137
    .line 138
    if-lez v0, :cond_7

    .line 139
    .line 140
    iput p1, p0, Lh5/d;->X:F

    .line 141
    .line 142
    iput v5, p0, Lh5/d;->Y:I

    .line 143
    .line 144
    :cond_7
    return-void

    .line 145
    :cond_8
    :goto_2
    iput v0, p0, Lh5/d;->X:F

    .line 146
    .line 147
    return-void
.end method

.method public final L(II)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh5/d;->l:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lh5/d;->J:Lh5/c;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lh5/c;->l(I)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    invoke-virtual {v0, p2}, Lh5/c;->l(I)V

    .line 14
    .line 15
    .line 16
    iput p1, p0, Lh5/d;->Z:I

    .line 17
    .line 18
    sub-int/2addr p2, p1

    .line 19
    iput p2, p0, Lh5/d;->V:I

    .line 20
    .line 21
    const/4 p1, 0x1

    .line 22
    iput-boolean p1, p0, Lh5/d;->l:Z

    .line 23
    .line 24
    return-void
.end method

.method public final M(II)V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lh5/d;->m:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 7
    .line 8
    invoke-virtual {v0, p1}, Lh5/c;->l(I)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lh5/d;->M:Lh5/c;

    .line 12
    .line 13
    invoke-virtual {v0, p2}, Lh5/c;->l(I)V

    .line 14
    .line 15
    .line 16
    iput p1, p0, Lh5/d;->a0:I

    .line 17
    .line 18
    sub-int/2addr p2, p1

    .line 19
    iput p2, p0, Lh5/d;->W:I

    .line 20
    .line 21
    iget-boolean p2, p0, Lh5/d;->F:Z

    .line 22
    .line 23
    if-eqz p2, :cond_1

    .line 24
    .line 25
    iget p2, p0, Lh5/d;->b0:I

    .line 26
    .line 27
    add-int/2addr p1, p2

    .line 28
    iget-object p2, p0, Lh5/d;->N:Lh5/c;

    .line 29
    .line 30
    invoke-virtual {p2, p1}, Lh5/c;->l(I)V

    .line 31
    .line 32
    .line 33
    :cond_1
    const/4 p1, 0x1

    .line 34
    iput-boolean p1, p0, Lh5/d;->m:Z

    .line 35
    .line 36
    return-void
.end method

.method public final N(I)V
    .locals 1

    .line 1
    iput p1, p0, Lh5/d;->W:I

    .line 2
    .line 3
    iget v0, p0, Lh5/d;->d0:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    iput v0, p0, Lh5/d;->W:I

    .line 8
    .line 9
    :cond_0
    return-void
.end method

.method public final O(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh5/d;->q0:[I

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    aput p1, p0, v0

    .line 5
    .line 6
    return-void
.end method

.method public final P(IIIF)V
    .locals 0

    .line 1
    iput p1, p0, Lh5/d;->s:I

    .line 2
    .line 3
    iput p2, p0, Lh5/d;->v:I

    .line 4
    .line 5
    const p2, 0x7fffffff

    .line 6
    .line 7
    .line 8
    if-ne p3, p2, :cond_0

    .line 9
    .line 10
    const/4 p3, 0x0

    .line 11
    :cond_0
    iput p3, p0, Lh5/d;->w:I

    .line 12
    .line 13
    iput p4, p0, Lh5/d;->x:F

    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    cmpl-float p2, p4, p2

    .line 17
    .line 18
    if-lez p2, :cond_1

    .line 19
    .line 20
    const/high16 p2, 0x3f800000    # 1.0f

    .line 21
    .line 22
    cmpg-float p2, p4, p2

    .line 23
    .line 24
    if-gez p2, :cond_1

    .line 25
    .line 26
    if-nez p1, :cond_1

    .line 27
    .line 28
    const/4 p1, 0x2

    .line 29
    iput p1, p0, Lh5/d;->s:I

    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public final Q(I)V
    .locals 1

    .line 1
    iget-object p0, p0, Lh5/d;->q0:[I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    aput p1, p0, v0

    .line 5
    .line 6
    return-void
.end method

.method public final R(IIIF)V
    .locals 0

    .line 1
    iput p1, p0, Lh5/d;->t:I

    .line 2
    .line 3
    iput p2, p0, Lh5/d;->y:I

    .line 4
    .line 5
    const p2, 0x7fffffff

    .line 6
    .line 7
    .line 8
    if-ne p3, p2, :cond_0

    .line 9
    .line 10
    const/4 p3, 0x0

    .line 11
    :cond_0
    iput p3, p0, Lh5/d;->z:I

    .line 12
    .line 13
    iput p4, p0, Lh5/d;->A:F

    .line 14
    .line 15
    const/4 p2, 0x0

    .line 16
    cmpl-float p2, p4, p2

    .line 17
    .line 18
    if-lez p2, :cond_1

    .line 19
    .line 20
    const/high16 p2, 0x3f800000    # 1.0f

    .line 21
    .line 22
    cmpg-float p2, p4, p2

    .line 23
    .line 24
    if-gez p2, :cond_1

    .line 25
    .line 26
    if-nez p1, :cond_1

    .line 27
    .line 28
    const/4 p1, 0x2

    .line 29
    iput p1, p0, Lh5/d;->t:I

    .line 30
    .line 31
    :cond_1
    return-void
.end method

.method public final S(I)V
    .locals 1

    .line 1
    iput p1, p0, Lh5/d;->V:I

    .line 2
    .line 3
    iget v0, p0, Lh5/d;->c0:I

    .line 4
    .line 5
    if-ge p1, v0, :cond_0

    .line 6
    .line 7
    iput v0, p0, Lh5/d;->V:I

    .line 8
    .line 9
    :cond_0
    return-void
.end method

.method public T(ZZ)V
    .locals 7

    .line 1
    iget-object v0, p0, Lh5/d;->d:Li5/l;

    .line 2
    .line 3
    iget-boolean v1, v0, Li5/p;->g:Z

    .line 4
    .line 5
    and-int/2addr p1, v1

    .line 6
    iget-object v1, p0, Lh5/d;->e:Li5/n;

    .line 7
    .line 8
    iget-boolean v2, v1, Li5/p;->g:Z

    .line 9
    .line 10
    and-int/2addr p2, v2

    .line 11
    iget-object v2, v0, Li5/p;->h:Li5/g;

    .line 12
    .line 13
    iget v2, v2, Li5/g;->g:I

    .line 14
    .line 15
    iget-object v3, v1, Li5/p;->h:Li5/g;

    .line 16
    .line 17
    iget v3, v3, Li5/g;->g:I

    .line 18
    .line 19
    iget-object v0, v0, Li5/p;->i:Li5/g;

    .line 20
    .line 21
    iget v0, v0, Li5/g;->g:I

    .line 22
    .line 23
    iget-object v1, v1, Li5/p;->i:Li5/g;

    .line 24
    .line 25
    iget v1, v1, Li5/g;->g:I

    .line 26
    .line 27
    sub-int v4, v0, v2

    .line 28
    .line 29
    sub-int v5, v1, v3

    .line 30
    .line 31
    const/4 v6, 0x0

    .line 32
    if-ltz v4, :cond_0

    .line 33
    .line 34
    if-ltz v5, :cond_0

    .line 35
    .line 36
    const/high16 v4, -0x80000000

    .line 37
    .line 38
    if-eq v2, v4, :cond_0

    .line 39
    .line 40
    const v5, 0x7fffffff

    .line 41
    .line 42
    .line 43
    if-eq v2, v5, :cond_0

    .line 44
    .line 45
    if-eq v3, v4, :cond_0

    .line 46
    .line 47
    if-eq v3, v5, :cond_0

    .line 48
    .line 49
    if-eq v0, v4, :cond_0

    .line 50
    .line 51
    if-eq v0, v5, :cond_0

    .line 52
    .line 53
    if-eq v1, v4, :cond_0

    .line 54
    .line 55
    if-ne v1, v5, :cond_1

    .line 56
    .line 57
    :cond_0
    move v0, v6

    .line 58
    move v1, v0

    .line 59
    move v2, v1

    .line 60
    move v3, v2

    .line 61
    :cond_1
    sub-int/2addr v0, v2

    .line 62
    sub-int/2addr v1, v3

    .line 63
    if-eqz p1, :cond_2

    .line 64
    .line 65
    iput v2, p0, Lh5/d;->Z:I

    .line 66
    .line 67
    :cond_2
    if-eqz p2, :cond_3

    .line 68
    .line 69
    iput v3, p0, Lh5/d;->a0:I

    .line 70
    .line 71
    :cond_3
    iget v2, p0, Lh5/d;->h0:I

    .line 72
    .line 73
    const/16 v3, 0x8

    .line 74
    .line 75
    if-ne v2, v3, :cond_4

    .line 76
    .line 77
    iput v6, p0, Lh5/d;->V:I

    .line 78
    .line 79
    iput v6, p0, Lh5/d;->W:I

    .line 80
    .line 81
    return-void

    .line 82
    :cond_4
    const/4 v2, 0x1

    .line 83
    iget-object v3, p0, Lh5/d;->q0:[I

    .line 84
    .line 85
    if-eqz p1, :cond_6

    .line 86
    .line 87
    aget p1, v3, v6

    .line 88
    .line 89
    if-ne p1, v2, :cond_5

    .line 90
    .line 91
    iget p1, p0, Lh5/d;->V:I

    .line 92
    .line 93
    if-ge v0, p1, :cond_5

    .line 94
    .line 95
    move v0, p1

    .line 96
    :cond_5
    iput v0, p0, Lh5/d;->V:I

    .line 97
    .line 98
    iget p1, p0, Lh5/d;->c0:I

    .line 99
    .line 100
    if-ge v0, p1, :cond_6

    .line 101
    .line 102
    iput p1, p0, Lh5/d;->V:I

    .line 103
    .line 104
    :cond_6
    if-eqz p2, :cond_8

    .line 105
    .line 106
    aget p1, v3, v2

    .line 107
    .line 108
    if-ne p1, v2, :cond_7

    .line 109
    .line 110
    iget p1, p0, Lh5/d;->W:I

    .line 111
    .line 112
    if-ge v1, p1, :cond_7

    .line 113
    .line 114
    move v1, p1

    .line 115
    :cond_7
    iput v1, p0, Lh5/d;->W:I

    .line 116
    .line 117
    iget p1, p0, Lh5/d;->d0:I

    .line 118
    .line 119
    if-ge v1, p1, :cond_8

    .line 120
    .line 121
    iput p1, p0, Lh5/d;->W:I

    .line 122
    .line 123
    :cond_8
    return-void
.end method

.method public U(La5/c;Z)V
    .locals 6

    .line 1
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    iget-object p1, p0, Lh5/d;->J:Lh5/c;

    .line 5
    .line 6
    invoke-static {p1}, La5/c;->n(Ljava/lang/Object;)I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 11
    .line 12
    invoke-static {v0}, La5/c;->n(Ljava/lang/Object;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v1, p0, Lh5/d;->L:Lh5/c;

    .line 17
    .line 18
    invoke-static {v1}, La5/c;->n(Ljava/lang/Object;)I

    .line 19
    .line 20
    .line 21
    move-result v1

    .line 22
    iget-object v2, p0, Lh5/d;->M:Lh5/c;

    .line 23
    .line 24
    invoke-static {v2}, La5/c;->n(Ljava/lang/Object;)I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    if-eqz p2, :cond_0

    .line 29
    .line 30
    iget-object v3, p0, Lh5/d;->d:Li5/l;

    .line 31
    .line 32
    if-eqz v3, :cond_0

    .line 33
    .line 34
    iget-object v4, v3, Li5/p;->h:Li5/g;

    .line 35
    .line 36
    iget-boolean v5, v4, Li5/g;->j:Z

    .line 37
    .line 38
    if-eqz v5, :cond_0

    .line 39
    .line 40
    iget-object v3, v3, Li5/p;->i:Li5/g;

    .line 41
    .line 42
    iget-boolean v5, v3, Li5/g;->j:Z

    .line 43
    .line 44
    if-eqz v5, :cond_0

    .line 45
    .line 46
    iget p1, v4, Li5/g;->g:I

    .line 47
    .line 48
    iget v1, v3, Li5/g;->g:I

    .line 49
    .line 50
    :cond_0
    if-eqz p2, :cond_1

    .line 51
    .line 52
    iget-object p2, p0, Lh5/d;->e:Li5/n;

    .line 53
    .line 54
    if-eqz p2, :cond_1

    .line 55
    .line 56
    iget-object v3, p2, Li5/p;->h:Li5/g;

    .line 57
    .line 58
    iget-boolean v4, v3, Li5/g;->j:Z

    .line 59
    .line 60
    if-eqz v4, :cond_1

    .line 61
    .line 62
    iget-object p2, p2, Li5/p;->i:Li5/g;

    .line 63
    .line 64
    iget-boolean v4, p2, Li5/g;->j:Z

    .line 65
    .line 66
    if-eqz v4, :cond_1

    .line 67
    .line 68
    iget v0, v3, Li5/g;->g:I

    .line 69
    .line 70
    iget v2, p2, Li5/g;->g:I

    .line 71
    .line 72
    :cond_1
    sub-int p2, v1, p1

    .line 73
    .line 74
    sub-int v3, v2, v0

    .line 75
    .line 76
    const/4 v4, 0x0

    .line 77
    if-ltz p2, :cond_2

    .line 78
    .line 79
    if-ltz v3, :cond_2

    .line 80
    .line 81
    const/high16 p2, -0x80000000

    .line 82
    .line 83
    if-eq p1, p2, :cond_2

    .line 84
    .line 85
    const v3, 0x7fffffff

    .line 86
    .line 87
    .line 88
    if-eq p1, v3, :cond_2

    .line 89
    .line 90
    if-eq v0, p2, :cond_2

    .line 91
    .line 92
    if-eq v0, v3, :cond_2

    .line 93
    .line 94
    if-eq v1, p2, :cond_2

    .line 95
    .line 96
    if-eq v1, v3, :cond_2

    .line 97
    .line 98
    if-eq v2, p2, :cond_2

    .line 99
    .line 100
    if-ne v2, v3, :cond_3

    .line 101
    .line 102
    :cond_2
    move p1, v4

    .line 103
    move v0, p1

    .line 104
    move v1, v0

    .line 105
    move v2, v1

    .line 106
    :cond_3
    sub-int/2addr v1, p1

    .line 107
    sub-int/2addr v2, v0

    .line 108
    iput p1, p0, Lh5/d;->Z:I

    .line 109
    .line 110
    iput v0, p0, Lh5/d;->a0:I

    .line 111
    .line 112
    iget p1, p0, Lh5/d;->h0:I

    .line 113
    .line 114
    const/16 p2, 0x8

    .line 115
    .line 116
    if-ne p1, p2, :cond_4

    .line 117
    .line 118
    iput v4, p0, Lh5/d;->V:I

    .line 119
    .line 120
    iput v4, p0, Lh5/d;->W:I

    .line 121
    .line 122
    return-void

    .line 123
    :cond_4
    iget-object p1, p0, Lh5/d;->q0:[I

    .line 124
    .line 125
    aget p2, p1, v4

    .line 126
    .line 127
    const/4 v0, 0x1

    .line 128
    if-ne p2, v0, :cond_5

    .line 129
    .line 130
    iget v3, p0, Lh5/d;->V:I

    .line 131
    .line 132
    if-ge v1, v3, :cond_5

    .line 133
    .line 134
    move v1, v3

    .line 135
    :cond_5
    aget v3, p1, v0

    .line 136
    .line 137
    if-ne v3, v0, :cond_6

    .line 138
    .line 139
    iget v3, p0, Lh5/d;->W:I

    .line 140
    .line 141
    if-ge v2, v3, :cond_6

    .line 142
    .line 143
    move v2, v3

    .line 144
    :cond_6
    iput v1, p0, Lh5/d;->V:I

    .line 145
    .line 146
    iput v2, p0, Lh5/d;->W:I

    .line 147
    .line 148
    iget v3, p0, Lh5/d;->d0:I

    .line 149
    .line 150
    if-ge v2, v3, :cond_7

    .line 151
    .line 152
    iput v3, p0, Lh5/d;->W:I

    .line 153
    .line 154
    :cond_7
    iget v3, p0, Lh5/d;->c0:I

    .line 155
    .line 156
    if-ge v1, v3, :cond_8

    .line 157
    .line 158
    iput v3, p0, Lh5/d;->V:I

    .line 159
    .line 160
    :cond_8
    iget v3, p0, Lh5/d;->w:I

    .line 161
    .line 162
    const/4 v4, 0x3

    .line 163
    if-lez v3, :cond_9

    .line 164
    .line 165
    if-ne p2, v4, :cond_9

    .line 166
    .line 167
    iget p2, p0, Lh5/d;->V:I

    .line 168
    .line 169
    invoke-static {p2, v3}, Ljava/lang/Math;->min(II)I

    .line 170
    .line 171
    .line 172
    move-result p2

    .line 173
    iput p2, p0, Lh5/d;->V:I

    .line 174
    .line 175
    :cond_9
    iget p2, p0, Lh5/d;->z:I

    .line 176
    .line 177
    if-lez p2, :cond_a

    .line 178
    .line 179
    aget p1, p1, v0

    .line 180
    .line 181
    if-ne p1, v4, :cond_a

    .line 182
    .line 183
    iget p1, p0, Lh5/d;->W:I

    .line 184
    .line 185
    invoke-static {p1, p2}, Ljava/lang/Math;->min(II)I

    .line 186
    .line 187
    .line 188
    move-result p1

    .line 189
    iput p1, p0, Lh5/d;->W:I

    .line 190
    .line 191
    :cond_a
    iget p1, p0, Lh5/d;->V:I

    .line 192
    .line 193
    if-eq v1, p1, :cond_b

    .line 194
    .line 195
    iput p1, p0, Lh5/d;->h:I

    .line 196
    .line 197
    :cond_b
    iget p1, p0, Lh5/d;->W:I

    .line 198
    .line 199
    if-eq v2, p1, :cond_c

    .line 200
    .line 201
    iput p1, p0, Lh5/d;->i:I

    .line 202
    .line 203
    :cond_c
    return-void
.end method

.method public final a()V
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/d;->J:Lh5/c;

    .line 2
    .line 3
    iget-object v1, p0, Lh5/d;->S:Ljava/util/ArrayList;

    .line 4
    .line 5
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 9
    .line 10
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Lh5/d;->L:Lh5/c;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    iget-object v0, p0, Lh5/d;->M:Lh5/c;

    .line 19
    .line 20
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 21
    .line 22
    .line 23
    iget-object v0, p0, Lh5/d;->O:Lh5/c;

    .line 24
    .line 25
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 26
    .line 27
    .line 28
    iget-object v0, p0, Lh5/d;->P:Lh5/c;

    .line 29
    .line 30
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    iget-object v0, p0, Lh5/d;->Q:Lh5/c;

    .line 34
    .line 35
    invoke-virtual {v1, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 36
    .line 37
    .line 38
    iget-object p0, p0, Lh5/d;->N:Lh5/c;

    .line 39
    .line 40
    invoke-virtual {v1, p0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    return-void
.end method

.method public final b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V
    .locals 8

    .line 1
    if-eqz p5, :cond_1

    .line 2
    .line 3
    invoke-virtual {p3, p0}, Ljava/util/HashSet;->contains(Ljava/lang/Object;)Z

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    if-nez v1, :cond_0

    .line 8
    .line 9
    goto/16 :goto_5

    .line 10
    .line 11
    :cond_0
    invoke-static {p1, p2, p0}, Lh5/j;->b(Lh5/e;La5/c;Lh5/d;)V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p3, p0}, Ljava/util/HashSet;->remove(Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    const/16 v1, 0x40

    .line 18
    .line 19
    invoke-virtual {p1, v1}, Lh5/e;->c0(I)Z

    .line 20
    .line 21
    .line 22
    move-result v1

    .line 23
    invoke-virtual {p0, p2, v1}, Lh5/d;->c(La5/c;Z)V

    .line 24
    .line 25
    .line 26
    :cond_1
    if-nez p4, :cond_3

    .line 27
    .line 28
    iget-object v1, p0, Lh5/d;->J:Lh5/c;

    .line 29
    .line 30
    iget-object v1, v1, Lh5/c;->a:Ljava/util/HashSet;

    .line 31
    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 35
    .line 36
    .line 37
    move-result-object v7

    .line 38
    :goto_0
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v1

    .line 48
    check-cast v1, Lh5/c;

    .line 49
    .line 50
    iget-object v1, v1, Lh5/c;->d:Lh5/d;

    .line 51
    .line 52
    const/4 v6, 0x1

    .line 53
    move-object v2, p1

    .line 54
    move-object v3, p2

    .line 55
    move-object v4, p3

    .line 56
    move v5, p4

    .line 57
    invoke-virtual/range {v1 .. v6}, Lh5/d;->b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V

    .line 58
    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_2
    iget-object v0, p0, Lh5/d;->L:Lh5/c;

    .line 62
    .line 63
    iget-object v0, v0, Lh5/c;->a:Ljava/util/HashSet;

    .line 64
    .line 65
    if-eqz v0, :cond_6

    .line 66
    .line 67
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 68
    .line 69
    .line 70
    move-result-object v6

    .line 71
    :goto_1
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 72
    .line 73
    .line 74
    move-result v0

    .line 75
    if-eqz v0, :cond_6

    .line 76
    .line 77
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    check-cast v0, Lh5/c;

    .line 82
    .line 83
    iget-object v0, v0, Lh5/c;->d:Lh5/d;

    .line 84
    .line 85
    const/4 v5, 0x1

    .line 86
    move-object v1, p1

    .line 87
    move-object v2, p2

    .line 88
    move-object v3, p3

    .line 89
    move v4, p4

    .line 90
    invoke-virtual/range {v0 .. v5}, Lh5/d;->b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V

    .line 91
    .line 92
    .line 93
    goto :goto_1

    .line 94
    :cond_3
    iget-object v1, p0, Lh5/d;->K:Lh5/c;

    .line 95
    .line 96
    iget-object v1, v1, Lh5/c;->a:Ljava/util/HashSet;

    .line 97
    .line 98
    if-eqz v1, :cond_4

    .line 99
    .line 100
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 101
    .line 102
    .line 103
    move-result-object v7

    .line 104
    :goto_2
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 105
    .line 106
    .line 107
    move-result v1

    .line 108
    if-eqz v1, :cond_4

    .line 109
    .line 110
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v1

    .line 114
    check-cast v1, Lh5/c;

    .line 115
    .line 116
    iget-object v1, v1, Lh5/c;->d:Lh5/d;

    .line 117
    .line 118
    const/4 v6, 0x1

    .line 119
    move-object v2, p1

    .line 120
    move-object v3, p2

    .line 121
    move-object v4, p3

    .line 122
    move v5, p4

    .line 123
    invoke-virtual/range {v1 .. v6}, Lh5/d;->b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V

    .line 124
    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_4
    iget-object v1, p0, Lh5/d;->M:Lh5/c;

    .line 128
    .line 129
    iget-object v1, v1, Lh5/c;->a:Ljava/util/HashSet;

    .line 130
    .line 131
    if-eqz v1, :cond_5

    .line 132
    .line 133
    invoke-virtual {v1}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 134
    .line 135
    .line 136
    move-result-object v7

    .line 137
    :goto_3
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 138
    .line 139
    .line 140
    move-result v1

    .line 141
    if-eqz v1, :cond_5

    .line 142
    .line 143
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v1

    .line 147
    check-cast v1, Lh5/c;

    .line 148
    .line 149
    iget-object v1, v1, Lh5/c;->d:Lh5/d;

    .line 150
    .line 151
    const/4 v6, 0x1

    .line 152
    move-object v2, p1

    .line 153
    move-object v3, p2

    .line 154
    move-object v4, p3

    .line 155
    move v5, p4

    .line 156
    invoke-virtual/range {v1 .. v6}, Lh5/d;->b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V

    .line 157
    .line 158
    .line 159
    goto :goto_3

    .line 160
    :cond_5
    iget-object v0, p0, Lh5/d;->N:Lh5/c;

    .line 161
    .line 162
    iget-object v0, v0, Lh5/c;->a:Ljava/util/HashSet;

    .line 163
    .line 164
    if-eqz v0, :cond_6

    .line 165
    .line 166
    invoke-virtual {v0}, Ljava/util/HashSet;->iterator()Ljava/util/Iterator;

    .line 167
    .line 168
    .line 169
    move-result-object v6

    .line 170
    :goto_4
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 171
    .line 172
    .line 173
    move-result v0

    .line 174
    if-eqz v0, :cond_6

    .line 175
    .line 176
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    check-cast v0, Lh5/c;

    .line 181
    .line 182
    iget-object v0, v0, Lh5/c;->d:Lh5/d;

    .line 183
    .line 184
    const/4 v5, 0x1

    .line 185
    move-object v1, p1

    .line 186
    move-object v2, p2

    .line 187
    move-object v3, p3

    .line 188
    move v4, p4

    .line 189
    invoke-virtual/range {v0 .. v5}, Lh5/d;->b(Lh5/e;La5/c;Ljava/util/HashSet;IZ)V

    .line 190
    .line 191
    .line 192
    goto :goto_4

    .line 193
    :cond_6
    :goto_5
    return-void
.end method

.method public c(La5/c;Z)V
    .locals 58

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v0, Lh5/d;->J:Lh5/c;

    .line 6
    .line 7
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    iget-object v4, v0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    invoke-virtual {v1, v4}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 14
    .line 15
    .line 16
    move-result-object v5

    .line 17
    iget-object v6, v0, Lh5/d;->K:Lh5/c;

    .line 18
    .line 19
    invoke-virtual {v1, v6}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 20
    .line 21
    .line 22
    move-result-object v7

    .line 23
    iget-object v8, v0, Lh5/d;->M:Lh5/c;

    .line 24
    .line 25
    invoke-virtual {v1, v8}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 26
    .line 27
    .line 28
    move-result-object v9

    .line 29
    iget-object v10, v0, Lh5/d;->N:Lh5/c;

    .line 30
    .line 31
    invoke-virtual {v1, v10}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 32
    .line 33
    .line 34
    move-result-object v11

    .line 35
    iget-object v12, v0, Lh5/d;->U:Lh5/e;

    .line 36
    .line 37
    const/4 v13, 0x2

    .line 38
    const/4 v15, 0x1

    .line 39
    if-eqz v12, :cond_5

    .line 40
    .line 41
    iget-object v12, v12, Lh5/d;->q0:[I

    .line 42
    .line 43
    const/16 v17, 0x0

    .line 44
    .line 45
    aget v14, v12, v17

    .line 46
    .line 47
    if-ne v14, v13, :cond_0

    .line 48
    .line 49
    move v14, v15

    .line 50
    goto :goto_0

    .line 51
    :cond_0
    move/from16 v14, v17

    .line 52
    .line 53
    :goto_0
    aget v12, v12, v15

    .line 54
    .line 55
    if-ne v12, v13, :cond_1

    .line 56
    .line 57
    move/from16 v18, v15

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_1
    move/from16 v18, v17

    .line 61
    .line 62
    :goto_1
    iget v12, v0, Lh5/d;->r:I

    .line 63
    .line 64
    if-eq v12, v15, :cond_4

    .line 65
    .line 66
    if-eq v12, v13, :cond_3

    .line 67
    .line 68
    const/4 v13, 0x3

    .line 69
    if-eq v12, v13, :cond_2

    .line 70
    .line 71
    :goto_2
    move/from16 v12, v18

    .line 72
    .line 73
    goto :goto_4

    .line 74
    :cond_2
    :goto_3
    move/from16 v12, v17

    .line 75
    .line 76
    move v14, v12

    .line 77
    goto :goto_4

    .line 78
    :cond_3
    move/from16 v14, v17

    .line 79
    .line 80
    goto :goto_2

    .line 81
    :cond_4
    move/from16 v12, v17

    .line 82
    .line 83
    goto :goto_4

    .line 84
    :cond_5
    const/16 v17, 0x0

    .line 85
    .line 86
    goto :goto_3

    .line 87
    :goto_4
    iget v13, v0, Lh5/d;->h0:I

    .line 88
    .line 89
    move/from16 v18, v15

    .line 90
    .line 91
    iget-object v15, v0, Lh5/d;->T:[Z

    .line 92
    .line 93
    move/from16 v20, v12

    .line 94
    .line 95
    const/16 v12, 0x8

    .line 96
    .line 97
    if-ne v13, v12, :cond_9

    .line 98
    .line 99
    iget-object v13, v0, Lh5/d;->S:Ljava/util/ArrayList;

    .line 100
    .line 101
    invoke-virtual {v13}, Ljava/util/ArrayList;->size()I

    .line 102
    .line 103
    .line 104
    move-result v12

    .line 105
    move/from16 v22, v14

    .line 106
    .line 107
    move/from16 v14, v17

    .line 108
    .line 109
    :goto_5
    if-ge v14, v12, :cond_8

    .line 110
    .line 111
    invoke-virtual {v13, v14}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v23

    .line 115
    move/from16 v24, v12

    .line 116
    .line 117
    move-object/from16 v12, v23

    .line 118
    .line 119
    check-cast v12, Lh5/c;

    .line 120
    .line 121
    iget-object v12, v12, Lh5/c;->a:Ljava/util/HashSet;

    .line 122
    .line 123
    if-nez v12, :cond_6

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_6
    invoke-virtual {v12}, Ljava/util/HashSet;->size()I

    .line 127
    .line 128
    .line 129
    move-result v12

    .line 130
    if-lez v12, :cond_7

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_7
    :goto_6
    add-int/lit8 v14, v14, 0x1

    .line 134
    .line 135
    move/from16 v12, v24

    .line 136
    .line 137
    goto :goto_5

    .line 138
    :cond_8
    aget-boolean v12, v15, v17

    .line 139
    .line 140
    if-nez v12, :cond_a

    .line 141
    .line 142
    aget-boolean v12, v15, v18

    .line 143
    .line 144
    if-nez v12, :cond_a

    .line 145
    .line 146
    return-void

    .line 147
    :cond_9
    move/from16 v22, v14

    .line 148
    .line 149
    :cond_a
    :goto_7
    iget-boolean v12, v0, Lh5/d;->l:Z

    .line 150
    .line 151
    if-nez v12, :cond_b

    .line 152
    .line 153
    iget-boolean v13, v0, Lh5/d;->m:Z

    .line 154
    .line 155
    if-eqz v13, :cond_16

    .line 156
    .line 157
    :cond_b
    if-eqz v12, :cond_f

    .line 158
    .line 159
    iget v12, v0, Lh5/d;->Z:I

    .line 160
    .line 161
    invoke-virtual {v1, v3, v12}, La5/c;->d(La5/h;I)V

    .line 162
    .line 163
    .line 164
    iget v12, v0, Lh5/d;->Z:I

    .line 165
    .line 166
    iget v13, v0, Lh5/d;->V:I

    .line 167
    .line 168
    add-int/2addr v12, v13

    .line 169
    invoke-virtual {v1, v5, v12}, La5/c;->d(La5/h;I)V

    .line 170
    .line 171
    .line 172
    if-eqz v22, :cond_f

    .line 173
    .line 174
    iget-object v12, v0, Lh5/d;->U:Lh5/e;

    .line 175
    .line 176
    if-eqz v12, :cond_f

    .line 177
    .line 178
    iget-object v13, v12, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 179
    .line 180
    if-eqz v13, :cond_c

    .line 181
    .line 182
    invoke-virtual {v13}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v13

    .line 186
    if-eqz v13, :cond_c

    .line 187
    .line 188
    invoke-virtual {v2}, Lh5/c;->d()I

    .line 189
    .line 190
    .line 191
    move-result v13

    .line 192
    iget-object v14, v12, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 193
    .line 194
    invoke-virtual {v14}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 195
    .line 196
    .line 197
    move-result-object v14

    .line 198
    check-cast v14, Lh5/c;

    .line 199
    .line 200
    invoke-virtual {v14}, Lh5/c;->d()I

    .line 201
    .line 202
    .line 203
    move-result v14

    .line 204
    if-le v13, v14, :cond_d

    .line 205
    .line 206
    :cond_c
    new-instance v13, Ljava/lang/ref/WeakReference;

    .line 207
    .line 208
    invoke-direct {v13, v2}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 209
    .line 210
    .line 211
    iput-object v13, v12, Lh5/e;->I0:Ljava/lang/ref/WeakReference;

    .line 212
    .line 213
    :cond_d
    iget-object v13, v12, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 214
    .line 215
    if-eqz v13, :cond_e

    .line 216
    .line 217
    invoke-virtual {v13}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v13

    .line 221
    if-eqz v13, :cond_e

    .line 222
    .line 223
    invoke-virtual {v4}, Lh5/c;->d()I

    .line 224
    .line 225
    .line 226
    move-result v13

    .line 227
    iget-object v14, v12, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 228
    .line 229
    invoke-virtual {v14}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v14

    .line 233
    check-cast v14, Lh5/c;

    .line 234
    .line 235
    invoke-virtual {v14}, Lh5/c;->d()I

    .line 236
    .line 237
    .line 238
    move-result v14

    .line 239
    if-le v13, v14, :cond_f

    .line 240
    .line 241
    :cond_e
    new-instance v13, Ljava/lang/ref/WeakReference;

    .line 242
    .line 243
    invoke-direct {v13, v4}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 244
    .line 245
    .line 246
    iput-object v13, v12, Lh5/e;->K0:Ljava/lang/ref/WeakReference;

    .line 247
    .line 248
    :cond_f
    iget-boolean v12, v0, Lh5/d;->m:Z

    .line 249
    .line 250
    if-eqz v12, :cond_15

    .line 251
    .line 252
    iget v12, v0, Lh5/d;->a0:I

    .line 253
    .line 254
    invoke-virtual {v1, v7, v12}, La5/c;->d(La5/h;I)V

    .line 255
    .line 256
    .line 257
    iget v12, v0, Lh5/d;->a0:I

    .line 258
    .line 259
    iget v13, v0, Lh5/d;->W:I

    .line 260
    .line 261
    add-int/2addr v12, v13

    .line 262
    invoke-virtual {v1, v9, v12}, La5/c;->d(La5/h;I)V

    .line 263
    .line 264
    .line 265
    iget-object v12, v10, Lh5/c;->a:Ljava/util/HashSet;

    .line 266
    .line 267
    if-nez v12, :cond_10

    .line 268
    .line 269
    goto :goto_8

    .line 270
    :cond_10
    invoke-virtual {v12}, Ljava/util/HashSet;->size()I

    .line 271
    .line 272
    .line 273
    move-result v12

    .line 274
    if-lez v12, :cond_11

    .line 275
    .line 276
    iget v12, v0, Lh5/d;->a0:I

    .line 277
    .line 278
    iget v13, v0, Lh5/d;->b0:I

    .line 279
    .line 280
    add-int/2addr v12, v13

    .line 281
    invoke-virtual {v1, v11, v12}, La5/c;->d(La5/h;I)V

    .line 282
    .line 283
    .line 284
    :cond_11
    :goto_8
    if-eqz v20, :cond_15

    .line 285
    .line 286
    iget-object v12, v0, Lh5/d;->U:Lh5/e;

    .line 287
    .line 288
    if-eqz v12, :cond_15

    .line 289
    .line 290
    iget-object v13, v12, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 291
    .line 292
    if-eqz v13, :cond_12

    .line 293
    .line 294
    invoke-virtual {v13}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    move-result-object v13

    .line 298
    if-eqz v13, :cond_12

    .line 299
    .line 300
    invoke-virtual {v6}, Lh5/c;->d()I

    .line 301
    .line 302
    .line 303
    move-result v13

    .line 304
    iget-object v14, v12, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 305
    .line 306
    invoke-virtual {v14}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 307
    .line 308
    .line 309
    move-result-object v14

    .line 310
    check-cast v14, Lh5/c;

    .line 311
    .line 312
    invoke-virtual {v14}, Lh5/c;->d()I

    .line 313
    .line 314
    .line 315
    move-result v14

    .line 316
    if-le v13, v14, :cond_13

    .line 317
    .line 318
    :cond_12
    new-instance v13, Ljava/lang/ref/WeakReference;

    .line 319
    .line 320
    invoke-direct {v13, v6}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 321
    .line 322
    .line 323
    iput-object v13, v12, Lh5/e;->H0:Ljava/lang/ref/WeakReference;

    .line 324
    .line 325
    :cond_13
    iget-object v13, v12, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 326
    .line 327
    if-eqz v13, :cond_14

    .line 328
    .line 329
    invoke-virtual {v13}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 330
    .line 331
    .line 332
    move-result-object v13

    .line 333
    if-eqz v13, :cond_14

    .line 334
    .line 335
    invoke-virtual {v8}, Lh5/c;->d()I

    .line 336
    .line 337
    .line 338
    move-result v13

    .line 339
    iget-object v14, v12, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 340
    .line 341
    invoke-virtual {v14}, Ljava/lang/ref/Reference;->get()Ljava/lang/Object;

    .line 342
    .line 343
    .line 344
    move-result-object v14

    .line 345
    check-cast v14, Lh5/c;

    .line 346
    .line 347
    invoke-virtual {v14}, Lh5/c;->d()I

    .line 348
    .line 349
    .line 350
    move-result v14

    .line 351
    if-le v13, v14, :cond_15

    .line 352
    .line 353
    :cond_14
    new-instance v13, Ljava/lang/ref/WeakReference;

    .line 354
    .line 355
    invoke-direct {v13, v8}, Ljava/lang/ref/WeakReference;-><init>(Ljava/lang/Object;)V

    .line 356
    .line 357
    .line 358
    iput-object v13, v12, Lh5/e;->J0:Ljava/lang/ref/WeakReference;

    .line 359
    .line 360
    :cond_15
    iget-boolean v12, v0, Lh5/d;->l:Z

    .line 361
    .line 362
    if-eqz v12, :cond_16

    .line 363
    .line 364
    iget-boolean v12, v0, Lh5/d;->m:Z

    .line 365
    .line 366
    if-eqz v12, :cond_16

    .line 367
    .line 368
    move/from16 v12, v17

    .line 369
    .line 370
    iput-boolean v12, v0, Lh5/d;->l:Z

    .line 371
    .line 372
    iput-boolean v12, v0, Lh5/d;->m:Z

    .line 373
    .line 374
    return-void

    .line 375
    :cond_16
    iget-object v12, v0, Lh5/d;->f:[Z

    .line 376
    .line 377
    if-eqz p2, :cond_1a

    .line 378
    .line 379
    iget-object v13, v0, Lh5/d;->d:Li5/l;

    .line 380
    .line 381
    if-eqz v13, :cond_1a

    .line 382
    .line 383
    iget-object v14, v0, Lh5/d;->e:Li5/n;

    .line 384
    .line 385
    if-eqz v14, :cond_1a

    .line 386
    .line 387
    move-object/from16 v23, v10

    .line 388
    .line 389
    iget-object v10, v13, Li5/p;->h:Li5/g;

    .line 390
    .line 391
    move-object/from16 v24, v12

    .line 392
    .line 393
    iget-boolean v12, v10, Li5/g;->j:Z

    .line 394
    .line 395
    if-eqz v12, :cond_19

    .line 396
    .line 397
    iget-object v12, v13, Li5/p;->i:Li5/g;

    .line 398
    .line 399
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 400
    .line 401
    if-eqz v12, :cond_19

    .line 402
    .line 403
    iget-object v12, v14, Li5/p;->h:Li5/g;

    .line 404
    .line 405
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 406
    .line 407
    if-eqz v12, :cond_19

    .line 408
    .line 409
    iget-object v12, v14, Li5/p;->i:Li5/g;

    .line 410
    .line 411
    iget-boolean v12, v12, Li5/g;->j:Z

    .line 412
    .line 413
    if-eqz v12, :cond_19

    .line 414
    .line 415
    iget v2, v10, Li5/g;->g:I

    .line 416
    .line 417
    invoke-virtual {v1, v3, v2}, La5/c;->d(La5/h;I)V

    .line 418
    .line 419
    .line 420
    iget-object v2, v0, Lh5/d;->d:Li5/l;

    .line 421
    .line 422
    iget-object v2, v2, Li5/p;->i:Li5/g;

    .line 423
    .line 424
    iget v2, v2, Li5/g;->g:I

    .line 425
    .line 426
    invoke-virtual {v1, v5, v2}, La5/c;->d(La5/h;I)V

    .line 427
    .line 428
    .line 429
    iget-object v2, v0, Lh5/d;->e:Li5/n;

    .line 430
    .line 431
    iget-object v2, v2, Li5/p;->h:Li5/g;

    .line 432
    .line 433
    iget v2, v2, Li5/g;->g:I

    .line 434
    .line 435
    invoke-virtual {v1, v7, v2}, La5/c;->d(La5/h;I)V

    .line 436
    .line 437
    .line 438
    iget-object v2, v0, Lh5/d;->e:Li5/n;

    .line 439
    .line 440
    iget-object v2, v2, Li5/p;->i:Li5/g;

    .line 441
    .line 442
    iget v2, v2, Li5/g;->g:I

    .line 443
    .line 444
    invoke-virtual {v1, v9, v2}, La5/c;->d(La5/h;I)V

    .line 445
    .line 446
    .line 447
    iget-object v2, v0, Lh5/d;->e:Li5/n;

    .line 448
    .line 449
    iget-object v2, v2, Li5/n;->k:Li5/g;

    .line 450
    .line 451
    iget v2, v2, Li5/g;->g:I

    .line 452
    .line 453
    invoke-virtual {v1, v11, v2}, La5/c;->d(La5/h;I)V

    .line 454
    .line 455
    .line 456
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    .line 457
    .line 458
    if-eqz v2, :cond_18

    .line 459
    .line 460
    if-eqz v22, :cond_17

    .line 461
    .line 462
    const/4 v12, 0x0

    .line 463
    aget-boolean v2, v24, v12

    .line 464
    .line 465
    if-eqz v2, :cond_17

    .line 466
    .line 467
    invoke-virtual {v0}, Lh5/d;->y()Z

    .line 468
    .line 469
    .line 470
    move-result v2

    .line 471
    if-nez v2, :cond_17

    .line 472
    .line 473
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    .line 474
    .line 475
    iget-object v2, v2, Lh5/d;->L:Lh5/c;

    .line 476
    .line 477
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 478
    .line 479
    .line 480
    move-result-object v2

    .line 481
    const/16 v3, 0x8

    .line 482
    .line 483
    invoke-virtual {v1, v2, v5, v12, v3}, La5/c;->f(La5/h;La5/h;II)V

    .line 484
    .line 485
    .line 486
    :cond_17
    if-eqz v20, :cond_18

    .line 487
    .line 488
    aget-boolean v2, v24, v18

    .line 489
    .line 490
    if-eqz v2, :cond_18

    .line 491
    .line 492
    invoke-virtual {v0}, Lh5/d;->z()Z

    .line 493
    .line 494
    .line 495
    move-result v2

    .line 496
    if-nez v2, :cond_18

    .line 497
    .line 498
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    .line 499
    .line 500
    iget-object v2, v2, Lh5/d;->M:Lh5/c;

    .line 501
    .line 502
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 503
    .line 504
    .line 505
    move-result-object v2

    .line 506
    const/16 v3, 0x8

    .line 507
    .line 508
    const/4 v12, 0x0

    .line 509
    invoke-virtual {v1, v2, v9, v12, v3}, La5/c;->f(La5/h;La5/h;II)V

    .line 510
    .line 511
    .line 512
    goto :goto_9

    .line 513
    :cond_18
    const/4 v12, 0x0

    .line 514
    :goto_9
    iput-boolean v12, v0, Lh5/d;->l:Z

    .line 515
    .line 516
    iput-boolean v12, v0, Lh5/d;->m:Z

    .line 517
    .line 518
    return-void

    .line 519
    :cond_19
    :goto_a
    const/4 v12, 0x0

    .line 520
    goto :goto_b

    .line 521
    :cond_1a
    move-object/from16 v23, v10

    .line 522
    .line 523
    move-object/from16 v24, v12

    .line 524
    .line 525
    goto :goto_a

    .line 526
    :goto_b
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    .line 527
    .line 528
    if-eqz v10, :cond_1f

    .line 529
    .line 530
    invoke-virtual {v0, v12}, Lh5/d;->x(I)Z

    .line 531
    .line 532
    .line 533
    move-result v10

    .line 534
    if-eqz v10, :cond_1b

    .line 535
    .line 536
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    .line 537
    .line 538
    invoke-virtual {v10, v0, v12}, Lh5/e;->W(Lh5/d;I)V

    .line 539
    .line 540
    .line 541
    move/from16 v10, v18

    .line 542
    .line 543
    move v12, v10

    .line 544
    goto :goto_c

    .line 545
    :cond_1b
    invoke-virtual {v0}, Lh5/d;->y()Z

    .line 546
    .line 547
    .line 548
    move-result v10

    .line 549
    move/from16 v12, v18

    .line 550
    .line 551
    :goto_c
    invoke-virtual {v0, v12}, Lh5/d;->x(I)Z

    .line 552
    .line 553
    .line 554
    move-result v13

    .line 555
    if-eqz v13, :cond_1c

    .line 556
    .line 557
    iget-object v13, v0, Lh5/d;->U:Lh5/e;

    .line 558
    .line 559
    invoke-virtual {v13, v0, v12}, Lh5/e;->W(Lh5/d;I)V

    .line 560
    .line 561
    .line 562
    const/4 v12, 0x1

    .line 563
    goto :goto_d

    .line 564
    :cond_1c
    invoke-virtual {v0}, Lh5/d;->z()Z

    .line 565
    .line 566
    .line 567
    move-result v12

    .line 568
    :goto_d
    if-nez v10, :cond_1d

    .line 569
    .line 570
    if-eqz v22, :cond_1d

    .line 571
    .line 572
    iget v13, v0, Lh5/d;->h0:I

    .line 573
    .line 574
    const/16 v14, 0x8

    .line 575
    .line 576
    if-eq v13, v14, :cond_1d

    .line 577
    .line 578
    iget-object v13, v2, Lh5/c;->f:Lh5/c;

    .line 579
    .line 580
    if-nez v13, :cond_1d

    .line 581
    .line 582
    iget-object v13, v4, Lh5/c;->f:Lh5/c;

    .line 583
    .line 584
    if-nez v13, :cond_1d

    .line 585
    .line 586
    iget-object v13, v0, Lh5/d;->U:Lh5/e;

    .line 587
    .line 588
    iget-object v13, v13, Lh5/d;->L:Lh5/c;

    .line 589
    .line 590
    invoke-virtual {v1, v13}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 591
    .line 592
    .line 593
    move-result-object v13

    .line 594
    move-object/from16 v25, v2

    .line 595
    .line 596
    const/4 v2, 0x0

    .line 597
    const/4 v14, 0x1

    .line 598
    invoke-virtual {v1, v13, v5, v2, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 599
    .line 600
    .line 601
    goto :goto_e

    .line 602
    :cond_1d
    move-object/from16 v25, v2

    .line 603
    .line 604
    :goto_e
    if-nez v12, :cond_1e

    .line 605
    .line 606
    if-eqz v20, :cond_1e

    .line 607
    .line 608
    iget v2, v0, Lh5/d;->h0:I

    .line 609
    .line 610
    const/16 v14, 0x8

    .line 611
    .line 612
    if-eq v2, v14, :cond_1e

    .line 613
    .line 614
    iget-object v2, v6, Lh5/c;->f:Lh5/c;

    .line 615
    .line 616
    if-nez v2, :cond_1e

    .line 617
    .line 618
    iget-object v2, v8, Lh5/c;->f:Lh5/c;

    .line 619
    .line 620
    if-nez v2, :cond_1e

    .line 621
    .line 622
    if-nez v23, :cond_1e

    .line 623
    .line 624
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    .line 625
    .line 626
    iget-object v2, v2, Lh5/d;->M:Lh5/c;

    .line 627
    .line 628
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 629
    .line 630
    .line 631
    move-result-object v2

    .line 632
    const/4 v13, 0x0

    .line 633
    const/4 v14, 0x1

    .line 634
    invoke-virtual {v1, v2, v9, v13, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 635
    .line 636
    .line 637
    :cond_1e
    move-object v2, v4

    .line 638
    move/from16 v4, v20

    .line 639
    .line 640
    move/from16 v20, v12

    .line 641
    .line 642
    move v12, v10

    .line 643
    goto :goto_f

    .line 644
    :cond_1f
    move-object/from16 v25, v2

    .line 645
    .line 646
    move-object v2, v4

    .line 647
    move/from16 v4, v20

    .line 648
    .line 649
    const/4 v12, 0x0

    .line 650
    const/16 v20, 0x0

    .line 651
    .line 652
    :goto_f
    iget v10, v0, Lh5/d;->V:I

    .line 653
    .line 654
    iget v13, v0, Lh5/d;->c0:I

    .line 655
    .line 656
    if-ge v10, v13, :cond_20

    .line 657
    .line 658
    goto :goto_10

    .line 659
    :cond_20
    move v13, v10

    .line 660
    :goto_10
    iget v14, v0, Lh5/d;->W:I

    .line 661
    .line 662
    move-object/from16 v26, v2

    .line 663
    .line 664
    iget v2, v0, Lh5/d;->d0:I

    .line 665
    .line 666
    if-ge v14, v2, :cond_21

    .line 667
    .line 668
    move/from16 v27, v2

    .line 669
    .line 670
    goto :goto_11

    .line 671
    :cond_21
    move/from16 v27, v14

    .line 672
    .line 673
    :goto_11
    iget-object v2, v0, Lh5/d;->q0:[I

    .line 674
    .line 675
    move-object/from16 v28, v2

    .line 676
    .line 677
    const/16 v17, 0x0

    .line 678
    .line 679
    aget v2, v28, v17

    .line 680
    .line 681
    move/from16 v29, v4

    .line 682
    .line 683
    const/4 v4, 0x3

    .line 684
    if-eq v2, v4, :cond_22

    .line 685
    .line 686
    const/16 v30, 0x1

    .line 687
    .line 688
    :goto_12
    move-object/from16 v31, v6

    .line 689
    .line 690
    const/16 v18, 0x1

    .line 691
    .line 692
    goto :goto_13

    .line 693
    :cond_22
    const/16 v30, 0x0

    .line 694
    .line 695
    goto :goto_12

    .line 696
    :goto_13
    aget v6, v28, v18

    .line 697
    .line 698
    if-eq v6, v4, :cond_23

    .line 699
    .line 700
    const/16 v32, 0x1

    .line 701
    .line 702
    goto :goto_14

    .line 703
    :cond_23
    const/16 v32, 0x0

    .line 704
    .line 705
    :goto_14
    iget v4, v0, Lh5/d;->Y:I

    .line 706
    .line 707
    iput v4, v0, Lh5/d;->B:I

    .line 708
    .line 709
    move-object/from16 v33, v7

    .line 710
    .line 711
    iget v7, v0, Lh5/d;->X:F

    .line 712
    .line 713
    iput v7, v0, Lh5/d;->C:F

    .line 714
    .line 715
    move/from16 v34, v7

    .line 716
    .line 717
    iget v7, v0, Lh5/d;->s:I

    .line 718
    .line 719
    move/from16 v35, v7

    .line 720
    .line 721
    iget v7, v0, Lh5/d;->t:I

    .line 722
    .line 723
    const/16 v36, 0x0

    .line 724
    .line 725
    cmpl-float v36, v34, v36

    .line 726
    .line 727
    move/from16 v37, v7

    .line 728
    .line 729
    const/high16 v38, 0x3f800000    # 1.0f

    .line 730
    .line 731
    if-lez v36, :cond_36

    .line 732
    .line 733
    iget v7, v0, Lh5/d;->h0:I

    .line 734
    .line 735
    move-object/from16 v39, v8

    .line 736
    .line 737
    const/16 v8, 0x8

    .line 738
    .line 739
    if-eq v7, v8, :cond_35

    .line 740
    .line 741
    const/4 v7, 0x3

    .line 742
    if-ne v2, v7, :cond_24

    .line 743
    .line 744
    if-nez v35, :cond_24

    .line 745
    .line 746
    move v8, v7

    .line 747
    goto :goto_15

    .line 748
    :cond_24
    move/from16 v8, v35

    .line 749
    .line 750
    :goto_15
    if-ne v6, v7, :cond_25

    .line 751
    .line 752
    if-nez v37, :cond_25

    .line 753
    .line 754
    move-object/from16 v40, v9

    .line 755
    .line 756
    move v9, v7

    .line 757
    goto :goto_16

    .line 758
    :cond_25
    move-object/from16 v40, v9

    .line 759
    .line 760
    move/from16 v9, v37

    .line 761
    .line 762
    :goto_16
    if-ne v2, v7, :cond_30

    .line 763
    .line 764
    if-ne v6, v7, :cond_30

    .line 765
    .line 766
    if-ne v8, v7, :cond_30

    .line 767
    .line 768
    if-ne v9, v7, :cond_30

    .line 769
    .line 770
    const/4 v7, -0x1

    .line 771
    if-ne v4, v7, :cond_27

    .line 772
    .line 773
    if-eqz v30, :cond_26

    .line 774
    .line 775
    if-nez v32, :cond_26

    .line 776
    .line 777
    const/4 v2, 0x0

    .line 778
    iput v2, v0, Lh5/d;->B:I

    .line 779
    .line 780
    goto :goto_17

    .line 781
    :cond_26
    if-nez v30, :cond_27

    .line 782
    .line 783
    if-eqz v32, :cond_27

    .line 784
    .line 785
    const/4 v14, 0x1

    .line 786
    iput v14, v0, Lh5/d;->B:I

    .line 787
    .line 788
    if-ne v4, v7, :cond_27

    .line 789
    .line 790
    div-float v7, v38, v34

    .line 791
    .line 792
    iput v7, v0, Lh5/d;->C:F

    .line 793
    .line 794
    :cond_27
    :goto_17
    iget v2, v0, Lh5/d;->B:I

    .line 795
    .line 796
    if-nez v2, :cond_29

    .line 797
    .line 798
    invoke-virtual/range {v31 .. v31}, Lh5/c;->h()Z

    .line 799
    .line 800
    .line 801
    move-result v2

    .line 802
    if-eqz v2, :cond_28

    .line 803
    .line 804
    invoke-virtual/range {v39 .. v39}, Lh5/c;->h()Z

    .line 805
    .line 806
    .line 807
    move-result v2

    .line 808
    if-nez v2, :cond_29

    .line 809
    .line 810
    :cond_28
    const/4 v14, 0x1

    .line 811
    goto :goto_18

    .line 812
    :cond_29
    const/4 v14, 0x1

    .line 813
    goto :goto_19

    .line 814
    :goto_18
    iput v14, v0, Lh5/d;->B:I

    .line 815
    .line 816
    goto :goto_1a

    .line 817
    :goto_19
    iget v2, v0, Lh5/d;->B:I

    .line 818
    .line 819
    if-ne v2, v14, :cond_2b

    .line 820
    .line 821
    invoke-virtual/range {v25 .. v25}, Lh5/c;->h()Z

    .line 822
    .line 823
    .line 824
    move-result v2

    .line 825
    if-eqz v2, :cond_2a

    .line 826
    .line 827
    invoke-virtual/range {v26 .. v26}, Lh5/c;->h()Z

    .line 828
    .line 829
    .line 830
    move-result v2

    .line 831
    if-nez v2, :cond_2b

    .line 832
    .line 833
    :cond_2a
    const/4 v2, 0x0

    .line 834
    iput v2, v0, Lh5/d;->B:I

    .line 835
    .line 836
    :cond_2b
    :goto_1a
    iget v2, v0, Lh5/d;->B:I

    .line 837
    .line 838
    const/4 v7, -0x1

    .line 839
    if-ne v2, v7, :cond_2e

    .line 840
    .line 841
    invoke-virtual/range {v31 .. v31}, Lh5/c;->h()Z

    .line 842
    .line 843
    .line 844
    move-result v2

    .line 845
    if-eqz v2, :cond_2c

    .line 846
    .line 847
    invoke-virtual/range {v39 .. v39}, Lh5/c;->h()Z

    .line 848
    .line 849
    .line 850
    move-result v2

    .line 851
    if-eqz v2, :cond_2c

    .line 852
    .line 853
    invoke-virtual/range {v25 .. v25}, Lh5/c;->h()Z

    .line 854
    .line 855
    .line 856
    move-result v2

    .line 857
    if-eqz v2, :cond_2c

    .line 858
    .line 859
    invoke-virtual/range {v26 .. v26}, Lh5/c;->h()Z

    .line 860
    .line 861
    .line 862
    move-result v2

    .line 863
    if-nez v2, :cond_2e

    .line 864
    .line 865
    :cond_2c
    invoke-virtual/range {v31 .. v31}, Lh5/c;->h()Z

    .line 866
    .line 867
    .line 868
    move-result v2

    .line 869
    if-eqz v2, :cond_2d

    .line 870
    .line 871
    invoke-virtual/range {v39 .. v39}, Lh5/c;->h()Z

    .line 872
    .line 873
    .line 874
    move-result v2

    .line 875
    if-eqz v2, :cond_2d

    .line 876
    .line 877
    const/4 v2, 0x0

    .line 878
    iput v2, v0, Lh5/d;->B:I

    .line 879
    .line 880
    goto :goto_1b

    .line 881
    :cond_2d
    invoke-virtual/range {v25 .. v25}, Lh5/c;->h()Z

    .line 882
    .line 883
    .line 884
    move-result v2

    .line 885
    if-eqz v2, :cond_2e

    .line 886
    .line 887
    invoke-virtual/range {v26 .. v26}, Lh5/c;->h()Z

    .line 888
    .line 889
    .line 890
    move-result v2

    .line 891
    if-eqz v2, :cond_2e

    .line 892
    .line 893
    iget v2, v0, Lh5/d;->C:F

    .line 894
    .line 895
    div-float v7, v38, v2

    .line 896
    .line 897
    iput v7, v0, Lh5/d;->C:F

    .line 898
    .line 899
    const/4 v14, 0x1

    .line 900
    iput v14, v0, Lh5/d;->B:I

    .line 901
    .line 902
    :cond_2e
    :goto_1b
    iget v2, v0, Lh5/d;->B:I

    .line 903
    .line 904
    const/4 v7, -0x1

    .line 905
    if-ne v2, v7, :cond_31

    .line 906
    .line 907
    iget v2, v0, Lh5/d;->v:I

    .line 908
    .line 909
    if-lez v2, :cond_2f

    .line 910
    .line 911
    iget v4, v0, Lh5/d;->y:I

    .line 912
    .line 913
    if-nez v4, :cond_2f

    .line 914
    .line 915
    const/4 v4, 0x0

    .line 916
    iput v4, v0, Lh5/d;->B:I

    .line 917
    .line 918
    goto :goto_1d

    .line 919
    :cond_2f
    if-nez v2, :cond_31

    .line 920
    .line 921
    iget v2, v0, Lh5/d;->y:I

    .line 922
    .line 923
    if-lez v2, :cond_31

    .line 924
    .line 925
    iget v2, v0, Lh5/d;->C:F

    .line 926
    .line 927
    div-float v7, v38, v2

    .line 928
    .line 929
    iput v7, v0, Lh5/d;->C:F

    .line 930
    .line 931
    const/4 v14, 0x1

    .line 932
    iput v14, v0, Lh5/d;->B:I

    .line 933
    .line 934
    goto :goto_1d

    .line 935
    :cond_30
    if-ne v2, v7, :cond_32

    .line 936
    .line 937
    if-ne v8, v7, :cond_32

    .line 938
    .line 939
    const/4 v7, 0x0

    .line 940
    iput v7, v0, Lh5/d;->B:I

    .line 941
    .line 942
    int-to-float v2, v14

    .line 943
    mul-float v7, v34, v2

    .line 944
    .line 945
    float-to-int v2, v7

    .line 946
    const/4 v7, 0x3

    .line 947
    move v13, v2

    .line 948
    if-eq v6, v7, :cond_31

    .line 949
    .line 950
    move-object/from16 v2, v23

    .line 951
    .line 952
    move/from16 v30, v27

    .line 953
    .line 954
    const/4 v7, 0x4

    .line 955
    const/16 v31, 0x0

    .line 956
    .line 957
    :goto_1c
    move/from16 v23, v9

    .line 958
    .line 959
    goto :goto_22

    .line 960
    :cond_31
    :goto_1d
    move v7, v8

    .line 961
    move-object/from16 v2, v23

    .line 962
    .line 963
    move/from16 v30, v27

    .line 964
    .line 965
    :goto_1e
    const/16 v31, 0x1

    .line 966
    .line 967
    goto :goto_1c

    .line 968
    :cond_32
    if-ne v6, v7, :cond_31

    .line 969
    .line 970
    if-ne v9, v7, :cond_31

    .line 971
    .line 972
    const/4 v14, 0x1

    .line 973
    iput v14, v0, Lh5/d;->B:I

    .line 974
    .line 975
    const/4 v6, -0x1

    .line 976
    if-ne v4, v6, :cond_33

    .line 977
    .line 978
    div-float v4, v38, v34

    .line 979
    .line 980
    iput v4, v0, Lh5/d;->C:F

    .line 981
    .line 982
    :cond_33
    iget v4, v0, Lh5/d;->C:F

    .line 983
    .line 984
    int-to-float v6, v10

    .line 985
    mul-float/2addr v4, v6

    .line 986
    float-to-int v4, v4

    .line 987
    move/from16 v30, v4

    .line 988
    .line 989
    if-eq v2, v7, :cond_34

    .line 990
    .line 991
    move v7, v8

    .line 992
    move-object/from16 v2, v23

    .line 993
    .line 994
    const/16 v23, 0x4

    .line 995
    .line 996
    :goto_1f
    const/16 v31, 0x0

    .line 997
    .line 998
    goto :goto_22

    .line 999
    :cond_34
    move v7, v8

    .line 1000
    move-object/from16 v2, v23

    .line 1001
    .line 1002
    goto :goto_1e

    .line 1003
    :cond_35
    :goto_20
    move-object/from16 v40, v9

    .line 1004
    .line 1005
    goto :goto_21

    .line 1006
    :cond_36
    move-object/from16 v39, v8

    .line 1007
    .line 1008
    goto :goto_20

    .line 1009
    :goto_21
    move-object/from16 v2, v23

    .line 1010
    .line 1011
    move/from16 v30, v27

    .line 1012
    .line 1013
    move/from16 v7, v35

    .line 1014
    .line 1015
    move/from16 v23, v37

    .line 1016
    .line 1017
    goto :goto_1f

    .line 1018
    :goto_22
    iget-object v4, v0, Lh5/d;->u:[I

    .line 1019
    .line 1020
    const/16 v17, 0x0

    .line 1021
    .line 1022
    aput v7, v4, v17

    .line 1023
    .line 1024
    const/16 v18, 0x1

    .line 1025
    .line 1026
    aput v23, v4, v18

    .line 1027
    .line 1028
    if-eqz v31, :cond_38

    .line 1029
    .line 1030
    iget v4, v0, Lh5/d;->B:I

    .line 1031
    .line 1032
    const/4 v6, -0x1

    .line 1033
    if-eqz v4, :cond_37

    .line 1034
    .line 1035
    if-ne v4, v6, :cond_39

    .line 1036
    .line 1037
    :cond_37
    const/4 v4, 0x1

    .line 1038
    goto :goto_23

    .line 1039
    :cond_38
    const/4 v6, -0x1

    .line 1040
    :cond_39
    const/4 v4, 0x0

    .line 1041
    :goto_23
    if-eqz v31, :cond_3b

    .line 1042
    .line 1043
    iget v8, v0, Lh5/d;->B:I

    .line 1044
    .line 1045
    const/4 v14, 0x1

    .line 1046
    if-eq v8, v14, :cond_3a

    .line 1047
    .line 1048
    if-ne v8, v6, :cond_3b

    .line 1049
    .line 1050
    :cond_3a
    const/16 v32, 0x1

    .line 1051
    .line 1052
    :goto_24
    const/16 v17, 0x0

    .line 1053
    .line 1054
    goto :goto_25

    .line 1055
    :cond_3b
    const/16 v32, 0x0

    .line 1056
    .line 1057
    goto :goto_24

    .line 1058
    :goto_25
    aget v6, v28, v17

    .line 1059
    .line 1060
    const/4 v8, 0x2

    .line 1061
    if-ne v6, v8, :cond_3c

    .line 1062
    .line 1063
    instance-of v6, v0, Lh5/e;

    .line 1064
    .line 1065
    if-eqz v6, :cond_3c

    .line 1066
    .line 1067
    const/4 v9, 0x1

    .line 1068
    goto :goto_26

    .line 1069
    :cond_3c
    const/4 v9, 0x0

    .line 1070
    :goto_26
    if-eqz v9, :cond_3d

    .line 1071
    .line 1072
    const/4 v13, 0x0

    .line 1073
    :cond_3d
    iget-object v6, v0, Lh5/d;->Q:Lh5/c;

    .line 1074
    .line 1075
    invoke-virtual {v6}, Lh5/c;->h()Z

    .line 1076
    .line 1077
    .line 1078
    move-result v8

    .line 1079
    const/16 v18, 0x1

    .line 1080
    .line 1081
    xor-int/lit8 v27, v8, 0x1

    .line 1082
    .line 1083
    const/16 v14, 0x8

    .line 1084
    .line 1085
    const/16 v17, 0x0

    .line 1086
    .line 1087
    aget-boolean v21, v15, v17

    .line 1088
    .line 1089
    aget-boolean v34, v15, v18

    .line 1090
    .line 1091
    iget v8, v0, Lh5/d;->p:I

    .line 1092
    .line 1093
    iget-object v10, v0, Lh5/d;->D:[I

    .line 1094
    .line 1095
    const/16 v35, 0x0

    .line 1096
    .line 1097
    const/4 v15, 0x2

    .line 1098
    if-eq v8, v15, :cond_40

    .line 1099
    .line 1100
    iget-boolean v8, v0, Lh5/d;->l:Z

    .line 1101
    .line 1102
    if-nez v8, :cond_40

    .line 1103
    .line 1104
    if-eqz p2, :cond_41

    .line 1105
    .line 1106
    iget-object v8, v0, Lh5/d;->d:Li5/l;

    .line 1107
    .line 1108
    if-eqz v8, :cond_41

    .line 1109
    .line 1110
    iget-object v14, v8, Li5/p;->h:Li5/g;

    .line 1111
    .line 1112
    iget-boolean v15, v14, Li5/g;->j:Z

    .line 1113
    .line 1114
    if-eqz v15, :cond_3e

    .line 1115
    .line 1116
    iget-object v8, v8, Li5/p;->i:Li5/g;

    .line 1117
    .line 1118
    iget-boolean v8, v8, Li5/g;->j:Z

    .line 1119
    .line 1120
    if-nez v8, :cond_3f

    .line 1121
    .line 1122
    :cond_3e
    const/16 v14, 0x8

    .line 1123
    .line 1124
    goto :goto_27

    .line 1125
    :cond_3f
    if-eqz p2, :cond_40

    .line 1126
    .line 1127
    iget v4, v14, Li5/g;->g:I

    .line 1128
    .line 1129
    invoke-virtual {v1, v3, v4}, La5/c;->d(La5/h;I)V

    .line 1130
    .line 1131
    .line 1132
    iget-object v4, v0, Lh5/d;->d:Li5/l;

    .line 1133
    .line 1134
    iget-object v4, v4, Li5/p;->i:Li5/g;

    .line 1135
    .line 1136
    iget v4, v4, Li5/g;->g:I

    .line 1137
    .line 1138
    invoke-virtual {v1, v5, v4}, La5/c;->d(La5/h;I)V

    .line 1139
    .line 1140
    .line 1141
    iget-object v4, v0, Lh5/d;->U:Lh5/e;

    .line 1142
    .line 1143
    if-eqz v4, :cond_40

    .line 1144
    .line 1145
    if-eqz v22, :cond_40

    .line 1146
    .line 1147
    const/4 v13, 0x0

    .line 1148
    aget-boolean v4, v24, v13

    .line 1149
    .line 1150
    if-eqz v4, :cond_40

    .line 1151
    .line 1152
    invoke-virtual {v0}, Lh5/d;->y()Z

    .line 1153
    .line 1154
    .line 1155
    move-result v4

    .line 1156
    if-nez v4, :cond_40

    .line 1157
    .line 1158
    iget-object v4, v0, Lh5/d;->U:Lh5/e;

    .line 1159
    .line 1160
    iget-object v4, v4, Lh5/d;->L:Lh5/c;

    .line 1161
    .line 1162
    invoke-virtual {v1, v4}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1163
    .line 1164
    .line 1165
    move-result-object v4

    .line 1166
    const/16 v14, 0x8

    .line 1167
    .line 1168
    invoke-virtual {v1, v4, v5, v13, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 1169
    .line 1170
    .line 1171
    :cond_40
    move-object/from16 v55, v2

    .line 1172
    .line 1173
    move-object/from16 v49, v3

    .line 1174
    .line 1175
    move-object/from16 v50, v5

    .line 1176
    .line 1177
    move-object/from16 v41, v6

    .line 1178
    .line 1179
    move-object/from16 v46, v10

    .line 1180
    .line 1181
    move-object/from16 v53, v11

    .line 1182
    .line 1183
    move/from16 v19, v12

    .line 1184
    .line 1185
    move/from16 v3, v22

    .line 1186
    .line 1187
    move/from16 v4, v29

    .line 1188
    .line 1189
    move-object/from16 v51, v33

    .line 1190
    .line 1191
    move-object/from16 v54, v39

    .line 1192
    .line 1193
    move-object/from16 v52, v40

    .line 1194
    .line 1195
    move/from16 v22, v7

    .line 1196
    .line 1197
    move-object/from16 v29, v24

    .line 1198
    .line 1199
    goto/16 :goto_2c

    .line 1200
    .line 1201
    :cond_41
    :goto_27
    iget-object v8, v0, Lh5/d;->U:Lh5/e;

    .line 1202
    .line 1203
    if-eqz v8, :cond_42

    .line 1204
    .line 1205
    iget-object v8, v8, Lh5/d;->L:Lh5/c;

    .line 1206
    .line 1207
    invoke-virtual {v1, v8}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1208
    .line 1209
    .line 1210
    move-result-object v8

    .line 1211
    goto :goto_28

    .line 1212
    :cond_42
    move-object/from16 v8, v35

    .line 1213
    .line 1214
    :goto_28
    iget-object v15, v0, Lh5/d;->U:Lh5/e;

    .line 1215
    .line 1216
    if-eqz v15, :cond_43

    .line 1217
    .line 1218
    iget-object v15, v15, Lh5/d;->J:Lh5/c;

    .line 1219
    .line 1220
    invoke-virtual {v1, v15}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1221
    .line 1222
    .line 1223
    move-result-object v15

    .line 1224
    :goto_29
    move-object/from16 v19, v5

    .line 1225
    .line 1226
    const/16 v17, 0x0

    .line 1227
    .line 1228
    goto :goto_2a

    .line 1229
    :cond_43
    move-object/from16 v15, v35

    .line 1230
    .line 1231
    goto :goto_29

    .line 1232
    :goto_2a
    aget-boolean v5, v24, v17

    .line 1233
    .line 1234
    move-object/from16 v26, v3

    .line 1235
    .line 1236
    move/from16 v3, v22

    .line 1237
    .line 1238
    move/from16 v22, v7

    .line 1239
    .line 1240
    move-object v7, v8

    .line 1241
    aget v8, v28, v17

    .line 1242
    .line 1243
    move-object/from16 v36, v19

    .line 1244
    .line 1245
    move/from16 v19, v12

    .line 1246
    .line 1247
    iget v12, v0, Lh5/d;->Z:I

    .line 1248
    .line 1249
    move/from16 v37, v14

    .line 1250
    .line 1251
    iget v14, v0, Lh5/d;->c0:I

    .line 1252
    .line 1253
    move-object/from16 v41, v6

    .line 1254
    .line 1255
    move-object v6, v15

    .line 1256
    aget v15, v10, v17

    .line 1257
    .line 1258
    iget v1, v0, Lh5/d;->e0:F

    .line 1259
    .line 1260
    move/from16 v42, v1

    .line 1261
    .line 1262
    const/16 v18, 0x1

    .line 1263
    .line 1264
    aget v1, v28, v18

    .line 1265
    .line 1266
    move-object/from16 v43, v2

    .line 1267
    .line 1268
    const/4 v2, 0x3

    .line 1269
    if-ne v1, v2, :cond_44

    .line 1270
    .line 1271
    goto :goto_2b

    .line 1272
    :cond_44
    move/from16 v18, v17

    .line 1273
    .line 1274
    :goto_2b
    iget v1, v0, Lh5/d;->v:I

    .line 1275
    .line 1276
    iget v2, v0, Lh5/d;->w:I

    .line 1277
    .line 1278
    move/from16 v44, v1

    .line 1279
    .line 1280
    iget v1, v0, Lh5/d;->x:F

    .line 1281
    .line 1282
    move/from16 v25, v2

    .line 1283
    .line 1284
    const/16 v45, 0x2

    .line 1285
    .line 1286
    const/4 v2, 0x1

    .line 1287
    move-object/from16 v46, v10

    .line 1288
    .line 1289
    iget-object v10, v0, Lh5/d;->J:Lh5/c;

    .line 1290
    .line 1291
    move-object/from16 v47, v11

    .line 1292
    .line 1293
    iget-object v11, v0, Lh5/d;->L:Lh5/c;

    .line 1294
    .line 1295
    move/from16 v17, v4

    .line 1296
    .line 1297
    move-object/from16 v49, v26

    .line 1298
    .line 1299
    move/from16 v4, v29

    .line 1300
    .line 1301
    move-object/from16 v51, v33

    .line 1302
    .line 1303
    move-object/from16 v50, v36

    .line 1304
    .line 1305
    move-object/from16 v54, v39

    .line 1306
    .line 1307
    move-object/from16 v52, v40

    .line 1308
    .line 1309
    move/from16 v16, v42

    .line 1310
    .line 1311
    move-object/from16 v55, v43

    .line 1312
    .line 1313
    move-object/from16 v53, v47

    .line 1314
    .line 1315
    move/from16 v26, v1

    .line 1316
    .line 1317
    move-object/from16 v29, v24

    .line 1318
    .line 1319
    move/from16 v24, v44

    .line 1320
    .line 1321
    move-object/from16 v1, p1

    .line 1322
    .line 1323
    invoke-virtual/range {v0 .. v27}, Lh5/d;->e(La5/c;ZZZZLa5/h;La5/h;IZLh5/c;Lh5/c;IIIIFZZZZZIIIIFZ)V

    .line 1324
    .line 1325
    .line 1326
    :goto_2c
    if-eqz p2, :cond_47

    .line 1327
    .line 1328
    iget-object v2, v0, Lh5/d;->e:Li5/n;

    .line 1329
    .line 1330
    if-eqz v2, :cond_47

    .line 1331
    .line 1332
    iget-object v5, v2, Li5/p;->h:Li5/g;

    .line 1333
    .line 1334
    iget-boolean v6, v5, Li5/g;->j:Z

    .line 1335
    .line 1336
    if-eqz v6, :cond_47

    .line 1337
    .line 1338
    iget-object v2, v2, Li5/p;->i:Li5/g;

    .line 1339
    .line 1340
    iget-boolean v2, v2, Li5/g;->j:Z

    .line 1341
    .line 1342
    if-eqz v2, :cond_47

    .line 1343
    .line 1344
    iget v2, v5, Li5/g;->g:I

    .line 1345
    .line 1346
    move-object/from16 v5, v51

    .line 1347
    .line 1348
    invoke-virtual {v1, v5, v2}, La5/c;->d(La5/h;I)V

    .line 1349
    .line 1350
    .line 1351
    iget-object v2, v0, Lh5/d;->e:Li5/n;

    .line 1352
    .line 1353
    iget-object v2, v2, Li5/p;->i:Li5/g;

    .line 1354
    .line 1355
    iget v2, v2, Li5/g;->g:I

    .line 1356
    .line 1357
    move-object/from16 v6, v52

    .line 1358
    .line 1359
    invoke-virtual {v1, v6, v2}, La5/c;->d(La5/h;I)V

    .line 1360
    .line 1361
    .line 1362
    iget-object v2, v0, Lh5/d;->e:Li5/n;

    .line 1363
    .line 1364
    iget-object v2, v2, Li5/n;->k:Li5/g;

    .line 1365
    .line 1366
    iget v2, v2, Li5/g;->g:I

    .line 1367
    .line 1368
    move-object/from16 v7, v53

    .line 1369
    .line 1370
    invoke-virtual {v1, v7, v2}, La5/c;->d(La5/h;I)V

    .line 1371
    .line 1372
    .line 1373
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    .line 1374
    .line 1375
    if-eqz v2, :cond_46

    .line 1376
    .line 1377
    if-nez v20, :cond_46

    .line 1378
    .line 1379
    if-eqz v4, :cond_46

    .line 1380
    .line 1381
    const/16 v18, 0x1

    .line 1382
    .line 1383
    aget-boolean v8, v29, v18

    .line 1384
    .line 1385
    if-eqz v8, :cond_45

    .line 1386
    .line 1387
    iget-object v2, v2, Lh5/d;->M:Lh5/c;

    .line 1388
    .line 1389
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1390
    .line 1391
    .line 1392
    move-result-object v2

    .line 1393
    const/4 v8, 0x0

    .line 1394
    const/16 v14, 0x8

    .line 1395
    .line 1396
    invoke-virtual {v1, v2, v6, v8, v14}, La5/c;->f(La5/h;La5/h;II)V

    .line 1397
    .line 1398
    .line 1399
    goto :goto_2d

    .line 1400
    :cond_45
    const/4 v8, 0x0

    .line 1401
    const/16 v14, 0x8

    .line 1402
    .line 1403
    goto :goto_2d

    .line 1404
    :cond_46
    const/4 v8, 0x0

    .line 1405
    const/16 v14, 0x8

    .line 1406
    .line 1407
    const/16 v18, 0x1

    .line 1408
    .line 1409
    :goto_2d
    move v15, v8

    .line 1410
    goto :goto_2e

    .line 1411
    :cond_47
    move-object/from16 v5, v51

    .line 1412
    .line 1413
    move-object/from16 v6, v52

    .line 1414
    .line 1415
    move-object/from16 v7, v53

    .line 1416
    .line 1417
    const/4 v8, 0x0

    .line 1418
    const/16 v14, 0x8

    .line 1419
    .line 1420
    const/16 v18, 0x1

    .line 1421
    .line 1422
    move/from16 v15, v18

    .line 1423
    .line 1424
    :goto_2e
    iget v2, v0, Lh5/d;->q:I

    .line 1425
    .line 1426
    const/4 v9, 0x2

    .line 1427
    if-ne v2, v9, :cond_48

    .line 1428
    .line 1429
    move v15, v8

    .line 1430
    :cond_48
    const/4 v2, 0x5

    .line 1431
    if-eqz v15, :cond_53

    .line 1432
    .line 1433
    iget-boolean v10, v0, Lh5/d;->m:Z

    .line 1434
    .line 1435
    if-nez v10, :cond_53

    .line 1436
    .line 1437
    aget v10, v28, v18

    .line 1438
    .line 1439
    if-ne v10, v9, :cond_49

    .line 1440
    .line 1441
    instance-of v10, v0, Lh5/e;

    .line 1442
    .line 1443
    if-eqz v10, :cond_49

    .line 1444
    .line 1445
    move/from16 v15, v18

    .line 1446
    .line 1447
    goto :goto_2f

    .line 1448
    :cond_49
    move v15, v8

    .line 1449
    :goto_2f
    if-eqz v15, :cond_4a

    .line 1450
    .line 1451
    move v13, v8

    .line 1452
    goto :goto_30

    .line 1453
    :cond_4a
    move/from16 v13, v30

    .line 1454
    .line 1455
    :goto_30
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    .line 1456
    .line 1457
    if-eqz v10, :cond_4b

    .line 1458
    .line 1459
    iget-object v10, v10, Lh5/d;->M:Lh5/c;

    .line 1460
    .line 1461
    invoke-virtual {v1, v10}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1462
    .line 1463
    .line 1464
    move-result-object v10

    .line 1465
    goto :goto_31

    .line 1466
    :cond_4b
    move-object/from16 v10, v35

    .line 1467
    .line 1468
    :goto_31
    iget-object v11, v0, Lh5/d;->U:Lh5/e;

    .line 1469
    .line 1470
    if-eqz v11, :cond_4c

    .line 1471
    .line 1472
    iget-object v11, v11, Lh5/d;->K:Lh5/c;

    .line 1473
    .line 1474
    invoke-virtual {v1, v11}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1475
    .line 1476
    .line 1477
    move-result-object v35

    .line 1478
    :cond_4c
    iget v11, v0, Lh5/d;->b0:I

    .line 1479
    .line 1480
    if-gtz v11, :cond_4d

    .line 1481
    .line 1482
    iget v12, v0, Lh5/d;->h0:I

    .line 1483
    .line 1484
    if-ne v12, v14, :cond_51

    .line 1485
    .line 1486
    :cond_4d
    move-object/from16 v12, v55

    .line 1487
    .line 1488
    iget-object v9, v12, Lh5/c;->f:Lh5/c;

    .line 1489
    .line 1490
    if-eqz v9, :cond_4f

    .line 1491
    .line 1492
    invoke-virtual {v1, v7, v5, v11, v14}, La5/c;->e(La5/h;La5/h;II)V

    .line 1493
    .line 1494
    .line 1495
    iget-object v9, v12, Lh5/c;->f:Lh5/c;

    .line 1496
    .line 1497
    invoke-virtual {v1, v9}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1498
    .line 1499
    .line 1500
    move-result-object v9

    .line 1501
    invoke-virtual {v12}, Lh5/c;->e()I

    .line 1502
    .line 1503
    .line 1504
    move-result v11

    .line 1505
    invoke-virtual {v1, v7, v9, v11, v14}, La5/c;->e(La5/h;La5/h;II)V

    .line 1506
    .line 1507
    .line 1508
    if-eqz v4, :cond_4e

    .line 1509
    .line 1510
    move-object/from16 v7, v54

    .line 1511
    .line 1512
    invoke-virtual {v1, v7}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1513
    .line 1514
    .line 1515
    move-result-object v7

    .line 1516
    invoke-virtual {v1, v10, v7, v8, v2}, La5/c;->f(La5/h;La5/h;II)V

    .line 1517
    .line 1518
    .line 1519
    :cond_4e
    move/from16 v27, v8

    .line 1520
    .line 1521
    goto :goto_32

    .line 1522
    :cond_4f
    iget v9, v0, Lh5/d;->h0:I

    .line 1523
    .line 1524
    if-ne v9, v14, :cond_50

    .line 1525
    .line 1526
    invoke-virtual {v12}, Lh5/c;->e()I

    .line 1527
    .line 1528
    .line 1529
    move-result v9

    .line 1530
    invoke-virtual {v1, v7, v5, v9, v14}, La5/c;->e(La5/h;La5/h;II)V

    .line 1531
    .line 1532
    .line 1533
    goto :goto_32

    .line 1534
    :cond_50
    invoke-virtual {v1, v7, v5, v11, v14}, La5/c;->e(La5/h;La5/h;II)V

    .line 1535
    .line 1536
    .line 1537
    :cond_51
    :goto_32
    aget-boolean v7, v29, v18

    .line 1538
    .line 1539
    move/from16 v17, v8

    .line 1540
    .line 1541
    aget v8, v28, v18

    .line 1542
    .line 1543
    iget v12, v0, Lh5/d;->a0:I

    .line 1544
    .line 1545
    iget v14, v0, Lh5/d;->d0:I

    .line 1546
    .line 1547
    aget v9, v46, v18

    .line 1548
    .line 1549
    iget v11, v0, Lh5/d;->f0:F

    .line 1550
    .line 1551
    aget v2, v28, v17

    .line 1552
    .line 1553
    const/4 v1, 0x3

    .line 1554
    move/from16 v16, v18

    .line 1555
    .line 1556
    if-ne v2, v1, :cond_52

    .line 1557
    .line 1558
    goto :goto_33

    .line 1559
    :cond_52
    move/from16 v18, v17

    .line 1560
    .line 1561
    :goto_33
    iget v2, v0, Lh5/d;->y:I

    .line 1562
    .line 1563
    iget v1, v0, Lh5/d;->z:I

    .line 1564
    .line 1565
    move/from16 v21, v1

    .line 1566
    .line 1567
    iget v1, v0, Lh5/d;->A:F

    .line 1568
    .line 1569
    move/from16 v24, v2

    .line 1570
    .line 1571
    const/4 v2, 0x0

    .line 1572
    move-object/from16 v33, v5

    .line 1573
    .line 1574
    move v5, v7

    .line 1575
    move-object v7, v10

    .line 1576
    iget-object v10, v0, Lh5/d;->K:Lh5/c;

    .line 1577
    .line 1578
    move/from16 v48, v16

    .line 1579
    .line 1580
    move/from16 v16, v11

    .line 1581
    .line 1582
    iget-object v11, v0, Lh5/d;->M:Lh5/c;

    .line 1583
    .line 1584
    move/from16 v17, v4

    .line 1585
    .line 1586
    move v4, v3

    .line 1587
    move/from16 v3, v17

    .line 1588
    .line 1589
    move/from16 v17, v15

    .line 1590
    .line 1591
    move v15, v9

    .line 1592
    move/from16 v9, v17

    .line 1593
    .line 1594
    move/from16 v17, v20

    .line 1595
    .line 1596
    move/from16 v20, v19

    .line 1597
    .line 1598
    move/from16 v19, v17

    .line 1599
    .line 1600
    move/from16 v17, v23

    .line 1601
    .line 1602
    move/from16 v23, v22

    .line 1603
    .line 1604
    move/from16 v22, v17

    .line 1605
    .line 1606
    move/from16 v26, v1

    .line 1607
    .line 1608
    move-object/from16 v57, v6

    .line 1609
    .line 1610
    move/from16 v25, v21

    .line 1611
    .line 1612
    move/from16 v17, v32

    .line 1613
    .line 1614
    move-object/from16 v56, v33

    .line 1615
    .line 1616
    move/from16 v21, v34

    .line 1617
    .line 1618
    move-object/from16 v6, v35

    .line 1619
    .line 1620
    move-object/from16 v1, p1

    .line 1621
    .line 1622
    invoke-virtual/range {v0 .. v27}, Lh5/d;->e(La5/c;ZZZZLa5/h;La5/h;IZLh5/c;Lh5/c;IIIIFZZZZZIIIIFZ)V

    .line 1623
    .line 1624
    .line 1625
    goto :goto_34

    .line 1626
    :cond_53
    move-object/from16 v56, v5

    .line 1627
    .line 1628
    move-object/from16 v57, v6

    .line 1629
    .line 1630
    :goto_34
    if-eqz v31, :cond_55

    .line 1631
    .line 1632
    iget v2, v0, Lh5/d;->B:I

    .line 1633
    .line 1634
    const/high16 v3, -0x40800000    # -1.0f

    .line 1635
    .line 1636
    const/4 v14, 0x1

    .line 1637
    if-ne v2, v14, :cond_54

    .line 1638
    .line 1639
    iget v2, v0, Lh5/d;->C:F

    .line 1640
    .line 1641
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 1642
    .line 1643
    .line 1644
    move-result-object v4

    .line 1645
    iget-object v5, v4, La5/b;->d:La5/a;

    .line 1646
    .line 1647
    move-object/from16 v6, v57

    .line 1648
    .line 1649
    invoke-virtual {v5, v6, v3}, La5/a;->g(La5/h;F)V

    .line 1650
    .line 1651
    .line 1652
    iget-object v3, v4, La5/b;->d:La5/a;

    .line 1653
    .line 1654
    move-object/from16 v5, v56

    .line 1655
    .line 1656
    const/high16 v7, 0x3f800000    # 1.0f

    .line 1657
    .line 1658
    invoke-virtual {v3, v5, v7}, La5/a;->g(La5/h;F)V

    .line 1659
    .line 1660
    .line 1661
    iget-object v3, v4, La5/b;->d:La5/a;

    .line 1662
    .line 1663
    move-object/from16 v8, v50

    .line 1664
    .line 1665
    invoke-virtual {v3, v8, v2}, La5/a;->g(La5/h;F)V

    .line 1666
    .line 1667
    .line 1668
    iget-object v3, v4, La5/b;->d:La5/a;

    .line 1669
    .line 1670
    neg-float v2, v2

    .line 1671
    move-object/from16 v9, v49

    .line 1672
    .line 1673
    invoke-virtual {v3, v9, v2}, La5/a;->g(La5/h;F)V

    .line 1674
    .line 1675
    .line 1676
    invoke-virtual {v1, v4}, La5/c;->c(La5/b;)V

    .line 1677
    .line 1678
    .line 1679
    goto :goto_35

    .line 1680
    :cond_54
    move-object/from16 v9, v49

    .line 1681
    .line 1682
    move-object/from16 v8, v50

    .line 1683
    .line 1684
    move-object/from16 v5, v56

    .line 1685
    .line 1686
    move-object/from16 v6, v57

    .line 1687
    .line 1688
    const/high16 v7, 0x3f800000    # 1.0f

    .line 1689
    .line 1690
    iget v2, v0, Lh5/d;->C:F

    .line 1691
    .line 1692
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 1693
    .line 1694
    .line 1695
    move-result-object v4

    .line 1696
    iget-object v10, v4, La5/b;->d:La5/a;

    .line 1697
    .line 1698
    invoke-virtual {v10, v8, v3}, La5/a;->g(La5/h;F)V

    .line 1699
    .line 1700
    .line 1701
    iget-object v3, v4, La5/b;->d:La5/a;

    .line 1702
    .line 1703
    invoke-virtual {v3, v9, v7}, La5/a;->g(La5/h;F)V

    .line 1704
    .line 1705
    .line 1706
    iget-object v3, v4, La5/b;->d:La5/a;

    .line 1707
    .line 1708
    invoke-virtual {v3, v6, v2}, La5/a;->g(La5/h;F)V

    .line 1709
    .line 1710
    .line 1711
    iget-object v3, v4, La5/b;->d:La5/a;

    .line 1712
    .line 1713
    neg-float v2, v2

    .line 1714
    invoke-virtual {v3, v5, v2}, La5/a;->g(La5/h;F)V

    .line 1715
    .line 1716
    .line 1717
    invoke-virtual {v1, v4}, La5/c;->c(La5/b;)V

    .line 1718
    .line 1719
    .line 1720
    :cond_55
    :goto_35
    invoke-virtual/range {v41 .. v41}, Lh5/c;->h()Z

    .line 1721
    .line 1722
    .line 1723
    move-result v2

    .line 1724
    if-eqz v2, :cond_56

    .line 1725
    .line 1726
    move-object/from16 v2, v41

    .line 1727
    .line 1728
    iget-object v3, v2, Lh5/c;->f:Lh5/c;

    .line 1729
    .line 1730
    iget-object v3, v3, Lh5/c;->d:Lh5/d;

    .line 1731
    .line 1732
    iget v4, v0, Lh5/d;->E:F

    .line 1733
    .line 1734
    const/high16 v5, 0x42b40000    # 90.0f

    .line 1735
    .line 1736
    add-float/2addr v4, v5

    .line 1737
    float-to-double v4, v4

    .line 1738
    invoke-static {v4, v5}, Ljava/lang/Math;->toRadians(D)D

    .line 1739
    .line 1740
    .line 1741
    move-result-wide v4

    .line 1742
    double-to-float v4, v4

    .line 1743
    invoke-virtual {v2}, Lh5/c;->e()I

    .line 1744
    .line 1745
    .line 1746
    move-result v2

    .line 1747
    const/4 v15, 0x2

    .line 1748
    invoke-virtual {v0, v15}, Lh5/d;->j(I)Lh5/c;

    .line 1749
    .line 1750
    .line 1751
    move-result-object v5

    .line 1752
    invoke-virtual {v1, v5}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1753
    .line 1754
    .line 1755
    move-result-object v5

    .line 1756
    const/4 v7, 0x3

    .line 1757
    invoke-virtual {v0, v7}, Lh5/d;->j(I)Lh5/c;

    .line 1758
    .line 1759
    .line 1760
    move-result-object v6

    .line 1761
    invoke-virtual {v1, v6}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1762
    .line 1763
    .line 1764
    move-result-object v6

    .line 1765
    const/4 v8, 0x4

    .line 1766
    invoke-virtual {v0, v8}, Lh5/d;->j(I)Lh5/c;

    .line 1767
    .line 1768
    .line 1769
    move-result-object v9

    .line 1770
    invoke-virtual {v1, v9}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1771
    .line 1772
    .line 1773
    move-result-object v9

    .line 1774
    const/4 v10, 0x5

    .line 1775
    invoke-virtual {v0, v10}, Lh5/d;->j(I)Lh5/c;

    .line 1776
    .line 1777
    .line 1778
    move-result-object v11

    .line 1779
    invoke-virtual {v1, v11}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1780
    .line 1781
    .line 1782
    move-result-object v11

    .line 1783
    invoke-virtual {v3, v15}, Lh5/d;->j(I)Lh5/c;

    .line 1784
    .line 1785
    .line 1786
    move-result-object v12

    .line 1787
    invoke-virtual {v1, v12}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1788
    .line 1789
    .line 1790
    move-result-object v12

    .line 1791
    invoke-virtual {v3, v7}, Lh5/d;->j(I)Lh5/c;

    .line 1792
    .line 1793
    .line 1794
    move-result-object v7

    .line 1795
    invoke-virtual {v1, v7}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1796
    .line 1797
    .line 1798
    move-result-object v7

    .line 1799
    invoke-virtual {v3, v8}, Lh5/d;->j(I)Lh5/c;

    .line 1800
    .line 1801
    .line 1802
    move-result-object v8

    .line 1803
    invoke-virtual {v1, v8}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1804
    .line 1805
    .line 1806
    move-result-object v8

    .line 1807
    invoke-virtual {v3, v10}, Lh5/d;->j(I)Lh5/c;

    .line 1808
    .line 1809
    .line 1810
    move-result-object v3

    .line 1811
    invoke-virtual {v1, v3}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 1812
    .line 1813
    .line 1814
    move-result-object v3

    .line 1815
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 1816
    .line 1817
    .line 1818
    move-result-object v10

    .line 1819
    float-to-double v13, v4

    .line 1820
    invoke-static {v13, v14}, Ljava/lang/Math;->sin(D)D

    .line 1821
    .line 1822
    .line 1823
    move-result-wide v15

    .line 1824
    move-wide/from16 v17, v13

    .line 1825
    .line 1826
    int-to-double v13, v2

    .line 1827
    move-wide/from16 v19, v13

    .line 1828
    .line 1829
    mul-double v13, v15, v19

    .line 1830
    .line 1831
    double-to-float v2, v13

    .line 1832
    iget-object v4, v10, La5/b;->d:La5/a;

    .line 1833
    .line 1834
    const/high16 v13, 0x3f000000    # 0.5f

    .line 1835
    .line 1836
    invoke-virtual {v4, v7, v13}, La5/a;->g(La5/h;F)V

    .line 1837
    .line 1838
    .line 1839
    iget-object v4, v10, La5/b;->d:La5/a;

    .line 1840
    .line 1841
    invoke-virtual {v4, v3, v13}, La5/a;->g(La5/h;F)V

    .line 1842
    .line 1843
    .line 1844
    iget-object v3, v10, La5/b;->d:La5/a;

    .line 1845
    .line 1846
    const/high16 v4, -0x41000000    # -0.5f

    .line 1847
    .line 1848
    invoke-virtual {v3, v6, v4}, La5/a;->g(La5/h;F)V

    .line 1849
    .line 1850
    .line 1851
    iget-object v3, v10, La5/b;->d:La5/a;

    .line 1852
    .line 1853
    invoke-virtual {v3, v11, v4}, La5/a;->g(La5/h;F)V

    .line 1854
    .line 1855
    .line 1856
    neg-float v2, v2

    .line 1857
    iput v2, v10, La5/b;->b:F

    .line 1858
    .line 1859
    invoke-virtual {v1, v10}, La5/c;->c(La5/b;)V

    .line 1860
    .line 1861
    .line 1862
    invoke-virtual {v1}, La5/c;->l()La5/b;

    .line 1863
    .line 1864
    .line 1865
    move-result-object v2

    .line 1866
    invoke-static/range {v17 .. v18}, Ljava/lang/Math;->cos(D)D

    .line 1867
    .line 1868
    .line 1869
    move-result-wide v6

    .line 1870
    mul-double v6, v6, v19

    .line 1871
    .line 1872
    double-to-float v3, v6

    .line 1873
    iget-object v6, v2, La5/b;->d:La5/a;

    .line 1874
    .line 1875
    invoke-virtual {v6, v12, v13}, La5/a;->g(La5/h;F)V

    .line 1876
    .line 1877
    .line 1878
    iget-object v6, v2, La5/b;->d:La5/a;

    .line 1879
    .line 1880
    invoke-virtual {v6, v8, v13}, La5/a;->g(La5/h;F)V

    .line 1881
    .line 1882
    .line 1883
    iget-object v6, v2, La5/b;->d:La5/a;

    .line 1884
    .line 1885
    invoke-virtual {v6, v5, v4}, La5/a;->g(La5/h;F)V

    .line 1886
    .line 1887
    .line 1888
    iget-object v5, v2, La5/b;->d:La5/a;

    .line 1889
    .line 1890
    invoke-virtual {v5, v9, v4}, La5/a;->g(La5/h;F)V

    .line 1891
    .line 1892
    .line 1893
    neg-float v3, v3

    .line 1894
    iput v3, v2, La5/b;->b:F

    .line 1895
    .line 1896
    invoke-virtual {v1, v2}, La5/c;->c(La5/b;)V

    .line 1897
    .line 1898
    .line 1899
    :cond_56
    const/4 v2, 0x0

    .line 1900
    iput-boolean v2, v0, Lh5/d;->l:Z

    .line 1901
    .line 1902
    iput-boolean v2, v0, Lh5/d;->m:Z

    .line 1903
    .line 1904
    return-void
.end method

.method public d()Z
    .locals 1

    .line 1
    iget p0, p0, Lh5/d;->h0:I

    .line 2
    .line 3
    const/16 v0, 0x8

    .line 4
    .line 5
    if-eq p0, v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    const/4 p0, 0x0

    .line 10
    return p0
.end method

.method public final e(La5/c;ZZZZLa5/h;La5/h;IZLh5/c;Lh5/c;IIIIFZZZZZIIIIFZ)V
    .locals 29

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    move-object/from16 v12, p10

    move-object/from16 v13, p11

    move/from16 v14, p14

    move/from16 v2, p15

    move/from16 v4, p24

    move/from16 v5, p25

    move/from16 v6, p26

    .line 1
    invoke-virtual {v1, v12}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v7

    .line 2
    invoke-virtual {v1, v13}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v8

    .line 3
    iget-object v9, v12, Lh5/c;->f:Lh5/c;

    .line 4
    invoke-virtual {v1, v9}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v9

    .line 5
    iget-object v15, v13, Lh5/c;->f:Lh5/c;

    .line 6
    invoke-virtual {v1, v15}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v15

    .line 7
    invoke-virtual {v12}, Lh5/c;->h()Z

    move-result v16

    .line 8
    invoke-virtual {v13}, Lh5/c;->h()Z

    move-result v17

    .line 9
    iget-object v11, v0, Lh5/d;->Q:Lh5/c;

    invoke-virtual {v11}, Lh5/c;->h()Z

    move-result v11

    if-eqz v17, :cond_0

    add-int/lit8 v18, v16, 0x1

    goto :goto_0

    :cond_0
    move/from16 v18, v16

    :goto_0
    if-eqz v11, :cond_1

    add-int/lit8 v18, v18, 0x1

    :cond_1
    move/from16 v19, v11

    move/from16 v11, v18

    if-eqz p17, :cond_2

    const/4 v3, 0x3

    goto :goto_1

    :cond_2
    move/from16 v3, p22

    .line 10
    :goto_1
    invoke-static/range {p8 .. p8}, Lu/w;->o(I)I

    move-result v13

    const/4 v10, 0x1

    move-object/from16 v20, v15

    if-eqz v13, :cond_3

    if-eq v13, v10, :cond_3

    const/4 v10, 0x2

    if-eq v13, v10, :cond_4

    :cond_3
    const/4 v10, 0x0

    goto :goto_2

    :cond_4
    const/4 v10, 0x4

    if-eq v3, v10, :cond_3

    const/4 v10, 0x1

    .line 11
    :goto_2
    iget v13, v0, Lh5/d;->h:I

    const/4 v15, -0x1

    if-eq v13, v15, :cond_5

    if-eqz p2, :cond_5

    .line 12
    iput v15, v0, Lh5/d;->h:I

    const/16 p13, 0x0

    goto :goto_3

    :cond_5
    move/from16 v13, p13

    move/from16 p13, v10

    .line 13
    :goto_3
    iget v10, v0, Lh5/d;->i:I

    if-eq v10, v15, :cond_6

    if-nez p2, :cond_6

    .line 14
    iput v15, v0, Lh5/d;->i:I

    move v13, v10

    const/4 v10, 0x0

    goto :goto_4

    :cond_6
    move/from16 v10, p13

    .line 15
    :goto_4
    iget v15, v0, Lh5/d;->h0:I

    move/from16 p13, v10

    const/16 v10, 0x8

    if-ne v15, v10, :cond_7

    const/4 v13, 0x0

    const/4 v15, 0x0

    goto :goto_5

    :cond_7
    move v15, v13

    move/from16 v13, p13

    :goto_5
    if-eqz p27, :cond_a

    if-nez v16, :cond_9

    if-nez v17, :cond_9

    if-nez v19, :cond_9

    move/from16 v10, p12

    .line 16
    invoke-virtual {v1, v7, v10}, La5/c;->d(La5/h;I)V

    :cond_8
    move/from16 v24, v13

    const/16 v13, 0x8

    goto :goto_6

    :cond_9
    if-eqz v16, :cond_8

    if-nez v17, :cond_8

    .line 17
    invoke-virtual {v12}, Lh5/c;->e()I

    move-result v10

    move/from16 v24, v13

    const/16 v13, 0x8

    .line 18
    invoke-virtual {v1, v7, v9, v10, v13}, La5/c;->e(La5/h;La5/h;II)V

    goto :goto_6

    :cond_a
    move/from16 v24, v13

    move v13, v10

    :goto_6
    if-nez v24, :cond_e

    if-eqz p9, :cond_c

    const/4 v6, 0x3

    const/4 v10, 0x0

    .line 19
    invoke-virtual {v1, v8, v7, v10, v6}, La5/c;->e(La5/h;La5/h;II)V

    if-lez v14, :cond_b

    .line 20
    invoke-virtual {v1, v8, v7, v14, v13}, La5/c;->f(La5/h;La5/h;II)V

    :cond_b
    const v6, 0x7fffffff

    if-ge v2, v6, :cond_d

    .line 21
    invoke-virtual {v1, v8, v7, v2, v13}, La5/c;->g(La5/h;La5/h;II)V

    goto :goto_7

    .line 22
    :cond_c
    invoke-virtual {v1, v8, v7, v15, v13}, La5/c;->e(La5/h;La5/h;II)V

    :cond_d
    :goto_7
    move/from16 v10, p5

    move v13, v4

    goto/16 :goto_b

    :cond_e
    const/4 v10, 0x2

    if-eq v11, v10, :cond_11

    if-nez p17, :cond_11

    const/4 v2, 0x1

    if-eq v3, v2, :cond_f

    if-nez v3, :cond_11

    .line 23
    :cond_f
    invoke-static {v4, v15}, Ljava/lang/Math;->max(II)I

    move-result v2

    if-lez v5, :cond_10

    .line 24
    invoke-static {v5, v2}, Ljava/lang/Math;->min(II)I

    move-result v2

    :cond_10
    const/16 v13, 0x8

    .line 25
    invoke-virtual {v1, v8, v7, v2, v13}, La5/c;->e(La5/h;La5/h;II)V

    move/from16 v10, p5

    move v13, v4

    const/16 v24, 0x0

    goto/16 :goto_b

    :cond_11
    const/4 v2, -0x2

    if-ne v4, v2, :cond_12

    move v4, v15

    :cond_12
    if-ne v5, v2, :cond_13

    move v5, v15

    :cond_13
    if-lez v15, :cond_14

    const/4 v2, 0x1

    if-eq v3, v2, :cond_14

    const/4 v15, 0x0

    :cond_14
    const/16 v13, 0x8

    if-lez v4, :cond_15

    .line 26
    invoke-virtual {v1, v8, v7, v4, v13}, La5/c;->f(La5/h;La5/h;II)V

    .line 27
    invoke-static {v15, v4}, Ljava/lang/Math;->max(II)I

    move-result v15

    :cond_15
    const/4 v2, 0x1

    if-lez v5, :cond_17

    if-eqz p3, :cond_16

    if-ne v3, v2, :cond_16

    goto :goto_8

    .line 28
    :cond_16
    invoke-virtual {v1, v8, v7, v5, v13}, La5/c;->g(La5/h;La5/h;II)V

    .line 29
    :goto_8
    invoke-static {v15, v5}, Ljava/lang/Math;->min(II)I

    move-result v15

    :cond_17
    if-ne v3, v2, :cond_1a

    if-eqz p3, :cond_18

    .line 30
    invoke-virtual {v1, v8, v7, v15, v13}, La5/c;->e(La5/h;La5/h;II)V

    const/4 v2, 0x5

    goto :goto_7

    :cond_18
    if-eqz p19, :cond_19

    const/4 v2, 0x5

    .line 31
    invoke-virtual {v1, v8, v7, v15, v2}, La5/c;->e(La5/h;La5/h;II)V

    .line 32
    invoke-virtual {v1, v8, v7, v15, v13}, La5/c;->g(La5/h;La5/h;II)V

    goto :goto_7

    :cond_19
    const/4 v2, 0x5

    .line 33
    invoke-virtual {v1, v8, v7, v15, v2}, La5/c;->e(La5/h;La5/h;II)V

    .line 34
    invoke-virtual {v1, v8, v7, v15, v13}, La5/c;->g(La5/h;La5/h;II)V

    goto :goto_7

    :cond_1a
    const/4 v2, 0x5

    const/4 v10, 0x2

    if-ne v3, v10, :cond_1e

    .line 35
    iget v13, v12, Lh5/c;->e:I

    const/4 v15, 0x3

    if-eq v13, v15, :cond_1b

    if-ne v13, v2, :cond_1c

    :cond_1b
    const/4 v13, 0x4

    goto :goto_9

    .line 36
    :cond_1c
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    .line 37
    invoke-virtual {v2, v10}, Lh5/d;->j(I)Lh5/c;

    move-result-object v2

    .line 38
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v2

    .line 39
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    const/4 v13, 0x4

    .line 40
    invoke-virtual {v10, v13}, Lh5/d;->j(I)Lh5/c;

    move-result-object v10

    .line 41
    invoke-virtual {v1, v10}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v10

    goto :goto_a

    .line 42
    :goto_9
    iget-object v2, v0, Lh5/d;->U:Lh5/e;

    const/4 v15, 0x3

    .line 43
    invoke-virtual {v2, v15}, Lh5/d;->j(I)Lh5/c;

    move-result-object v2

    .line 44
    invoke-virtual {v1, v2}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v2

    .line 45
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    const/4 v15, 0x5

    .line 46
    invoke-virtual {v10, v15}, Lh5/d;->j(I)Lh5/c;

    move-result-object v10

    .line 47
    invoke-virtual {v1, v10}, La5/c;->k(Ljava/lang/Object;)La5/h;

    move-result-object v10

    .line 48
    :goto_a
    invoke-virtual {v1}, La5/c;->l()La5/b;

    move-result-object v15

    .line 49
    iget-object v13, v15, La5/b;->d:La5/a;

    move/from16 p9, v4

    const/high16 v4, -0x40800000    # -1.0f

    invoke-virtual {v13, v8, v4}, La5/a;->g(La5/h;F)V

    .line 50
    iget-object v4, v15, La5/b;->d:La5/a;

    const/high16 v13, 0x3f800000    # 1.0f

    invoke-virtual {v4, v7, v13}, La5/a;->g(La5/h;F)V

    .line 51
    iget-object v4, v15, La5/b;->d:La5/a;

    invoke-virtual {v4, v10, v6}, La5/a;->g(La5/h;F)V

    .line 52
    iget-object v4, v15, La5/b;->d:La5/a;

    neg-float v6, v6

    invoke-virtual {v4, v2, v6}, La5/a;->g(La5/h;F)V

    .line 53
    invoke-virtual {v1, v15}, La5/c;->c(La5/b;)V

    if-eqz p3, :cond_1d

    const/16 v24, 0x0

    :cond_1d
    move/from16 v10, p5

    move/from16 v13, p9

    goto :goto_b

    :cond_1e
    move/from16 p9, v4

    move/from16 v13, p9

    const/4 v10, 0x1

    :goto_b
    if-eqz p27, :cond_1f

    if-eqz p19, :cond_20

    :cond_1f
    move-object/from16 v15, p6

    move-object/from16 v4, p7

    move-object v2, v7

    move-object v7, v8

    move/from16 p5, v10

    const/4 v3, 0x3

    const/4 v10, 0x2

    goto/16 :goto_2c

    :cond_20
    if-nez v16, :cond_21

    if-nez v17, :cond_21

    if-nez v19, :cond_21

    move-object/from16 v13, p11

    move-object v7, v8

    move/from16 p5, v10

    move-object/from16 v6, v20

    :goto_c
    const/4 v15, 0x5

    goto/16 :goto_28

    :cond_21
    if-eqz v16, :cond_23

    if-nez v17, :cond_23

    .line 54
    iget-object v0, v12, Lh5/c;->f:Lh5/c;

    iget-object v0, v0, Lh5/c;->d:Lh5/d;

    if-eqz p3, :cond_22

    .line 55
    instance-of v0, v0, Lh5/a;

    if-eqz v0, :cond_22

    const/16 v0, 0x8

    goto :goto_d

    :cond_22
    const/4 v0, 0x5

    :goto_d
    move-object/from16 v13, p11

    move-object v7, v8

    move/from16 p5, v10

    move-object/from16 v6, v20

    move/from16 v20, p3

    move v10, v0

    goto/16 :goto_29

    :cond_23
    if-nez v16, :cond_25

    if-eqz v17, :cond_25

    .line 56
    invoke-virtual/range {p11 .. p11}, Lh5/c;->e()I

    move-result v0

    neg-int v0, v0

    move-object/from16 v6, v20

    const/16 v13, 0x8

    .line 57
    invoke-virtual {v1, v8, v6, v0, v13}, La5/c;->e(La5/h;La5/h;II)V

    if-eqz p3, :cond_24

    move-object/from16 v15, p6

    const/4 v0, 0x0

    const/4 v2, 0x5

    .line 58
    invoke-virtual {v1, v7, v15, v0, v2}, La5/c;->f(La5/h;La5/h;II)V

    move-object/from16 v13, p11

    move v15, v2

    move-object v7, v8

    move/from16 p5, v10

    goto/16 :goto_28

    :cond_24
    move-object/from16 v13, p11

    move-object v7, v8

    move/from16 p5, v10

    goto :goto_c

    :cond_25
    move-object/from16 v15, p6

    move-object/from16 v6, v20

    if-eqz v16, :cond_24

    if-eqz v17, :cond_24

    .line 59
    iget-object v2, v12, Lh5/c;->f:Lh5/c;

    iget-object v11, v2, Lh5/c;->d:Lh5/d;

    move-object/from16 v2, p11

    .line 60
    iget-object v4, v2, Lh5/c;->f:Lh5/c;

    iget-object v4, v4, Lh5/c;->d:Lh5/d;

    move/from16 p5, v10

    .line 61
    iget-object v10, v0, Lh5/d;->U:Lh5/e;

    const/16 v16, 0x6

    if-eqz v24, :cond_3a

    if-nez v3, :cond_2a

    if-nez v5, :cond_27

    if-nez v13, :cond_27

    .line 62
    iget-boolean v5, v9, La5/h;->i:Z

    if-eqz v5, :cond_26

    iget-boolean v5, v6, La5/h;->i:Z

    if-eqz v5, :cond_26

    .line 63
    invoke-virtual {v12}, Lh5/c;->e()I

    move-result v0

    const/16 v13, 0x8

    .line 64
    invoke-virtual {v1, v7, v9, v0, v13}, La5/c;->e(La5/h;La5/h;II)V

    .line 65
    invoke-virtual {v2}, Lh5/c;->e()I

    move-result v0

    neg-int v0, v0

    .line 66
    invoke-virtual {v1, v8, v6, v0, v13}, La5/c;->e(La5/h;La5/h;II)V

    return-void

    :cond_26
    const/16 v5, 0x8

    const/16 v17, 0x8

    const/16 v19, 0x0

    const/16 v20, 0x1

    const/16 v23, 0x0

    goto :goto_e

    :cond_27
    const/4 v5, 0x5

    const/16 v17, 0x5

    const/16 v19, 0x1

    const/16 v20, 0x0

    const/16 v23, 0x1

    .line 67
    :goto_e
    instance-of v1, v11, Lh5/a;

    if-nez v1, :cond_29

    instance-of v1, v4, Lh5/a;

    if-eqz v1, :cond_28

    goto :goto_10

    :cond_28
    move-object/from16 v1, p1

    move-object v2, v7

    move-object v7, v8

    move/from16 v25, v20

    move v8, v5

    move-object v5, v9

    move/from16 v9, v16

    move/from16 v20, v19

    move/from16 v19, v17

    move/from16 v17, v3

    :goto_f
    move-object/from16 v3, p7

    goto/16 :goto_1d

    :cond_29
    :goto_10
    move-object/from16 v1, p1

    move/from16 v17, v3

    move-object v2, v7

    move-object v7, v8

    move/from16 v25, v20

    move-object/from16 v3, p7

    move v8, v5

    move-object v5, v9

    move/from16 v9, v16

    move/from16 v20, v19

    const/16 v19, 0x4

    goto/16 :goto_1d

    :cond_2a
    const/4 v1, 0x2

    if-ne v3, v1, :cond_2d

    .line 68
    instance-of v1, v11, Lh5/a;

    if-nez v1, :cond_2c

    instance-of v1, v4, Lh5/a;

    if-eqz v1, :cond_2b

    goto :goto_12

    :cond_2b
    move-object/from16 v1, p1

    move/from16 v17, v3

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    const/16 v19, 0x5

    :goto_11
    const/16 v20, 0x1

    const/16 v23, 0x1

    const/16 v25, 0x0

    goto :goto_f

    :cond_2c
    :goto_12
    move-object/from16 v1, p1

    move/from16 v17, v3

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    :goto_13
    const/16 v19, 0x4

    goto :goto_11

    :cond_2d
    const/4 v1, 0x1

    if-ne v3, v1, :cond_2e

    move-object/from16 v1, p1

    move/from16 v17, v3

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/16 v8, 0x8

    goto :goto_13

    :cond_2e
    const/4 v1, 0x3

    if-ne v3, v1, :cond_39

    .line 69
    iget v1, v0, Lh5/d;->B:I

    move/from16 v17, v3

    const/4 v3, -0x1

    if-ne v1, v3, :cond_31

    if-eqz p20, :cond_30

    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    const/16 v8, 0x8

    if-eqz p3, :cond_2f

    const/4 v9, 0x5

    :goto_14
    const/16 v19, 0x5

    :goto_15
    const/16 v20, 0x1

    const/16 v23, 0x1

    const/16 v25, 0x1

    goto/16 :goto_1d

    :cond_2f
    const/4 v9, 0x4

    goto :goto_14

    :cond_30
    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    const/16 v8, 0x8

    const/16 v9, 0x8

    goto :goto_14

    :cond_31
    if-eqz p17, :cond_34

    move/from16 v3, p23

    const/4 v1, 0x2

    if-eq v3, v1, :cond_33

    const/4 v1, 0x1

    if-ne v3, v1, :cond_32

    goto :goto_16

    :cond_32
    const/16 v1, 0x8

    const/4 v3, 0x5

    goto :goto_17

    :cond_33
    :goto_16
    const/4 v1, 0x5

    const/4 v3, 0x4

    :goto_17
    move/from16 v19, v3

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/16 v20, 0x1

    const/16 v23, 0x1

    const/16 v25, 0x1

    move-object/from16 v3, p7

    :goto_18
    move v8, v1

    move-object/from16 v1, p1

    goto/16 :goto_1d

    :cond_34
    if-lez v5, :cond_35

    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    goto :goto_14

    :cond_35
    if-nez v5, :cond_38

    if-nez v13, :cond_38

    if-nez p20, :cond_36

    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    const/16 v19, 0x8

    goto :goto_15

    :cond_36
    if-eq v11, v10, :cond_37

    if-eq v4, v10, :cond_37

    const/4 v1, 0x4

    goto :goto_19

    :cond_37
    const/4 v1, 0x5

    :goto_19
    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/16 v19, 0x4

    const/16 v20, 0x1

    const/16 v23, 0x1

    const/16 v25, 0x1

    goto :goto_18

    :cond_38
    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    const/16 v19, 0x4

    goto :goto_15

    :cond_39
    move/from16 v17, v3

    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    const/16 v19, 0x4

    const/16 v20, 0x0

    const/16 v23, 0x0

    :goto_1a
    const/16 v25, 0x0

    goto :goto_1d

    :cond_3a
    move/from16 v17, v3

    .line 70
    iget-boolean v1, v9, La5/h;->i:Z

    if-eqz v1, :cond_3c

    iget-boolean v1, v6, La5/h;->i:Z

    if-eqz v1, :cond_3c

    .line 71
    invoke-virtual {v12}, Lh5/c;->e()I

    move-result v0

    .line 72
    invoke-virtual {v2}, Lh5/c;->e()I

    move-result v1

    const/16 v3, 0x8

    move-object/from16 p17, p1

    move/from16 p21, p16

    move/from16 p20, v0

    move/from16 p24, v1

    move/from16 p25, v3

    move-object/from16 p22, v6

    move-object/from16 p18, v7

    move-object/from16 p23, v8

    move-object/from16 p19, v9

    .line 73
    invoke-virtual/range {p17 .. p25}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    move-object/from16 v1, p17

    move-object/from16 v7, p23

    if-eqz p3, :cond_5b

    if-eqz p5, :cond_5b

    .line 74
    iget-object v0, v2, Lh5/c;->f:Lh5/c;

    if-eqz v0, :cond_3b

    .line 75
    invoke-virtual {v2}, Lh5/c;->e()I

    move-result v15

    :goto_1b
    move-object/from16 v3, p7

    goto :goto_1c

    :cond_3b
    const/4 v15, 0x0

    goto :goto_1b

    :goto_1c
    if-eq v6, v3, :cond_5b

    const/4 v2, 0x5

    .line 76
    invoke-virtual {v1, v3, v7, v15, v2}, La5/c;->f(La5/h;La5/h;II)V

    return-void

    :cond_3c
    move-object/from16 v1, p1

    move-object/from16 v3, p7

    move-object v2, v7

    move-object v7, v8

    move-object v5, v9

    move/from16 v9, v16

    const/4 v8, 0x5

    const/16 v19, 0x4

    const/16 v20, 0x1

    const/16 v23, 0x1

    goto :goto_1a

    :goto_1d
    if-eqz v23, :cond_3d

    if-ne v5, v6, :cond_3d

    if-eq v11, v10, :cond_3d

    const/16 v23, 0x0

    const/16 v26, 0x0

    goto :goto_1e

    :cond_3d
    const/16 v26, 0x1

    :goto_1e
    if-eqz v20, :cond_3f

    if-nez v24, :cond_3e

    if-nez p18, :cond_3e

    if-nez p20, :cond_3e

    if-ne v5, v15, :cond_3e

    if-ne v6, v3, :cond_3e

    const/16 v9, 0x8

    const/16 v20, 0x0

    const/16 v26, 0x8

    const/16 v27, 0x0

    :goto_1f
    move-object v8, v4

    goto :goto_20

    :cond_3e
    move/from16 v20, p3

    move/from16 v27, v26

    move/from16 v26, v8

    goto :goto_1f

    .line 77
    :goto_20
    invoke-virtual {v12}, Lh5/c;->e()I

    move-result v4

    move-object/from16 v28, v8

    .line 78
    invoke-virtual/range {p11 .. p11}, Lh5/c;->e()I

    move-result v8

    move-object v3, v5

    move/from16 p8, v13

    move/from16 v14, v17

    move-object/from16 v12, v28

    move-object/from16 v13, p11

    move/from16 v5, p16

    .line 79
    invoke-virtual/range {v1 .. v9}, La5/c;->b(La5/h;La5/h;IFLa5/h;La5/h;II)V

    move-object v5, v3

    move/from16 v8, v26

    move/from16 v26, v27

    goto :goto_21

    :cond_3f
    move-object v12, v4

    move/from16 p8, v13

    move/from16 v14, v17

    move-object/from16 v13, p11

    move/from16 v20, p3

    .line 80
    :goto_21
    iget v0, v0, Lh5/d;->h0:I

    const/16 v3, 0x8

    if-ne v0, v3, :cond_41

    .line 81
    iget-object v0, v13, Lh5/c;->a:Ljava/util/HashSet;

    if-nez v0, :cond_40

    goto/16 :goto_30

    .line 82
    :cond_40
    invoke-virtual {v0}, Ljava/util/HashSet;->size()I

    move-result v0

    if-lez v0, :cond_5b

    :cond_41
    if-eqz v23, :cond_44

    if-eqz v20, :cond_43

    if-eq v5, v6, :cond_43

    if-nez v24, :cond_43

    .line 83
    instance-of v0, v11, Lh5/a;

    if-nez v0, :cond_42

    instance-of v0, v12, Lh5/a;

    if-eqz v0, :cond_43

    :cond_42
    move/from16 v8, v16

    .line 84
    :cond_43
    invoke-virtual/range {p10 .. p10}, Lh5/c;->e()I

    move-result v0

    .line 85
    invoke-virtual {v1, v2, v5, v0, v8}, La5/c;->f(La5/h;La5/h;II)V

    .line 86
    invoke-virtual {v13}, Lh5/c;->e()I

    move-result v0

    neg-int v0, v0

    invoke-virtual {v1, v7, v6, v0, v8}, La5/c;->g(La5/h;La5/h;II)V

    :cond_44
    if-eqz v20, :cond_45

    if-eqz p21, :cond_45

    .line 87
    instance-of v0, v11, Lh5/a;

    if-nez v0, :cond_45

    instance-of v0, v12, Lh5/a;

    if-nez v0, :cond_45

    if-eq v12, v10, :cond_45

    move/from16 v0, v16

    move v8, v0

    const/16 v21, 0x1

    goto :goto_22

    :cond_45
    move/from16 v0, v19

    move/from16 v21, v26

    :goto_22
    if-eqz v21, :cond_51

    if-eqz v25, :cond_4e

    if-eqz p20, :cond_46

    if-eqz p4, :cond_4e

    :cond_46
    if-eq v11, v10, :cond_48

    if-ne v12, v10, :cond_47

    goto :goto_23

    :cond_47
    move/from16 v16, v0

    .line 88
    :cond_48
    :goto_23
    instance-of v3, v11, Lh5/h;

    if-nez v3, :cond_49

    instance-of v3, v12, Lh5/h;

    if-eqz v3, :cond_4a

    :cond_49
    const/16 v16, 0x5

    .line 89
    :cond_4a
    instance-of v3, v11, Lh5/a;

    if-nez v3, :cond_4b

    instance-of v3, v12, Lh5/a;

    if-eqz v3, :cond_4c

    :cond_4b
    const/16 v16, 0x5

    :cond_4c
    if-eqz p20, :cond_4d

    const/4 v3, 0x5

    goto :goto_24

    :cond_4d
    move/from16 v3, v16

    .line 90
    :goto_24
    invoke-static {v3, v0}, Ljava/lang/Math;->max(II)I

    move-result v0

    :cond_4e
    if-eqz v20, :cond_50

    .line 91
    invoke-static {v8, v0}, Ljava/lang/Math;->min(II)I

    move-result v0

    if-eqz p17, :cond_50

    if-nez p20, :cond_50

    if-eq v11, v10, :cond_4f

    if-ne v12, v10, :cond_50

    :cond_4f
    const/4 v10, 0x4

    goto :goto_25

    :cond_50
    move v10, v0

    .line 92
    :goto_25
    invoke-virtual/range {p10 .. p10}, Lh5/c;->e()I

    move-result v0

    .line 93
    invoke-virtual {v1, v2, v5, v0, v10}, La5/c;->e(La5/h;La5/h;II)V

    .line 94
    invoke-virtual {v13}, Lh5/c;->e()I

    move-result v0

    neg-int v0, v0

    invoke-virtual {v1, v7, v6, v0, v10}, La5/c;->e(La5/h;La5/h;II)V

    :cond_51
    if-eqz v20, :cond_53

    if-ne v15, v5, :cond_52

    .line 95
    invoke-virtual/range {p10 .. p10}, Lh5/c;->e()I

    move-result v0

    goto :goto_26

    :cond_52
    const/4 v0, 0x0

    :goto_26
    if-eq v5, v15, :cond_53

    const/4 v3, 0x5

    .line 96
    invoke-virtual {v1, v2, v15, v0, v3}, La5/c;->f(La5/h;La5/h;II)V

    :cond_53
    if-eqz v20, :cond_54

    if-eqz v24, :cond_54

    if-nez p14, :cond_54

    if-nez p8, :cond_54

    if-eqz v24, :cond_55

    const/4 v3, 0x3

    if-ne v14, v3, :cond_55

    const/16 v3, 0x8

    const/4 v10, 0x0

    .line 97
    invoke-virtual {v1, v7, v2, v10, v3}, La5/c;->f(La5/h;La5/h;II)V

    :cond_54
    const/4 v15, 0x5

    goto :goto_27

    :cond_55
    const/4 v10, 0x0

    const/4 v15, 0x5

    .line 98
    invoke-virtual {v1, v7, v2, v10, v15}, La5/c;->f(La5/h;La5/h;II)V

    :goto_27
    move v10, v15

    goto :goto_29

    :goto_28
    move/from16 v20, p3

    goto :goto_27

    :goto_29
    if-eqz v20, :cond_5b

    if-eqz p5, :cond_5b

    .line 99
    iget-object v0, v13, Lh5/c;->f:Lh5/c;

    if-eqz v0, :cond_56

    .line 100
    invoke-virtual {v13}, Lh5/c;->e()I

    move-result v15

    :goto_2a
    move-object/from16 v4, p7

    goto :goto_2b

    :cond_56
    const/4 v15, 0x0

    goto :goto_2a

    :goto_2b
    if-eq v6, v4, :cond_5b

    .line 101
    invoke-virtual {v1, v4, v7, v15, v10}, La5/c;->f(La5/h;La5/h;II)V

    return-void

    :goto_2c
    if-ge v11, v10, :cond_5b

    if-eqz p3, :cond_5b

    if-eqz p5, :cond_5b

    const/4 v10, 0x0

    const/16 v13, 0x8

    .line 102
    invoke-virtual {v1, v2, v15, v10, v13}, La5/c;->f(La5/h;La5/h;II)V

    .line 103
    iget-object v0, v0, Lh5/d;->N:Lh5/c;

    if-nez p2, :cond_58

    iget-object v2, v0, Lh5/c;->f:Lh5/c;

    if-nez v2, :cond_57

    goto :goto_2d

    :cond_57
    const/4 v10, 0x0

    goto :goto_2e

    :cond_58
    :goto_2d
    const/4 v10, 0x1

    :goto_2e
    if-nez p2, :cond_5a

    .line 104
    iget-object v0, v0, Lh5/c;->f:Lh5/c;

    if-eqz v0, :cond_5a

    .line 105
    iget-object v0, v0, Lh5/c;->d:Lh5/d;

    .line 106
    iget v2, v0, Lh5/d;->X:F

    const/4 v5, 0x0

    cmpl-float v2, v2, v5

    if-eqz v2, :cond_59

    iget-object v0, v0, Lh5/d;->q0:[I

    const/16 v22, 0x0

    aget v2, v0, v22

    if-ne v2, v3, :cond_59

    const/16 v21, 0x1

    aget v0, v0, v21

    if-ne v0, v3, :cond_59

    move/from16 v10, v21

    goto :goto_2f

    :cond_59
    const/4 v10, 0x0

    :cond_5a
    :goto_2f
    if-eqz v10, :cond_5b

    const/4 v10, 0x0

    const/16 v13, 0x8

    .line 107
    invoke-virtual {v1, v4, v7, v10, v13}, La5/c;->f(La5/h;La5/h;II)V

    :cond_5b
    :goto_30
    return-void
.end method

.method public final f(ILh5/d;II)V
    .locals 10

    .line 1
    const/16 v0, 0x9

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x3

    .line 7
    const/4 v4, 0x4

    .line 8
    const/4 v5, 0x5

    .line 9
    const/4 v6, 0x0

    .line 10
    const/4 v7, 0x7

    .line 11
    if-ne p1, v7, :cond_c

    .line 12
    .line 13
    if-ne p3, v7, :cond_8

    .line 14
    .line 15
    invoke-virtual {p0, v2}, Lh5/d;->j(I)Lh5/c;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-virtual {p0, v4}, Lh5/d;->j(I)Lh5/c;

    .line 20
    .line 21
    .line 22
    move-result-object p3

    .line 23
    invoke-virtual {p0, v3}, Lh5/d;->j(I)Lh5/c;

    .line 24
    .line 25
    .line 26
    move-result-object p4

    .line 27
    invoke-virtual {p0, v5}, Lh5/d;->j(I)Lh5/c;

    .line 28
    .line 29
    .line 30
    move-result-object v8

    .line 31
    const/4 v9, 0x1

    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    invoke-virtual {p1}, Lh5/c;->h()Z

    .line 35
    .line 36
    .line 37
    move-result p1

    .line 38
    if-nez p1, :cond_1

    .line 39
    .line 40
    :cond_0
    if-eqz p3, :cond_2

    .line 41
    .line 42
    invoke-virtual {p3}, Lh5/c;->h()Z

    .line 43
    .line 44
    .line 45
    move-result p1

    .line 46
    if-eqz p1, :cond_2

    .line 47
    .line 48
    :cond_1
    move p1, v6

    .line 49
    goto :goto_0

    .line 50
    :cond_2
    invoke-virtual {p0, v2, p2, v2, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 51
    .line 52
    .line 53
    invoke-virtual {p0, v4, p2, v4, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 54
    .line 55
    .line 56
    move p1, v9

    .line 57
    :goto_0
    if-eqz p4, :cond_3

    .line 58
    .line 59
    invoke-virtual {p4}, Lh5/c;->h()Z

    .line 60
    .line 61
    .line 62
    move-result p3

    .line 63
    if-nez p3, :cond_4

    .line 64
    .line 65
    :cond_3
    if-eqz v8, :cond_5

    .line 66
    .line 67
    invoke-virtual {v8}, Lh5/c;->h()Z

    .line 68
    .line 69
    .line 70
    move-result p3

    .line 71
    if-eqz p3, :cond_5

    .line 72
    .line 73
    :cond_4
    move v9, v6

    .line 74
    goto :goto_1

    .line 75
    :cond_5
    invoke-virtual {p0, v3, p2, v3, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, v5, p2, v5, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 79
    .line 80
    .line 81
    :goto_1
    if-eqz p1, :cond_6

    .line 82
    .line 83
    if-eqz v9, :cond_6

    .line 84
    .line 85
    invoke-virtual {p0, v7}, Lh5/d;->j(I)Lh5/c;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {p2, v7}, Lh5/d;->j(I)Lh5/c;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 94
    .line 95
    .line 96
    return-void

    .line 97
    :cond_6
    if-eqz p1, :cond_7

    .line 98
    .line 99
    invoke-virtual {p0, v1}, Lh5/d;->j(I)Lh5/c;

    .line 100
    .line 101
    .line 102
    move-result-object p0

    .line 103
    invoke-virtual {p2, v1}, Lh5/d;->j(I)Lh5/c;

    .line 104
    .line 105
    .line 106
    move-result-object p1

    .line 107
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 108
    .line 109
    .line 110
    return-void

    .line 111
    :cond_7
    if-eqz v9, :cond_1c

    .line 112
    .line 113
    invoke-virtual {p0, v0}, Lh5/d;->j(I)Lh5/c;

    .line 114
    .line 115
    .line 116
    move-result-object p0

    .line 117
    invoke-virtual {p2, v0}, Lh5/d;->j(I)Lh5/c;

    .line 118
    .line 119
    .line 120
    move-result-object p1

    .line 121
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 122
    .line 123
    .line 124
    return-void

    .line 125
    :cond_8
    if-eq p3, v2, :cond_b

    .line 126
    .line 127
    if-ne p3, v4, :cond_9

    .line 128
    .line 129
    goto :goto_2

    .line 130
    :cond_9
    if-eq p3, v3, :cond_a

    .line 131
    .line 132
    if-ne p3, v5, :cond_1c

    .line 133
    .line 134
    :cond_a
    invoke-virtual {p0, v3, p2, p3, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 135
    .line 136
    .line 137
    invoke-virtual {p0, v5, p2, p3, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 138
    .line 139
    .line 140
    invoke-virtual {p0, v7}, Lh5/d;->j(I)Lh5/c;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 149
    .line 150
    .line 151
    return-void

    .line 152
    :cond_b
    :goto_2
    invoke-virtual {p0, v2, p2, p3, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {p0, v4, p2, p3, v6}, Lh5/d;->f(ILh5/d;II)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {p0, v7}, Lh5/d;->j(I)Lh5/c;

    .line 159
    .line 160
    .line 161
    move-result-object p0

    .line 162
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 167
    .line 168
    .line 169
    return-void

    .line 170
    :cond_c
    if-ne p1, v1, :cond_e

    .line 171
    .line 172
    if-eq p3, v2, :cond_d

    .line 173
    .line 174
    if-ne p3, v4, :cond_e

    .line 175
    .line 176
    :cond_d
    invoke-virtual {p0, v2}, Lh5/d;->j(I)Lh5/c;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 181
    .line 182
    .line 183
    move-result-object p2

    .line 184
    invoke-virtual {p0, v4}, Lh5/d;->j(I)Lh5/c;

    .line 185
    .line 186
    .line 187
    move-result-object p3

    .line 188
    invoke-virtual {p1, p2, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 189
    .line 190
    .line 191
    invoke-virtual {p3, p2, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 192
    .line 193
    .line 194
    invoke-virtual {p0, v1}, Lh5/d;->j(I)Lh5/c;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    invoke-virtual {p0, p2, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 199
    .line 200
    .line 201
    return-void

    .line 202
    :cond_e
    if-ne p1, v0, :cond_10

    .line 203
    .line 204
    if-eq p3, v3, :cond_f

    .line 205
    .line 206
    if-ne p3, v5, :cond_10

    .line 207
    .line 208
    :cond_f
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 209
    .line 210
    .line 211
    move-result-object p1

    .line 212
    invoke-virtual {p0, v3}, Lh5/d;->j(I)Lh5/c;

    .line 213
    .line 214
    .line 215
    move-result-object p2

    .line 216
    invoke-virtual {p2, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 217
    .line 218
    .line 219
    invoke-virtual {p0, v5}, Lh5/d;->j(I)Lh5/c;

    .line 220
    .line 221
    .line 222
    move-result-object p2

    .line 223
    invoke-virtual {p2, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 224
    .line 225
    .line 226
    invoke-virtual {p0, v0}, Lh5/d;->j(I)Lh5/c;

    .line 227
    .line 228
    .line 229
    move-result-object p0

    .line 230
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 231
    .line 232
    .line 233
    return-void

    .line 234
    :cond_10
    if-ne p1, v1, :cond_11

    .line 235
    .line 236
    if-ne p3, v1, :cond_11

    .line 237
    .line 238
    invoke-virtual {p0, v2}, Lh5/d;->j(I)Lh5/c;

    .line 239
    .line 240
    .line 241
    move-result-object p1

    .line 242
    invoke-virtual {p2, v2}, Lh5/d;->j(I)Lh5/c;

    .line 243
    .line 244
    .line 245
    move-result-object p4

    .line 246
    invoke-virtual {p1, p4, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 247
    .line 248
    .line 249
    invoke-virtual {p0, v4}, Lh5/d;->j(I)Lh5/c;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    invoke-virtual {p2, v4}, Lh5/d;->j(I)Lh5/c;

    .line 254
    .line 255
    .line 256
    move-result-object p4

    .line 257
    invoke-virtual {p1, p4, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 258
    .line 259
    .line 260
    invoke-virtual {p0, v1}, Lh5/d;->j(I)Lh5/c;

    .line 261
    .line 262
    .line 263
    move-result-object p0

    .line 264
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 265
    .line 266
    .line 267
    move-result-object p1

    .line 268
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 269
    .line 270
    .line 271
    return-void

    .line 272
    :cond_11
    if-ne p1, v0, :cond_12

    .line 273
    .line 274
    if-ne p3, v0, :cond_12

    .line 275
    .line 276
    invoke-virtual {p0, v3}, Lh5/d;->j(I)Lh5/c;

    .line 277
    .line 278
    .line 279
    move-result-object p1

    .line 280
    invoke-virtual {p2, v3}, Lh5/d;->j(I)Lh5/c;

    .line 281
    .line 282
    .line 283
    move-result-object p4

    .line 284
    invoke-virtual {p1, p4, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 285
    .line 286
    .line 287
    invoke-virtual {p0, v5}, Lh5/d;->j(I)Lh5/c;

    .line 288
    .line 289
    .line 290
    move-result-object p1

    .line 291
    invoke-virtual {p2, v5}, Lh5/d;->j(I)Lh5/c;

    .line 292
    .line 293
    .line 294
    move-result-object p4

    .line 295
    invoke-virtual {p1, p4, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {p0, v0}, Lh5/d;->j(I)Lh5/c;

    .line 299
    .line 300
    .line 301
    move-result-object p0

    .line 302
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 303
    .line 304
    .line 305
    move-result-object p1

    .line 306
    invoke-virtual {p0, p1, v6}, Lh5/c;->a(Lh5/c;I)V

    .line 307
    .line 308
    .line 309
    return-void

    .line 310
    :cond_12
    invoke-virtual {p0, p1}, Lh5/d;->j(I)Lh5/c;

    .line 311
    .line 312
    .line 313
    move-result-object v6

    .line 314
    invoke-virtual {p2, p3}, Lh5/d;->j(I)Lh5/c;

    .line 315
    .line 316
    .line 317
    move-result-object p2

    .line 318
    invoke-virtual {v6, p2}, Lh5/c;->i(Lh5/c;)Z

    .line 319
    .line 320
    .line 321
    move-result p3

    .line 322
    if-eqz p3, :cond_1c

    .line 323
    .line 324
    const/4 p3, 0x6

    .line 325
    if-ne p1, p3, :cond_14

    .line 326
    .line 327
    invoke-virtual {p0, v3}, Lh5/d;->j(I)Lh5/c;

    .line 328
    .line 329
    .line 330
    move-result-object p1

    .line 331
    invoke-virtual {p0, v5}, Lh5/d;->j(I)Lh5/c;

    .line 332
    .line 333
    .line 334
    move-result-object p0

    .line 335
    if-eqz p1, :cond_13

    .line 336
    .line 337
    invoke-virtual {p1}, Lh5/c;->j()V

    .line 338
    .line 339
    .line 340
    :cond_13
    if-eqz p0, :cond_1b

    .line 341
    .line 342
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 343
    .line 344
    .line 345
    goto :goto_4

    .line 346
    :cond_14
    if-eq p1, v3, :cond_18

    .line 347
    .line 348
    if-ne p1, v5, :cond_15

    .line 349
    .line 350
    goto :goto_3

    .line 351
    :cond_15
    if-eq p1, v2, :cond_16

    .line 352
    .line 353
    if-ne p1, v4, :cond_1b

    .line 354
    .line 355
    :cond_16
    invoke-virtual {p0, v7}, Lh5/d;->j(I)Lh5/c;

    .line 356
    .line 357
    .line 358
    move-result-object p3

    .line 359
    iget-object v0, p3, Lh5/c;->f:Lh5/c;

    .line 360
    .line 361
    if-eq v0, p2, :cond_17

    .line 362
    .line 363
    invoke-virtual {p3}, Lh5/c;->j()V

    .line 364
    .line 365
    .line 366
    :cond_17
    invoke-virtual {p0, p1}, Lh5/d;->j(I)Lh5/c;

    .line 367
    .line 368
    .line 369
    move-result-object p1

    .line 370
    invoke-virtual {p1}, Lh5/c;->f()Lh5/c;

    .line 371
    .line 372
    .line 373
    move-result-object p1

    .line 374
    invoke-virtual {p0, v1}, Lh5/d;->j(I)Lh5/c;

    .line 375
    .line 376
    .line 377
    move-result-object p0

    .line 378
    invoke-virtual {p0}, Lh5/c;->h()Z

    .line 379
    .line 380
    .line 381
    move-result p3

    .line 382
    if-eqz p3, :cond_1b

    .line 383
    .line 384
    invoke-virtual {p1}, Lh5/c;->j()V

    .line 385
    .line 386
    .line 387
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 388
    .line 389
    .line 390
    goto :goto_4

    .line 391
    :cond_18
    :goto_3
    invoke-virtual {p0, p3}, Lh5/d;->j(I)Lh5/c;

    .line 392
    .line 393
    .line 394
    move-result-object p3

    .line 395
    if-eqz p3, :cond_19

    .line 396
    .line 397
    invoke-virtual {p3}, Lh5/c;->j()V

    .line 398
    .line 399
    .line 400
    :cond_19
    invoke-virtual {p0, v7}, Lh5/d;->j(I)Lh5/c;

    .line 401
    .line 402
    .line 403
    move-result-object p3

    .line 404
    iget-object v1, p3, Lh5/c;->f:Lh5/c;

    .line 405
    .line 406
    if-eq v1, p2, :cond_1a

    .line 407
    .line 408
    invoke-virtual {p3}, Lh5/c;->j()V

    .line 409
    .line 410
    .line 411
    :cond_1a
    invoke-virtual {p0, p1}, Lh5/d;->j(I)Lh5/c;

    .line 412
    .line 413
    .line 414
    move-result-object p1

    .line 415
    invoke-virtual {p1}, Lh5/c;->f()Lh5/c;

    .line 416
    .line 417
    .line 418
    move-result-object p1

    .line 419
    invoke-virtual {p0, v0}, Lh5/d;->j(I)Lh5/c;

    .line 420
    .line 421
    .line 422
    move-result-object p0

    .line 423
    invoke-virtual {p0}, Lh5/c;->h()Z

    .line 424
    .line 425
    .line 426
    move-result p3

    .line 427
    if-eqz p3, :cond_1b

    .line 428
    .line 429
    invoke-virtual {p1}, Lh5/c;->j()V

    .line 430
    .line 431
    .line 432
    invoke-virtual {p0}, Lh5/c;->j()V

    .line 433
    .line 434
    .line 435
    :cond_1b
    :goto_4
    invoke-virtual {v6, p2, p4}, Lh5/c;->a(Lh5/c;I)V

    .line 436
    .line 437
    .line 438
    :cond_1c
    return-void
.end method

.method public final g(Lh5/c;Lh5/c;I)V
    .locals 1

    .line 1
    iget-object v0, p1, Lh5/c;->d:Lh5/d;

    .line 2
    .line 3
    if-ne v0, p0, :cond_0

    .line 4
    .line 5
    iget p1, p1, Lh5/c;->e:I

    .line 6
    .line 7
    iget-object v0, p2, Lh5/c;->d:Lh5/d;

    .line 8
    .line 9
    iget p2, p2, Lh5/c;->e:I

    .line 10
    .line 11
    invoke-virtual {p0, p1, v0, p2, p3}, Lh5/d;->f(ILh5/d;II)V

    .line 12
    .line 13
    .line 14
    :cond_0
    return-void
.end method

.method public final h(La5/c;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lh5/d;->J:Lh5/c;

    .line 2
    .line 3
    invoke-virtual {p1, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lh5/d;->M:Lh5/c;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 19
    .line 20
    .line 21
    iget v0, p0, Lh5/d;->b0:I

    .line 22
    .line 23
    if-lez v0, :cond_0

    .line 24
    .line 25
    iget-object p0, p0, Lh5/d;->N:Lh5/c;

    .line 26
    .line 27
    invoke-virtual {p1, p0}, La5/c;->k(Ljava/lang/Object;)La5/h;

    .line 28
    .line 29
    .line 30
    :cond_0
    return-void
.end method

.method public final i()V
    .locals 4

    .line 1
    iget-object v0, p0, Lh5/d;->d:Li5/l;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Li5/l;

    .line 6
    .line 7
    invoke-direct {v0, p0}, Li5/p;-><init>(Lh5/d;)V

    .line 8
    .line 9
    .line 10
    iget-object v1, v0, Li5/p;->h:Li5/g;

    .line 11
    .line 12
    const/4 v2, 0x4

    .line 13
    iput v2, v1, Li5/g;->e:I

    .line 14
    .line 15
    iget-object v1, v0, Li5/p;->i:Li5/g;

    .line 16
    .line 17
    const/4 v2, 0x5

    .line 18
    iput v2, v1, Li5/g;->e:I

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    iput v1, v0, Li5/p;->f:I

    .line 22
    .line 23
    iput-object v0, p0, Lh5/d;->d:Li5/l;

    .line 24
    .line 25
    :cond_0
    iget-object v0, p0, Lh5/d;->e:Li5/n;

    .line 26
    .line 27
    if-nez v0, :cond_1

    .line 28
    .line 29
    new-instance v0, Li5/n;

    .line 30
    .line 31
    invoke-direct {v0, p0}, Li5/p;-><init>(Lh5/d;)V

    .line 32
    .line 33
    .line 34
    new-instance v1, Li5/g;

    .line 35
    .line 36
    invoke-direct {v1, v0}, Li5/g;-><init>(Li5/p;)V

    .line 37
    .line 38
    .line 39
    iput-object v1, v0, Li5/n;->k:Li5/g;

    .line 40
    .line 41
    const/4 v2, 0x0

    .line 42
    iput-object v2, v0, Li5/n;->l:Li5/a;

    .line 43
    .line 44
    iget-object v2, v0, Li5/p;->h:Li5/g;

    .line 45
    .line 46
    const/4 v3, 0x6

    .line 47
    iput v3, v2, Li5/g;->e:I

    .line 48
    .line 49
    iget-object v2, v0, Li5/p;->i:Li5/g;

    .line 50
    .line 51
    const/4 v3, 0x7

    .line 52
    iput v3, v2, Li5/g;->e:I

    .line 53
    .line 54
    const/16 v2, 0x8

    .line 55
    .line 56
    iput v2, v1, Li5/g;->e:I

    .line 57
    .line 58
    const/4 v1, 0x1

    .line 59
    iput v1, v0, Li5/p;->f:I

    .line 60
    .line 61
    iput-object v0, p0, Lh5/d;->e:Li5/n;

    .line 62
    .line 63
    :cond_1
    return-void
.end method

.method public j(I)Lh5/c;
    .locals 1

    .line 1
    invoke-static {p1}, Lu/w;->o(I)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p0, Ljava/lang/AssertionError;

    .line 9
    .line 10
    invoke-static {p1}, Lf2/m0;->y(I)Ljava/lang/String;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    invoke-direct {p0, p1}, Ljava/lang/AssertionError;-><init>(Ljava/lang/Object;)V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :pswitch_0
    iget-object p0, p0, Lh5/d;->P:Lh5/c;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_1
    iget-object p0, p0, Lh5/d;->O:Lh5/c;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_2
    iget-object p0, p0, Lh5/d;->Q:Lh5/c;

    .line 25
    .line 26
    return-object p0

    .line 27
    :pswitch_3
    iget-object p0, p0, Lh5/d;->N:Lh5/c;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_4
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 31
    .line 32
    return-object p0

    .line 33
    :pswitch_5
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 34
    .line 35
    return-object p0

    .line 36
    :pswitch_6
    iget-object p0, p0, Lh5/d;->K:Lh5/c;

    .line 37
    .line 38
    return-object p0

    .line 39
    :pswitch_7
    iget-object p0, p0, Lh5/d;->J:Lh5/c;

    .line 40
    .line 41
    return-object p0

    .line 42
    :pswitch_8
    const/4 p0, 0x0

    .line 43
    return-object p0

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final k(I)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    iget-object p0, p0, Lh5/d;->q0:[I

    .line 3
    .line 4
    if-nez p1, :cond_0

    .line 5
    .line 6
    aget p0, p0, v0

    .line 7
    .line 8
    return p0

    .line 9
    :cond_0
    const/4 v1, 0x1

    .line 10
    if-ne p1, v1, :cond_1

    .line 11
    .line 12
    aget p0, p0, v1

    .line 13
    .line 14
    return p0

    .line 15
    :cond_1
    return v0
.end method

.method public final l()I
    .locals 2

    .line 1
    iget v0, p0, Lh5/d;->h0:I

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget p0, p0, Lh5/d;->W:I

    .line 10
    .line 11
    return p0
.end method

.method public final m(I)Lh5/d;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 4
    .line 5
    iget-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 6
    .line 7
    if-eqz p1, :cond_1

    .line 8
    .line 9
    iget-object v0, p1, Lh5/c;->f:Lh5/c;

    .line 10
    .line 11
    if-ne v0, p0, :cond_1

    .line 12
    .line 13
    iget-object p0, p1, Lh5/c;->d:Lh5/d;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 v0, 0x1

    .line 17
    if-ne p1, v0, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 20
    .line 21
    iget-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 22
    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    iget-object v0, p1, Lh5/c;->f:Lh5/c;

    .line 26
    .line 27
    if-ne v0, p0, :cond_1

    .line 28
    .line 29
    iget-object p0, p1, Lh5/c;->d:Lh5/d;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method

.method public final n(I)Lh5/d;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p0, p0, Lh5/d;->J:Lh5/c;

    .line 4
    .line 5
    iget-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 6
    .line 7
    if-eqz p1, :cond_1

    .line 8
    .line 9
    iget-object v0, p1, Lh5/c;->f:Lh5/c;

    .line 10
    .line 11
    if-ne v0, p0, :cond_1

    .line 12
    .line 13
    iget-object p0, p1, Lh5/c;->d:Lh5/d;

    .line 14
    .line 15
    return-object p0

    .line 16
    :cond_0
    const/4 v0, 0x1

    .line 17
    if-ne p1, v0, :cond_1

    .line 18
    .line 19
    iget-object p0, p0, Lh5/d;->K:Lh5/c;

    .line 20
    .line 21
    iget-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 22
    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    iget-object v0, p1, Lh5/c;->f:Lh5/c;

    .line 26
    .line 27
    if-ne v0, p0, :cond_1

    .line 28
    .line 29
    iget-object p0, p1, Lh5/c;->d:Lh5/d;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method

.method public o(Ljava/lang/StringBuilder;)V
    .locals 14

    .line 1
    new-instance v2, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v3, "  "

    .line 4
    .line 5
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget-object v3, p0, Lh5/d;->k:Ljava/lang/String;

    .line 9
    .line 10
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 11
    .line 12
    .line 13
    const-string v3, ":{\n"

    .line 14
    .line 15
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 19
    .line 20
    .line 21
    move-result-object v2

    .line 22
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    new-instance v2, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v3, "    actualWidth:"

    .line 28
    .line 29
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget v3, p0, Lh5/d;->V:I

    .line 33
    .line 34
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 38
    .line 39
    .line 40
    move-result-object v2

    .line 41
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    const-string v2, "\n"

    .line 45
    .line 46
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    new-instance v3, Ljava/lang/StringBuilder;

    .line 50
    .line 51
    const-string v4, "    actualHeight:"

    .line 52
    .line 53
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    iget v4, p0, Lh5/d;->W:I

    .line 57
    .line 58
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object v3

    .line 65
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 66
    .line 67
    .line 68
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    new-instance v3, Ljava/lang/StringBuilder;

    .line 72
    .line 73
    const-string v4, "    actualLeft:"

    .line 74
    .line 75
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    iget v4, p0, Lh5/d;->Z:I

    .line 79
    .line 80
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 91
    .line 92
    .line 93
    new-instance v3, Ljava/lang/StringBuilder;

    .line 94
    .line 95
    const-string v4, "    actualTop:"

    .line 96
    .line 97
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 98
    .line 99
    .line 100
    iget v4, p0, Lh5/d;->a0:I

    .line 101
    .line 102
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 103
    .line 104
    .line 105
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 110
    .line 111
    .line 112
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 113
    .line 114
    .line 115
    const-string v2, "left"

    .line 116
    .line 117
    iget-object v3, p0, Lh5/d;->J:Lh5/c;

    .line 118
    .line 119
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 120
    .line 121
    .line 122
    const-string v2, "top"

    .line 123
    .line 124
    iget-object v3, p0, Lh5/d;->K:Lh5/c;

    .line 125
    .line 126
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 127
    .line 128
    .line 129
    const-string v2, "right"

    .line 130
    .line 131
    iget-object v3, p0, Lh5/d;->L:Lh5/c;

    .line 132
    .line 133
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 134
    .line 135
    .line 136
    const-string v2, "bottom"

    .line 137
    .line 138
    iget-object v3, p0, Lh5/d;->M:Lh5/c;

    .line 139
    .line 140
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 141
    .line 142
    .line 143
    const-string v2, "baseline"

    .line 144
    .line 145
    iget-object v3, p0, Lh5/d;->N:Lh5/c;

    .line 146
    .line 147
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 148
    .line 149
    .line 150
    const-string v2, "centerX"

    .line 151
    .line 152
    iget-object v3, p0, Lh5/d;->O:Lh5/c;

    .line 153
    .line 154
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 155
    .line 156
    .line 157
    const-string v2, "centerY"

    .line 158
    .line 159
    iget-object v3, p0, Lh5/d;->P:Lh5/c;

    .line 160
    .line 161
    invoke-static {p1, v2, v3}, Lh5/d;->q(Ljava/lang/StringBuilder;Ljava/lang/String;Lh5/c;)V

    .line 162
    .line 163
    .line 164
    iget v3, p0, Lh5/d;->V:I

    .line 165
    .line 166
    iget v4, p0, Lh5/d;->c0:I

    .line 167
    .line 168
    iget-object v10, p0, Lh5/d;->D:[I

    .line 169
    .line 170
    const/4 v11, 0x0

    .line 171
    aget v5, v10, v11

    .line 172
    .line 173
    iget v6, p0, Lh5/d;->v:I

    .line 174
    .line 175
    iget v7, p0, Lh5/d;->s:I

    .line 176
    .line 177
    iget v8, p0, Lh5/d;->x:F

    .line 178
    .line 179
    iget-object v12, p0, Lh5/d;->q0:[I

    .line 180
    .line 181
    aget v9, v12, v11

    .line 182
    .line 183
    iget-object v13, p0, Lh5/d;->l0:[F

    .line 184
    .line 185
    aget v2, v13, v11

    .line 186
    .line 187
    const-string v2, "    width"

    .line 188
    .line 189
    move-object v1, p1

    .line 190
    invoke-static/range {v1 .. v9}, Lh5/d;->p(Ljava/lang/StringBuilder;Ljava/lang/String;IIIIIFI)V

    .line 191
    .line 192
    .line 193
    iget v3, p0, Lh5/d;->W:I

    .line 194
    .line 195
    iget v4, p0, Lh5/d;->d0:I

    .line 196
    .line 197
    const/4 v1, 0x1

    .line 198
    aget v5, v10, v1

    .line 199
    .line 200
    iget v6, p0, Lh5/d;->y:I

    .line 201
    .line 202
    iget v7, p0, Lh5/d;->t:I

    .line 203
    .line 204
    iget v8, p0, Lh5/d;->A:F

    .line 205
    .line 206
    aget v9, v12, v1

    .line 207
    .line 208
    aget v1, v13, v1

    .line 209
    .line 210
    const-string v2, "    height"

    .line 211
    .line 212
    move-object v1, p1

    .line 213
    invoke-static/range {v1 .. v9}, Lh5/d;->p(Ljava/lang/StringBuilder;Ljava/lang/String;IIIIIFI)V

    .line 214
    .line 215
    .line 216
    iget v2, p0, Lh5/d;->X:F

    .line 217
    .line 218
    iget v3, p0, Lh5/d;->Y:I

    .line 219
    .line 220
    const/4 v4, 0x0

    .line 221
    cmpl-float v4, v2, v4

    .line 222
    .line 223
    if-nez v4, :cond_0

    .line 224
    .line 225
    goto :goto_0

    .line 226
    :cond_0
    const-string v4, "    dimensionRatio"

    .line 227
    .line 228
    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    const-string v4, " :  ["

    .line 232
    .line 233
    invoke-virtual {p1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(F)Ljava/lang/StringBuilder;

    .line 237
    .line 238
    .line 239
    const-string v2, ","

    .line 240
    .line 241
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 242
    .line 243
    .line 244
    invoke-virtual {p1, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 245
    .line 246
    .line 247
    const-string v2, ""

    .line 248
    .line 249
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 250
    .line 251
    .line 252
    const-string v2, "],\n"

    .line 253
    .line 254
    invoke-virtual {p1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 255
    .line 256
    .line 257
    :goto_0
    const-string v2, "    horizontalBias"

    .line 258
    .line 259
    iget v3, p0, Lh5/d;->e0:F

    .line 260
    .line 261
    const/high16 v4, 0x3f000000    # 0.5f

    .line 262
    .line 263
    invoke-static {p1, v2, v3, v4}, Lh5/d;->I(Ljava/lang/StringBuilder;Ljava/lang/String;FF)V

    .line 264
    .line 265
    .line 266
    const-string v2, "    verticalBias"

    .line 267
    .line 268
    iget v3, p0, Lh5/d;->f0:F

    .line 269
    .line 270
    invoke-static {p1, v2, v3, v4}, Lh5/d;->I(Ljava/lang/StringBuilder;Ljava/lang/String;FF)V

    .line 271
    .line 272
    .line 273
    const-string v2, "    horizontalChainStyle"

    .line 274
    .line 275
    iget v3, p0, Lh5/d;->j0:I

    .line 276
    .line 277
    invoke-static {v3, v11, v2, p1}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 278
    .line 279
    .line 280
    const-string v2, "    verticalChainStyle"

    .line 281
    .line 282
    iget v0, p0, Lh5/d;->k0:I

    .line 283
    .line 284
    invoke-static {v0, v11, v2, p1}, Lh5/d;->H(IILjava/lang/String;Ljava/lang/StringBuilder;)V

    .line 285
    .line 286
    .line 287
    const-string v0, "  }"

    .line 288
    .line 289
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 290
    .line 291
    .line 292
    return-void
.end method

.method public final r()I
    .locals 2

    .line 1
    iget v0, p0, Lh5/d;->h0:I

    .line 2
    .line 3
    const/16 v1, 0x8

    .line 4
    .line 5
    if-ne v0, v1, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x0

    .line 8
    return p0

    .line 9
    :cond_0
    iget p0, p0, Lh5/d;->V:I

    .line 10
    .line 11
    return p0
.end method

.method public final s()I
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/d;->U:Lh5/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    instance-of v1, v0, Lh5/e;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget v0, v0, Lh5/e;->y0:I

    .line 10
    .line 11
    iget p0, p0, Lh5/d;->Z:I

    .line 12
    .line 13
    add-int/2addr v0, p0

    .line 14
    return v0

    .line 15
    :cond_0
    iget p0, p0, Lh5/d;->Z:I

    .line 16
    .line 17
    return p0
.end method

.method public final t()I
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/d;->U:Lh5/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    instance-of v1, v0, Lh5/e;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    iget v0, v0, Lh5/e;->z0:I

    .line 10
    .line 11
    iget p0, p0, Lh5/d;->a0:I

    .line 12
    .line 13
    add-int/2addr v0, p0

    .line 14
    return v0

    .line 15
    :cond_0
    iget p0, p0, Lh5/d;->a0:I

    .line 16
    .line 17
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 4

    .line 1
    const-string v0, ""

    .line 2
    .line 3
    invoke-static {v0}, Lf2/m0;->n(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-object v2, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 8
    .line 9
    if-eqz v2, :cond_0

    .line 10
    .line 11
    new-instance v0, Ljava/lang/StringBuilder;

    .line 12
    .line 13
    const-string v2, "id: "

    .line 14
    .line 15
    invoke-direct {v0, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 16
    .line 17
    .line 18
    iget-object v2, p0, Lh5/d;->i0:Ljava/lang/String;

    .line 19
    .line 20
    const-string v3, " "

    .line 21
    .line 22
    invoke-static {v0, v2, v3}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    :cond_0
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    const-string v0, "("

    .line 30
    .line 31
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 32
    .line 33
    .line 34
    iget v0, p0, Lh5/d;->Z:I

    .line 35
    .line 36
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", "

    .line 40
    .line 41
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    iget v0, p0, Lh5/d;->a0:I

    .line 45
    .line 46
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v0, ") - ("

    .line 50
    .line 51
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    iget v0, p0, Lh5/d;->V:I

    .line 55
    .line 56
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 57
    .line 58
    .line 59
    const-string v0, " x "

    .line 60
    .line 61
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 62
    .line 63
    .line 64
    iget p0, p0, Lh5/d;->W:I

    .line 65
    .line 66
    const-string v0, ")"

    .line 67
    .line 68
    invoke-static {p0, v0, v1}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    return-object p0
.end method

.method public final u(I)Z
    .locals 4

    .line 1
    const/4 v0, 0x2

    .line 2
    const/4 v1, 0x0

    .line 3
    const/4 v2, 0x1

    .line 4
    if-nez p1, :cond_2

    .line 5
    .line 6
    iget-object p1, p0, Lh5/d;->J:Lh5/c;

    .line 7
    .line 8
    iget-object p1, p1, Lh5/c;->f:Lh5/c;

    .line 9
    .line 10
    if-eqz p1, :cond_0

    .line 11
    .line 12
    move p1, v2

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    move p1, v1

    .line 15
    :goto_0
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 16
    .line 17
    iget-object p0, p0, Lh5/c;->f:Lh5/c;

    .line 18
    .line 19
    if-eqz p0, :cond_1

    .line 20
    .line 21
    move p0, v2

    .line 22
    goto :goto_1

    .line 23
    :cond_1
    move p0, v1

    .line 24
    :goto_1
    add-int/2addr p1, p0

    .line 25
    if-ge p1, v0, :cond_6

    .line 26
    .line 27
    goto :goto_5

    .line 28
    :cond_2
    iget-object p1, p0, Lh5/d;->K:Lh5/c;

    .line 29
    .line 30
    iget-object p1, p1, Lh5/c;->f:Lh5/c;

    .line 31
    .line 32
    if-eqz p1, :cond_3

    .line 33
    .line 34
    move p1, v2

    .line 35
    goto :goto_2

    .line 36
    :cond_3
    move p1, v1

    .line 37
    :goto_2
    iget-object v3, p0, Lh5/d;->M:Lh5/c;

    .line 38
    .line 39
    iget-object v3, v3, Lh5/c;->f:Lh5/c;

    .line 40
    .line 41
    if-eqz v3, :cond_4

    .line 42
    .line 43
    move v3, v2

    .line 44
    goto :goto_3

    .line 45
    :cond_4
    move v3, v1

    .line 46
    :goto_3
    add-int/2addr p1, v3

    .line 47
    iget-object p0, p0, Lh5/d;->N:Lh5/c;

    .line 48
    .line 49
    iget-object p0, p0, Lh5/c;->f:Lh5/c;

    .line 50
    .line 51
    if-eqz p0, :cond_5

    .line 52
    .line 53
    move p0, v2

    .line 54
    goto :goto_4

    .line 55
    :cond_5
    move p0, v1

    .line 56
    :goto_4
    add-int/2addr p1, p0

    .line 57
    if-ge p1, v0, :cond_6

    .line 58
    .line 59
    :goto_5
    return v2

    .line 60
    :cond_6
    return v1
.end method

.method public final v(II)Z
    .locals 2

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    iget-object p1, p0, Lh5/d;->J:Lh5/c;

    .line 4
    .line 5
    iget-object v0, p1, Lh5/c;->f:Lh5/c;

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    iget-boolean v0, v0, Lh5/c;->c:Z

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 14
    .line 15
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    iget-boolean v1, v0, Lh5/c;->c:Z

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    invoke-virtual {v0}, Lh5/c;->d()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 28
    .line 29
    .line 30
    move-result p0

    .line 31
    sub-int/2addr v0, p0

    .line 32
    iget-object p0, p1, Lh5/c;->f:Lh5/c;

    .line 33
    .line 34
    invoke-virtual {p0}, Lh5/c;->d()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    invoke-virtual {p1}, Lh5/c;->e()I

    .line 39
    .line 40
    .line 41
    move-result p1

    .line 42
    add-int/2addr p1, p0

    .line 43
    sub-int/2addr v0, p1

    .line 44
    if-lt v0, p2, :cond_1

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_0
    iget-object p1, p0, Lh5/d;->K:Lh5/c;

    .line 48
    .line 49
    iget-object v0, p1, Lh5/c;->f:Lh5/c;

    .line 50
    .line 51
    if-eqz v0, :cond_1

    .line 52
    .line 53
    iget-boolean v0, v0, Lh5/c;->c:Z

    .line 54
    .line 55
    if-eqz v0, :cond_1

    .line 56
    .line 57
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 58
    .line 59
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 60
    .line 61
    if-eqz v0, :cond_1

    .line 62
    .line 63
    iget-boolean v1, v0, Lh5/c;->c:Z

    .line 64
    .line 65
    if-eqz v1, :cond_1

    .line 66
    .line 67
    invoke-virtual {v0}, Lh5/c;->d()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    invoke-virtual {p0}, Lh5/c;->e()I

    .line 72
    .line 73
    .line 74
    move-result p0

    .line 75
    sub-int/2addr v0, p0

    .line 76
    iget-object p0, p1, Lh5/c;->f:Lh5/c;

    .line 77
    .line 78
    invoke-virtual {p0}, Lh5/c;->d()I

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    invoke-virtual {p1}, Lh5/c;->e()I

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    add-int/2addr p1, p0

    .line 87
    sub-int/2addr v0, p1

    .line 88
    if-lt v0, p2, :cond_1

    .line 89
    .line 90
    :goto_0
    const/4 p0, 0x1

    .line 91
    return p0

    .line 92
    :cond_1
    const/4 p0, 0x0

    .line 93
    return p0
.end method

.method public final w(IIIILh5/d;)V
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lh5/d;->j(I)Lh5/c;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p5, p2}, Lh5/d;->j(I)Lh5/c;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    const/4 p2, 0x1

    .line 10
    invoke-virtual {p0, p1, p3, p4, p2}, Lh5/c;->b(Lh5/c;IIZ)Z

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public final x(I)Z
    .locals 2

    .line 1
    mul-int/lit8 p1, p1, 0x2

    .line 2
    .line 3
    iget-object p0, p0, Lh5/d;->R:[Lh5/c;

    .line 4
    .line 5
    aget-object v0, p0, p1

    .line 6
    .line 7
    iget-object v1, v0, Lh5/c;->f:Lh5/c;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    iget-object v1, v1, Lh5/c;->f:Lh5/c;

    .line 12
    .line 13
    if-eq v1, v0, :cond_0

    .line 14
    .line 15
    const/4 v0, 0x1

    .line 16
    add-int/2addr p1, v0

    .line 17
    aget-object p0, p0, p1

    .line 18
    .line 19
    iget-object p1, p0, Lh5/c;->f:Lh5/c;

    .line 20
    .line 21
    if-eqz p1, :cond_0

    .line 22
    .line 23
    iget-object p1, p1, Lh5/c;->f:Lh5/c;

    .line 24
    .line 25
    if-ne p1, p0, :cond_0

    .line 26
    .line 27
    return v0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public final y()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/d;->J:Lh5/c;

    .line 2
    .line 3
    iget-object v1, v0, Lh5/c;->f:Lh5/c;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v1, Lh5/c;->f:Lh5/c;

    .line 8
    .line 9
    if-eq v1, v0, :cond_1

    .line 10
    .line 11
    :cond_0
    iget-object p0, p0, Lh5/d;->L:Lh5/c;

    .line 12
    .line 13
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object v0, v0, Lh5/c;->f:Lh5/c;

    .line 18
    .line 19
    if-ne v0, p0, :cond_2

    .line 20
    .line 21
    :cond_1
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_2
    const/4 p0, 0x0

    .line 24
    return p0
.end method

.method public final z()Z
    .locals 2

    .line 1
    iget-object v0, p0, Lh5/d;->K:Lh5/c;

    .line 2
    .line 3
    iget-object v1, v0, Lh5/c;->f:Lh5/c;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, v1, Lh5/c;->f:Lh5/c;

    .line 8
    .line 9
    if-eq v1, v0, :cond_1

    .line 10
    .line 11
    :cond_0
    iget-object p0, p0, Lh5/d;->M:Lh5/c;

    .line 12
    .line 13
    iget-object v0, p0, Lh5/c;->f:Lh5/c;

    .line 14
    .line 15
    if-eqz v0, :cond_2

    .line 16
    .line 17
    iget-object v0, v0, Lh5/c;->f:Lh5/c;

    .line 18
    .line 19
    if-ne v0, p0, :cond_2

    .line 20
    .line 21
    :cond_1
    const/4 p0, 0x1

    .line 22
    return p0

    .line 23
    :cond_2
    const/4 p0, 0x0

    .line 24
    return p0
.end method

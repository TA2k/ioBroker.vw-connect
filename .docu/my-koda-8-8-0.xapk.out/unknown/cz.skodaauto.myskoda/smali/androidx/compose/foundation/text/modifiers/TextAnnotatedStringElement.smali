.class public final Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;",
        "Lv3/z0;",
        "Ld2/i;",
        "foundation_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Lg4/g;

.field public final c:Lg4/p0;

.field public final d:Lk4/m;

.field public final e:Lay0/k;

.field public final f:I

.field public final g:Z

.field public final h:I

.field public final i:I

.field public final j:Ljava/util/List;

.field public final k:Lay0/k;

.field public final l:Le3/t;

.field public final m:Lay0/k;


# direct methods
.method public constructor <init>(Lg4/g;Lg4/p0;Lk4/m;Lay0/k;IZIILjava/util/List;Lay0/k;Le3/t;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->b:Lg4/g;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 7
    .line 8
    iput-object p3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->d:Lk4/m;

    .line 9
    .line 10
    iput-object p4, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->e:Lay0/k;

    .line 11
    .line 12
    iput p5, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->f:I

    .line 13
    .line 14
    iput-boolean p6, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->g:Z

    .line 15
    .line 16
    iput p7, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->h:I

    .line 17
    .line 18
    iput p8, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->i:I

    .line 19
    .line 20
    iput-object p9, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->j:Ljava/util/List;

    .line 21
    .line 22
    iput-object p10, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->k:Lay0/k;

    .line 23
    .line 24
    iput-object p11, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->l:Le3/t;

    .line 25
    .line 26
    iput-object p12, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->m:Lay0/k;

    .line 27
    .line 28
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 2

    .line 1
    if-ne p0, p1, :cond_0

    .line 2
    .line 3
    goto/16 :goto_0

    .line 4
    .line 5
    :cond_0
    instance-of v0, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    goto/16 :goto_1

    .line 10
    .line 11
    :cond_1
    check-cast p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;

    .line 12
    .line 13
    iget-object v0, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->l:Le3/t;

    .line 14
    .line 15
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->l:Le3/t;

    .line 16
    .line 17
    invoke-static {v1, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_2

    .line 22
    .line 23
    goto/16 :goto_1

    .line 24
    .line 25
    :cond_2
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->b:Lg4/g;

    .line 26
    .line 27
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->b:Lg4/g;

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
    goto :goto_1

    .line 36
    :cond_3
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 37
    .line 38
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 39
    .line 40
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    if-nez v0, :cond_4

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_4
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->j:Ljava/util/List;

    .line 48
    .line 49
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->j:Ljava/util/List;

    .line 50
    .line 51
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 52
    .line 53
    .line 54
    move-result v0

    .line 55
    if-nez v0, :cond_5

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_5
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->d:Lk4/m;

    .line 59
    .line 60
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->d:Lk4/m;

    .line 61
    .line 62
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    if-nez v0, :cond_6

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_6
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->e:Lay0/k;

    .line 70
    .line 71
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->e:Lay0/k;

    .line 72
    .line 73
    if-eq v0, v1, :cond_7

    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_7
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->m:Lay0/k;

    .line 77
    .line 78
    iget-object v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->m:Lay0/k;

    .line 79
    .line 80
    if-eq v0, v1, :cond_8

    .line 81
    .line 82
    goto :goto_1

    .line 83
    :cond_8
    iget v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->f:I

    .line 84
    .line 85
    iget v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->f:I

    .line 86
    .line 87
    if-ne v0, v1, :cond_d

    .line 88
    .line 89
    iget-boolean v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->g:Z

    .line 90
    .line 91
    iget-boolean v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->g:Z

    .line 92
    .line 93
    if-eq v0, v1, :cond_9

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_9
    iget v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->h:I

    .line 97
    .line 98
    iget v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->h:I

    .line 99
    .line 100
    if-eq v0, v1, :cond_a

    .line 101
    .line 102
    goto :goto_1

    .line 103
    :cond_a
    iget v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->i:I

    .line 104
    .line 105
    iget v1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->i:I

    .line 106
    .line 107
    if-eq v0, v1, :cond_b

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_b
    iget-object p0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->k:Lay0/k;

    .line 111
    .line 112
    iget-object p1, p1, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->k:Lay0/k;

    .line 113
    .line 114
    if-eq p0, p1, :cond_c

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_c
    :goto_0
    const/4 p0, 0x1

    .line 118
    return p0

    .line 119
    :cond_d
    :goto_1
    const/4 p0, 0x0

    .line 120
    return p0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Ld2/i;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->b:Lg4/g;

    .line 7
    .line 8
    iput-object v1, v0, Ld2/i;->r:Lg4/g;

    .line 9
    .line 10
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 11
    .line 12
    iput-object v1, v0, Ld2/i;->s:Lg4/p0;

    .line 13
    .line 14
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->d:Lk4/m;

    .line 15
    .line 16
    iput-object v1, v0, Ld2/i;->t:Lk4/m;

    .line 17
    .line 18
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->e:Lay0/k;

    .line 19
    .line 20
    iput-object v1, v0, Ld2/i;->u:Lay0/k;

    .line 21
    .line 22
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->f:I

    .line 23
    .line 24
    iput v1, v0, Ld2/i;->v:I

    .line 25
    .line 26
    iget-boolean v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->g:Z

    .line 27
    .line 28
    iput-boolean v1, v0, Ld2/i;->w:Z

    .line 29
    .line 30
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->h:I

    .line 31
    .line 32
    iput v1, v0, Ld2/i;->x:I

    .line 33
    .line 34
    iget v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->i:I

    .line 35
    .line 36
    iput v1, v0, Ld2/i;->y:I

    .line 37
    .line 38
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->j:Ljava/util/List;

    .line 39
    .line 40
    iput-object v1, v0, Ld2/i;->z:Ljava/util/List;

    .line 41
    .line 42
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->k:Lay0/k;

    .line 43
    .line 44
    iput-object v1, v0, Ld2/i;->A:Lay0/k;

    .line 45
    .line 46
    iget-object v1, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->l:Le3/t;

    .line 47
    .line 48
    iput-object v1, v0, Ld2/i;->B:Le3/t;

    .line 49
    .line 50
    iget-object p0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->m:Lay0/k;

    .line 51
    .line 52
    iput-object p0, v0, Ld2/i;->C:Lay0/k;

    .line 53
    .line 54
    return-object v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->b:Lg4/g;

    .line 2
    .line 3
    invoke-virtual {v0}, Lg4/g;->hashCode()I

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
    iget-object v2, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->c(IILg4/p0;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->d:Lk4/m;

    .line 17
    .line 18
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 19
    .line 20
    .line 21
    move-result v2

    .line 22
    add-int/2addr v2, v0

    .line 23
    mul-int/2addr v2, v1

    .line 24
    const/4 v0, 0x0

    .line 25
    iget-object v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->e:Lay0/k;

    .line 26
    .line 27
    if-eqz v3, :cond_0

    .line 28
    .line 29
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 30
    .line 31
    .line 32
    move-result v3

    .line 33
    goto :goto_0

    .line 34
    :cond_0
    move v3, v0

    .line 35
    :goto_0
    add-int/2addr v2, v3

    .line 36
    mul-int/2addr v2, v1

    .line 37
    iget v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->f:I

    .line 38
    .line 39
    invoke-static {v3, v2, v1}, Lc1/j0;->g(III)I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    iget-boolean v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->g:Z

    .line 44
    .line 45
    invoke-static {v2, v1, v3}, La7/g0;->e(IIZ)I

    .line 46
    .line 47
    .line 48
    move-result v2

    .line 49
    iget v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->h:I

    .line 50
    .line 51
    add-int/2addr v2, v3

    .line 52
    mul-int/2addr v2, v1

    .line 53
    iget v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->i:I

    .line 54
    .line 55
    add-int/2addr v2, v3

    .line 56
    mul-int/2addr v2, v1

    .line 57
    iget-object v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->j:Ljava/util/List;

    .line 58
    .line 59
    if-eqz v3, :cond_1

    .line 60
    .line 61
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 62
    .line 63
    .line 64
    move-result v3

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    move v3, v0

    .line 67
    :goto_1
    add-int/2addr v2, v3

    .line 68
    mul-int/2addr v2, v1

    .line 69
    iget-object v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->k:Lay0/k;

    .line 70
    .line 71
    if-eqz v3, :cond_2

    .line 72
    .line 73
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 74
    .line 75
    .line 76
    move-result v3

    .line 77
    goto :goto_2

    .line 78
    :cond_2
    move v3, v0

    .line 79
    :goto_2
    add-int/2addr v2, v3

    .line 80
    mul-int/lit16 v2, v2, 0x3c1

    .line 81
    .line 82
    iget-object v3, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->l:Le3/t;

    .line 83
    .line 84
    if-eqz v3, :cond_3

    .line 85
    .line 86
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 87
    .line 88
    .line 89
    move-result v3

    .line 90
    goto :goto_3

    .line 91
    :cond_3
    move v3, v0

    .line 92
    :goto_3
    add-int/2addr v2, v3

    .line 93
    mul-int/2addr v2, v1

    .line 94
    iget-object p0, p0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->m:Lay0/k;

    .line 95
    .line 96
    if-eqz p0, :cond_4

    .line 97
    .line 98
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 99
    .line 100
    .line 101
    move-result v0

    .line 102
    :cond_4
    add-int/2addr v2, v0

    .line 103
    return v2
.end method

.method public final j(Lx2/r;)V
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    check-cast v1, Ld2/i;

    .line 6
    .line 7
    iget-object v2, v1, Ld2/i;->B:Le3/t;

    .line 8
    .line 9
    iget-object v3, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->l:Le3/t;

    .line 10
    .line 11
    invoke-static {v3, v2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result v2

    .line 15
    iput-object v3, v1, Ld2/i;->B:Le3/t;

    .line 16
    .line 17
    if-eqz v2, :cond_1

    .line 18
    .line 19
    iget-object v2, v1, Ld2/i;->s:Lg4/p0;

    .line 20
    .line 21
    iget-object v3, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 22
    .line 23
    if-eq v3, v2, :cond_0

    .line 24
    .line 25
    iget-object v3, v3, Lg4/p0;->a:Lg4/g0;

    .line 26
    .line 27
    iget-object v2, v2, Lg4/p0;->a:Lg4/g0;

    .line 28
    .line 29
    invoke-virtual {v3, v2}, Lg4/g0;->c(Lg4/g0;)Z

    .line 30
    .line 31
    .line 32
    move-result v2

    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 37
    .line 38
    .line 39
    :goto_0
    const/4 v2, 0x0

    .line 40
    goto :goto_1

    .line 41
    :cond_1
    const/4 v2, 0x1

    .line 42
    :goto_1
    iget-object v3, v1, Ld2/i;->r:Lg4/g;

    .line 43
    .line 44
    iget-object v3, v3, Lg4/g;->e:Ljava/lang/String;

    .line 45
    .line 46
    iget-object v4, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->b:Lg4/g;

    .line 47
    .line 48
    iget-object v5, v4, Lg4/g;->e:Ljava/lang/String;

    .line 49
    .line 50
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 51
    .line 52
    .line 53
    move-result v3

    .line 54
    iget-object v5, v1, Ld2/i;->r:Lg4/g;

    .line 55
    .line 56
    iget-object v5, v5, Lg4/g;->d:Ljava/util/List;

    .line 57
    .line 58
    iget-object v6, v4, Lg4/g;->d:Ljava/util/List;

    .line 59
    .line 60
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v5

    .line 64
    if-eqz v3, :cond_3

    .line 65
    .line 66
    if-nez v5, :cond_2

    .line 67
    .line 68
    goto :goto_2

    .line 69
    :cond_2
    const/4 v5, 0x0

    .line 70
    goto :goto_3

    .line 71
    :cond_3
    :goto_2
    const/4 v5, 0x1

    .line 72
    :goto_3
    if-eqz v5, :cond_4

    .line 73
    .line 74
    iput-object v4, v1, Ld2/i;->r:Lg4/g;

    .line 75
    .line 76
    :cond_4
    if-nez v3, :cond_5

    .line 77
    .line 78
    const/4 v3, 0x0

    .line 79
    iput-object v3, v1, Ld2/i;->G:Ld2/h;

    .line 80
    .line 81
    :cond_5
    iget-object v3, v1, Ld2/i;->s:Lg4/p0;

    .line 82
    .line 83
    iget-object v4, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->c:Lg4/p0;

    .line 84
    .line 85
    invoke-virtual {v3, v4}, Lg4/p0;->c(Lg4/p0;)Z

    .line 86
    .line 87
    .line 88
    move-result v3

    .line 89
    const/4 v6, 0x1

    .line 90
    xor-int/2addr v3, v6

    .line 91
    iput-object v4, v1, Ld2/i;->s:Lg4/p0;

    .line 92
    .line 93
    iget-object v4, v1, Ld2/i;->z:Ljava/util/List;

    .line 94
    .line 95
    iget-object v7, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->j:Ljava/util/List;

    .line 96
    .line 97
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 98
    .line 99
    .line 100
    move-result v4

    .line 101
    if-nez v4, :cond_6

    .line 102
    .line 103
    iput-object v7, v1, Ld2/i;->z:Ljava/util/List;

    .line 104
    .line 105
    move v3, v6

    .line 106
    :cond_6
    iget v4, v1, Ld2/i;->y:I

    .line 107
    .line 108
    iget v7, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->i:I

    .line 109
    .line 110
    if-eq v4, v7, :cond_7

    .line 111
    .line 112
    iput v7, v1, Ld2/i;->y:I

    .line 113
    .line 114
    move v3, v6

    .line 115
    :cond_7
    iget v4, v1, Ld2/i;->x:I

    .line 116
    .line 117
    iget v7, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->h:I

    .line 118
    .line 119
    if-eq v4, v7, :cond_8

    .line 120
    .line 121
    iput v7, v1, Ld2/i;->x:I

    .line 122
    .line 123
    move v3, v6

    .line 124
    :cond_8
    iget-boolean v4, v1, Ld2/i;->w:Z

    .line 125
    .line 126
    iget-boolean v7, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->g:Z

    .line 127
    .line 128
    if-eq v4, v7, :cond_9

    .line 129
    .line 130
    iput-boolean v7, v1, Ld2/i;->w:Z

    .line 131
    .line 132
    move v3, v6

    .line 133
    :cond_9
    iget-object v4, v1, Ld2/i;->t:Lk4/m;

    .line 134
    .line 135
    iget-object v7, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->d:Lk4/m;

    .line 136
    .line 137
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 138
    .line 139
    .line 140
    move-result v4

    .line 141
    if-nez v4, :cond_a

    .line 142
    .line 143
    iput-object v7, v1, Ld2/i;->t:Lk4/m;

    .line 144
    .line 145
    move v3, v6

    .line 146
    :cond_a
    iget v4, v1, Ld2/i;->v:I

    .line 147
    .line 148
    iget v7, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->f:I

    .line 149
    .line 150
    if-ne v4, v7, :cond_b

    .line 151
    .line 152
    move v6, v3

    .line 153
    goto :goto_4

    .line 154
    :cond_b
    iput v7, v1, Ld2/i;->v:I

    .line 155
    .line 156
    :goto_4
    iget-object v3, v1, Ld2/i;->u:Lay0/k;

    .line 157
    .line 158
    iget-object v4, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->e:Lay0/k;

    .line 159
    .line 160
    const/4 v7, 0x1

    .line 161
    if-eq v3, v4, :cond_c

    .line 162
    .line 163
    iput-object v4, v1, Ld2/i;->u:Lay0/k;

    .line 164
    .line 165
    move v3, v7

    .line 166
    goto :goto_5

    .line 167
    :cond_c
    const/4 v3, 0x0

    .line 168
    :goto_5
    iget-object v4, v1, Ld2/i;->A:Lay0/k;

    .line 169
    .line 170
    iget-object v8, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->k:Lay0/k;

    .line 171
    .line 172
    if-eq v4, v8, :cond_d

    .line 173
    .line 174
    iput-object v8, v1, Ld2/i;->A:Lay0/k;

    .line 175
    .line 176
    move v3, v7

    .line 177
    :cond_d
    iget-object v4, v1, Ld2/i;->C:Lay0/k;

    .line 178
    .line 179
    iget-object v0, v0, Landroidx/compose/foundation/text/modifiers/TextAnnotatedStringElement;->m:Lay0/k;

    .line 180
    .line 181
    if-eq v4, v0, :cond_e

    .line 182
    .line 183
    iput-object v0, v1, Ld2/i;->C:Lay0/k;

    .line 184
    .line 185
    goto :goto_6

    .line 186
    :cond_e
    move v7, v3

    .line 187
    :goto_6
    if-nez v5, :cond_10

    .line 188
    .line 189
    if-nez v6, :cond_10

    .line 190
    .line 191
    if-eqz v7, :cond_f

    .line 192
    .line 193
    goto :goto_7

    .line 194
    :cond_f
    move/from16 p1, v5

    .line 195
    .line 196
    goto :goto_9

    .line 197
    :cond_10
    :goto_7
    invoke-virtual {v1}, Ld2/i;->X0()Ld2/d;

    .line 198
    .line 199
    .line 200
    move-result-object v0

    .line 201
    iget-object v3, v1, Ld2/i;->r:Lg4/g;

    .line 202
    .line 203
    iget-object v4, v1, Ld2/i;->s:Lg4/p0;

    .line 204
    .line 205
    iget-object v8, v1, Ld2/i;->t:Lk4/m;

    .line 206
    .line 207
    iget v9, v1, Ld2/i;->v:I

    .line 208
    .line 209
    iget-boolean v10, v1, Ld2/i;->w:Z

    .line 210
    .line 211
    iget v11, v1, Ld2/i;->x:I

    .line 212
    .line 213
    iget v12, v1, Ld2/i;->y:I

    .line 214
    .line 215
    iget-object v13, v1, Ld2/i;->z:Ljava/util/List;

    .line 216
    .line 217
    iput-object v3, v0, Ld2/d;->a:Lg4/g;

    .line 218
    .line 219
    iget-object v3, v0, Ld2/d;->k:Lg4/p0;

    .line 220
    .line 221
    invoke-virtual {v4, v3}, Lg4/p0;->c(Lg4/p0;)Z

    .line 222
    .line 223
    .line 224
    move-result v3

    .line 225
    iput-object v4, v0, Ld2/d;->k:Lg4/p0;

    .line 226
    .line 227
    const/4 v14, 0x0

    .line 228
    const/4 v15, 0x2

    .line 229
    if-nez v3, :cond_11

    .line 230
    .line 231
    move/from16 p1, v5

    .line 232
    .line 233
    iget-wide v4, v0, Ld2/d;->q:J

    .line 234
    .line 235
    shl-long v3, v4, v15

    .line 236
    .line 237
    iput-wide v3, v0, Ld2/d;->q:J

    .line 238
    .line 239
    iput-object v14, v0, Ld2/d;->l:Landroidx/lifecycle/c1;

    .line 240
    .line 241
    iput-object v14, v0, Ld2/d;->n:Lg4/l0;

    .line 242
    .line 243
    const/4 v3, -0x1

    .line 244
    iput v3, v0, Ld2/d;->p:I

    .line 245
    .line 246
    iput v3, v0, Ld2/d;->o:I

    .line 247
    .line 248
    goto :goto_8

    .line 249
    :cond_11
    move/from16 p1, v5

    .line 250
    .line 251
    :goto_8
    iput-object v8, v0, Ld2/d;->b:Lk4/m;

    .line 252
    .line 253
    iput v9, v0, Ld2/d;->c:I

    .line 254
    .line 255
    iput-boolean v10, v0, Ld2/d;->d:Z

    .line 256
    .line 257
    iput v11, v0, Ld2/d;->e:I

    .line 258
    .line 259
    iput v12, v0, Ld2/d;->f:I

    .line 260
    .line 261
    iput-object v13, v0, Ld2/d;->g:Ljava/util/List;

    .line 262
    .line 263
    iget-wide v3, v0, Ld2/d;->q:J

    .line 264
    .line 265
    shl-long/2addr v3, v15

    .line 266
    const-wide/16 v8, 0x2

    .line 267
    .line 268
    or-long/2addr v3, v8

    .line 269
    iput-wide v3, v0, Ld2/d;->q:J

    .line 270
    .line 271
    iput-object v14, v0, Ld2/d;->l:Landroidx/lifecycle/c1;

    .line 272
    .line 273
    iput-object v14, v0, Ld2/d;->n:Lg4/l0;

    .line 274
    .line 275
    const/4 v3, -0x1

    .line 276
    iput v3, v0, Ld2/d;->p:I

    .line 277
    .line 278
    iput v3, v0, Ld2/d;->o:I

    .line 279
    .line 280
    :goto_9
    iget-boolean v0, v1, Lx2/r;->q:Z

    .line 281
    .line 282
    if-nez v0, :cond_12

    .line 283
    .line 284
    goto :goto_a

    .line 285
    :cond_12
    if-nez p1, :cond_13

    .line 286
    .line 287
    if-eqz v2, :cond_14

    .line 288
    .line 289
    iget-object v0, v1, Ld2/i;->F:Ld2/f;

    .line 290
    .line 291
    if-eqz v0, :cond_14

    .line 292
    .line 293
    :cond_13
    invoke-static {v1}, Lv3/f;->o(Lv3/x1;)V

    .line 294
    .line 295
    .line 296
    :cond_14
    if-nez p1, :cond_15

    .line 297
    .line 298
    if-nez v6, :cond_15

    .line 299
    .line 300
    if-eqz v7, :cond_16

    .line 301
    .line 302
    :cond_15
    invoke-static {v1}, Lv3/f;->n(Lv3/y;)V

    .line 303
    .line 304
    .line 305
    invoke-static {v1}, Lv3/f;->m(Lv3/p;)V

    .line 306
    .line 307
    .line 308
    :cond_16
    if-eqz v2, :cond_17

    .line 309
    .line 310
    invoke-static {v1}, Lv3/f;->m(Lv3/p;)V

    .line 311
    .line 312
    .line 313
    :cond_17
    :goto_a
    return-void
.end method

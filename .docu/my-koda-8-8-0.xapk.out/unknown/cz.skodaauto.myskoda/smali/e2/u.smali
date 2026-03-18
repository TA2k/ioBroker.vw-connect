.class public final synthetic Le2/u;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:Landroidx/collection/h;

.field public final synthetic e:I

.field public final synthetic f:I

.field public final synthetic g:Lcom/google/android/gms/internal/measurement/i4;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Landroidx/collection/h;IILcom/google/android/gms/internal/measurement/i4;Llx0/i;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Le2/u;->d:Landroidx/collection/h;

    .line 5
    .line 6
    iput p2, p0, Le2/u;->e:I

    .line 7
    .line 8
    iput p3, p0, Le2/u;->f:I

    .line 9
    .line 10
    iput-object p4, p0, Le2/u;->g:Lcom/google/android/gms/internal/measurement/i4;

    .line 11
    .line 12
    iput-object p5, p0, Le2/u;->h:Ljava/lang/Object;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Le2/u;->d:Landroidx/collection/h;

    .line 4
    .line 5
    iget-object v2, v1, Landroidx/collection/h;->h:Ljava/lang/Object;

    .line 6
    .line 7
    check-cast v2, Lg4/l0;

    .line 8
    .line 9
    iget-object v3, v0, Le2/u;->h:Ljava/lang/Object;

    .line 10
    .line 11
    invoke-interface {v3}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    check-cast v3, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {v3}, Ljava/lang/Number;->intValue()I

    .line 18
    .line 19
    .line 20
    move-result v3

    .line 21
    iget-object v4, v0, Le2/u;->g:Lcom/google/android/gms/internal/measurement/i4;

    .line 22
    .line 23
    iget-boolean v5, v4, Lcom/google/android/gms/internal/measurement/i4;->e:Z

    .line 24
    .line 25
    invoke-virtual {v4}, Lcom/google/android/gms/internal/measurement/i4;->s()Le2/j;

    .line 26
    .line 27
    .line 28
    move-result-object v4

    .line 29
    sget-object v6, Le2/j;->d:Le2/j;

    .line 30
    .line 31
    const/4 v7, 0x0

    .line 32
    const/4 v8, 0x1

    .line 33
    if-ne v4, v6, :cond_0

    .line 34
    .line 35
    move v4, v8

    .line 36
    goto :goto_0

    .line 37
    :cond_0
    move v4, v7

    .line 38
    :goto_0
    iget v6, v0, Le2/u;->e:I

    .line 39
    .line 40
    invoke-virtual {v2, v6}, Lg4/l0;->j(I)J

    .line 41
    .line 42
    .line 43
    move-result-wide v9

    .line 44
    iget-object v11, v2, Lg4/l0;->b:Lg4/o;

    .line 45
    .line 46
    sget v12, Lg4/o0;->c:I

    .line 47
    .line 48
    const/16 v12, 0x20

    .line 49
    .line 50
    shr-long v12, v9, v12

    .line 51
    .line 52
    long-to-int v12, v12

    .line 53
    invoke-virtual {v11, v12}, Lg4/o;->d(I)I

    .line 54
    .line 55
    .line 56
    move-result v13

    .line 57
    iget v14, v11, Lg4/o;->f:I

    .line 58
    .line 59
    if-ne v13, v3, :cond_1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    if-lt v3, v14, :cond_2

    .line 63
    .line 64
    add-int/lit8 v12, v14, -0x1

    .line 65
    .line 66
    invoke-virtual {v2, v12}, Lg4/l0;->g(I)I

    .line 67
    .line 68
    .line 69
    move-result v12

    .line 70
    goto :goto_1

    .line 71
    :cond_2
    invoke-virtual {v2, v3}, Lg4/l0;->g(I)I

    .line 72
    .line 73
    .line 74
    move-result v12

    .line 75
    :goto_1
    const-wide v15, 0xffffffffL

    .line 76
    .line 77
    .line 78
    .line 79
    .line 80
    and-long/2addr v9, v15

    .line 81
    long-to-int v2, v9

    .line 82
    invoke-virtual {v11, v2}, Lg4/o;->d(I)I

    .line 83
    .line 84
    .line 85
    move-result v9

    .line 86
    if-ne v9, v3, :cond_3

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_3
    if-lt v3, v14, :cond_4

    .line 90
    .line 91
    sub-int/2addr v14, v8

    .line 92
    invoke-virtual {v11, v14, v7}, Lg4/o;->c(IZ)I

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    goto :goto_2

    .line 97
    :cond_4
    invoke-virtual {v11, v3, v7}, Lg4/o;->c(IZ)I

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    :goto_2
    iget v0, v0, Le2/u;->f:I

    .line 102
    .line 103
    if-ne v12, v0, :cond_5

    .line 104
    .line 105
    invoke-virtual {v1, v2}, Landroidx/collection/h;->b(I)Le2/r;

    .line 106
    .line 107
    .line 108
    move-result-object v0

    .line 109
    return-object v0

    .line 110
    :cond_5
    if-ne v2, v0, :cond_6

    .line 111
    .line 112
    invoke-virtual {v1, v12}, Landroidx/collection/h;->b(I)Le2/r;

    .line 113
    .line 114
    .line 115
    move-result-object v0

    .line 116
    return-object v0

    .line 117
    :cond_6
    xor-int v0, v5, v4

    .line 118
    .line 119
    if-eqz v0, :cond_7

    .line 120
    .line 121
    if-gt v6, v2, :cond_8

    .line 122
    .line 123
    goto :goto_3

    .line 124
    :cond_7
    if-lt v6, v12, :cond_9

    .line 125
    .line 126
    :cond_8
    move v12, v2

    .line 127
    :cond_9
    :goto_3
    invoke-virtual {v1, v12}, Landroidx/collection/h;->b(I)Le2/r;

    .line 128
    .line 129
    .line 130
    move-result-object v0

    .line 131
    return-object v0
.end method

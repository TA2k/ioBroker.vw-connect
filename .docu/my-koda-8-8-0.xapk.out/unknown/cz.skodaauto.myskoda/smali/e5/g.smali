.class public final Le5/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final h:Ljava/lang/String;

.field public static final i:Ljava/lang/String;

.field public static final j:Ljava/lang/String;

.field public static final k:Ljava/lang/String;

.field public static final l:Ljava/lang/String;

.field public static final m:Ljava/lang/String;


# instance fields
.field public a:I

.field public b:I

.field public c:F

.field public d:I

.field public e:Ljava/lang/String;

.field public f:Ljava/lang/String;

.field public g:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/String;

    .line 2
    .line 3
    const-string v1, "FIXED_DIMENSION"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Le5/g;->h:Ljava/lang/String;

    .line 9
    .line 10
    new-instance v0, Ljava/lang/String;

    .line 11
    .line 12
    const-string v1, "WRAP_DIMENSION"

    .line 13
    .line 14
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Le5/g;->i:Ljava/lang/String;

    .line 18
    .line 19
    new-instance v0, Ljava/lang/String;

    .line 20
    .line 21
    const-string v1, "SPREAD_DIMENSION"

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Le5/g;->j:Ljava/lang/String;

    .line 27
    .line 28
    new-instance v0, Ljava/lang/String;

    .line 29
    .line 30
    const-string v1, "PARENT_DIMENSION"

    .line 31
    .line 32
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Le5/g;->k:Ljava/lang/String;

    .line 36
    .line 37
    new-instance v0, Ljava/lang/String;

    .line 38
    .line 39
    const-string v1, "PERCENT_DIMENSION"

    .line 40
    .line 41
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    sput-object v0, Le5/g;->l:Ljava/lang/String;

    .line 45
    .line 46
    new-instance v0, Ljava/lang/String;

    .line 47
    .line 48
    const-string v1, "RATIO_DIMENSION"

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/String;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    sput-object v0, Le5/g;->m:Ljava/lang/String;

    .line 54
    .line 55
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Le5/g;->a:I

    .line 6
    .line 7
    const v1, 0x7fffffff

    .line 8
    .line 9
    .line 10
    iput v1, p0, Le5/g;->b:I

    .line 11
    .line 12
    const/high16 v1, 0x3f800000    # 1.0f

    .line 13
    .line 14
    iput v1, p0, Le5/g;->c:F

    .line 15
    .line 16
    iput v0, p0, Le5/g;->d:I

    .line 17
    .line 18
    const/4 v1, 0x0

    .line 19
    iput-object v1, p0, Le5/g;->e:Ljava/lang/String;

    .line 20
    .line 21
    iput-boolean v0, p0, Le5/g;->g:Z

    .line 22
    .line 23
    iput-object p1, p0, Le5/g;->f:Ljava/lang/String;

    .line 24
    .line 25
    return-void
.end method

.method public static b(I)Le5/g;
    .locals 2

    .line 1
    new-instance v0, Le5/g;

    .line 2
    .line 3
    sget-object v1, Le5/g;->h:Ljava/lang/String;

    .line 4
    .line 5
    invoke-direct {v0, v1}, Le5/g;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    iput-object v1, v0, Le5/g;->f:Ljava/lang/String;

    .line 10
    .line 11
    iput p0, v0, Le5/g;->d:I

    .line 12
    .line 13
    return-object v0
.end method

.method public static c(Ljava/lang/String;)Le5/g;
    .locals 3

    .line 1
    new-instance v0, Le5/g;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    const/4 v1, 0x0

    .line 7
    iput v1, v0, Le5/g;->a:I

    .line 8
    .line 9
    const v2, 0x7fffffff

    .line 10
    .line 11
    .line 12
    iput v2, v0, Le5/g;->b:I

    .line 13
    .line 14
    const/high16 v2, 0x3f800000    # 1.0f

    .line 15
    .line 16
    iput v2, v0, Le5/g;->c:F

    .line 17
    .line 18
    iput v1, v0, Le5/g;->d:I

    .line 19
    .line 20
    const/4 v1, 0x0

    .line 21
    iput-object v1, v0, Le5/g;->e:Ljava/lang/String;

    .line 22
    .line 23
    iput-object p0, v0, Le5/g;->f:Ljava/lang/String;

    .line 24
    .line 25
    const/4 p0, 0x1

    .line 26
    iput-boolean p0, v0, Le5/g;->g:Z

    .line 27
    .line 28
    return-object v0
.end method


# virtual methods
.method public final a(Lh5/d;I)V
    .locals 9

    .line 1
    iget-object v0, p0, Le5/g;->e:Ljava/lang/String;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p1, v0}, Lh5/d;->K(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    :cond_0
    const/4 v0, 0x1

    .line 9
    const/4 v1, 0x4

    .line 10
    sget-object v2, Le5/g;->k:Ljava/lang/String;

    .line 11
    .line 12
    const/4 v3, 0x2

    .line 13
    const v4, 0x7fffffff

    .line 14
    .line 15
    .line 16
    sget-object v5, Le5/g;->l:Ljava/lang/String;

    .line 17
    .line 18
    const/4 v6, 0x0

    .line 19
    const/4 v7, 0x3

    .line 20
    sget-object v8, Le5/g;->i:Ljava/lang/String;

    .line 21
    .line 22
    if-nez p2, :cond_9

    .line 23
    .line 24
    iget-boolean p2, p0, Le5/g;->g:Z

    .line 25
    .line 26
    if-eqz p2, :cond_3

    .line 27
    .line 28
    invoke-virtual {p1, v7}, Lh5/d;->O(I)V

    .line 29
    .line 30
    .line 31
    iget-object p2, p0, Le5/g;->f:Ljava/lang/String;

    .line 32
    .line 33
    if-ne p2, v8, :cond_1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    if-ne p2, v5, :cond_2

    .line 37
    .line 38
    move v0, v3

    .line 39
    goto :goto_0

    .line 40
    :cond_2
    move v0, v6

    .line 41
    :goto_0
    iget p2, p0, Le5/g;->a:I

    .line 42
    .line 43
    iget v1, p0, Le5/g;->b:I

    .line 44
    .line 45
    iget p0, p0, Le5/g;->c:F

    .line 46
    .line 47
    invoke-virtual {p1, v0, p2, v1, p0}, Lh5/d;->P(IIIF)V

    .line 48
    .line 49
    .line 50
    return-void

    .line 51
    :cond_3
    iget p2, p0, Le5/g;->a:I

    .line 52
    .line 53
    if-lez p2, :cond_5

    .line 54
    .line 55
    if-gez p2, :cond_4

    .line 56
    .line 57
    iput v6, p1, Lh5/d;->c0:I

    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_4
    iput p2, p1, Lh5/d;->c0:I

    .line 61
    .line 62
    :cond_5
    :goto_1
    iget p2, p0, Le5/g;->b:I

    .line 63
    .line 64
    if-ge p2, v4, :cond_6

    .line 65
    .line 66
    iget-object v4, p1, Lh5/d;->D:[I

    .line 67
    .line 68
    aput p2, v4, v6

    .line 69
    .line 70
    :cond_6
    iget-object p2, p0, Le5/g;->f:Ljava/lang/String;

    .line 71
    .line 72
    if-ne p2, v8, :cond_7

    .line 73
    .line 74
    invoke-virtual {p1, v3}, Lh5/d;->O(I)V

    .line 75
    .line 76
    .line 77
    return-void

    .line 78
    :cond_7
    if-ne p2, v2, :cond_8

    .line 79
    .line 80
    invoke-virtual {p1, v1}, Lh5/d;->O(I)V

    .line 81
    .line 82
    .line 83
    return-void

    .line 84
    :cond_8
    if-nez p2, :cond_12

    .line 85
    .line 86
    invoke-virtual {p1, v0}, Lh5/d;->O(I)V

    .line 87
    .line 88
    .line 89
    iget p0, p0, Le5/g;->d:I

    .line 90
    .line 91
    invoke-virtual {p1, p0}, Lh5/d;->S(I)V

    .line 92
    .line 93
    .line 94
    return-void

    .line 95
    :cond_9
    iget-boolean p2, p0, Le5/g;->g:Z

    .line 96
    .line 97
    if-eqz p2, :cond_c

    .line 98
    .line 99
    invoke-virtual {p1, v7}, Lh5/d;->Q(I)V

    .line 100
    .line 101
    .line 102
    iget-object p2, p0, Le5/g;->f:Ljava/lang/String;

    .line 103
    .line 104
    if-ne p2, v8, :cond_a

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_a
    if-ne p2, v5, :cond_b

    .line 108
    .line 109
    move v0, v3

    .line 110
    goto :goto_2

    .line 111
    :cond_b
    move v0, v6

    .line 112
    :goto_2
    iget p2, p0, Le5/g;->a:I

    .line 113
    .line 114
    iget v1, p0, Le5/g;->b:I

    .line 115
    .line 116
    iget p0, p0, Le5/g;->c:F

    .line 117
    .line 118
    invoke-virtual {p1, v0, p2, v1, p0}, Lh5/d;->R(IIIF)V

    .line 119
    .line 120
    .line 121
    return-void

    .line 122
    :cond_c
    iget p2, p0, Le5/g;->a:I

    .line 123
    .line 124
    if-lez p2, :cond_e

    .line 125
    .line 126
    if-gez p2, :cond_d

    .line 127
    .line 128
    iput v6, p1, Lh5/d;->d0:I

    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_d
    iput p2, p1, Lh5/d;->d0:I

    .line 132
    .line 133
    :cond_e
    :goto_3
    iget p2, p0, Le5/g;->b:I

    .line 134
    .line 135
    if-ge p2, v4, :cond_f

    .line 136
    .line 137
    iget-object v4, p1, Lh5/d;->D:[I

    .line 138
    .line 139
    aput p2, v4, v0

    .line 140
    .line 141
    :cond_f
    iget-object p2, p0, Le5/g;->f:Ljava/lang/String;

    .line 142
    .line 143
    if-ne p2, v8, :cond_10

    .line 144
    .line 145
    invoke-virtual {p1, v3}, Lh5/d;->Q(I)V

    .line 146
    .line 147
    .line 148
    return-void

    .line 149
    :cond_10
    if-ne p2, v2, :cond_11

    .line 150
    .line 151
    invoke-virtual {p1, v1}, Lh5/d;->Q(I)V

    .line 152
    .line 153
    .line 154
    return-void

    .line 155
    :cond_11
    if-nez p2, :cond_12

    .line 156
    .line 157
    invoke-virtual {p1, v0}, Lh5/d;->Q(I)V

    .line 158
    .line 159
    .line 160
    iget p0, p0, Le5/g;->d:I

    .line 161
    .line 162
    invoke-virtual {p1, p0}, Lh5/d;->N(I)V

    .line 163
    .line 164
    .line 165
    :cond_12
    return-void
.end method

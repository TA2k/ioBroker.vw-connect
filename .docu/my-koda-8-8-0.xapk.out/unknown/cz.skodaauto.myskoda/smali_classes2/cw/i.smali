.class public final Lcw/i;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lqz0/g;
.end annotation


# static fields
.field public static final Companion:Lcw/h;

.field public static final l:[Llx0/i;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Ljava/lang/String;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Lqy0/b;

.field public final g:Lcw/o;

.field public final h:Lcw/r;

.field public final i:Lqy0/c;

.field public final j:Lqy0/c;

.field public final k:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 6

    .line 1
    new-instance v0, Lcw/h;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcw/i;->Companion:Lcw/h;

    .line 7
    .line 8
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 9
    .line 10
    new-instance v1, Lc91/u;

    .line 11
    .line 12
    const/16 v2, 0x18

    .line 13
    .line 14
    invoke-direct {v1, v2}, Lc91/u;-><init>(I)V

    .line 15
    .line 16
    .line 17
    invoke-static {v0, v1}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    new-instance v2, Lc91/u;

    .line 22
    .line 23
    const/16 v3, 0x19

    .line 24
    .line 25
    invoke-direct {v2, v3}, Lc91/u;-><init>(I)V

    .line 26
    .line 27
    .line 28
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 29
    .line 30
    .line 31
    move-result-object v2

    .line 32
    new-instance v3, Lc91/u;

    .line 33
    .line 34
    const/16 v4, 0x1a

    .line 35
    .line 36
    invoke-direct {v3, v4}, Lc91/u;-><init>(I)V

    .line 37
    .line 38
    .line 39
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 40
    .line 41
    .line 42
    move-result-object v0

    .line 43
    const/16 v3, 0xb

    .line 44
    .line 45
    new-array v3, v3, [Llx0/i;

    .line 46
    .line 47
    const/4 v4, 0x0

    .line 48
    const/4 v5, 0x0

    .line 49
    aput-object v5, v3, v4

    .line 50
    .line 51
    const/4 v4, 0x1

    .line 52
    aput-object v5, v3, v4

    .line 53
    .line 54
    const/4 v4, 0x2

    .line 55
    aput-object v5, v3, v4

    .line 56
    .line 57
    const/4 v4, 0x3

    .line 58
    aput-object v5, v3, v4

    .line 59
    .line 60
    const/4 v4, 0x4

    .line 61
    aput-object v5, v3, v4

    .line 62
    .line 63
    const/4 v4, 0x5

    .line 64
    aput-object v1, v3, v4

    .line 65
    .line 66
    const/4 v1, 0x6

    .line 67
    aput-object v5, v3, v1

    .line 68
    .line 69
    const/4 v1, 0x7

    .line 70
    aput-object v5, v3, v1

    .line 71
    .line 72
    const/16 v1, 0x8

    .line 73
    .line 74
    aput-object v2, v3, v1

    .line 75
    .line 76
    const/16 v1, 0x9

    .line 77
    .line 78
    aput-object v0, v3, v1

    .line 79
    .line 80
    const/16 v0, 0xa

    .line 81
    .line 82
    aput-object v5, v3, v0

    .line 83
    .line 84
    sput-object v3, Lcw/i;->l:[Llx0/i;

    .line 85
    .line 86
    return-void
.end method

.method public constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqy0/b;Lcw/o;Lcw/r;Lqy0/c;Lqy0/c;Ljava/lang/String;)V
    .locals 3

    and-int/lit16 v0, p1, 0xff

    const/4 v1, 0x0

    const/16 v2, 0xff

    if-ne v2, v0, :cond_3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lcw/i;->a:Ljava/lang/String;

    iput-object p3, p0, Lcw/i;->b:Ljava/lang/String;

    iput-object p4, p0, Lcw/i;->c:Ljava/lang/String;

    iput-object p5, p0, Lcw/i;->d:Ljava/lang/String;

    iput-object p6, p0, Lcw/i;->e:Ljava/lang/String;

    iput-object p7, p0, Lcw/i;->f:Lqy0/b;

    iput-object p8, p0, Lcw/i;->g:Lcw/o;

    iput-object p9, p0, Lcw/i;->h:Lcw/r;

    and-int/lit16 p2, p1, 0x100

    if-nez p2, :cond_0

    .line 2
    sget-object p2, Lty0/b;->g:Lty0/b;

    .line 3
    iput-object p2, p0, Lcw/i;->i:Lqy0/c;

    goto :goto_0

    :cond_0
    iput-object p10, p0, Lcw/i;->i:Lqy0/c;

    :goto_0
    and-int/lit16 p2, p1, 0x200

    if-nez p2, :cond_1

    .line 4
    sget-object p2, Lty0/b;->g:Lty0/b;

    .line 5
    iput-object p2, p0, Lcw/i;->j:Lqy0/c;

    goto :goto_1

    :cond_1
    iput-object p11, p0, Lcw/i;->j:Lqy0/c;

    :goto_1
    and-int/lit16 p1, p1, 0x400

    if-nez p1, :cond_2

    iput-object v1, p0, Lcw/i;->k:Ljava/lang/String;

    return-void

    :cond_2
    iput-object p12, p0, Lcw/i;->k:Ljava/lang/String;

    return-void

    :cond_3
    sget-object p0, Lcw/g;->a:Lcw/g;

    invoke-virtual {p0}, Lcw/g;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    throw v1
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lqy0/b;Lcw/o;Lcw/r;Lqy0/c;Lqy0/c;Ljava/lang/String;)V
    .locals 1

    const-string v0, "developers"

    invoke-static {p6, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lcw/i;->a:Ljava/lang/String;

    .line 8
    iput-object p2, p0, Lcw/i;->b:Ljava/lang/String;

    .line 9
    iput-object p3, p0, Lcw/i;->c:Ljava/lang/String;

    .line 10
    iput-object p4, p0, Lcw/i;->d:Ljava/lang/String;

    .line 11
    iput-object p5, p0, Lcw/i;->e:Ljava/lang/String;

    .line 12
    iput-object p6, p0, Lcw/i;->f:Lqy0/b;

    .line 13
    iput-object p7, p0, Lcw/i;->g:Lcw/o;

    .line 14
    iput-object p8, p0, Lcw/i;->h:Lcw/r;

    .line 15
    iput-object p9, p0, Lcw/i;->i:Lqy0/c;

    .line 16
    iput-object p10, p0, Lcw/i;->j:Lqy0/c;

    .line 17
    iput-object p11, p0, Lcw/i;->k:Ljava/lang/String;

    return-void
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
    instance-of v1, p1, Lcw/i;

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
    check-cast p1, Lcw/i;

    .line 12
    .line 13
    iget-object v1, p0, Lcw/i;->a:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lcw/i;->a:Ljava/lang/String;

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
    iget-object v1, p0, Lcw/i;->b:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lcw/i;->b:Ljava/lang/String;

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
    iget-object v1, p0, Lcw/i;->c:Ljava/lang/String;

    .line 36
    .line 37
    iget-object v3, p1, Lcw/i;->c:Ljava/lang/String;

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
    iget-object v1, p0, Lcw/i;->d:Ljava/lang/String;

    .line 47
    .line 48
    iget-object v3, p1, Lcw/i;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lcw/i;->e:Ljava/lang/String;

    .line 58
    .line 59
    iget-object v3, p1, Lcw/i;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lcw/i;->f:Lqy0/b;

    .line 69
    .line 70
    iget-object v3, p1, Lcw/i;->f:Lqy0/b;

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
    iget-object v1, p0, Lcw/i;->g:Lcw/o;

    .line 80
    .line 81
    iget-object v3, p1, Lcw/i;->g:Lcw/o;

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
    iget-object v1, p0, Lcw/i;->h:Lcw/r;

    .line 91
    .line 92
    iget-object v3, p1, Lcw/i;->h:Lcw/r;

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
    iget-object v1, p0, Lcw/i;->i:Lqy0/c;

    .line 102
    .line 103
    iget-object v3, p1, Lcw/i;->i:Lqy0/c;

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
    iget-object v1, p0, Lcw/i;->j:Lqy0/c;

    .line 113
    .line 114
    iget-object v3, p1, Lcw/i;->j:Lqy0/c;

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
    iget-object p0, p0, Lcw/i;->k:Ljava/lang/String;

    .line 124
    .line 125
    iget-object p1, p1, Lcw/i;->k:Ljava/lang/String;

    .line 126
    .line 127
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 128
    .line 129
    .line 130
    move-result p0

    .line 131
    if-nez p0, :cond_c

    .line 132
    .line 133
    return v2

    .line 134
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcw/i;->a:Ljava/lang/String;

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
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lcw/i;->b:Ljava/lang/String;

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
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

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
    iget-object v3, p0, Lcw/i;->c:Ljava/lang/String;

    .line 24
    .line 25
    invoke-static {v0, v1, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object v3, p0, Lcw/i;->d:Ljava/lang/String;

    .line 30
    .line 31
    if-nez v3, :cond_1

    .line 32
    .line 33
    move v3, v2

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 36
    .line 37
    .line 38
    move-result v3

    .line 39
    :goto_1
    add-int/2addr v0, v3

    .line 40
    mul-int/2addr v0, v1

    .line 41
    iget-object v3, p0, Lcw/i;->e:Ljava/lang/String;

    .line 42
    .line 43
    if-nez v3, :cond_2

    .line 44
    .line 45
    move v3, v2

    .line 46
    goto :goto_2

    .line 47
    :cond_2
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 48
    .line 49
    .line 50
    move-result v3

    .line 51
    :goto_2
    add-int/2addr v0, v3

    .line 52
    mul-int/2addr v0, v1

    .line 53
    iget-object v3, p0, Lcw/i;->f:Lqy0/b;

    .line 54
    .line 55
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 56
    .line 57
    .line 58
    move-result v3

    .line 59
    add-int/2addr v3, v0

    .line 60
    mul-int/2addr v3, v1

    .line 61
    iget-object v0, p0, Lcw/i;->g:Lcw/o;

    .line 62
    .line 63
    if-nez v0, :cond_3

    .line 64
    .line 65
    move v0, v2

    .line 66
    goto :goto_3

    .line 67
    :cond_3
    invoke-virtual {v0}, Lcw/o;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v0

    .line 71
    :goto_3
    add-int/2addr v3, v0

    .line 72
    mul-int/2addr v3, v1

    .line 73
    iget-object v0, p0, Lcw/i;->h:Lcw/r;

    .line 74
    .line 75
    if-nez v0, :cond_4

    .line 76
    .line 77
    move v0, v2

    .line 78
    goto :goto_4

    .line 79
    :cond_4
    invoke-virtual {v0}, Lcw/r;->hashCode()I

    .line 80
    .line 81
    .line 82
    move-result v0

    .line 83
    :goto_4
    add-int/2addr v3, v0

    .line 84
    mul-int/2addr v3, v1

    .line 85
    iget-object v0, p0, Lcw/i;->i:Lqy0/c;

    .line 86
    .line 87
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 88
    .line 89
    .line 90
    move-result v0

    .line 91
    add-int/2addr v0, v3

    .line 92
    mul-int/2addr v0, v1

    .line 93
    iget-object v3, p0, Lcw/i;->j:Lqy0/c;

    .line 94
    .line 95
    invoke-virtual {v3}, Ljava/lang/Object;->hashCode()I

    .line 96
    .line 97
    .line 98
    move-result v3

    .line 99
    add-int/2addr v3, v0

    .line 100
    mul-int/2addr v3, v1

    .line 101
    iget-object p0, p0, Lcw/i;->k:Ljava/lang/String;

    .line 102
    .line 103
    if-nez p0, :cond_5

    .line 104
    .line 105
    goto :goto_5

    .line 106
    :cond_5
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    :goto_5
    add-int/2addr v3, v2

    .line 111
    return v3
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", artifactVersion="

    .line 2
    .line 3
    const-string v1, ", name="

    .line 4
    .line 5
    const-string v2, "Library(uniqueId="

    .line 6
    .line 7
    iget-object v3, p0, Lcw/i;->a:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lcw/i;->b:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    const-string v1, ", description="

    .line 16
    .line 17
    const-string v2, ", website="

    .line 18
    .line 19
    iget-object v3, p0, Lcw/i;->c:Ljava/lang/String;

    .line 20
    .line 21
    iget-object v4, p0, Lcw/i;->d:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    iget-object v1, p0, Lcw/i;->e:Ljava/lang/String;

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v1, ", developers="

    .line 32
    .line 33
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    iget-object v1, p0, Lcw/i;->f:Lqy0/b;

    .line 37
    .line 38
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v1, ", organization="

    .line 42
    .line 43
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    iget-object v1, p0, Lcw/i;->g:Lcw/o;

    .line 47
    .line 48
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    const-string v1, ", scm="

    .line 52
    .line 53
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 54
    .line 55
    .line 56
    iget-object v1, p0, Lcw/i;->h:Lcw/r;

    .line 57
    .line 58
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    const-string v1, ", licenses="

    .line 62
    .line 63
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 64
    .line 65
    .line 66
    iget-object v1, p0, Lcw/i;->i:Lqy0/c;

    .line 67
    .line 68
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 69
    .line 70
    .line 71
    const-string v1, ", funding="

    .line 72
    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    iget-object v1, p0, Lcw/i;->j:Lqy0/c;

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    const-string v1, ", tag="

    .line 82
    .line 83
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string v1, ")"

    .line 87
    .line 88
    iget-object p0, p0, Lcw/i;->k:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0
.end method

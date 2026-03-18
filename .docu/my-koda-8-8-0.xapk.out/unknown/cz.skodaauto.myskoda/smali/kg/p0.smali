.class public final Lkg/p0;
.super Ljava/lang/Object;
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
            "Lkg/p0;",
            ">;"
        }
    .end annotation
.end field

.field public static final Companion:Lkg/o0;

.field public static final o:[Llx0/i;


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljava/lang/String;

.field public final f:Ljava/util/List;

.field public final g:Lkg/o;

.field public final h:Ljava/util/List;

.field public final i:Ljava/util/List;

.field public final j:Z

.field public final k:Z

.field public final l:Ljava/lang/String;

.field public final m:Ljava/lang/String;

.field public final n:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Lkg/o0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lkg/p0;->Companion:Lkg/o0;

    .line 7
    .line 8
    new-instance v0, Lkg/l0;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, v1}, Lkg/l0;-><init>(I)V

    .line 12
    .line 13
    .line 14
    sput-object v0, Lkg/p0;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 15
    .line 16
    sget-object v0, Llx0/j;->e:Llx0/j;

    .line 17
    .line 18
    new-instance v2, Ljv0/c;

    .line 19
    .line 20
    const/16 v3, 0x11

    .line 21
    .line 22
    invoke-direct {v2, v3}, Ljv0/c;-><init>(I)V

    .line 23
    .line 24
    .line 25
    invoke-static {v0, v2}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 26
    .line 27
    .line 28
    move-result-object v2

    .line 29
    new-instance v3, Ljv0/c;

    .line 30
    .line 31
    const/16 v4, 0x12

    .line 32
    .line 33
    invoke-direct {v3, v4}, Ljv0/c;-><init>(I)V

    .line 34
    .line 35
    .line 36
    invoke-static {v0, v3}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 37
    .line 38
    .line 39
    move-result-object v3

    .line 40
    new-instance v4, Ljv0/c;

    .line 41
    .line 42
    const/16 v5, 0x13

    .line 43
    .line 44
    invoke-direct {v4, v5}, Ljv0/c;-><init>(I)V

    .line 45
    .line 46
    .line 47
    invoke-static {v0, v4}, Lpm/a;->c(Llx0/j;Lay0/a;)Llx0/i;

    .line 48
    .line 49
    .line 50
    move-result-object v0

    .line 51
    const/16 v4, 0xb

    .line 52
    .line 53
    new-array v4, v4, [Llx0/i;

    .line 54
    .line 55
    const/4 v5, 0x0

    .line 56
    const/4 v6, 0x0

    .line 57
    aput-object v6, v4, v5

    .line 58
    .line 59
    aput-object v6, v4, v1

    .line 60
    .line 61
    const/4 v1, 0x2

    .line 62
    aput-object v2, v4, v1

    .line 63
    .line 64
    const/4 v1, 0x3

    .line 65
    aput-object v6, v4, v1

    .line 66
    .line 67
    const/4 v1, 0x4

    .line 68
    aput-object v3, v4, v1

    .line 69
    .line 70
    const/4 v1, 0x5

    .line 71
    aput-object v0, v4, v1

    .line 72
    .line 73
    const/4 v0, 0x6

    .line 74
    aput-object v6, v4, v0

    .line 75
    .line 76
    const/4 v0, 0x7

    .line 77
    aput-object v6, v4, v0

    .line 78
    .line 79
    const/16 v0, 0x8

    .line 80
    .line 81
    aput-object v6, v4, v0

    .line 82
    .line 83
    const/16 v0, 0x9

    .line 84
    .line 85
    aput-object v6, v4, v0

    .line 86
    .line 87
    const/16 v0, 0xa

    .line 88
    .line 89
    aput-object v6, v4, v0

    .line 90
    .line 91
    sput-object v4, Lkg/p0;->o:[Llx0/i;

    .line 92
    .line 93
    return-void
.end method

.method public synthetic constructor <init>(ILjava/lang/String;Ljava/lang/String;Ljava/util/List;Lkg/o;Ljava/util/List;Ljava/util/List;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    and-int/lit16 v0, p1, 0x1ff

    const/4 v1, 0x0

    const/16 v2, 0x1ff

    if-ne v2, v0, :cond_2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Lkg/p0;->d:Ljava/lang/String;

    iput-object p3, p0, Lkg/p0;->e:Ljava/lang/String;

    iput-object p4, p0, Lkg/p0;->f:Ljava/util/List;

    iput-object p5, p0, Lkg/p0;->g:Lkg/o;

    iput-object p6, p0, Lkg/p0;->h:Ljava/util/List;

    iput-object p7, p0, Lkg/p0;->i:Ljava/util/List;

    iput-boolean p8, p0, Lkg/p0;->j:Z

    iput-boolean p9, p0, Lkg/p0;->k:Z

    iput-object p10, p0, Lkg/p0;->l:Ljava/lang/String;

    and-int/lit16 p2, p1, 0x200

    if-nez p2, :cond_0

    iput-object v1, p0, Lkg/p0;->m:Ljava/lang/String;

    goto :goto_0

    :cond_0
    iput-object p11, p0, Lkg/p0;->m:Ljava/lang/String;

    :goto_0
    and-int/lit16 p1, p1, 0x400

    if-nez p1, :cond_1

    iput-object v1, p0, Lkg/p0;->n:Ljava/lang/String;

    return-void

    :cond_1
    iput-object p12, p0, Lkg/p0;->n:Ljava/lang/String;

    return-void

    :cond_2
    sget-object p0, Lkg/n0;->a:Lkg/n0;

    invoke-virtual {p0}, Lkg/n0;->getDescriptor()Lsz0/g;

    move-result-object p0

    invoke-static {p1, v2, p0}, Luz0/b1;->l(IILsz0/g;)V

    throw v1
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/ArrayList;Lkg/o;Ljava/util/ArrayList;Ljava/util/ArrayList;ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V
    .locals 1

    const-string v0, "id"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "name"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "legalDisclaimers"

    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "subscriptionMonthlyFee"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "localizedPdfLinkLabel"

    invoke-static {p9, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-object p1, p0, Lkg/p0;->d:Ljava/lang/String;

    .line 4
    iput-object p2, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 5
    iput-object p3, p0, Lkg/p0;->f:Ljava/util/List;

    .line 6
    iput-object p4, p0, Lkg/p0;->g:Lkg/o;

    .line 7
    iput-object p5, p0, Lkg/p0;->h:Ljava/util/List;

    .line 8
    iput-object p6, p0, Lkg/p0;->i:Ljava/util/List;

    .line 9
    iput-boolean p7, p0, Lkg/p0;->j:Z

    .line 10
    iput-boolean p8, p0, Lkg/p0;->k:Z

    .line 11
    iput-object p9, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 12
    iput-object p10, p0, Lkg/p0;->m:Ljava/lang/String;

    .line 13
    iput-object p11, p0, Lkg/p0;->n:Ljava/lang/String;

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
    instance-of v1, p1, Lkg/p0;

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
    check-cast p1, Lkg/p0;

    .line 12
    .line 13
    iget-object v1, p0, Lkg/p0;->d:Ljava/lang/String;

    .line 14
    .line 15
    iget-object v3, p1, Lkg/p0;->d:Ljava/lang/String;

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
    iget-object v1, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 25
    .line 26
    iget-object v3, p1, Lkg/p0;->e:Ljava/lang/String;

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
    iget-object v1, p0, Lkg/p0;->f:Ljava/util/List;

    .line 36
    .line 37
    iget-object v3, p1, Lkg/p0;->f:Ljava/util/List;

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
    iget-object v1, p0, Lkg/p0;->g:Lkg/o;

    .line 47
    .line 48
    iget-object v3, p1, Lkg/p0;->g:Lkg/o;

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
    iget-object v1, p0, Lkg/p0;->h:Ljava/util/List;

    .line 58
    .line 59
    iget-object v3, p1, Lkg/p0;->h:Ljava/util/List;

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
    iget-object v1, p0, Lkg/p0;->i:Ljava/util/List;

    .line 69
    .line 70
    iget-object v3, p1, Lkg/p0;->i:Ljava/util/List;

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
    iget-boolean v1, p0, Lkg/p0;->j:Z

    .line 80
    .line 81
    iget-boolean v3, p1, Lkg/p0;->j:Z

    .line 82
    .line 83
    if-eq v1, v3, :cond_8

    .line 84
    .line 85
    return v2

    .line 86
    :cond_8
    iget-boolean v1, p0, Lkg/p0;->k:Z

    .line 87
    .line 88
    iget-boolean v3, p1, Lkg/p0;->k:Z

    .line 89
    .line 90
    if-eq v1, v3, :cond_9

    .line 91
    .line 92
    return v2

    .line 93
    :cond_9
    iget-object v1, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 94
    .line 95
    iget-object v3, p1, Lkg/p0;->l:Ljava/lang/String;

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
    iget-object v1, p0, Lkg/p0;->m:Ljava/lang/String;

    .line 105
    .line 106
    iget-object v3, p1, Lkg/p0;->m:Ljava/lang/String;

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
    iget-object p0, p0, Lkg/p0;->n:Ljava/lang/String;

    .line 116
    .line 117
    iget-object p1, p1, Lkg/p0;->n:Ljava/lang/String;

    .line 118
    .line 119
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    if-nez p0, :cond_c

    .line 124
    .line 125
    return v2

    .line 126
    :cond_c
    return v0
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lkg/p0;->d:Ljava/lang/String;

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
    iget-object v2, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-object v2, p0, Lkg/p0;->f:Ljava/util/List;

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-object v2, p0, Lkg/p0;->g:Lkg/o;

    .line 23
    .line 24
    invoke-virtual {v2}, Lkg/o;->hashCode()I

    .line 25
    .line 26
    .line 27
    move-result v2

    .line 28
    add-int/2addr v2, v0

    .line 29
    mul-int/2addr v2, v1

    .line 30
    iget-object v0, p0, Lkg/p0;->h:Ljava/util/List;

    .line 31
    .line 32
    invoke-static {v2, v1, v0}, Lia/b;->a(IILjava/util/List;)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-object v2, p0, Lkg/p0;->i:Ljava/util/List;

    .line 37
    .line 38
    invoke-static {v0, v1, v2}, Lia/b;->a(IILjava/util/List;)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-boolean v2, p0, Lkg/p0;->j:Z

    .line 43
    .line 44
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-boolean v2, p0, Lkg/p0;->k:Z

    .line 49
    .line 50
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-object v2, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 55
    .line 56
    invoke-static {v0, v1, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->d(IILjava/lang/String;)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    const/4 v2, 0x0

    .line 61
    iget-object v3, p0, Lkg/p0;->m:Ljava/lang/String;

    .line 62
    .line 63
    if-nez v3, :cond_0

    .line 64
    .line 65
    move v3, v2

    .line 66
    goto :goto_0

    .line 67
    :cond_0
    invoke-virtual {v3}, Ljava/lang/String;->hashCode()I

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    :goto_0
    add-int/2addr v0, v3

    .line 72
    mul-int/2addr v0, v1

    .line 73
    iget-object p0, p0, Lkg/p0;->n:Ljava/lang/String;

    .line 74
    .line 75
    if-nez p0, :cond_1

    .line 76
    .line 77
    goto :goto_1

    .line 78
    :cond_1
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 79
    .line 80
    .line 81
    move-result v2

    .line 82
    :goto_1
    add-int/2addr v0, v2

    .line 83
    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 5

    .line 1
    const-string v0, ", name="

    .line 2
    .line 3
    const-string v1, ", legalDisclaimers="

    .line 4
    .line 5
    const-string v2, "Tariff(id="

    .line 6
    .line 7
    iget-object v3, p0, Lkg/p0;->d:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v4, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 10
    .line 11
    invoke-static {v2, v3, v0, v4, v1}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iget-object v1, p0, Lkg/p0;->f:Ljava/util/List;

    .line 16
    .line 17
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    const-string v1, ", subscriptionMonthlyFee="

    .line 21
    .line 22
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    iget-object v1, p0, Lkg/p0;->g:Lkg/o;

    .line 26
    .line 27
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    const-string v1, ", conditionsSummary="

    .line 31
    .line 32
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v1, ", conditionsDetails="

    .line 36
    .line 37
    const-string v2, ", canBeUsedForUpgrade="

    .line 38
    .line 39
    iget-object v3, p0, Lkg/p0;->h:Ljava/util/List;

    .line 40
    .line 41
    iget-object v4, p0, Lkg/p0;->i:Ljava/util/List;

    .line 42
    .line 43
    invoke-static {v0, v3, v1, v4, v2}, La7/g0;->v(Ljava/lang/StringBuilder;Ljava/util/List;Ljava/lang/String;Ljava/util/List;Ljava/lang/String;)V

    .line 44
    .line 45
    .line 46
    const-string v1, ", canBeUsedForFollowUp="

    .line 47
    .line 48
    const-string v2, ", localizedPdfLinkLabel="

    .line 49
    .line 50
    iget-boolean v3, p0, Lkg/p0;->j:Z

    .line 51
    .line 52
    iget-boolean v4, p0, Lkg/p0;->k:Z

    .line 53
    .line 54
    invoke-static {v0, v3, v1, v4, v2}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 55
    .line 56
    .line 57
    const-string v1, ", promotionText="

    .line 58
    .line 59
    const-string v2, ", description="

    .line 60
    .line 61
    iget-object v3, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 62
    .line 63
    iget-object v4, p0, Lkg/p0;->m:Ljava/lang/String;

    .line 64
    .line 65
    invoke-static {v0, v3, v1, v4, v2}, Lf2/m0;->v(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    const-string v1, ")"

    .line 69
    .line 70
    iget-object p0, p0, Lkg/p0;->n:Ljava/lang/String;

    .line 71
    .line 72
    invoke-static {v0, p0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const-string v0, "dest"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lkg/p0;->d:Ljava/lang/String;

    .line 7
    .line 8
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object v0, p0, Lkg/p0;->e:Ljava/lang/String;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, p0, Lkg/p0;->f:Ljava/util/List;

    .line 17
    .line 18
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeStringList(Ljava/util/List;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lkg/p0;->g:Lkg/o;

    .line 22
    .line 23
    invoke-virtual {v0, p1, p2}, Lkg/o;->writeToParcel(Landroid/os/Parcel;I)V

    .line 24
    .line 25
    .line 26
    iget-object v0, p0, Lkg/p0;->h:Ljava/util/List;

    .line 27
    .line 28
    invoke-static {v0, p1}, Lvj/b;->p(Ljava/util/List;Landroid/os/Parcel;)Ljava/util/Iterator;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 33
    .line 34
    .line 35
    move-result v1

    .line 36
    if-eqz v1, :cond_0

    .line 37
    .line 38
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object v1

    .line 42
    check-cast v1, Lkg/f;

    .line 43
    .line 44
    invoke-virtual {v1, p1, p2}, Lkg/f;->writeToParcel(Landroid/os/Parcel;I)V

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    iget-object v0, p0, Lkg/p0;->i:Ljava/util/List;

    .line 49
    .line 50
    invoke-static {v0, p1}, Lvj/b;->p(Ljava/util/List;Landroid/os/Parcel;)Ljava/util/Iterator;

    .line 51
    .line 52
    .line 53
    move-result-object v0

    .line 54
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 55
    .line 56
    .line 57
    move-result v1

    .line 58
    if-eqz v1, :cond_1

    .line 59
    .line 60
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    check-cast v1, Lkg/i;

    .line 65
    .line 66
    invoke-virtual {v1, p1, p2}, Lkg/i;->writeToParcel(Landroid/os/Parcel;I)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_1
    iget-boolean p2, p0, Lkg/p0;->j:Z

    .line 71
    .line 72
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 73
    .line 74
    .line 75
    iget-boolean p2, p0, Lkg/p0;->k:Z

    .line 76
    .line 77
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 78
    .line 79
    .line 80
    iget-object p2, p0, Lkg/p0;->l:Ljava/lang/String;

    .line 81
    .line 82
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    iget-object p2, p0, Lkg/p0;->m:Ljava/lang/String;

    .line 86
    .line 87
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 88
    .line 89
    .line 90
    iget-object p0, p0, Lkg/p0;->n:Ljava/lang/String;

    .line 91
    .line 92
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeString(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    return-void
.end method

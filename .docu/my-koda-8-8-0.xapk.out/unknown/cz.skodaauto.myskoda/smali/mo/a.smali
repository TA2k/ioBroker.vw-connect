.class public final Lmo/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final d:Lmo/c;

.field public e:I


# direct methods
.method public constructor <init>(Lmo/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmo/a;->d:Lmo/c;

    .line 5
    .line 6
    const/4 p1, -0x1

    .line 7
    iput p1, p0, Lmo/a;->e:I

    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Lmo/a;->e:I

    .line 2
    .line 3
    iget-object p0, p0, Lmo/a;->d:Lmo/c;

    .line 4
    .line 5
    invoke-virtual {p0}, Lmo/c;->B()V

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-virtual {p0}, Ljava/util/ArrayList;->size()I

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    add-int/lit8 p0, p0, -0x1

    .line 15
    .line 16
    if-ge v0, p0, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x1

    .line 19
    return p0

    .line 20
    :cond_0
    const/4 p0, 0x0

    .line 21
    return p0
.end method

.method public final next()Ljava/lang/Object;
    .locals 6

    .line 1
    invoke-virtual {p0}, Lmo/a;->hasNext()Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    if-eqz v0, :cond_3

    .line 6
    .line 7
    iget v0, p0, Lmo/a;->e:I

    .line 8
    .line 9
    add-int/lit8 v1, v0, 0x1

    .line 10
    .line 11
    iput v1, p0, Lmo/a;->e:I

    .line 12
    .line 13
    iget-object p0, p0, Lmo/a;->d:Lmo/c;

    .line 14
    .line 15
    iget-object v2, p0, Lmo/c;->d:Lcom/google/android/gms/common/data/DataHolder;

    .line 16
    .line 17
    invoke-virtual {p0}, Lmo/c;->B()V

    .line 18
    .line 19
    .line 20
    invoke-virtual {p0, v1}, Lmo/c;->k(I)I

    .line 21
    .line 22
    .line 23
    move-result v3

    .line 24
    const/4 v4, 0x0

    .line 25
    if-ltz v1, :cond_2

    .line 26
    .line 27
    iget-object v5, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 28
    .line 29
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 30
    .line 31
    .line 32
    move-result v5

    .line 33
    if-ne v1, v5, :cond_0

    .line 34
    .line 35
    goto :goto_2

    .line 36
    :cond_0
    iget-object v4, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 37
    .line 38
    invoke-virtual {v4}, Ljava/util/ArrayList;->size()I

    .line 39
    .line 40
    .line 41
    move-result v4

    .line 42
    add-int/lit8 v4, v4, -0x1

    .line 43
    .line 44
    if-ne v1, v4, :cond_1

    .line 45
    .line 46
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget v0, v2, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 50
    .line 51
    iget-object v4, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 52
    .line 53
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object v4

    .line 57
    check-cast v4, Ljava/lang/Integer;

    .line 58
    .line 59
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 60
    .line 61
    .line 62
    move-result v4

    .line 63
    :goto_0
    sub-int/2addr v0, v4

    .line 64
    move v4, v0

    .line 65
    goto :goto_1

    .line 66
    :cond_1
    iget-object v4, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 67
    .line 68
    add-int/lit8 v0, v0, 0x2

    .line 69
    .line 70
    invoke-virtual {v4, v0}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v0

    .line 74
    check-cast v0, Ljava/lang/Integer;

    .line 75
    .line 76
    invoke-virtual {v0}, Ljava/lang/Integer;->intValue()I

    .line 77
    .line 78
    .line 79
    move-result v0

    .line 80
    iget-object v4, p0, Lmo/c;->f:Ljava/util/ArrayList;

    .line 81
    .line 82
    invoke-virtual {v4, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    check-cast v4, Ljava/lang/Integer;

    .line 87
    .line 88
    invoke-virtual {v4}, Ljava/lang/Integer;->intValue()I

    .line 89
    .line 90
    .line 91
    move-result v4

    .line 92
    goto :goto_0

    .line 93
    :goto_1
    const/4 v0, 0x1

    .line 94
    if-ne v4, v0, :cond_2

    .line 95
    .line 96
    invoke-virtual {p0, v1}, Lmo/c;->k(I)I

    .line 97
    .line 98
    .line 99
    move-result v1

    .line 100
    invoke-static {v2}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-virtual {v2, v1}, Lcom/google/android/gms/common/data/DataHolder;->x0(I)I

    .line 104
    .line 105
    .line 106
    move v4, v0

    .line 107
    :cond_2
    :goto_2
    invoke-virtual {p0, v3, v4}, Lmo/c;->g(II)Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object p0

    .line 111
    return-object p0

    .line 112
    :cond_3
    new-instance v0, Ljava/util/NoSuchElementException;

    .line 113
    .line 114
    iget p0, p0, Lmo/a;->e:I

    .line 115
    .line 116
    const-string v1, "Cannot advance the iterator beyond "

    .line 117
    .line 118
    invoke-static {p0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 119
    .line 120
    .line 121
    move-result-object p0

    .line 122
    invoke-direct {v0, p0}, Ljava/util/NoSuchElementException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw v0
.end method

.method public final remove()V
    .locals 1

    .line 1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 2
    .line 3
    const-string v0, "Cannot remove elements from a DataBufferIterator"

    .line 4
    .line 5
    invoke-direct {p0, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    throw p0
.end method
